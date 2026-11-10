from collections.abc import AsyncGenerator
import asyncio
from contextlib import asynccontextmanager, suppress
import os
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app import models
from app.admin import router as admin_router
from app.auth import router as auth_router
from app.bootstrap import bootstrap_admin, bootstrap_demo_accounts
from app.config import Settings, vercel_blob_credentials_available
from app.database import (
    build_engine,
    ensure_audit_chain_lock,
    ensure_download_permission_column,
    ensure_document_storage_provider_column,
    ensure_document_storage_state_column,
    ensure_user_display_name_column,
    get_db,
    settings as default_settings,
)
from app.documents import router as documents_router
from app.storage import (
    DocumentStorage,
    FilesystemStorage,
    StorageProviderRegistry,
    VercelBlobStorage,
)
from app.storage_operations import recover_storage_operations

logger = logging.getLogger(__name__)
STORAGE_RECOVERY_INTERVAL_SECONDS = 30
FRONTEND_BUILD_DIRECTORY = Path(__file__).resolve().parents[2] / "frontend" / "dist"


async def _storage_recovery_loop(app: FastAPI) -> None:
    while True:
        await asyncio.sleep(STORAGE_RECOVERY_INTERVAL_SECONDS)
        recovery_task = asyncio.create_task(
            asyncio.to_thread(
                recover_storage_operations,
                app.state.session_factory,
                app.state.storage_providers,
            )
        )
        try:
            processed, completed = await asyncio.shield(recovery_task)
            if processed:
                logger.info(
                    "Storage recovery processed %d operations; completed %d",
                    processed,
                    completed,
                )
        except asyncio.CancelledError:
            try:
                await recovery_task
            except SQLAlchemyError as error:
                logger.error(
                    "Storage recovery shutdown wait failed (%s)",
                    type(error).__name__,
                )
            raise
        except SQLAlchemyError as error:
            logger.error(
                "Storage recovery pass failed (%s)", type(error).__name__
            )


def create_app(
    database_url: str | None = None,
    cookie_secure: bool | None = None,
    session_lifetime_seconds: int | None = None,
    storage_directory: str | None = None,
    storage_provider: str | None = None,
    cookie_samesite: str | None = None,
    frontend_origins: tuple[str, ...] | None = None,
    bootstrap_admin_email: str | None = None,
    bootstrap_admin_password: str | None = None,
    seed_demo_accounts: bool | None = None,
    demo_admin_password: str | None = None,
    demo_owner_password: str | None = None,
    demo_viewer_password: str | None = None,
) -> FastAPI:
    settings = Settings(
        database_url=database_url or default_settings.database_url,
        storage_directory=(
            default_settings.storage_directory
            if storage_directory is None
            else storage_directory
        ),
        storage_provider=(
            default_settings.storage_provider
            if storage_provider is None
            else storage_provider
        ),
        session_cookie_name=default_settings.session_cookie_name,
        session_lifetime_seconds=(
            default_settings.session_lifetime_seconds
            if session_lifetime_seconds is None
            else session_lifetime_seconds
        ),
        cookie_secure=(
            default_settings.cookie_secure if cookie_secure is None else cookie_secure
        ),
        cookie_samesite=(
            default_settings.cookie_samesite
            if cookie_samesite is None
            else cookie_samesite
        ),
        frontend_origins=(
            default_settings.frontend_origins
            if frontend_origins is None
            else frontend_origins
        ),
        bootstrap_admin_email=(
            default_settings.bootstrap_admin_email
            if bootstrap_admin_email is None
            else bootstrap_admin_email
        ),
        bootstrap_admin_password=(
            default_settings.bootstrap_admin_password
            if bootstrap_admin_password is None
            else bootstrap_admin_password
        ),
        seed_demo_accounts=(
            default_settings.seed_demo_accounts
            if seed_demo_accounts is None
            else seed_demo_accounts
        ),
        demo_admin_password=(
            default_settings.demo_admin_password
            if demo_admin_password is None
            else demo_admin_password
        ),
        demo_owner_password=(
            default_settings.demo_owner_password
            if demo_owner_password is None
            else demo_owner_password
        ),
        demo_viewer_password=(
            default_settings.demo_viewer_password
            if demo_viewer_password is None
            else demo_viewer_password
        ),
    )
    storage_path = Path(settings.storage_directory).resolve()
    frontend_path = (Path(__file__).resolve().parents[2] / "frontend").resolve()
    if storage_path == frontend_path or frontend_path in storage_path.parents:
        raise ValueError("Document storage must be outside the frontend directory")
    blob_credentials_available = vercel_blob_credentials_available()
    if settings.storage_provider == "vercel_blob" and not blob_credentials_available:
        raise ValueError(
            "Vercel Blob requires BLOB_READ_WRITE_TOKEN or a connected Vercel Blob store"
        )
    providers: dict[str, DocumentStorage] = {
        "filesystem": FilesystemStorage(storage_path)
    }
    if blob_credentials_available:
        providers["vercel_blob"] = VercelBlobStorage()
    storage_providers = StorageProviderRegistry(providers)
    storage_providers.get(settings.storage_provider)
    engine = build_engine(settings.database_url)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def db_dependency():
        with session_factory() as db:
            yield db

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        models.Base.metadata.create_all(bind=app.state.engine)
        ensure_audit_chain_lock(app.state.engine)
        ensure_download_permission_column(app.state.engine)
        ensure_user_display_name_column(app.state.engine)
        ensure_document_storage_provider_column(app.state.engine)
        ensure_document_storage_state_column(app.state.engine)
        if (
            app.state.settings.bootstrap_admin_email is not None
            and app.state.settings.bootstrap_admin_password is not None
        ):
            created = bootstrap_admin(
                app.state.session_factory,
                app.state.settings.bootstrap_admin_email,
                app.state.settings.bootstrap_admin_password,
            )
            if created:
                logger.info("Bootstrap administrator created.")
            else:
                logger.warning(
                    "Bootstrap administrator was not created because the "
                    "configured email is already registered; no account was changed."
                )
        if app.state.settings.seed_demo_accounts:
            admin_password = app.state.settings.demo_admin_password
            owner_password = app.state.settings.demo_owner_password
            viewer_password = app.state.settings.demo_viewer_password
            if (
                admin_password is None
                or owner_password is None
                or viewer_password is None
            ):
                raise RuntimeError(
                    "Demo-account seeding is enabled but demo passwords are missing"
                )
            created, existing = bootstrap_demo_accounts(
                app.state.session_factory,
                admin_password,
                owner_password,
                viewer_password,
            )
            logger.info(
                "Demo account seeding completed: created %d, left existing %d.",
                created,
                existing,
            )
        app.state.storage_directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            app.state.storage_directory.chmod(0o700)
        processed, completed = recover_storage_operations(
            app.state.session_factory, app.state.storage_providers
        )
        if processed:
            logger.info(
                "Storage recovery processed %d operations; completed %d",
                processed,
                completed,
            )
        recovery_task = asyncio.create_task(_storage_recovery_loop(app))
        try:
            yield
        finally:
            recovery_task.cancel()
            with suppress(asyncio.CancelledError):
                await recovery_task
            app.state.engine.dispose()
    app = FastAPI(title="TrustVault API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.frontend_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.storage_directory = storage_path
    app.state.storage_providers = storage_providers
    app.state.default_storage_provider = settings.storage_provider
    app.state.session_factory = session_factory
    app.dependency_overrides[get_db] = db_dependency
    app.include_router(auth_router)
    app.include_router(documents_router)
    app.include_router(admin_router)
    app.include_router(auth_router, prefix="/api", include_in_schema=False)
    app.include_router(documents_router, prefix="/api", include_in_schema=False)
    app.include_router(admin_router, prefix="/api", include_in_schema=False)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    frontend_directory = FRONTEND_BUILD_DIRECTORY.resolve()
    assets_directory = (frontend_directory / "assets").resolve()
    if assets_directory.is_relative_to(frontend_directory) and assets_directory.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=assets_directory),
            name="frontend-assets",
        )

    def frontend_index() -> FileResponse:
        index_file = (frontend_directory / "index.html").resolve()
        if (
            not index_file.is_relative_to(frontend_directory)
            or not index_file.is_file()
        ):
            raise HTTPException(
                status_code=503,
                detail="Frontend build is unavailable. Build frontend/dist before serving the app.",
            )
        return FileResponse(index_file)

    @app.get("/", include_in_schema=False)
    def frontend_root() -> FileResponse:
        return frontend_index()

    @app.get("/{frontend_path:path}", include_in_schema=False)
    def frontend_route(frontend_path: str) -> FileResponse:
        if frontend_path.split("/", maxsplit=1)[0].lower() in {
            "admin",
            "api",
            "auth",
            "documents",
            "health",
            "docs",
            "redoc",
            "openapi.json",
        }:
            raise HTTPException(status_code=404, detail="Not Found")

        requested_file = (frontend_directory / frontend_path).resolve()
        try:
            requested_file.relative_to(frontend_directory)
        except ValueError:
            raise HTTPException(status_code=404, detail="Not Found") from None

        if requested_file.is_file():
            return FileResponse(requested_file)
        if Path(frontend_path).suffix:
            raise HTTPException(status_code=404, detail="Not Found")

        return frontend_index()

    return app


app = create_app()
