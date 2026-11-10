from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings


class Base(DeclarativeBase):
    pass


def build_engine(database_url: str):
    is_sqlite = database_url.startswith("sqlite")
    if not is_sqlite:
        raise ValueError("TrustVault supports SQLite databases only")

    is_memory_sqlite = database_url in {"sqlite://", "sqlite:///:memory:"}
    database_name = make_url(database_url).database
    if (
        database_name
        and database_name != ":memory:"
        and not (
            database_name.startswith("file:")
            and "mode=memory" in database_url
        )
    ):
        Path(database_name).expanduser().parent.mkdir(parents=True, exist_ok=True)
    connect_args = (
        {"check_same_thread": False, "timeout": 30} if is_sqlite else {}
    )
    pool_args = {"poolclass": StaticPool} if is_memory_sqlite else {}
    engine = create_engine(database_url, connect_args=connect_args, **pool_args)

    if is_sqlite:
        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(connection, _record):
            del _record
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def ensure_audit_chain_lock(engine: Engine) -> None:
    from app.models import AuditChainLock

    table = AuditChainLock.__table__
    with engine.begin() as connection:
        if engine.dialect.name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert
        else:
            raise RuntimeError(
                f"Audit chain serialization is unsupported for "
                f"{engine.dialect.name}"
            )
        connection.execute(
            insert(table).values(id=1).on_conflict_do_nothing(index_elements=["id"])
        )


def ensure_download_permission_column(engine: Engine) -> None:
    inspector = inspect(engine)
    if "document_permissions" not in inspector.get_table_names():
        return
    if "can_download" in {
        column["name"] for column in inspector.get_columns("document_permissions")
    }:
        return

    with engine.begin() as connection:
        columns = {
            column["name"]
            for column in inspect(connection).get_columns("document_permissions")
        }
        if "can_download" not in columns:
            connection.execute(
                text(
                    "ALTER TABLE document_permissions "
                    "ADD COLUMN can_download BOOLEAN NOT NULL DEFAULT FALSE"
                )
            )


def ensure_document_storage_provider_column(engine: Engine) -> None:
    inspector = inspect(engine)
    if "documents" not in inspector.get_table_names():
        return

    with engine.connect() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            connection.begin()
        try:
            columns = {
                column["name"]
                for column in inspect(connection).get_columns("documents")
            }
            if "storage_provider" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE documents ADD COLUMN storage_provider "
                        "VARCHAR(32) NOT NULL DEFAULT 'filesystem'"
                    )
                )
            connection.execute(
                text(
                    "UPDATE documents SET storage_provider = 'filesystem' "
                    "WHERE storage_provider IS NULL OR trim(storage_provider) = ''"
                )
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def ensure_document_storage_state_column(engine: Engine) -> None:
    if "documents" not in inspect(engine).get_table_names():
        return

    with engine.connect() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            connection.begin()
        try:
            columns = {
                column["name"]
                for column in inspect(connection).get_columns("documents")
            }
            if "storage_state" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE documents ADD COLUMN storage_state "
                        "VARCHAR(16) NOT NULL DEFAULT 'active'"
                    )
                )
            connection.execute(
                text(
                    "UPDATE documents SET storage_state = 'active' "
                    "WHERE storage_state IS NULL OR trim(storage_state) = ''"
                )
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def ensure_user_display_name_column(engine: Engine) -> None:
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    with engine.connect() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            connection.begin()
        try:
            _upgrade_user_display_name(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def _upgrade_user_display_name(connection: Connection) -> None:
    if "users" not in inspect(connection).get_table_names():
        return
    columns = {
        column["name"] for column in inspect(connection).get_columns("users")
    }
    if "display_name" not in columns:
        connection.execute(
            text(
                "ALTER TABLE users ADD COLUMN display_name "
                "VARCHAR(254) NOT NULL DEFAULT ''"
            )
        )
    connection.execute(
        text(
            "UPDATE users SET display_name = email "
            "WHERE display_name IS NULL OR trim(display_name) = ''"
        )
    )


settings = Settings.from_environment()
engine = build_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as db:
        yield db
