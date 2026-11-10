from fastapi.testclient import TestClient
import pytest

import app.main as main_module
from app.config import Settings
from app.database import build_engine
from app.main import create_app


FRONTEND_ORIGIN = "https://trustvault-frontend.onrender.com"


@pytest.fixture
def cors_client(tmp_path):
    app = create_app(
        "sqlite://",
        cookie_secure=True,
        cookie_samesite="none",
        storage_directory=str(tmp_path / "private-storage"),
        frontend_origins=(FRONTEND_ORIGIN,),
    )
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def test_credentialed_cors_preflight_allows_frontend_and_csrf_headers(cors_client):
    response = cors_client.options(
        "/auth/login",
        headers={
            "Origin": FRONTEND_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == FRONTEND_ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    assert "POST" in response.headers["access-control-allow-methods"]
    allowed_headers = response.headers["access-control-allow-headers"].lower()
    assert "content-type" in allowed_headers
    assert "x-csrf-token" in allowed_headers


def test_cross_origin_csrf_registration_and_login_keep_secure_cookies(cors_client):
    csrf_response = cors_client.get(
        "/auth/csrf", headers={"Origin": FRONTEND_ORIGIN}
    )
    assert csrf_response.status_code == 200
    assert csrf_response.headers["access-control-allow-origin"] == FRONTEND_ORIGIN
    assert csrf_response.headers["access-control-allow-credentials"] == "true"
    assert "samesite=none" in csrf_response.headers["set-cookie"].lower()
    assert "secure" in csrf_response.headers["set-cookie"].lower()

    token = csrf_response.json()["csrf_token"]
    registration = cors_client.post(
        "/auth/register",
        headers={"Origin": FRONTEND_ORIGIN, "X-CSRF-Token": token},
        json={"email": "person@example.com", "password": "a-strong-password"},
    )
    assert registration.status_code == 201
    assert registration.headers["access-control-allow-origin"] == FRONTEND_ORIGIN

    token = cors_client.get("/auth/csrf").json()["csrf_token"]
    login = cors_client.post(
        "/auth/login",
        headers={"Origin": FRONTEND_ORIGIN, "X-CSRF-Token": token},
        json={"email": "person@example.com", "password": "a-strong-password"},
    )
    assert login.status_code == 200
    assert "httponly" in login.headers["set-cookie"].lower()
    assert "samesite=none" in login.headers["set-cookie"].lower()
    assert "secure" in login.headers["set-cookie"].lower()


def test_unapproved_origin_is_not_granted_cors_access(cors_client):
    response = cors_client.options(
        "/auth/login",
        headers={
            "Origin": "https://unapproved.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_settings_reject_non_sqlite_database_and_wildcard_origin():
    with pytest.raises(ValueError, match="SQLite"):
        Settings(database_url="postgresql://example")

    with pytest.raises(ValueError, match="explicit HTTP"):
        Settings(frontend_origins=("*",))


def test_samesite_none_requires_secure_cookies():
    with pytest.raises(ValueError, match="require Secure"):
        Settings(cookie_samesite="none", cookie_secure=False)


def test_demo_seed_requires_explicit_opt_in_and_all_passwords():
    with pytest.raises(ValueError, match="Enable demo-account seeding"):
        Settings(demo_admin_password="a-strong-demo-password")

    with pytest.raises(ValueError, match="requires all three"):
        Settings(seed_demo_accounts=True, demo_admin_password="a-strong-demo-password")

    with pytest.raises(ValueError, match="12 to 128 characters"):
        Settings(
            seed_demo_accounts=True,
            demo_admin_password="short",
            demo_owner_password="a-strong-owner-password",
            demo_viewer_password="a-strong-viewer-password",
        )


def test_demo_seed_settings_are_read_from_environment(monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_SEED_DEMO_ACCOUNTS", "true")
    monkeypatch.setenv("TRUSTVAULT_DEMO_ADMIN_PASSWORD", "a-strong-admin-password")
    monkeypatch.setenv("TRUSTVAULT_DEMO_OWNER_PASSWORD", "a-strong-owner-password")
    monkeypatch.setenv("TRUSTVAULT_DEMO_VIEWER_PASSWORD", "a-strong-viewer-password")

    settings = Settings.from_environment()

    assert settings.seed_demo_accounts is True
    assert settings.demo_admin_password == "a-strong-admin-password"
    assert settings.demo_owner_password == "a-strong-owner-password"
    assert settings.demo_viewer_password == "a-strong-viewer-password"


def test_sqlite_database_parent_directory_is_created(tmp_path):
    database_path = tmp_path / "nested" / "data" / "trustvault.db"
    engine = build_engine(f"sqlite:///{database_path.as_posix()}")
    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT 1").scalar_one() == 1
        assert database_path.is_file()
    finally:
        engine.dispose()


def test_frontend_is_served_with_spa_fallback_and_api_routes(tmp_path, monkeypatch):
    frontend_directory = tmp_path / "dist"
    assets_directory = frontend_directory / "assets"
    assets_directory.mkdir(parents=True)
    (frontend_directory / "index.html").write_text(
        "<!doctype html><title>TrustVault test frontend</title>",
        encoding="utf-8",
    )
    (frontend_directory / "favicon.svg").write_text(
        "<svg></svg>",
        encoding="utf-8",
    )
    (assets_directory / "app.js").write_text("console.log('test')", encoding="utf-8")
    monkeypatch.setattr(main_module, "FRONTEND_BUILD_DIRECTORY", frontend_directory)

    app = create_app(
        "sqlite://",
        storage_directory=str(tmp_path / "private-storage"),
    )
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert "TrustVault test frontend" in client.get("/").text
        assert client.get("/dashboard").status_code == 200
        assert client.get("/favicon.svg").text == "<svg></svg>"
        assert client.get("/assets/app.js").text == "console.log('test')"
        assert client.get("/api/auth/csrf").status_code == 200
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/docs").status_code == 200
        assert client.get("/api/not-a-route").status_code == 404


def test_root_reports_missing_frontend_build(tmp_path, monkeypatch):
    monkeypatch.setattr(
        main_module, "FRONTEND_BUILD_DIRECTORY", tmp_path / "missing-dist"
    )
    app = create_app(
        "sqlite://",
        storage_directory=str(tmp_path / "private-storage"),
    )
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 503
    assert "Frontend build is unavailable" in response.json()["detail"]
