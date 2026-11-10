from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text

from app.database import build_engine, ensure_user_display_name_column
from app.main import create_app
from app.models import AuthSession
from app.security import hash_password, hash_session_token, verify_password


def make_client(
    session_lifetime_seconds: int = 12 * 60 * 60,
    cookie_secure: bool = False,
    base_url: str = "http://testserver",
) -> TestClient:
    app = create_app(
        "sqlite://",
        cookie_secure=cookie_secure,
        session_lifetime_seconds=session_lifetime_seconds,
    )
    return TestClient(app, base_url=base_url)


def csrf_headers(client: TestClient) -> dict[str, str]:
    response = client.get("/auth/csrf")
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def test_registration_login_me_and_logout():
    with make_client() as client:
        headers = csrf_headers(client)
        response = client.post(
            "/auth/register",
            json={"email": "Owner@Example.com", "password": "a-strong-password"},
            headers=headers,
        )
        assert response.status_code == 201
        assert response.json()["email"] == "owner@example.com"
        assert response.json()["display_name"] == "owner@example.com"
        assert "password_hash" not in response.json()
        assert "a-strong-password" not in response.text

        headers = csrf_headers(client)
        response = client.post(
            "/auth/login",
            json={"email": "owner@example.com", "password": "a-strong-password"},
            headers=headers,
        )
        assert response.status_code == 200
        assert "httponly" in response.headers["set-cookie"].lower()
        assert "samesite=lax" in response.headers["set-cookie"].lower()
        assert "trustvault_session=" in response.headers["set-cookie"]
        assert "password_hash" not in response.json()
        raw_token = client.cookies.get("trustvault_session")
        assert raw_token
        assert raw_token not in response.text
        with client.app.state.session_factory() as db:
            session = db.scalar(select(AuthSession))
            assert session is not None
            assert session.token_hash == hash_session_token(raw_token)
            assert session.token_hash != raw_token
        me_response = client.get("/auth/me")
        assert me_response.status_code == 200
        assert raw_token not in me_response.text
        assert "password_hash" not in me_response.text
        assert me_response.json()["display_name"] == "owner@example.com"

        headers = csrf_headers(client)
        response = client.post("/auth/logout", headers=headers)
        assert response.status_code == 204
        assert raw_token not in response.text
        assert client.get("/auth/me").status_code == 401
        with client.app.state.session_factory() as db:
            session = db.scalar(select(AuthSession))
            assert session is not None
            assert session.revoked_at is not None


def test_registration_requires_matching_csrf_token():
    with make_client() as client:
        response = client.post(
            "/auth/register",
            json={"email": "person@example.com", "password": "a-strong-password"},
        )
        assert response.status_code == 403


def test_registration_rejects_mismatched_csrf_token():
    with make_client() as client:
        csrf_headers(client)
        response = client.post(
            "/auth/register",
            json={"email": "person@example.com", "password": "a-strong-password"},
            headers={"X-CSRF-Token": "not-the-cookie-token"},
        )
        assert response.status_code == 403


def test_registration_accepts_and_returns_display_name():
    with make_client() as client:
        response = client.post(
            "/auth/register",
            json={
                "email": "person@example.com",
                "password": "a-strong-password",
                "display_name": "  Alex Example  ",
            },
            headers=csrf_headers(client),
        )
        assert response.status_code == 201
        assert response.json()["display_name"] == "Alex Example"
        login = client.post(
            "/auth/login",
            json={"email": "person@example.com", "password": "a-strong-password"},
            headers=csrf_headers(client),
        )
        assert login.status_code == 200
        assert client.get("/auth/me").json()["display_name"] == "Alex Example"


def test_display_name_schema_upgrade_backfills_and_preserves_custom_values():
    engine = build_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL)")
            )
            connection.execute(
                text(
                    "INSERT INTO users (id, email) VALUES "
                    "('one', 'one@example.com'), ('two', 'two@example.com')"
                )
            )

        ensure_user_display_name_column(engine)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE users SET display_name = 'Customized Name' WHERE id = 'one'"
                )
            )
            connection.execute(
                text("UPDATE users SET display_name = '' WHERE id = 'two'")
            )
        ensure_user_display_name_column(engine)
        ensure_user_display_name_column(engine)

        with engine.connect() as connection:
            rows = dict(
                connection.execute(
                    text("SELECT id, display_name FROM users")
                ).all()
            )
        assert rows == {
            "one": "Customized Name",
            "two": "two@example.com",
        }
    finally:
        engine.dispose()


def test_display_name_schema_upgrade_backfills_existing_null_values():
    engine = build_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL, "
                    "display_name TEXT NULL)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO users (id, email, display_name) VALUES "
                    "('custom', 'custom@example.com', 'Custom'), "
                    "('missing', 'missing@example.com', NULL)"
                )
            )

        ensure_user_display_name_column(engine)
        with engine.connect() as connection:
            rows = dict(
                connection.execute(
                    text("SELECT id, display_name FROM users")
                ).all()
            )
        assert rows == {
            "custom": "Custom",
            "missing": "missing@example.com",
        }
    finally:
        engine.dispose()


def test_duplicate_registration_and_invalid_password_are_rejected():
    with make_client() as client:
        headers = csrf_headers(client)
        payload = {"email": "person@example.com", "password": "a-strong-password"}
        assert client.post("/auth/register", json=payload, headers=headers).status_code == 201
        assert client.post("/auth/register", json=payload, headers=headers).status_code == 409
        assert client.post(
            "/auth/login",
            json={"email": "person@example.com", "password": "incorrect-password"},
            headers=headers,
        ).status_code == 401


def test_session_cookie_is_missing_for_anonymous_requests():
    with make_client() as client:
        assert client.get("/auth/me").status_code == 401


def test_expired_session_is_rejected():
    with make_client() as client:
        headers = csrf_headers(client)
        client.post(
            "/auth/register",
            json={"email": "person@example.com", "password": "a-strong-password"},
            headers=headers,
        )
        client.post(
            "/auth/login",
            json={"email": "person@example.com", "password": "a-strong-password"},
            headers=csrf_headers(client),
        )
        raw_token = client.cookies.get("trustvault_session")
        assert raw_token
        with client.app.state.session_factory() as db:
            session = db.scalar(
                select(AuthSession).where(
                    AuthSession.token_hash == hash_session_token(raw_token)
                )
            )
            assert session is not None
            session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
        assert client.get("/auth/me").status_code == 401


def test_password_hashing_uses_argon2id():
    password = "another-strong-password"
    password_hash = hash_password(password)
    assert password_hash.startswith("$argon2id$")
    assert verify_password(password, password_hash)
    assert not verify_password("incorrect-password", password_hash)


def test_session_and_csrf_cookies_are_secure_when_enabled():
    with make_client(cookie_secure=True, base_url="https://testserver") as client:
        csrf_response = client.get("/auth/csrf")
        csrf_cookie = next(
            cookie
            for cookie in csrf_response.headers.get_list("set-cookie")
            if cookie.startswith("trustvault_csrf=")
        )
        assert "secure" in csrf_cookie.lower()
        assert "samesite=lax" in csrf_cookie.lower()

        client.post(
            "/auth/register",
            json={"email": "person@example.com", "password": "a-strong-password"},
            headers={"X-CSRF-Token": csrf_response.json()["csrf_token"]},
        )
        login_response = client.post(
            "/auth/login",
            json={"email": "person@example.com", "password": "a-strong-password"},
            headers={"X-CSRF-Token": csrf_response.json()["csrf_token"]},
        )
        assert login_response.status_code == 200
        session_cookie = next(
            cookie
            for cookie in login_response.headers.get_list("set-cookie")
            if cookie.startswith("trustvault_session=")
        )
        assert "secure" in session_cookie.lower()
        assert "httponly" in session_cookie.lower()
        assert "samesite=lax" in session_cookie.lower()


def test_registration_validates_email_and_password_length():
    with make_client() as client:
        response = client.post(
            "/auth/register",
            json={"email": "not-an-email", "password": "a-strong-password"},
            headers=csrf_headers(client),
        )
        assert response.status_code == 422


def test_authentication_schema_includes_sharing_and_preview_routes():
    with make_client() as client:
        table_names = set(
            inspect(client.app.state.engine).get_table_names()
        )
        assert {
            "users",
            "documents",
            "document_permissions",
            "sessions",
            "audit_events",
        } <= table_names
        route_paths = set(client.app.openapi()["paths"])
        assert "/documents" in route_paths
        assert "/documents/{document_id}" in route_paths
        assert "/documents/{document_id}/download" in route_paths
        assert "/documents/shared" in route_paths
        assert "/documents/{document_id}/permissions" in route_paths
        assert "/documents/{document_id}/permissions/{permission_id}" in route_paths
        assert "/admin/users" in route_paths
        assert "/admin/users/{user_id}" in route_paths
        assert "/admin/users/{user_id}/status" in route_paths
        assert "/admin/documents" in route_paths
        assert "/admin/permissions" in route_paths
        assert "/admin/audit" in route_paths
        assert "/admin/audit/integrity" in route_paths
        assert "/documents/{document_id}/preview" in route_paths
        response = client.post(
            "/auth/register",
            json={"email": "person@example.com", "password": "short"},
            headers=csrf_headers(client),
        )
        assert response.status_code == 422
        privileged_registration = client.post(
            "/auth/register",
            json={
                "email": "admin@example.com",
                "password": "a-strong-password",
                "is_admin": True,
            },
            headers=csrf_headers(client),
        )
        assert privileged_registration.status_code == 422
