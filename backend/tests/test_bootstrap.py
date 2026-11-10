from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import create_app
from app.models import User
from app.security import verify_password
from app.bootstrap import bootstrap_demo_accounts


PASSWORD = "a-bootstrap-password"


def database_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def test_bootstrap_creates_admin_and_never_resets_existing_credentials(tmp_path):
    url = database_url(tmp_path / "nested" / "trustvault.db")
    app = create_app(
        url,
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        bootstrap_admin_email="Admin@Example.com",
        bootstrap_admin_password=PASSWORD,
    )
    with TestClient(app) as client:
        with client.app.state.session_factory() as db:
            admin = db.scalar(select(User).where(User.email == "admin@example.com"))
            assert admin is not None
            assert admin.is_admin
            assert verify_password(PASSWORD, admin.password_hash)
            admin_id = admin.id
            original_hash = admin.password_hash

        csrf = client.get("/auth/csrf").json()["csrf_token"]
        login = client.post(
            "/auth/login",
            json={"email": "admin@example.com", "password": PASSWORD},
            headers={"X-CSRF-Token": csrf},
        )
        assert login.status_code == 200
        assert login.json()["is_admin"] is True
        assert client.get("/admin/users").status_code == 200

    restarted_app = create_app(
        url,
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        bootstrap_admin_email="admin@example.com",
        bootstrap_admin_password="a-different-bootstrap-password",
    )
    with TestClient(restarted_app) as client:
        with client.app.state.session_factory() as db:
            admin = db.get(User, admin_id)
            assert admin is not None
            assert admin.is_admin
            assert admin.password_hash == original_hash

        csrf = client.get("/auth/csrf").json()["csrf_token"]
        login = client.post(
            "/auth/login",
            json={"email": "admin@example.com", "password": PASSWORD},
            headers={"X-CSRF-Token": csrf},
        )
        assert login.status_code == 200
        assert login.json()["is_admin"] is True


def test_bootstrap_never_promotes_an_existing_regular_account(tmp_path):
    url = database_url(tmp_path / "trustvault.db")
    app = create_app(
        url,
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
    )
    with TestClient(app) as client:
        csrf = client.get("/auth/csrf").json()["csrf_token"]
        registration = client.post(
            "/auth/register",
            json={"email": "person@example.com", "password": PASSWORD},
            headers={"X-CSRF-Token": csrf},
        )
        assert registration.status_code == 201
        user_id = registration.json()["id"]

        from app.bootstrap import bootstrap_admin

        assert (
            bootstrap_admin(
                client.app.state.session_factory,
                "person@example.com",
                "another-bootstrap-password",
            )
            is False
        )
        with client.app.state.session_factory() as db:
            user = db.get(User, user_id)
            assert user is not None
            assert user.is_admin is False
            assert verify_password(PASSWORD, user.password_hash)


def test_demo_accounts_are_created_once_and_authenticate_with_expected_access(tmp_path):
    url = database_url(tmp_path / "demo.db")
    passwords = (
        "demo-admin-password",
        "demo-owner-password",
        "demo-viewer-password",
    )
    app = create_app(
        url,
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        seed_demo_accounts=True,
        demo_admin_password=passwords[0],
        demo_owner_password=passwords[1],
        demo_viewer_password=passwords[2],
    )
    expected_accounts = (
        ("admin@trustvault.com", passwords[0], True),
        ("owner@trustvault.com", passwords[1], False),
        ("viewer@trustvault.com", passwords[2], False),
    )
    with TestClient(app) as client:
        with client.app.state.session_factory() as db:
            for email, password, is_admin in expected_accounts:
                user = db.scalar(select(User).where(User.email == email))
                assert user is not None
                assert user.is_admin is is_admin
                assert user.password_hash != password
                assert verify_password(password, user.password_hash)

        for email, password, is_admin in expected_accounts:
            csrf = client.get("/auth/csrf").json()["csrf_token"]
            response = client.post(
                "/auth/login",
                json={"email": email, "password": password},
                headers={"X-CSRF-Token": csrf},
            )
            assert response.status_code == 200
            assert response.json()["is_admin"] is is_admin
            assert "password" not in response.json()
            assert "password_hash" not in response.json()
            if is_admin:
                assert client.get("/admin/users").status_code == 200
            else:
                assert client.get("/admin/users").status_code == 403
                assert client.get("/documents/shared").json() == []

        with client.app.state.session_factory() as db:
            original_hashes = {
                email: db.scalar(select(User).where(User.email == email)).password_hash
                for email, _, _ in expected_accounts
            }

    restarted_app = create_app(
        url,
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        seed_demo_accounts=True,
        demo_admin_password="replacement-admin-password",
        demo_owner_password="replacement-owner-password",
        demo_viewer_password="replacement-viewer-password",
    )
    with TestClient(restarted_app) as client:
        with client.app.state.session_factory() as db:
            users = db.scalars(select(User)).all()
            assert len(users) == 3
            for email, _, is_admin in expected_accounts:
                user = db.scalar(select(User).where(User.email == email))
                assert user is not None
                assert user.is_admin is is_admin
                assert user.password_hash == original_hashes[email]


def test_demo_seed_preserves_existing_account_role_and_password(tmp_path):
    url = database_url(tmp_path / "existing-demo.db")
    app = create_app(
        url,
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
    )
    with TestClient(app) as client:
        csrf = client.get("/auth/csrf").json()["csrf_token"]
        response = client.post(
            "/auth/register",
            json={"email": "owner@trustvault.com", "password": PASSWORD},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 201
        existing_id = response.json()["id"]
        with client.app.state.session_factory() as db:
            existing = db.get(User, existing_id)
            assert existing is not None
            existing_hash = existing.password_hash

        assert bootstrap_demo_accounts(
            client.app.state.session_factory,
            "demo-admin-password",
            "replacement-owner-password",
            "demo-viewer-password",
        ) == (2, 1)

        with client.app.state.session_factory() as db:
            existing = db.get(User, existing_id)
            assert existing is not None
            assert existing.is_admin is False
            assert existing.password_hash == existing_hash
            assert verify_password(PASSWORD, existing.password_hash)


def test_seeded_owner_shares_document_with_seeded_viewer_using_existing_permissions(
    tmp_path,
):
    app = create_app(
        database_url(tmp_path / "shared-demo.db"),
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        seed_demo_accounts=True,
        demo_admin_password="demo-admin-password",
        demo_owner_password="demo-owner-password",
        demo_viewer_password="demo-viewer-password",
    )
    with TestClient(app) as client:
        csrf = client.get("/auth/csrf").json()["csrf_token"]
        login = client.post(
            "/auth/login",
            json={
                "email": "owner@trustvault.com",
                "password": "demo-owner-password",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert login.status_code == 200
        upload = client.post(
            "/documents",
            files={"file": ("sample.pdf", b"%PDF-1.7\ndemo document", "application/pdf")},
            headers={"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]},
        )
        assert upload.status_code == 201
        document_id = upload.json()["id"]

        grant = client.post(
            f"/documents/{document_id}/permissions",
            json={
                "email": "viewer@trustvault.com",
                "access_level": "read",
                "can_download": False,
            },
            headers={"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]},
        )
        assert grant.status_code == 200

        csrf = client.get("/auth/csrf").json()["csrf_token"]
        login = client.post(
            "/auth/login",
            json={
                "email": "viewer@trustvault.com",
                "password": "demo-viewer-password",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert login.status_code == 200
        assert [item["id"] for item in client.get("/documents/shared").json()] == [
            document_id
        ]
        assert client.get(f"/documents/{document_id}/preview").status_code == 200
        assert client.get(f"/documents/{document_id}/download").status_code == 403

        csrf = client.get("/auth/csrf").json()["csrf_token"]
        login = client.post(
            "/auth/login",
            json={
                "email": "owner@trustvault.com",
                "password": "demo-owner-password",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert login.status_code == 200
        permissions = client.get(f"/documents/{document_id}/permissions").json()
        permission_id = permissions[0]["id"]
        updated = client.patch(
            f"/documents/{document_id}/permissions/{permission_id}",
            json={"can_download": True},
            headers={"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]},
        )
        assert updated.status_code == 200
        assert updated.json()["can_download"] is True

        csrf = client.get("/auth/csrf").json()["csrf_token"]
        login = client.post(
            "/auth/login",
            json={
                "email": "viewer@trustvault.com",
                "password": "demo-viewer-password",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert login.status_code == 200
        assert client.get(f"/documents/{document_id}/download").status_code == 200
