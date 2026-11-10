import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import URL, func, select

from app.audit import record_audit, verify_audit_chain
from app.main import create_app
from app.models import AuditEvent, AuthSession, Document, DocumentPermission, User
from app.security import hash_session_token

PASSWORD = "a-strong-password"
PDF = b"%PDF-1.7\nprivate admin test document"


@pytest.fixture
def workspace(tmp_path: Path):
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
    )
    with TestClient(app) as client:
        yield client


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]}


def register_user(client: TestClient, email: str) -> str:
    client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )
    login = client.post(
        "/auth/login",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert login.status_code == 200
    return client.get("/auth/me").json()["id"]


def make_admin(client: TestClient, email: str) -> str:
    user_id = register_user(client, email)
    with client.app.state.session_factory() as db:
        admin = db.get(User, user_id)
        assert admin is not None
        admin.is_admin = True
        db.commit()
    return user_id


def upload_pdf(client: TestClient) -> str:
    response = client.post(
        "/documents",
        files={"file": ("private.pdf", PDF, "application/pdf")},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_admin_apis_reject_anonymous_and_non_admin_users(workspace):
    client = workspace
    user_id = "00000000-0000-0000-0000-000000000001"
    endpoints = [
        ("GET", "/admin/users"),
        ("GET", f"/admin/users/{user_id}"),
        ("PATCH", f"/admin/users/{user_id}/status"),
        ("GET", "/admin/documents"),
        ("GET", "/admin/permissions"),
        ("GET", "/admin/audit"),
        ("GET", "/admin/audit/integrity"),
    ]
    for method, path in endpoints:
        response = client.request(
            method,
            path,
            json={"is_active": False} if method == "PATCH" else None,
            headers=csrf_headers(client) if method == "PATCH" else None,
        )
        assert response.status_code in {401, 403}

    register_user(client, "ordinary@example.com")
    for method, path in endpoints:
        response = client.request(
            method,
            path,
            json={"is_active": False} if method == "PATCH" else None,
            headers=csrf_headers(client) if method == "PATCH" else None,
        )
        assert response.status_code == 403


def test_admin_user_listing_and_detail_omit_credentials(workspace):
    client = workspace
    admin_id = make_admin(client, "admin@example.com")
    person_client = TestClient(client.app)
    user_id = register_user(person_client, "person@example.com")
    with client.app.state.session_factory() as db:
        admin_session = db.scalar(
            select(AuthSession).where(AuthSession.user_id == admin_id)
        )
        assert admin_session is not None
        admin_token_hash = admin_session.token_hash
    token = client.cookies.get("trustvault_session")
    assert token

    listing = client.get("/admin/users?limit=1&offset=0")
    assert listing.status_code == 200
    assert listing.json()["total"] == 2
    assert len(listing.json()["items"]) == 1
    assert "password_hash" not in listing.text
    assert token not in listing.text
    assert admin_token_hash not in listing.text

    detail = client.get(f"/admin/users/{user_id}")
    assert detail.status_code == 200
    assert detail.json()["email"] == "person@example.com"
    assert detail.json()["is_active"] is True
    assert "password_hash" not in detail.text
    assert token not in detail.text


def test_admin_can_deactivate_and_reactivate_user_and_old_sessions_stay_revoked(
    workspace,
):
    admin_client = workspace
    admin_id = make_admin(admin_client, "admin@example.com")
    user_client = TestClient(admin_client.app)
    user_id = register_user(user_client, "person@example.com")
    old_token = user_client.cookies.get("trustvault_session")
    assert old_token

    changed = admin_client.patch(
        f"/admin/users/{user_id}/status",
        json={"is_active": False},
        headers=csrf_headers(admin_client),
    )
    assert changed.status_code == 200
    assert changed.json()["is_active"] is False
    assert user_client.get("/auth/me").status_code == 401
    assert user_client.get("/documents").status_code == 401
    with admin_client.app.state.session_factory() as db:
        session = db.scalar(
            select(AuthSession).where(
                AuthSession.token_hash == hash_session_token(old_token)
            )
        )
        assert session is not None
        assert session.revoked_at is not None

    activated = admin_client.patch(
        f"/admin/users/{user_id}/status",
        json={"is_active": True},
        headers=csrf_headers(admin_client),
    )
    assert activated.status_code == 200
    assert activated.json()["is_active"] is True
    assert user_client.get("/auth/me").status_code == 401
    login = user_client.post(
        "/auth/login",
        json={"email": "person@example.com", "password": PASSWORD},
        headers=csrf_headers(user_client),
    )
    assert login.status_code == 200
    assert user_client.get("/auth/me").status_code == 200

    with admin_client.app.state.session_factory() as db:
        events = list(
            db.scalars(
                select(AuditEvent)
                .where(AuditEvent.actor_id == admin_id)
                .order_by(AuditEvent.id)
            )
        )
    assert [event.action for event in events] == [
        "admin.user.deactivated",
        "admin.user.activated",
    ]
    previous_hash = "0" * 64
    for event in events:
        assert event.previous_hash == previous_hash
        data = json.dumps(
            {
                "action": event.action,
                "actor_id": event.actor_id,
                "created_at": event.created_at.isoformat(),
                "metadata_json": event.metadata_json,
                "previous_hash": event.previous_hash,
                "target_id": event.target_id,
                "target_type": event.target_type,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        assert event.event_hash == hashlib.sha256(data.encode("utf-8")).hexdigest()
        assert "password" not in event.metadata_json.lower()
        assert "token" not in event.metadata_json.lower()
        previous_hash = event.event_hash


def test_last_active_admin_cannot_be_deactivated(workspace):
    client = workspace
    admin_id = make_admin(client, "only-admin@example.com")
    response = client.patch(
        f"/admin/users/{admin_id}/status",
        json={"is_active": False},
        headers=csrf_headers(client),
    )
    assert response.status_code == 409
    assert client.get("/auth/me").status_code == 200
    with client.app.state.session_factory() as db:
        admin = db.get(User, admin_id)
        assert admin is not None
        assert admin.disabled_at is None
        assert db.scalar(select(AuditEvent).where(
            AuditEvent.action == "admin.user.deactivated"
        )) is None

        second_admin = User(
            id="00000000-0000-0000-0000-000000000003",
            email="second-admin@example.com",
            password_hash="test-only",
            is_admin=True,
        )
        db.add(second_admin)
        db.commit()

    deactivated = client.patch(
        "/admin/users/00000000-0000-0000-0000-000000000003/status",
        json={"is_active": False},
        headers=csrf_headers(client),
    )
    assert deactivated.status_code == 200
    still_last_admin = client.patch(
        f"/admin/users/{admin_id}/status",
        json={"is_active": False},
        headers=csrf_headers(client),
    )
    assert still_last_admin.status_code == 409


def test_concurrent_admin_deactivation_preserves_last_active_admin(tmp_path: Path):
    database_url = URL.create(
        "sqlite", database=str(tmp_path / "admin-concurrency.sqlite")
    ).render_as_string(hide_password=False)
    app = create_app(
        database_url,
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
    )
    with TestClient(app) as setup_client:
        first_admin_id = make_admin(setup_client, "first-admin@example.com")
        with setup_client.app.state.session_factory() as db:
            db.add(
                User(
                    id="00000000-0000-0000-0000-000000000005",
                    email="second-admin@example.com",
                    password_hash="test-only",
                    is_admin=True,
                )
            )
            db.commit()

        session_token = setup_client.cookies.get("trustvault_session")
        csrf_token = setup_client.cookies.get("trustvault_csrf")
        assert session_token and csrf_token
        clients = [TestClient(app), TestClient(app)]
        for client in clients:
            client.cookies.set("trustvault_session", session_token)
            client.cookies.set("trustvault_csrf", csrf_token)

        barrier = Barrier(2)

        def deactivate(client: TestClient, user_id: str):
            barrier.wait()
            return client.patch(
                f"/admin/users/{user_id}/status",
                json={"is_active": False},
                headers={"X-CSRF-Token": csrf_token},
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(
                pool.map(
                    lambda pair: deactivate(*pair),
                    [
                        (clients[0], first_admin_id),
                        (clients[1], "00000000-0000-0000-0000-000000000005"),
                    ],
                )
            )

        assert [response.status_code for response in responses].count(200) == 1
        assert all(response.status_code in {200, 401, 409} for response in responses)
        with setup_client.app.state.session_factory() as db:
            active_admin_count = db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.is_admin.is_(True), User.disabled_at.is_(None))
            )
            deactivation_events = db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "admin.user.deactivated")
            )
        assert active_admin_count == 1
        assert deactivation_events == 1


def _append_test_audit_events(client: TestClient, count: int = 3) -> None:
    with client.app.state.session_factory() as db:
        for index in range(count):
            record_audit(
                db,
                None,
                "test.audit.event",
                "test",
                str(index),
                {"index": index},
            )
            db.flush()
        db.commit()


def test_admin_audit_integrity_endpoint_reports_valid_chain(workspace):
    client = workspace
    make_admin(client, "admin@example.com")
    _append_test_audit_events(client)

    response = client.get("/admin/audit/integrity")

    assert response.status_code == 200
    assert response.json() == {
        "is_valid": True,
        "event_count": 3,
        "first_invalid_event_id": None,
        "failure_reason": None,
    }


@pytest.mark.parametrize(
    ("tampering", "failure_reason"),
    [
        ("event_hash", "event_hash"),
        ("broken_link", "broken_link"),
        ("missing_event", "broken_link"),
    ],
)
def test_admin_audit_integrity_endpoint_detects_chain_tampering(
    workspace, tampering: str, failure_reason: str
):
    client = workspace
    make_admin(client, "admin@example.com")
    _append_test_audit_events(client)

    with client.app.state.session_factory() as db:
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        if tampering == "event_hash":
            events[1].action = "tampered.audit.event"
        elif tampering == "broken_link":
            events[1].previous_hash = "f" * 64
        else:
            db.delete(events[1])
        db.commit()
        invalid_event_id = events[2].id if tampering == "missing_event" else events[1].id

    response = client.get("/admin/audit/integrity")

    assert response.status_code == 200
    result = response.json()
    assert result["is_valid"] is False
    assert result["first_invalid_event_id"] == invalid_event_id
    assert result["failure_reason"] == failure_reason


def test_audit_integrity_verifier_rejects_reordered_events(workspace):
    client = workspace
    _append_test_audit_events(client)
    with client.app.state.session_factory() as db:
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))

    result = verify_audit_chain([events[0], events[2], events[1]])

    assert result.is_valid is False
    assert result.first_invalid_event_id == events[1].id
    assert result.failure_reason == "event_order"


def test_admin_sees_document_metadata_and_permissions_but_cannot_read_content(
    workspace,
):
    admin_client = workspace
    make_admin(admin_client, "admin@example.com")
    owner_client = TestClient(admin_client.app)
    owner_id = register_user(owner_client, "owner@example.com")
    document_id = upload_pdf(owner_client)
    viewer_client = TestClient(admin_client.app)
    viewer_id = register_user(viewer_client, "viewer@example.com")

    owner_client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "viewer@example.com", "access_level": "read"},
        headers=csrf_headers(owner_client),
    )
    grant = owner_client.get(f"/documents/{document_id}/permissions").json()[0]
    owner_client.delete(
        f"/documents/{document_id}/permissions/{grant['id']}",
        headers=csrf_headers(owner_client),
    )

    metadata = admin_client.get("/admin/documents")
    assert metadata.status_code == 200
    document = metadata.json()["items"][0]
    assert document["id"] == document_id
    assert document["filename"] == "private.pdf"
    assert document["owner_id"] == owner_id
    assert document["owner_email"] == "owner@example.com"
    assert document["size_bytes"] == len(PDF)
    assert document["content_type"] == "application/pdf"
    assert "storage" not in metadata.text.lower()
    assert "private admin test document" not in metadata.text

    permissions = admin_client.get("/admin/permissions")
    assert permissions.status_code == 200
    permission = permissions.json()["items"][0]
    assert permission["document_id"] == document_id
    assert permission["owner_id"] == owner_id
    assert permission["user_id"] == viewer_id
    assert permission["access_level"] == "read"
    assert permission["status"] == "revoked"
    assert permission["revoked_at"] is not None

    assert admin_client.get(f"/documents/{document_id}/preview").status_code == 404
    assert admin_client.get(f"/documents/{document_id}/download").status_code == 404


def test_admin_permission_status_identifies_inert_legacy_grants(workspace):
    client = workspace
    make_admin(client, "admin@example.com")
    owner_client = TestClient(client.app)
    owner_id = register_user(owner_client, "owner@example.com")
    document_id = upload_pdf(owner_client)
    viewer_client = TestClient(client.app)
    viewer_id = register_user(viewer_client, "viewer@example.com")

    with client.app.state.session_factory() as db:
        db.add(
            DocumentPermission(
                id="00000000-0000-0000-0000-000000000004",
                document_id=document_id,
                user_id=viewer_id,
                access_level="edit",
                granted_by=owner_id,
            )
        )
        db.commit()

    response = client.get("/admin/permissions")
    assert response.status_code == 200
    assert response.json()["items"][0]["status"] == "legacy_inactive"


def test_admin_audit_pagination_filters_and_hash_chain(workspace):
    client = workspace
    admin_id = make_admin(client, "admin@example.com")
    owner_client = TestClient(client.app)
    owner_id = register_user(owner_client, "owner@example.com")
    document_id = upload_pdf(owner_client)
    grant = owner_client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "admin@example.com", "access_level": "read"},
        headers=csrf_headers(owner_client),
    )
    assert grant.status_code == 200
    assert client.get(f"/documents/{document_id}/preview").status_code == 200

    first_page = client.get("/admin/audit?limit=2&offset=0")
    second_page = client.get("/admin/audit?limit=2&offset=2")
    assert first_page.status_code == 200
    assert first_page.json()["total"] >= 3
    assert len(first_page.json()["items"]) == 2
    assert first_page.json()["items"][0]["id"] > second_page.json()["items"][0]["id"]

    by_action = client.get("/admin/audit?event_type=permission.granted")
    assert by_action.status_code == 200
    assert all(item["action"] == "permission.granted" for item in by_action.json()["items"])
    permission_event = by_action.json()["items"][0]
    assert permission_event["target_display"] == "private.pdf · admin@example.com"
    assert permission_event["document_id"] == document_id
    assert permission_event["document_name"] == "private.pdf"
    assert permission_event["permission_id"] == grant.json()["id"]
    assert permission_event["permission_owner"] == "owner@example.com"
    assert permission_event["permission_viewer"] == "admin@example.com"
    assert permission_event["download_allowed"] is False
    assert permission_event["permission_status"] == "active"
    assert permission_event["actor_display_name"] == "owner@example.com"
    assert permission_event["actor_email"] == "owner@example.com"
    assert permission_event["actor_role"] == "User"
    assert permission_event["previous_hash"]
    assert permission_event["event_hash"]
    assert PDF.decode("latin-1") not in by_action.text
    assert "private_storage" not in by_action.text
    by_user = client.get(f"/admin/audit?user_id={owner_id}")
    assert by_user.status_code == 200
    assert all(item["actor_id"] == owner_id for item in by_user.json()["items"])
    recipient_events = client.get(f"/admin/audit?user_id={admin_id}")
    assert recipient_events.status_code == 200
    assert any(
        item["action"] == "permission.granted"
        for item in recipient_events.json()["items"]
    )
    by_document = client.get(f"/admin/audit?document_id={document_id}")
    assert by_document.status_code == 200
    assert {item["action"] for item in by_document.json()["items"]} >= {
        "document.uploaded",
        "permission.granted",
    }

    with client.app.state.session_factory() as db:
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    previous_hash = "0" * 64
    for event in events:
        assert event.previous_hash == previous_hash
        data = json.dumps(
            {
                "action": event.action,
                "actor_id": event.actor_id,
                "created_at": event.created_at.isoformat(),
                "metadata_json": event.metadata_json,
                "previous_hash": event.previous_hash,
                "target_id": event.target_id,
                "target_type": event.target_type,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        assert event.event_hash == hashlib.sha256(data.encode("utf-8")).hexdigest()
        assert "password" not in event.metadata_json.lower()
        assert "token" not in event.metadata_json.lower()
        assert PDF.decode("latin-1") not in event.metadata_json
        previous_hash = event.event_hash

    assert client.post("/admin/audit").status_code == 405
    assert client.delete("/admin/audit").status_code == 405


def test_admin_audit_includes_actor_account_label_without_changing_event(workspace):
    client = workspace
    admin_id = make_admin(client, "admin@example.com")
    with client.app.state.session_factory() as db:
        admin = db.get(User, admin_id)
        assert admin is not None
        admin.display_name = "Audit Administrator"
        db.commit()
        record_audit(
            db,
            admin_id,
            "test.actor.label",
            "test",
            "target",
            {},
        )
        db.commit()
        event = db.scalar(
            select(AuditEvent).where(AuditEvent.action == "test.actor.label")
        )
        assert event is not None
        original_hash = event.event_hash
        original_actor_id = event.actor_id

    response = client.get("/admin/audit?event_type=test.actor.label")

    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["actor_id"] == admin_id
    assert item["actor_display_name"] == "Audit Administrator"
    assert item["actor_email"] == "admin@example.com"
    assert item["actor_role"] == "Admin"
    assert item["target_display"] is None
    with client.app.state.session_factory() as db:
        event = db.scalar(
            select(AuditEvent).where(AuditEvent.action == "test.actor.label")
        )
        assert event is not None
        assert event.event_hash == original_hash
        assert event.actor_id == original_actor_id


def test_admin_audit_uses_original_filename_after_document_rename(workspace):
    client = workspace
    make_admin(client, "admin@example.com")
    owner_client = TestClient(client.app)
    owner_id = register_user(owner_client, "owner@example.com")
    document_id = upload_pdf(owner_client)

    updated = owner_client.patch(
        f"/documents/{document_id}",
        json={"name": "Renamed document"},
        headers=csrf_headers(owner_client),
    )
    assert updated.status_code == 200

    events = client.get(
        f"/admin/audit?event_type=document.updated&document_id={document_id}"
    )
    assert events.status_code == 200
    item = events.json()["items"][0]
    assert item["actor_id"] == owner_id
    assert item["document_name"] == "private.pdf"
    assert item["action"] == "document.updated"
    assert "Name: private.pdf → Renamed document" in item["action_details"]
    assert item["target_id"] == document_id


def test_admin_audit_uses_safe_fallbacks_for_deleted_document_and_viewer(workspace):
    client = workspace
    make_admin(client, "admin@example.com")
    owner_client = TestClient(client.app)
    owner_id = register_user(owner_client, "owner@example.com")
    document_id = upload_pdf(owner_client)
    viewer_client = TestClient(client.app)
    viewer_id = register_user(viewer_client, "viewer@example.com")
    grant = owner_client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "viewer@example.com", "access_level": "read"},
        headers=csrf_headers(owner_client),
    )
    assert grant.status_code == 200

    with client.app.state.session_factory() as db:
        viewer = db.get(User, viewer_id)
        assert viewer is not None
        db.delete(viewer)
        db.commit()

    permission_events = client.get(
        "/admin/audit?event_type=permission.granted"
    )
    permission_event = permission_events.json()["items"][0]
    assert permission_event["permission_viewer"] == "Deleted User"
    assert permission_event["actor_id"] == owner_id

    deleted = owner_client.delete(
        f"/documents/{document_id}", headers=csrf_headers(owner_client)
    )
    assert deleted.status_code == 204
    deleted_event = client.get(
        f"/admin/audit?event_type=document.deleted&document_id={document_id}"
    ).json()["items"][0]
    assert deleted_event["document_name"] == "Deleted Document"
    assert deleted_event["document_id"] == document_id


def test_admin_audit_permission_state_comes_from_each_event_snapshot(workspace):
    client = workspace
    make_admin(client, "admin@example.com")
    owner_client = TestClient(client.app)
    owner_id = register_user(owner_client, "owner@example.com")
    document_id = upload_pdf(owner_client)
    viewer_client = TestClient(client.app)
    register_user(viewer_client, "viewer@example.com")
    grant = owner_client.post(
        f"/documents/{document_id}/permissions",
        json={
            "email": "viewer@example.com",
            "access_level": "read",
            "can_download": True,
        },
        headers=csrf_headers(owner_client),
    )
    assert grant.status_code == 200
    permission_id = grant.json()["id"]

    revoked = owner_client.delete(
        f"/documents/{document_id}/permissions/{permission_id}",
        headers=csrf_headers(owner_client),
    )
    assert revoked.status_code == 204

    granted_event = client.get(
        "/admin/audit?event_type=permission.granted"
    ).json()["items"][0]
    revoked_event = client.get(
        "/admin/audit?event_type=permission.revoked"
    ).json()["items"][0]
    assert granted_event["permission_owner"] == "owner@example.com"
    assert granted_event["permission_viewer"] == "viewer@example.com"
    assert granted_event["download_allowed"] is True
    assert granted_event["permission_status"] == "active"
    assert revoked_event["permission_id"] == permission_id
    assert revoked_event["permission_viewer"] == "viewer@example.com"
    assert revoked_event["download_allowed"] is True
    assert revoked_event["permission_status"] == "revoked"
    assert revoked_event["actor_id"] == owner_id
    assert client.get("/admin/audit/integrity").json()["is_valid"] is True
