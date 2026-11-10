import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import documents
from app.main import create_app
from app.database import build_engine, ensure_download_permission_column
from app.models import (
    AuditEvent,
    Document,
    DocumentPermission,
    StorageOperation,
    User,
)
from app.storage import FilesystemStorage, StorageOperationError
from app.storage_operations import recover_storage_operations


PASSWORD = "a-strong-password"
PDF = b"%PDF-1.7\nprivate test document"


@pytest.fixture
def workspace(tmp_path: Path):
    storage = tmp_path / "private-storage"
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(storage),
    )
    with TestClient(app) as client:
        yield client, storage


def test_existing_permission_rows_migrate_with_download_disabled():
    engine = build_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE document_permissions "
                "(id VARCHAR(36) PRIMARY KEY, access_level VARCHAR(8) NOT NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO document_permissions (id, access_level) "
                "VALUES ('legacy-grant', 'read')"
            )
        )

    ensure_download_permission_column(engine)
    ensure_download_permission_column(engine)

    with engine.connect() as connection:
        can_download = connection.scalar(
            text(
                "SELECT can_download FROM document_permissions "
                "WHERE id = 'legacy-grant'"
            )
        )
    assert can_download in (False, 0)
    engine.dispose()


def csrf_headers(client: TestClient) -> dict[str, str]:
    token = client.get("/auth/csrf").json()["csrf_token"]
    return {"X-CSRF-Token": token}


def use_authentication(
    client: TestClient, session_cookie: str | None, csrf_cookie: str | None = None
) -> None:
    assert session_cookie is not None
    client.cookies.clear()
    client.cookies.set("trustvault_session", session_cookie)
    if csrf_cookie is not None:
        client.cookies.set("trustvault_csrf", csrf_cookie)


def register_user(client: TestClient, email: str) -> None:
    headers = csrf_headers(client)
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD},
        headers=headers,
    )
    assert response.status_code == 201
    response = client.post(
        "/auth/login",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200


def upload_pdf(client: TestClient, filename: str = "private.pdf"):
    return client.post(
        "/documents",
        files={"file": (filename, PDF, "application/pdf")},
        data={"category": "Legal"},
        headers=csrf_headers(client),
    )


def test_preview_supports_each_uploaded_document_type(workspace):
    client, _ = workspace
    register_user(client, "owner@example.com")

    docx_buffer = io.BytesIO()
    with zipfile.ZipFile(docx_buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(
            "word/document.xml",
            (
                '<document xmlns:w="http://schemas.openxmlformats.org/'
                'wordprocessingml/2006/main"><body><w:p><w:r><w:t>'
                "DOCX preview text"
                "</w:t></w:r></w:p></body></document>"
            ),
        )
    samples = [
        ("notes.txt", b"Plain text preview", "text/plain", "Plain text preview"),
        (
            "scan.png",
            b"\x89PNG\r\n\x1a\nimage",
            "image/png",
            b"\x89PNG\r\n\x1a\nimage",
        ),
        (
            "report.docx",
            docx_buffer.getvalue(),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "DOCX preview text",
        ),
    ]

    for filename, content, content_type, expected in samples:
        uploaded = client.post(
            "/documents",
            files={"file": (filename, content, content_type)},
            data={"category": "Legal"},
            headers=csrf_headers(client),
        )
        assert uploaded.status_code == 201
        document_id = uploaded.json()["id"]
        preview = client.get(f"/documents/{document_id}/preview")
        assert preview.status_code == 200
        assert preview.headers["content-disposition"].startswith("inline;")
        if isinstance(expected, str):
            assert expected in preview.text
        else:
            assert preview.content == expected


def fail_commit_for_documents(monkeypatch, *, is_new: bool) -> None:
    commit = Session.commit

    def failing_commit(session: Session) -> None:
        instances = (
            (*session.new, *session.identity_map.values())
            if is_new
            else (*session.dirty, *session.new)
        )
        if any(
            isinstance(instance, Document)
            for instance in instances
        ):
            raise SQLAlchemyError("injected database commit failure")
        commit(session)

    monkeypatch.setattr(Session, "commit", failing_commit)


def document_count(client: TestClient) -> int:
    with client.app.state.session_factory() as db:
        return db.scalar(select(func.count()).select_from(Document)) or 0


def test_owner_can_upload_list_download_edit_and_delete(workspace):
    client, storage = workspace
    register_user(client, "owner@example.com")

    upload_response = upload_pdf(client, "agreement.pdf")
    assert upload_response.status_code == 201
    uploaded = upload_response.json()
    document_id = uploaded["id"]
    stored_files = list(storage.iterdir())
    assert len(stored_files) == 1
    assert stored_files[0].name != "agreement.pdf"
    assert stored_files[0].read_bytes() == PDF
    assert uploaded == {
        "id": document_id,
        "name": "agreement.pdf",
        "category": "Legal",
        "filename": "agreement.pdf",
        "content_type": "application/pdf",
        "size_bytes": len(PDF),
        "created_at": uploaded["created_at"],
        "owner_email": "owner@example.com",
    }
    assert str(storage) not in upload_response.text

    listed = client.get("/documents")
    assert listed.status_code == 200
    assert [document["id"] for document in listed.json()] == [document_id]
    assert client.get("/documents?search=agree").json()[0]["id"] == document_id
    assert client.get("/documents?search=not-found").json() == []

    downloaded = client.get(f"/documents/{document_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.content == PDF
    assert downloaded.headers["content-disposition"].startswith("attachment;")
    assert downloaded.headers["cache-control"] == "private, no-store"

    edited = client.patch(
        f"/documents/{document_id}",
        json={"name": "Updated agreement", "category": "Contracts"},
        headers=csrf_headers(client),
    )
    assert edited.status_code == 200
    assert edited.json()["name"] == "Updated agreement"
    assert edited.json()["category"] == "Contracts"

    events = client.app.state.session_factory
    with events() as db:
        audit_events = list(
            db.scalars(select(AuditEvent).order_by(AuditEvent.id))
        )
        actions = [event.action for event in audit_events]
    assert actions == [
        "document.uploaded",
        "document.downloaded",
        "document.updated",
    ]
    previous_hash = "0" * 64
    for event in audit_events:
        assert event.previous_hash == previous_hash
        event_data = json.dumps(
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
        assert event.event_hash == hashlib.sha256(
            event_data.encode("utf-8")
        ).hexdigest()
        previous_hash = event.event_hash

    deleted = client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    )
    assert deleted.status_code == 204
    assert not stored_files[0].exists()
    assert client.get("/documents").json() == []
    with events() as db:
        actions = list(
            db.scalars(
                select(AuditEvent.action).order_by(AuditEvent.id)
            )
        )
    assert actions[-1] == "document.deleted"


def test_document_routes_reject_unauthenticated_requests(workspace):
    client, _ = workspace
    document_id = "00000000-0000-0000-0000-000000000001"

    assert client.get("/documents").status_code == 401
    assert client.get("/documents/shared").status_code == 401
    assert client.post(
        "/documents",
        files={"file": ("document.pdf", PDF, "application/pdf")},
        headers=csrf_headers(client),
    ).status_code in {401, 403}
    assert client.get(f"/documents/{document_id}/download").status_code == 401
    assert client.get(f"/documents/{document_id}/preview").status_code == 401
    assert client.get(
        f"/documents/{document_id}/permissions"
    ).status_code == 401
    assert client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "reader@example.com", "access_level": "read"},
        headers=csrf_headers(client),
    ).status_code in {401, 403}
    assert client.delete(
        f"/documents/{document_id}/permissions/00000000-0000-0000-0000-000000000001",
        headers=csrf_headers(client),
    ).status_code in {401, 403}
    assert client.patch(
        f"/documents/{document_id}",
        json={"name": "Changed"},
        headers=csrf_headers(client),
    ).status_code in {401, 403}
    assert client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    ).status_code in {401, 403}


def test_private_storage_cannot_be_configured_inside_frontend():
    frontend_public = Path(__file__).resolve().parents[2] / "frontend" / "public"
    with pytest.raises(ValueError, match="outside the frontend"):
        create_app("sqlite://", storage_directory=str(frontend_public))


def test_other_users_cannot_list_download_edit_or_delete_documents(workspace):
    client, storage = workspace
    register_user(client, "owner@example.com")
    document_id = upload_pdf(client).json()["id"]
    owner_cookie = client.cookies.get("trustvault_session")

    register_user(client, "other@example.com")
    assert client.get("/documents").json() == []
    assert client.get(f"/documents/{document_id}/download").status_code == 404
    assert client.patch(
        f"/documents/{document_id}",
        json={"name": "stolen"},
        headers=csrf_headers(client),
    ).status_code == 404
    assert client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    ).status_code == 404
    assert len(list(storage.iterdir())) == 1

    use_authentication(client, owner_cookie)
    own_documents = client.get("/documents")
    assert own_documents.status_code == 200
    assert [document["id"] for document in own_documents.json()] == [document_id]


def test_document_ids_do_not_bypass_authorization_even_for_admins(workspace):
    client, _ = workspace
    register_user(client, "owner@example.com")
    document_id = upload_pdf(client).json()["id"]

    register_user(client, "admin@example.com")
    with client.app.state.session_factory() as db:
        admin = db.scalar(select(User).where(User.email == "admin@example.com"))
        assert admin is not None
        admin.is_admin = True
        db.commit()
    assert client.get("/documents/shared").json() == []
    assert client.get(f"/documents/{document_id}/download").status_code == 404
    assert client.get(f"/documents/{document_id}/preview").status_code == 404
    assert client.get(
        f"/documents/{document_id}/permissions"
    ).status_code == 404
    assert client.patch(
        f"/documents/{document_id}",
        json={"name": "admin override"},
        headers=csrf_headers(client),
    ).status_code == 404
    assert client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    ).status_code == 404


@pytest.mark.parametrize(
    ("filename", "content", "content_type", "expected_status"),
    [
        ("bad.exe", b"MZinvalid", "application/octet-stream", 415),
        ("fake.pdf", b"not a pdf", "application/pdf", 415),
        ("fake.pdf", PDF, "text/plain", 415),
    ],
)
def test_invalid_document_types_and_signatures_are_rejected(
    workspace, filename, content, content_type, expected_status
):
    client, storage = workspace
    register_user(client, "owner@example.com")
    response = client.post(
        "/documents",
        files={"file": (filename, content, content_type)},
        headers=csrf_headers(client),
    )
    assert response.status_code == expected_status
    assert list(storage.iterdir()) == []


def test_oversized_upload_is_rejected(workspace):
    client, storage = workspace
    register_user(client, "owner@example.com")
    response = client.post(
        "/documents",
        files={
            "file": (
                "oversized.pdf",
                b"%PDF-" + b"x" * documents.MAX_UPLOAD_BYTES,
                "application/pdf",
            )
        },
        headers=csrf_headers(client),
    )
    assert response.status_code == 413
    assert list(storage.iterdir()) == []


def test_upload_at_4_mib_limit_is_accepted(workspace):
    client, storage = workspace
    register_user(client, "owner@example.com")
    content = b"%PDF-" + b"x" * (documents.MAX_UPLOAD_BYTES - len(b"%PDF-"))
    response = client.post(
        "/documents",
        files={"file": ("maximum.pdf", content, "application/pdf")},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201


def test_path_traversal_filenames_and_metadata_are_rejected(workspace):
    client, storage = workspace
    register_user(client, "owner@example.com")
    response = client.post(
        "/documents",
        files={"file": ("..\\outside.pdf", PDF, "application/pdf")},
        headers=csrf_headers(client),
    )
    assert response.status_code == 400
    assert client.post(
        "/documents",
        files={"file": ("safe.pdf", PDF, "application/pdf")},
        data={"name": "../outside"},
        headers=csrf_headers(client),
    ).status_code == 422
    assert list(storage.iterdir()) == []


def test_docx_signature_is_validated_without_extracting_archive(workspace):
    client, storage = workspace
    register_user(client, "owner@example.com")
    valid_docx = io.BytesIO()
    with zipfile.ZipFile(valid_docx, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
    response = client.post(
        "/documents",
        files={
            "file": (
                "report.docx",
                valid_docx.getvalue(),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    assert len(list(storage.iterdir())) == 1


@pytest.mark.parametrize(
    ("filename", "content", "content_type"),
    [
        ("notes.txt", "Plain text".encode(), "text/plain"),
        ("image.png", b"\x89PNG\r\n\x1a\nimage", "image/png"),
        ("photo.jpg", b"\xff\xd8\xffimage", "image/jpeg"),
        ("photo.jpeg", b"\xff\xd8\xffimage", "image/jpeg"),
    ],
)
def test_supported_text_and_image_types_are_accepted(
    workspace, filename, content, content_type
):
    client, _ = workspace
    register_user(client, "owner@example.com")
    response = client.post(
        "/documents",
        files={"file": (filename, content, content_type)},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    assert response.json()["content_type"] == content_type


def test_viewer_permission_allows_preview_but_not_download_and_revocation_blocks(
    workspace,
):
    client, storage = workspace
    register_user(client, "owner@example.com")
    document_id = upload_pdf(client).json()["id"]
    owner_id = client.get("/auth/me").json()["id"]

    register_user(client, "reader@example.com")
    reader_id = client.get("/auth/me").json()["id"]
    with client.app.state.session_factory() as db:
        db.add(
            DocumentPermission(
                id="grant-1",
                document_id=document_id,
                user_id=reader_id,
                access_level="read",
                granted_by=owner_id,
            )
        )
        db.commit()
    preview = client.get(f"/documents/{document_id}/preview")
    assert preview.status_code == 200
    assert preview.content == PDF
    assert preview.headers["content-disposition"].startswith("inline;")
    assert preview.headers["cache-control"] == "no-store"
    assert str(storage) not in preview.headers.get("content-disposition", "")
    assert client.get(f"/documents/{document_id}/download").status_code == 403
    assert client.patch(
        f"/documents/{document_id}",
        json={"name": "not allowed"},
        headers=csrf_headers(client),
    ).status_code == 404
    assert client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    ).status_code == 404
    with client.app.state.session_factory() as db:
        permission = db.scalar(select(DocumentPermission))
        assert permission is not None
        permission.revoked_at = datetime.now(timezone.utc)
        db.commit()
    assert client.get(f"/documents/{document_id}/preview").status_code == 404
    assert client.get(f"/documents/{document_id}/download").status_code == 404


def test_owner_can_grant_and_revoke_viewer_with_audited_hash_chain(workspace):
    client, storage = workspace
    register_user(client, "owner@example.com")
    owner_cookie = client.cookies.get("trustvault_session")
    owner_csrf = client.cookies.get("trustvault_csrf")
    document_id = upload_pdf(client).json()["id"]
    owner_id = client.get("/auth/me").json()["id"]

    register_user(client, "viewer@example.com")
    viewer_cookie = client.cookies.get("trustvault_session")
    viewer_csrf = client.cookies.get("trustvault_csrf")
    viewer_id = client.get("/auth/me").json()["id"]

    use_authentication(client, owner_cookie, owner_csrf)
    grant = client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "VIEWER@example.com", "access_level": "read"},
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert grant.status_code == 200
    permission = grant.json()
    assert permission["user_id"] == viewer_id
    assert permission["user_email"] == "viewer@example.com"
    assert permission["access_level"] == "read"
    assert permission["can_download"] is False
    assert client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "viewer@example.com", "access_level": "read"},
    ).status_code == 403

    use_authentication(client, viewer_cookie, viewer_csrf)
    shared = client.get("/documents/shared")
    assert shared.status_code == 200
    assert [item["id"] for item in shared.json()] == [document_id]
    assert shared.json()[0]["access_level"] == "read"
    assert shared.json()[0]["can_download"] is False
    assert client.get("/documents").json() == []
    assert client.get(f"/documents/{document_id}/preview").content == PDF
    denied = client.get(f"/documents/{document_id}/download")
    assert denied.status_code == 403
    assert "Download permission is not enabled" in denied.json()["detail"]
    assert client.patch(
        f"/documents/{document_id}",
        json={"name": "unauthorized edit"},
        headers=csrf_headers(client),
    ).status_code == 404
    assert client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    ).status_code == 404
    assert client.get(
        f"/documents/{document_id}/permissions"
    ).status_code == 404
    assert client.patch(
        f"/documents/{document_id}/permissions/{permission['id']}",
        json={"can_download": True},
        headers=csrf_headers(client),
    ).status_code == 404
    assert client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "other@example.com", "access_level": "read"},
        headers=csrf_headers(client),
    ).status_code == 404

    use_authentication(client, owner_cookie, owner_csrf)
    active_permissions = client.get(
        f"/documents/{document_id}/permissions"
    ).json()
    assert active_permissions[0]["id"] == permission["id"]
    enabled = client.patch(
        f"/documents/{document_id}/permissions/{permission['id']}",
        json={"can_download": True},
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert enabled.status_code == 200
    assert enabled.json()["can_download"] is True

    use_authentication(client, viewer_cookie, viewer_csrf)
    shared = client.get("/documents/shared").json()[0]
    assert shared["can_download"] is True
    allowed = client.get(f"/documents/{document_id}/download")
    assert allowed.status_code == 200
    assert allowed.content == PDF

    use_authentication(client, owner_cookie, owner_csrf)
    disabled = client.patch(
        f"/documents/{document_id}/permissions/{permission['id']}",
        json={"can_download": False},
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert disabled.status_code == 200
    assert disabled.json()["can_download"] is False

    use_authentication(client, viewer_cookie, viewer_csrf)
    assert client.get(f"/documents/{document_id}/preview").content == PDF
    denied_again = client.get(f"/documents/{document_id}/download")
    assert denied_again.status_code == 403
    assert "Download permission is not enabled" in denied_again.json()["detail"]

    use_authentication(client, owner_cookie, owner_csrf)
    assert client.delete(
        f"/documents/{document_id}/permissions/{permission['id']}"
    ).status_code == 403
    revoked = client.delete(
        f"/documents/{document_id}/permissions/{permission['id']}",
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert revoked.status_code == 204

    use_authentication(client, viewer_cookie, viewer_csrf)
    assert client.get("/documents/shared").json() == []
    assert client.get(f"/documents/{document_id}/preview").status_code == 404
    assert client.get(f"/documents/{document_id}/download").status_code == 404

    with client.app.state.session_factory() as db:
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    assert [event.action for event in events] == [
        "document.uploaded",
        "permission.granted",
        "document.previewed",
        "document.download_denied",
        "permission.download_updated",
        "document.downloaded",
        "permission.download_updated",
        "document.previewed",
        "document.download_denied",
        "permission.revoked",
        "document.download_denied",
    ]
    previous_hash = "0" * 64
    for event in events:
        assert event.previous_hash == previous_hash
        event_data = json.dumps(
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
        assert event.event_hash == hashlib.sha256(
            event_data.encode("utf-8")
        ).hexdigest()
        assert str(storage) not in event.metadata_json
        assert PDF.decode("latin-1") not in event.metadata_json
        previous_hash = event.event_hash


def test_edit_grants_are_rejected_and_legacy_rows_are_non_authorizing(workspace):
    client, _ = workspace
    register_user(client, "owner@example.com")
    owner_cookie = client.cookies.get("trustvault_session")
    owner_csrf = client.cookies.get("trustvault_csrf")
    document_id = upload_pdf(client).json()["id"]
    owner_id = client.get("/auth/me").json()["id"]

    register_user(client, "viewer@example.com")
    viewer_cookie = client.cookies.get("trustvault_session")
    viewer_csrf = client.cookies.get("trustvault_csrf")
    viewer_id = client.get("/auth/me").json()["id"]

    use_authentication(client, owner_cookie, owner_csrf)
    rejected_grant = client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "viewer@example.com", "access_level": "edit"},
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert rejected_grant.status_code == 422
    with client.app.state.session_factory() as db:
        document = db.get(Document, document_id)
        assert document is not None
        db.add(
            DocumentPermission(
                id="00000000-0000-0000-0000-000000000002",
                document_id=document_id,
                user_id=viewer_id,
                access_level="edit",
                granted_by=owner_id,
            )
        )
        db.commit()

    use_authentication(client, viewer_cookie, viewer_csrf)
    assert client.get("/documents/shared").json() == []
    assert client.get(f"/documents/{document_id}/preview").status_code == 404
    assert client.get(f"/documents/{document_id}/download").status_code == 404
    assert client.patch(
        f"/documents/{document_id}",
        json={"name": "unauthorized edit"},
        headers=csrf_headers(client),
    ).status_code == 404
    assert client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    ).status_code == 404
    assert client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "another@example.com", "access_level": "read"},
        headers=csrf_headers(client),
    ).status_code == 404

    use_authentication(client, owner_cookie, owner_csrf)
    legacy = client.get(f"/documents/{document_id}/permissions")
    assert legacy.status_code == 200
    assert legacy.json()[0]["access_level"] == "edit"
    assert legacy.json()[0]["id"] == "00000000-0000-0000-0000-000000000002"

    viewer_grant = client.post(
        f"/documents/{document_id}/permissions",
        json={"email": "viewer@example.com", "access_level": "read"},
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert viewer_grant.status_code == 200
    assert viewer_grant.json()["id"] == "00000000-0000-0000-0000-000000000002"
    assert viewer_grant.json()["access_level"] == "read"

    use_authentication(client, viewer_cookie, viewer_csrf)
    assert client.get(f"/documents/{document_id}/preview").content == PDF
    assert client.get(f"/documents/{document_id}/download").status_code == 403
    assert client.patch(
        f"/documents/{document_id}",
        json={"name": "still unauthorized"},
        headers=csrf_headers(client),
    ).status_code == 404

    use_authentication(client, owner_cookie, owner_csrf)
    assert client.delete(
        f"/documents/{document_id}/permissions/00000000-0000-0000-0000-000000000002",
        headers={"X-CSRF-Token": owner_csrf},
    ).status_code == 204
    use_authentication(client, viewer_cookie)
    assert client.get(f"/documents/{document_id}/preview").status_code == 404

    with client.app.state.session_factory() as db:
        permission = db.get(
            DocumentPermission, "00000000-0000-0000-0000-000000000002"
        )
        assert permission is not None
        assert permission.access_level == "read"
        assert permission.revoked_at is not None
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    assert [event.action for event in events] == [
        "document.uploaded",
        "document.download_denied",
        "permission.updated",
        "document.previewed",
        "document.download_denied",
        "permission.revoked",
    ]
    assert json.loads(events[2].metadata_json)["previous_access_level"] == "edit"
    previous_hash = "0" * 64
    for event in events:
        assert event.previous_hash == previous_hash
        event_data = json.dumps(
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
        assert event.event_hash == hashlib.sha256(
            event_data.encode("utf-8")
        ).hexdigest()
        previous_hash = event.event_hash


def test_preview_supports_plain_text_files(workspace):
    client, _ = workspace
    register_user(client, "owner@example.com")
    upload = client.post(
        "/documents",
        files={"file": ("notes.txt", b"private text", "text/plain")},
        headers=csrf_headers(client),
    )
    assert upload.status_code == 201
    preview = client.get(f"/documents/{upload.json()['id']}/preview")
    assert preview.status_code == 200
    assert preview.headers["content-type"].startswith("text/plain")
    assert preview.text == "private text"


def test_missing_storage_file_can_be_deleted_without_leaving_record(workspace):
    client, storage = workspace
    register_user(client, "owner@example.com")
    document_id = upload_pdf(client).json()["id"]
    stored_file = next(storage.iterdir())
    stored_file.unlink()
    response = client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    )
    assert response.status_code == 204
    with client.app.state.session_factory() as db:
        assert db.scalar(select(Document).where(Document.id == document_id)) is None


def test_upload_commit_failure_cleans_file_and_rolls_back_record(workspace, monkeypatch):
    client, storage = workspace
    register_user(client, "owner@example.com")
    fail_commit_for_documents(monkeypatch, is_new=True)

    response = upload_pdf(client)

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to store document"}
    assert str(storage) not in response.text
    assert document_count(client) == 0
    assert list(storage.iterdir()) == []
    with client.app.state.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == 0


def test_delete_commit_failure_keeps_document_active_and_file(workspace, monkeypatch):
    client, storage = workspace
    register_user(client, "owner@example.com")
    document_id = upload_pdf(client).json()["id"]
    stored_file = next(storage.iterdir())
    fail_commit_for_documents(monkeypatch, is_new=False)
    response = client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    )

    assert response.status_code == 500
    assert response.json() == {"detail": "Unable to delete document"}
    assert str(storage) not in response.text
    assert document_count(client) == 1
    assert stored_file.read_bytes() == PDF
    with client.app.state.session_factory() as db:
        actions = list(db.scalars(select(AuditEvent.action)))
    assert actions == ["document.uploaded"]
    with client.app.state.session_factory() as db:
        assert db.scalar(select(StorageOperation).where(
            StorageOperation.document_id == document_id,
            StorageOperation.operation_type == "delete",
        )) is None


def test_delete_storage_failure_is_durable_and_recovery_completes_it(
    workspace, monkeypatch, caplog
):
    client, storage = workspace
    register_user(client, "owner@example.com")
    document_id = upload_pdf(client).json()["id"]
    stored_file = next(storage.iterdir())
    delete = FilesystemStorage.delete

    def failing_delete(provider, storage_key: str) -> None:
        raise StorageOperationError("private storage details")

    monkeypatch.setattr(FilesystemStorage, "delete", failing_delete)

    response = client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Document deletion is pending storage cleanup"
    }
    assert str(storage) not in response.text
    assert "private storage details" not in response.text
    assert document_count(client) == 1
    assert client.get(f"/documents/{document_id}/preview").status_code == 404
    assert stored_file.read_bytes() == PDF
    with client.app.state.session_factory() as db:
        operation = db.scalar(select(StorageOperation).where(
            StorageOperation.document_id == document_id,
            StorageOperation.operation_type == "delete",
        ))
        assert operation is not None
        assert operation.status == "retryable"
        assert operation.error_category == "storage_error"
        assert "private storage details" not in repr(operation.error_category)
        operation.next_attempt_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()

    monkeypatch.setattr(FilesystemStorage, "delete", delete)
    processed, completed = recover_storage_operations(
        client.app.state.session_factory, client.app.state.storage_providers
    )

    assert (processed, completed) == (1, 1)
    assert not stored_file.exists()
    assert document_count(client) == 0
    assert recover_storage_operations(
        client.app.state.session_factory, client.app.state.storage_providers
    ) == (0, 0)
    with client.app.state.session_factory() as db:
        operation = db.scalar(select(StorageOperation).where(
            StorageOperation.document_id == document_id,
            StorageOperation.operation_type == "delete",
        ))
        assert operation is not None
        assert operation.status == "completed"
        actions = list(db.scalars(select(AuditEvent.action)))
    assert actions == ["document.uploaded", "document.deleted"]
