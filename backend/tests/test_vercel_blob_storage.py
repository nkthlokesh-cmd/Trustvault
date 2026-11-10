from datetime import datetime, timedelta, timezone
from contextlib import AbstractContextManager
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.main import create_app
from app.models import AuditEvent, Document, StorageOperation
from app.storage import (
    StorageObjectNotFoundError,
    StorageProviderUnavailableError,
    StorageTimeoutError,
    VercelBlobStorage,
)
from app.storage_operations import recover_storage_operations
from vercel import blob

PASSWORD = "a-strong-password"
PDF = b"%PDF-1.7\nprivate blob test"
STORAGE_KEY = "0" * 32
EXPECTED_PATH = f"trustvault/documents/{STORAGE_KEY}"


class FakeDownload:
    def __init__(self, content: bytes, fail_after_first_chunk: bool = False):
        self._chunks = (content[:8], content[8:])
        self._fail_after_first_chunk = fail_after_first_chunk
        self.closed = False

    def __iter__(self):
        yield self._chunks[0]
        if self._fail_after_first_chunk:
            raise blob.BlobServiceNotAvailable()
        if self._chunks[1]:
            yield self._chunks[1]

    def close(self) -> None:
        self.closed = True


class FakeDownloadContext(AbstractContextManager[FakeDownload]):
    def __init__(self, download: FakeDownload):
        self.download = download

    def __enter__(self) -> FakeDownload:
        return self.download

    def __exit__(self, *_exc_info: object) -> None:
        del _exc_info
        self.download.close()


class FakeBlobSDK:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.put_calls: list[tuple[str, bytes, str, bool, bool]] = []
        self.delete_calls: list[str] = []
        self.stream_calls: list[FakeDownloadContext] = []
        self.head_calls: list[str] = []
        self.fail_delete_count = 0
        self.fail_put_count = 0
        self.fail_stream_after_first_chunk = False

    def put_blob(
        self,
        pathname: str,
        content: bytes,
        *,
        access: str,
        add_random_suffix: bool,
        allow_overwrite: bool,
    ) -> SimpleNamespace:
        self.put_calls.append(
            (pathname, content, access, add_random_suffix, allow_overwrite)
        )
        if self.fail_put_count:
            self.fail_put_count -= 1
            raise blob.BlobServiceNotAvailable()
        if pathname in self.objects and not allow_overwrite:
            raise blob.BlobError("Object already exists")
        self.objects[pathname] = content
        return SimpleNamespace(url="https://private.example.invalid/object")

    def stream_blob(
        self, pathname: str, *, access: str
    ) -> FakeDownloadContext:
        assert access == "private"
        if pathname not in self.objects:
            raise blob.BlobNotFoundError()
        context = FakeDownloadContext(
            FakeDownload(
                self.objects[pathname], self.fail_stream_after_first_chunk
            )
        )
        self.stream_calls.append(context)
        return context

    def head_blob(self, pathname: str) -> SimpleNamespace:
        self.head_calls.append(pathname)
        if pathname not in self.objects:
            raise blob.BlobNotFoundError()
        return SimpleNamespace(size=len(self.objects[pathname]))

    def delete_blob(self, pathname: str) -> None:
        self.delete_calls.append(pathname)
        if self.fail_delete_count:
            self.fail_delete_count -= 1
            raise blob.BlobServiceNotAvailable()
        self.objects.pop(pathname, None)


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]}


def register_user(client: TestClient, email: str) -> None:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    response = client.post(
        "/auth/login",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200


def login_user(client: TestClient, email: str) -> None:
    response = client.post(
        "/auth/login",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200


def use_auth_cookies(client: TestClient, session: str, csrf: str) -> None:
    client.cookies.clear()
    client.cookies.set("trustvault_session", session)
    client.cookies.set("trustvault_csrf", csrf)


def configure_blob(monkeypatch, fake: FakeBlobSDK) -> None:
    monkeypatch.setenv("BLOB_READ_WRITE_TOKEN", "test-token")
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("BLOB_STORE_ID", raising=False)
    monkeypatch.setattr("app.storage.vercel_blob_sync", fake)


def test_blob_operations_use_private_stable_paths_and_close_streams(monkeypatch):
    fake = FakeBlobSDK()
    monkeypatch.setattr("app.storage.vercel_blob_sync", fake)
    storage = VercelBlobStorage()

    storage.write(STORAGE_KEY, PDF)
    assert fake.put_calls == [(EXPECTED_PATH, PDF, "private", False, False)]
    assert storage.exists(STORAGE_KEY)

    with storage.open_read(STORAGE_KEY) as stored_file:
        assert stored_file.read() == PDF
    assert fake.stream_calls[-1].download.closed

    storage.delete(STORAGE_KEY)
    storage.delete(STORAGE_KEY)
    assert fake.delete_calls == [EXPECTED_PATH, EXPECTED_PATH]
    assert not fake.objects


def test_blob_missing_objects_and_stream_failures_are_safe(monkeypatch):
    fake = FakeBlobSDK()
    monkeypatch.setattr("app.storage.vercel_blob_sync", fake)
    storage = VercelBlobStorage()

    assert not storage.exists(STORAGE_KEY)
    with pytest.raises(StorageObjectNotFoundError):
        storage.open_read(STORAGE_KEY)

    fake.objects[EXPECTED_PATH] = PDF
    fake.fail_stream_after_first_chunk = True
    with pytest.raises(StorageProviderUnavailableError):
        with storage.open_read(STORAGE_KEY) as stored_file:
            stored_file.read()
    assert fake.stream_calls[-1].download.closed

    class TimeoutBlobSDK(FakeBlobSDK):
        def head_blob(self, pathname: str) -> SimpleNamespace:
            self.head_calls.append(pathname)
            raise TimeoutError

    monkeypatch.setattr("app.storage.vercel_blob_sync", TimeoutBlobSDK())
    with pytest.raises(StorageTimeoutError):
        storage.exists(STORAGE_KEY)


def test_blob_routes_preserve_authorization_and_revoke_access(
    tmp_path: Path, monkeypatch
):
    fake = FakeBlobSDK()
    configure_blob(monkeypatch, fake)
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        storage_provider="vercel_blob",
    )
    with TestClient(app) as client:
        register_user(client, "owner@example.com")
        owner_cookie = client.cookies.get("trustvault_session")
        owner_csrf = client.cookies.get("trustvault_csrf")

        uploaded = client.post(
            "/documents",
            files={"file": ("private.pdf", PDF, "application/pdf")},
            headers=csrf_headers(client),
        )
        assert uploaded.status_code == 201
        document_id = uploaded.json()["id"]
        assert "private.example.invalid" not in uploaded.text
        with app.state.session_factory() as db:
            document = db.get(Document, document_id)
            assert document is not None
            assert document.storage_provider == "vercel_blob"
            storage_key = document.storage_key
        blob_path = f"trustvault/documents/{storage_key}"
        assert fake.objects[blob_path] == PDF

        register_user(client, "viewer@example.com")
        viewer_cookie = client.cookies.get("trustvault_session")
        viewer_csrf = client.cookies.get("trustvault_csrf")
        assert client.get(f"/documents/{document_id}/preview").status_code == 404
        assert fake.stream_calls == []

        use_auth_cookies(client, owner_cookie, owner_csrf)
        grant = client.post(
            f"/documents/{document_id}/permissions",
            json={"email": "viewer@example.com", "access_level": "read"},
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert grant.status_code == 200, grant.text
        permission_id = grant.json()["id"]

        use_auth_cookies(client, viewer_cookie, viewer_csrf)
        assert client.get(f"/documents/{document_id}/preview").content == PDF
        reads_after_preview = len(fake.stream_calls)
        assert client.get(f"/documents/{document_id}/download").status_code == 403
        assert len(fake.stream_calls) == reads_after_preview

        use_auth_cookies(client, owner_cookie, owner_csrf)
        enabled = client.patch(
            f"/documents/{document_id}/permissions/{permission_id}",
            json={"can_download": True},
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert enabled.status_code == 200
        use_auth_cookies(client, viewer_cookie, viewer_csrf)
        assert client.get(f"/documents/{document_id}/download").content == PDF

        use_auth_cookies(client, owner_cookie, owner_csrf)
        revoked = client.delete(
            f"/documents/{document_id}/permissions/{permission_id}",
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert revoked.status_code == 204
        reads_after_revocation = len(fake.stream_calls)
        use_auth_cookies(client, viewer_cookie, viewer_csrf)
        assert client.get(f"/documents/{document_id}/preview").status_code == 404
        assert len(fake.stream_calls) == reads_after_revocation


def test_blob_delete_retries_through_outbox_without_duplicate_audit(
    tmp_path: Path, monkeypatch
):
    fake = FakeBlobSDK()
    configure_blob(monkeypatch, fake)
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        storage_provider="vercel_blob",
    )
    with TestClient(app) as client:
        register_user(client, "owner@example.com")
        uploaded = client.post(
            "/documents",
            files={"file": ("private.pdf", PDF, "application/pdf")},
            headers=csrf_headers(client),
        )
        assert uploaded.status_code == 201
        document_id = uploaded.json()["id"]

        fake.fail_delete_count = 1
        deleted = client.delete(
            f"/documents/{document_id}", headers=csrf_headers(client)
        )
        assert deleted.status_code == 503
        assert client.get(f"/documents/{document_id}/preview").status_code == 404
        with app.state.session_factory() as db:
            operation = db.scalar(
                select(StorageOperation).where(
                    StorageOperation.document_id == document_id,
                    StorageOperation.operation_type == "delete",
                )
            )
            assert operation is not None
            assert operation.provider == "vercel_blob"
            assert operation.status == "retryable"
            operation.next_attempt_at = operation.created_at
            db.commit()

        assert recover_storage_operations(
            app.state.session_factory, app.state.storage_providers
        ) == (1, 1)
        assert recover_storage_operations(
            app.state.session_factory, app.state.storage_providers
        ) == (0, 0)
        assert fake.delete_calls == [
            fake.put_calls[0][0],
            fake.put_calls[0][0],
        ]
        assert fake.objects == {}
        with app.state.session_factory() as db:
            actions = list(
                db.scalars(
                    select(AuditEvent.action).where(
                        AuditEvent.target_id == document_id
                    )
                )
            )
            assert actions.count("document.uploaded") == 1
            assert actions.count("document.deleted") == 1


def test_blob_upload_failure_is_cleaned_by_outbox_retry(
    tmp_path: Path, monkeypatch
):
    fake = FakeBlobSDK()
    configure_blob(monkeypatch, fake)
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        storage_provider="vercel_blob",
    )
    with TestClient(app) as client:
        register_user(client, "owner@example.com")
        fake.fail_put_count = 1
        response = client.post(
            "/documents",
            files={"file": ("private.pdf", PDF, "application/pdf")},
            headers=csrf_headers(client),
        )
        assert response.status_code == 503
        assert "private.example.invalid" not in response.text

        with app.state.session_factory() as db:
            operation = db.scalar(select(StorageOperation))
            document = db.scalar(select(Document))
            assert operation is not None
            assert operation.provider == "vercel_blob"
            assert operation.status == "retryable"
            assert document is not None
            assert document.storage_state == "uploading"
            operation.next_attempt_at = operation.created_at
            db.commit()

        assert recover_storage_operations(
            app.state.session_factory, app.state.storage_providers
        ) == (1, 1)
        with app.state.session_factory() as db:
            assert db.scalar(select(Document)) is None
            assert list(db.scalars(select(AuditEvent.action))) == []
        assert fake.delete_calls == [fake.put_calls[0][0]]
        assert fake.objects == {}


def test_blob_upload_after_storage_write_is_cleaned_after_activation_failure(
    tmp_path: Path, monkeypatch
):
    fake = FakeBlobSDK()
    configure_blob(monkeypatch, fake)
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
        storage_provider="vercel_blob",
    )
    with TestClient(app) as client:
        register_user(client, "owner@example.com")
        original_commit = app.state.session_factory.class_.commit

        def fail_activation(session):
            if any(
                isinstance(item, Document) and item.storage_state == "active"
                for item in session.dirty
            ):
                raise SQLAlchemyError("simulated activation failure")
            original_commit(session)

        app.state.session_factory.class_.commit = fail_activation
        response = client.post(
            "/documents",
            files={"file": ("private.pdf", PDF, "application/pdf")},
            headers=csrf_headers(client),
        )
        app.state.session_factory.class_.commit = original_commit
        assert response.status_code == 500
        assert len(fake.objects) == 1

        with app.state.session_factory() as db:
            operation = db.scalar(select(StorageOperation))
            assert operation is not None
            operation.lease_expires_at = (
                datetime.now(timezone.utc).replace(tzinfo=None)
                - timedelta(seconds=1)
            )
            db.commit()

        assert recover_storage_operations(
            app.state.session_factory, app.state.storage_providers
        ) == (1, 1)
        assert fake.objects == {}
        with app.state.session_factory() as db:
            assert db.scalar(select(Document)) is None
            assert list(db.scalars(select(AuditEvent.action))) == []


def test_filesystem_and_blob_documents_survive_provider_restart(
    tmp_path: Path, monkeypatch
):
    fake = FakeBlobSDK()
    configure_blob(monkeypatch, fake)
    database_path = tmp_path / "trustvault.db"
    storage_path = tmp_path / "filesystem-storage"
    database_url = f"sqlite:///{database_path.as_posix()}"
    filesystem_app = create_app(
        database_url,
        cookie_secure=False,
        storage_directory=str(storage_path),
        storage_provider="filesystem",
    )
    with TestClient(filesystem_app) as client:
        register_user(client, "owner@example.com")
        filesystem_document = client.post(
            "/documents",
            files={"file": ("filesystem.pdf", PDF, "application/pdf")},
            headers=csrf_headers(client),
        )
        assert filesystem_document.status_code == 201
        filesystem_id = filesystem_document.json()["id"]

    blob_app = create_app(
        database_url,
        cookie_secure=False,
        storage_directory=str(storage_path),
        storage_provider="vercel_blob",
    )
    with TestClient(blob_app) as client:
        login_user(client, "owner@example.com")
        assert client.get(
            f"/documents/{filesystem_id}/preview"
        ).content == PDF
        blob_document = client.post(
            "/documents",
            files={"file": ("blob.pdf", PDF, "application/pdf")},
            headers=csrf_headers(client),
        )
        assert blob_document.status_code == 201
        blob_id = blob_document.json()["id"]

    restarted_app = create_app(
        database_url,
        cookie_secure=False,
        storage_directory=str(storage_path),
        storage_provider="vercel_blob",
    )
    with TestClient(restarted_app) as client:
        login_user(client, "owner@example.com")
        assert client.get(f"/documents/{filesystem_id}/preview").content == PDF
        assert client.get(f"/documents/{blob_id}/preview").content == PDF
