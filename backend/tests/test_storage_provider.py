import asyncio
import io
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import documents
from app.database import (
    build_engine,
    ensure_document_storage_provider_column,
    ensure_document_storage_state_column,
)
from app.main import create_app
from app.models import AuditEvent, Document, StorageOperation
from app.storage import (
    FilesystemStorage,
    StorageObjectNotFoundError,
    StorageOperationError,
    StorageProviderRegistry,
    StorageProviderUnavailableError,
    StorageTimeoutError,
)

PASSWORD = "a-strong-password"
PDF = b"%PDF-1.7\nprovider dispatch test"


@pytest.fixture
def workspace(tmp_path: Path):
    storage_path = tmp_path / "private-storage"
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(storage_path),
    )
    with TestClient(app) as client:
        yield client, storage_path


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]}


def login_owner(client: TestClient) -> None:
    headers = csrf_headers(client)
    registered = client.post(
        "/auth/register",
        json={"email": "owner@example.com", "password": PASSWORD},
        headers=headers,
    )
    assert registered.status_code == 201
    login = client.post(
        "/auth/login",
        json={"email": "owner@example.com", "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert login.status_code == 200


def upload_pdf(client: TestClient) -> str:
    response = client.post(
        "/documents",
        files={"file": ("provider.pdf", PDF, "application/pdf")},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_storage_provider_upgrade_is_additive_and_idempotent():
    engine = build_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE documents (id TEXT PRIMARY KEY, "
                    "storage_key TEXT NOT NULL, owner_id TEXT NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO documents (id, storage_key, owner_id) VALUES "
                    "('one', 'key-one', 'owner-one'), "
                    "('two', 'key-two', 'owner-two')"
                )
            )

        ensure_document_storage_provider_column(engine)
        ensure_document_storage_state_column(engine)
        ensure_document_storage_provider_column(engine)
        ensure_document_storage_state_column(engine)

        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT id, storage_key, owner_id, storage_provider, storage_state "
                    "FROM documents ORDER BY id"
                )
            ).all()
            columns = {
                column["name"]
                for column in inspect(connection).get_columns("documents")
            }
        assert rows == [
            ("one", "key-one", "owner-one", "filesystem", "active"),
            ("two", "key-two", "owner-two", "filesystem", "active"),
        ]
        assert {
            "id",
            "storage_key",
            "owner_id",
            "storage_provider",
            "storage_state",
        } <= columns
    finally:
        engine.dispose()


def test_storage_provider_upgrade_only_fills_missing_values():
    engine = build_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE documents (id TEXT PRIMARY KEY, "
                    "storage_provider VARCHAR(32))"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO documents (id, storage_provider) VALUES "
                    "('existing', 'recording'), ('blank', ' ')"
                )
            )

        ensure_document_storage_provider_column(engine)

        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT id, storage_provider FROM documents ORDER BY id"
                )
            ).all()
        assert rows == [("blank", "filesystem"), ("existing", "recording")]
    finally:
        engine.dispose()


def test_new_documents_use_filesystem_provider(workspace):
    client, _ = workspace
    login_owner(client)
    document_id = upload_pdf(client)

    with client.app.state.session_factory() as db:
        document = db.get(Document, document_id)
        assert document is not None
        assert document.storage_provider == "filesystem"
        assert document.storage_state == "active"
        operation = db.scalar(
            select(StorageOperation).where(
                StorageOperation.document_id == document_id,
                StorageOperation.operation_type == "upload_cleanup",
            )
        )
        assert operation is not None
        assert operation.status == "completed"
        actions = list(
            db.scalars(
                select(AuditEvent.action).where(
                    AuditEvent.target_id == document_id,
                    AuditEvent.action == "document.uploaded",
                )
            )
        )
        assert actions == ["document.uploaded"]


def test_existing_document_operations_dispatch_by_stored_provider(workspace):
    client, storage_path = workspace
    login_owner(client)
    document_id = upload_pdf(client)

    class RecordingFilesystemStorage(FilesystemStorage):
        open_read_calls = 0
        delete_calls = 0

        def open_read(self, storage_key):
            self.open_read_calls += 1
            return super().open_read(storage_key)

        def delete(self, storage_key):
            self.delete_calls += 1
            return super().delete(storage_key)

    recording_provider = RecordingFilesystemStorage(storage_path)
    client.app.state.storage_providers = StorageProviderRegistry(
        {
            "filesystem": FilesystemStorage(storage_path),
            "recording": recording_provider,
        }
    )
    with client.app.state.session_factory() as db:
        document = db.get(Document, document_id)
        assert document is not None
        document.storage_provider = "recording"
        db.commit()

    preview = client.get(f"/documents/{document_id}/preview")
    assert preview.status_code == 200
    assert preview.content == PDF
    assert recording_provider.open_read_calls == 1

    deleted = client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    )
    assert deleted.status_code == 204
    assert recording_provider.delete_calls == 1
    assert list(storage_path.iterdir()) == []


def test_unknown_stored_provider_fails_closed_without_filesystem_fallback(workspace):
    client, storage_path = workspace
    login_owner(client)
    document_id = upload_pdf(client)
    stored_file = next(storage_path.iterdir())
    with client.app.state.session_factory() as db:
        document = db.get(Document, document_id)
        assert document is not None
        document.storage_provider = "unsupported"
        db.commit()

    for path in (
        f"/documents/{document_id}/preview",
        f"/documents/{document_id}/download",
    ):
        response = client.get(path)
        assert response.status_code == 503
        assert str(storage_path) not in response.text

    deleted = client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    )
    assert deleted.status_code == 503
    assert stored_file.read_bytes() == PDF
    with client.app.state.session_factory() as db:
        assert db.get(Document, document_id) is not None


def test_unsupported_default_provider_is_rejected_at_app_creation(tmp_path: Path):
    with pytest.raises(
        StorageProviderUnavailableError, match="Storage provider is unavailable"
    ):
        create_app(
            "sqlite://",
            storage_directory=str(tmp_path / "private-storage"),
            storage_provider="unsupported",
        )


def test_blob_provider_requires_credentials_at_app_creation(
    tmp_path: Path, monkeypatch
):
    monkeypatch.delenv("BLOB_READ_WRITE_TOKEN", raising=False)
    monkeypatch.delenv("BLOB_STORE_ID", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)

    with pytest.raises(ValueError, match="BLOB_READ_WRITE_TOKEN"):
        create_app(
            "sqlite://",
            storage_directory=str(tmp_path / "private-storage"),
            storage_provider="vercel_blob",
        )


class NonSeekableStream:
    def __init__(self, content: bytes, fail_after: int | None = None):
        self._stream = io.BytesIO(content)
        self._reads = 0
        self._fail_after = fail_after
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        self._reads += 1
        if self._fail_after is not None and self._reads > self._fail_after:
            raise StorageOperationError("provider-specific private failure")
        return self._stream.read(size)

    def close(self) -> None:
        self.closed = True
        self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def seek(self, *_args, **_kwargs):
        raise AssertionError("Provider stream must not need to be seekable")


class StreamProvider:
    def __init__(self, stream: NonSeekableStream):
        self.stream = stream

    def open_read(self, _storage_key: str):
        return self.stream


def make_docx(extra_bytes: int = 0) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "word/document.xml",
            "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>"
            "<w:body><w:p><w:r><w:t>Remote stream preview</w:t></w:r></w:p></w:body>"
            "</w:document>",
        )
        if extra_bytes:
            archive.writestr("padding.bin", b"x" * extra_bytes)
    return buffer.getvalue()


def test_stream_generator_closes_provider_stream_on_completion_failure_and_cancel():
    completed_stream = NonSeekableStream(b"complete")
    assert (
        b"".join(documents._stream_file(StreamProvider(completed_stream), "key"))
        == b"complete"
    )
    assert completed_stream.closed

    failed_stream = NonSeekableStream(b"firstsecond", fail_after=1)
    stream = documents._stream_file(StreamProvider(failed_stream), "key")
    assert next(stream) == b"firstsecond"
    with pytest.raises(StorageOperationError):
        next(stream)
    assert failed_stream.closed

    interrupted_stream = NonSeekableStream(b"chunk")
    stream = documents._stream_file(StreamProvider(interrupted_stream), "key")
    assert next(stream) == b"chunk"
    stream.close()
    assert interrupted_stream.closed


def test_async_response_stream_closes_underlying_stream_when_cancelled():
    source = NonSeekableStream(b"first chunk and more")

    async def consume_one_chunk_then_cancel():
        response_stream = documents._async_stream(
            documents._stream_file(StreamProvider(source), "key")
        )
        assert await response_stream.__anext__() == b"first chunk and more"
        await response_stream.aclose()

    asyncio.run(consume_one_chunk_then_cancel())
    assert source.closed


def test_async_response_stream_closes_underlying_stream_after_read_failure():
    source = NonSeekableStream(b"first chunk", fail_after=1)

    async def consume_until_provider_failure():
        response_stream = documents._async_stream(
            documents._stream_file(StreamProvider(source), "key")
        )
        assert await response_stream.__anext__() == b"first chunk"
        with pytest.raises(StorageOperationError):
            await response_stream.__anext__()

    asyncio.run(consume_until_provider_failure())
    assert source.closed


def test_download_response_closes_provider_stream_after_normal_completion(workspace):
    client, storage_path = workspace
    login_owner(client)
    document_id = upload_pdf(client)
    source = NonSeekableStream(PDF)

    class TrackingProvider:
        def exists(self, _storage_key):
            return True

        def open_read(self, _storage_key):
            return source

    with client.app.state.session_factory() as db:
        document = db.get(Document, document_id)
        assert document is not None
        document.storage_provider = "tracking"
        db.commit()
    client.app.state.storage_providers = StorageProviderRegistry(
        {
            "filesystem": FilesystemStorage(storage_path),
            "tracking": TrackingProvider(),
        }
    )

    response = client.get(f"/documents/{document_id}/download")

    assert response.status_code == 200
    assert response.content == PDF
    assert source.closed


def test_docx_preview_accepts_nonseekable_provider_stream():
    source = NonSeekableStream(make_docx())

    preview = documents._docx_preview_text(StreamProvider(source), "key")

    assert preview == b"Remote stream preview"
    assert source.closed


def test_docx_preview_spools_to_bounded_temporary_storage(monkeypatch):
    source = NonSeekableStream(make_docx(extra_bytes=1_200_000))
    created_spools = []
    original_spooled_file = documents.tempfile.SpooledTemporaryFile

    def tracking_spooled_file(*args, **kwargs):
        spool = original_spooled_file(*args, **kwargs)
        created_spools.append((spool, kwargs.get("max_size")))
        return spool

    monkeypatch.setattr(
        documents.tempfile, "SpooledTemporaryFile", tracking_spooled_file
    )
    preview = documents._docx_preview_text(StreamProvider(source), "key")

    assert preview == b"Remote stream preview"
    assert source.closed
    assert created_spools[0][1] == documents.DOCX_SPOOL_MEMORY_BYTES
    assert created_spools[0][0]._rolled
    assert created_spools[0][0].closed


def test_docx_preview_rejects_input_over_spool_limit_and_closes_stream():
    source = NonSeekableStream(b"x" * (documents.MAX_UPLOAD_BYTES + 1))

    with pytest.raises(HTTPException) as error:
        documents._docx_preview_text(StreamProvider(source), "key")

    assert error.value.status_code == 413
    assert source.closed


def test_filesystem_cleanup_and_restore_operations_are_idempotent(tmp_path: Path):
    storage = FilesystemStorage(tmp_path)
    key = "a" * 32
    storage.write(key, b"private")

    quarantine_key = storage.quarantine(key)
    assert quarantine_key is not None
    assert storage.quarantine(key) is None
    storage.restore(key, quarantine_key)
    storage.restore(key, quarantine_key)
    with storage.open_read(key) as stored_file:
        assert stored_file.read() == b"private"

    quarantine_key = storage.quarantine(key)
    assert quarantine_key is not None
    storage.delete_quarantined(quarantine_key)
    storage.delete_quarantined(quarantine_key)
    storage.delete(key)
    storage.delete(key)
    assert not storage.exists(key)


def test_non_owner_request_does_not_invoke_storage(workspace):
    client, storage_path = workspace
    login_owner(client)
    document_id = upload_pdf(client)

    class CountingFilesystem(FilesystemStorage):
        exists_calls = 0
        read_calls = 0

        def exists(self, storage_key):
            self.exists_calls += 1
            return super().exists(storage_key)

        def open_read(self, storage_key):
            self.read_calls += 1
            return super().open_read(storage_key)

    provider = CountingFilesystem(storage_path)
    client.app.state.storage_providers = StorageProviderRegistry(
        {"filesystem": provider}
    )
    assert client.post("/auth/logout", headers=csrf_headers(client)).status_code == 204
    registered = client.post(
        "/auth/register",
        json={"email": "viewer@example.com", "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert registered.status_code == 201
    logged_in = client.post(
        "/auth/login",
        json={"email": "viewer@example.com", "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert logged_in.status_code == 200

    response = client.get(f"/documents/{document_id}/preview")

    assert response.status_code == 404
    assert provider.exists_calls == 0
    assert provider.read_calls == 0


def test_provider_timeout_uses_safe_response_and_missing_object_is_404(workspace):
    client, _ = workspace
    login_owner(client)
    document_id = upload_pdf(client)

    class FailingProvider:
        def exists(self, _storage_key):
            raise StorageTimeoutError("private URL and token must not escape")

    with client.app.state.session_factory() as db:
        document = db.get(Document, document_id)
        assert document is not None
        document.storage_provider = "failing"
        db.commit()
    client.app.state.storage_providers = StorageProviderRegistry(
        {
            "filesystem": FilesystemStorage(Path(client.app.state.storage_directory)),
            "failing": FailingProvider(),
        }
    )

    timeout_response = client.get(f"/documents/{document_id}/preview")
    assert timeout_response.status_code == 503
    assert "private URL" not in timeout_response.text
    assert "token" not in timeout_response.text

    class MissingProvider:
        def exists(self, _storage_key):
            raise StorageObjectNotFoundError("internal provider details")

    client.app.state.storage_providers = StorageProviderRegistry(
        {
            "filesystem": FilesystemStorage(Path(client.app.state.storage_directory)),
            "failing": MissingProvider(),
        }
    )
    missing_response = client.get(f"/documents/{document_id}/preview")
    assert missing_response.status_code == 404
    assert "internal provider details" not in missing_response.text


def test_provider_without_filesystem_recovery_capability_deletes_after_commit(
    workspace,
):
    client, storage_path = workspace
    login_owner(client)
    document_id = upload_pdf(client)
    stored_file = next(storage_path.iterdir())

    class BasicProvider:
        def __init__(self):
            self.delete_calls = 0

        def exists(self, _storage_key):
            return True

        def delete(self, _storage_key):
            self.delete_calls += 1
            stored_file.unlink(missing_ok=True)

    provider = BasicProvider()
    with client.app.state.session_factory() as db:
        document = db.get(Document, document_id)
        assert document is not None
        document.storage_provider = "basic"
        db.commit()
    client.app.state.storage_providers = StorageProviderRegistry(
        {"filesystem": FilesystemStorage(storage_path), "basic": provider}
    )

    original_commit = Session.commit

    def fail_delete_commit(session: Session):
        if any(
            isinstance(item, Document) and item.deleted_at is not None
            for item in session.dirty
        ):
            raise SQLAlchemyError("private database failure")
        original_commit(session)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Session, "commit", fail_delete_commit)
        failed = client.delete(
            f"/documents/{document_id}", headers=csrf_headers(client)
        )

    assert failed.status_code == 500
    assert provider.delete_calls == 0
    assert stored_file.read_bytes() == PDF
    with client.app.state.session_factory() as db:
        assert db.get(Document, document_id) is not None

    deleted = client.delete(
        f"/documents/{document_id}", headers=csrf_headers(client)
    )
    assert deleted.status_code == 204
    assert provider.delete_calls == 1
    assert not stored_file.exists()
