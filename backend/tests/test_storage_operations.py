import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.audit import verify_audit_chain
from app.main import create_app
from app.models import AuditEvent, Document, StorageOperation, User
from app.storage import FilesystemStorage, StorageProviderRegistry
from app.storage_operations import recover_storage_operations

PASSWORD = "a-strong-password"
PDF = b"%PDF-1.7\nstorage outbox test"


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]}


def register_owner(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={"email": "outbox-owner@example.com", "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    response = client.post(
        "/auth/login",
        json={"email": "outbox-owner@example.com", "password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200


def upload(client: TestClient) -> str:
    response = client.post(
        "/documents",
        files={"file": ("outbox.pdf", PDF, "application/pdf")},
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_process_crash_after_upload_is_cleaned_without_success_audit(
    tmp_path: Path,
    monkeypatch,
):
    database_path = tmp_path / "trustvault.db"
    storage_path = tmp_path / "storage"
    app = create_app(
        f"sqlite:///{database_path.as_posix()}",
        cookie_secure=False,
        storage_directory=str(storage_path),
    )
    with TestClient(app) as client:
        register_owner(client)
        original_commit = app.state.session_factory.class_.commit

        def fail_upload_activation(session):
            if any(
                isinstance(item, Document) and item.storage_state == "active"
                for item in session.dirty
            ):
                raise SQLAlchemyError("simulated process loss after storage write")
            original_commit(session)

        monkeypatch.setattr(
            app.state.session_factory.class_, "commit", fail_upload_activation
        )
        response = client.post(
            "/documents",
            files={"file": ("crash.pdf", PDF, "application/pdf")},
            headers=csrf_headers(client),
        )
        monkeypatch.setattr(
            app.state.session_factory.class_, "commit", original_commit
        )

        assert response.status_code == 500
        stored_file = next(storage_path.iterdir())
        assert stored_file.read_bytes() == PDF
        with app.state.session_factory() as db:
            document = db.scalar(select(Document))
            operation = db.scalar(select(StorageOperation))
            actions = list(db.scalars(select(AuditEvent.action)))
            assert document is not None
            assert document.storage_state == "uploading"
            assert operation is not None
            assert operation.status == "processing"
            operation.lease_expires_at = datetime.now(timezone.utc).replace(
                tzinfo=None
            ) - timedelta(seconds=1)
            db.commit()
        assert actions == []

        processed, completed = recover_storage_operations(
            app.state.session_factory, app.state.storage_providers
        )

        assert (processed, completed) == (1, 1)
        assert list(storage_path.iterdir()) == []
        with app.state.session_factory() as db:
            assert db.scalar(select(Document)) is None
            operation = db.scalar(select(StorageOperation))
            assert operation is not None
            assert operation.status == "completed"
            assert list(db.scalars(select(AuditEvent.action))) == []


def test_concurrent_recovery_workers_claim_operation_once(tmp_path: Path):
    database_path = tmp_path / "concurrent.db"
    storage_path = tmp_path / "storage"
    app = create_app(
        f"sqlite:///{database_path.as_posix()}",
        cookie_secure=False,
        storage_directory=str(storage_path),
    )
    with TestClient(app) as client:
        register_owner(client)
        document_id = upload(client)
        storage_key = next(storage_path.iterdir()).name
        with app.state.session_factory() as db:
            document = db.get(Document, document_id)
            assert document is not None
            document.deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
            document.storage_state = "deleting"
            db.add(
                StorageOperation(
                    id="op-concurrent",
                    document_id=document_id,
                    provider="filesystem",
                    storage_key=storage_key,
                    operation_type="delete",
                    status="pending",
                    attempt_count=0,
                    actor_id=document.owner_id,
                )
            )
            db.commit()

        entered_provider = threading.Event()
        allow_delete = threading.Event()

        class BlockingFilesystem(FilesystemStorage):
            def __init__(self, root: Path):
                super().__init__(root)
                self.delete_calls = 0
                self._lock = threading.Lock()

            def delete(self, key: str) -> None:
                with self._lock:
                    self.delete_calls += 1
                entered_provider.set()
                if not allow_delete.wait(timeout=5):
                    raise TimeoutError("test provider release timed out")
                super().delete(key)

        provider = BlockingFilesystem(storage_path)
        providers = StorageProviderRegistry({"filesystem": provider})
        first_result: list[tuple[int, int]] = []
        first_worker = threading.Thread(
            target=lambda: first_result.append(
                recover_storage_operations(app.state.session_factory, providers)
            )
        )
        first_worker.start()
        assert entered_provider.wait(timeout=5)

        second_result = recover_storage_operations(
            app.state.session_factory, providers
        )
        allow_delete.set()
        first_worker.join(timeout=10)

        assert not first_worker.is_alive()
        assert first_result == [(1, 1)]
        assert second_result == (0, 0)
        assert provider.delete_calls == 1
        with app.state.session_factory() as db:
            operation = db.get(StorageOperation, "op-concurrent")
            assert operation is not None
            assert operation.status == "completed"
            deleted_events = list(
                db.scalars(
                    select(AuditEvent).where(AuditEvent.action == "document.deleted")
                )
            )
            assert len(deleted_events) == 1
            audit_events = list(
                db.scalars(select(AuditEvent).order_by(AuditEvent.id))
            )
            assert verify_audit_chain(audit_events).is_valid


def test_delete_request_is_idempotent_and_records_one_audit_event(tmp_path: Path):
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(tmp_path / "storage"),
    )
    with TestClient(app) as client:
        register_owner(client)
        document_id = upload(client)

        first = client.delete(
            f"/documents/{document_id}", headers=csrf_headers(client)
        )
        second = client.delete(
            f"/documents/{document_id}", headers=csrf_headers(client)
        )

        assert first.status_code == 204
        assert second.status_code == 404
        with app.state.session_factory() as db:
            operations = list(
                db.scalars(
                    select(StorageOperation).where(
                        StorageOperation.document_id == document_id,
                        StorageOperation.operation_type == "delete",
                    )
                )
            )
            assert len(operations) == 1
            deleted_events = list(
                db.scalars(
                    select(AuditEvent).where(
                        AuditEvent.target_id == document_id,
                        AuditEvent.action == "document.deleted",
                    )
                )
            )
            assert len(deleted_events) == 1


def test_exhausted_operation_is_retained_as_failed_for_operator_review(tmp_path: Path):
    storage_path = tmp_path / "storage"
    app = create_app(
        "sqlite://",
        cookie_secure=False,
        storage_directory=str(storage_path),
    )
    with TestClient(app) as client:
        register_owner(client)
        document_id = upload(client)
        with app.state.session_factory() as db:
            document = db.get(Document, document_id)
            assert document is not None
            document.deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
            document.storage_state = "deleting"
            db.add(
                StorageOperation(
                    id="op-exhausted",
                    document_id=document_id,
                    provider="filesystem",
                    storage_key=next(storage_path.iterdir()).name,
                    operation_type="delete",
                    status="processing",
                    attempt_count=5,
                    actor_id=document.owner_id,
                    lease_expires_at=datetime.now(timezone.utc).replace(
                        tzinfo=None
                    )
                    - timedelta(seconds=1),
                )
            )
            db.commit()

        assert recover_storage_operations(
            app.state.session_factory, app.state.storage_providers
        ) == (0, 0)
        with app.state.session_factory() as db:
            operation = db.get(StorageOperation, "op-exhausted")
            assert operation is not None
            assert operation.status == "failed"
            assert operation.error_category == "retry_limit"
            assert db.get(Document, document_id) is not None


def test_startup_recovers_durable_incomplete_upload(tmp_path: Path):
    database_path = tmp_path / "startup-recovery.db"
    storage_path = tmp_path / "storage"
    first_app = create_app(
        f"sqlite:///{database_path.as_posix()}",
        cookie_secure=False,
        storage_directory=str(storage_path),
    )
    with TestClient(first_app) as client:
        register_owner(client)
        with first_app.state.session_factory() as db:
            owner_id = db.scalar(select(User.id))
            assert owner_id is not None
            document_id = str(uuid4())
            storage_key = uuid4().hex
            document = Document(
                id=document_id,
                owner_id=owner_id,
                name="incomplete",
                category="test",
                original_name="incomplete.pdf",
                storage_key=storage_key,
                storage_provider="filesystem",
                storage_state="uploading",
                content_type="application/pdf",
                size_bytes=len(PDF),
            )
            operation = StorageOperation(
                id=str(uuid4()),
                document_id=document_id,
                provider="filesystem",
                storage_key=storage_key,
                operation_type="upload_cleanup",
                status="retryable",
                attempt_count=1,
                actor_id=owner_id,
                next_attempt_at=datetime.now(timezone.utc).replace(tzinfo=None)
                - timedelta(seconds=1),
            )
            db.add_all((document, operation))
            db.commit()
        FilesystemStorage(storage_path).write(storage_key, PDF)

    restarted_app = create_app(
        f"sqlite:///{database_path.as_posix()}",
        cookie_secure=False,
        storage_directory=str(storage_path),
    )
    with TestClient(restarted_app):
        assert list(storage_path.iterdir()) == []
        with restarted_app.state.session_factory() as db:
            assert db.get(Document, document_id) is None
            operation = db.scalar(select(StorageOperation).where(
                StorageOperation.document_id == document_id
            ))
            assert operation is not None
            assert operation.status == "completed"
