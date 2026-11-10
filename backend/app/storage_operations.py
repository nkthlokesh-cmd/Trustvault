import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.audit import record_audit
from app.models import Document, StorageOperation, User
from app.storage import (
    InvalidStorageKeyError,
    StorageError,
    StorageObjectNotFoundError,
    StorageProviderRegistry,
    StorageProviderUnavailableError,
    StorageTimeoutError,
)

logger = logging.getLogger(__name__)

MAX_STORAGE_OPERATION_ATTEMPTS = 5
STORAGE_OPERATION_LEASE = timedelta(minutes=15)
STORAGE_OPERATION_RETRY_BASE_SECONDS = 2
STORAGE_OPERATION_RETRY_MAX_SECONDS = 300


@dataclass(frozen=True)
class StorageOperationClaim:
    id: str
    document_id: str
    provider: str
    storage_key: str
    operation_type: str
    actor_id: str | None
    lease_token: str
    attempt_count: int


def utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def create_upload_operation(
    db: Session,
    document: Document,
    actor_id: str,
) -> tuple[StorageOperation, str]:
    token = str(uuid4())
    now = utcnow_naive()
    document.storage_state = "uploading"
    operation = StorageOperation(
        id=str(uuid4()),
        document_id=document.id,
        provider=document.storage_provider,
        storage_key=document.storage_key,
        operation_type="upload_cleanup",
        status="processing",
        attempt_count=1,
        actor_id=actor_id,
        lease_token=token,
        lease_expires_at=now + STORAGE_OPERATION_LEASE,
    )
    db.add(document)
    db.add(operation)
    return operation, token


def activate_uploaded_document(
    db: Session,
    operation_id: str,
    lease_token: str,
    document: Document,
    actor_id: str,
    metadata: dict[str, object],
) -> None:
    operation = db.get(StorageOperation, operation_id)
    if (
        operation is None
        or operation.status != "processing"
        or operation.lease_token != lease_token
    ):
        raise StorageOperationLeaseLostError
    document.storage_state = "active"
    operation.status = "completed"
    operation.completed_at = utcnow_naive()
    operation.updated_at = operation.completed_at
    operation.lease_token = None
    operation.lease_expires_at = None
    operation.error_category = None
    record_audit(
        db,
        actor_id,
        "document.uploaded",
        "document",
        document.id,
        metadata,
    )


class StorageOperationLeaseLostError(RuntimeError):
    pass


def mark_storage_operation_retryable(
    session_factory: sessionmaker[Session],
    operation_id: str,
    lease_token: str,
    error_category: str,
) -> None:
    with session_factory() as db:
        operation = db.get(StorageOperation, operation_id)
        if (
            operation is None
            or operation.status != "processing"
            or operation.lease_token != lease_token
        ):
            return
        operation.status = (
            "failed"
            if operation.attempt_count >= MAX_STORAGE_OPERATION_ATTEMPTS
            else "retryable"
        )
        operation.error_category = error_category
        operation.lease_token = None
        operation.lease_expires_at = None
        operation.updated_at = utcnow_naive()
        if operation.status == "retryable":
            delay = min(
                STORAGE_OPERATION_RETRY_BASE_SECONDS
                * (2 ** max(0, operation.attempt_count - 1)),
                STORAGE_OPERATION_RETRY_MAX_SECONDS,
            )
            operation.next_attempt_at = operation.updated_at + timedelta(seconds=delay)
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            logger.error("Could not persist storage operation retry state")


def _eligible_operation_filter(now: datetime):
    return or_(
        and_(
            StorageOperation.status.in_(("pending", "retryable")),
            or_(
                StorageOperation.next_attempt_at.is_(None),
                StorageOperation.next_attempt_at <= now,
            ),
        ),
        and_(
            StorageOperation.status == "processing",
            StorageOperation.lease_expires_at <= now,
        ),
    )


def claim_storage_operation(
    session_factory: sessionmaker[Session],
    operation_id: str | None = None,
) -> StorageOperationClaim | None:
    now = utcnow_naive()
    with session_factory() as db:
        eligible = _eligible_operation_filter(now)
        exhausted = eligible & (
            StorageOperation.attempt_count >= MAX_STORAGE_OPERATION_ATTEMPTS
        )
        db.execute(
            update(StorageOperation)
            .where(exhausted)
            .values(
                status="failed",
                lease_token=None,
                lease_expires_at=None,
                error_category="retry_limit",
                updated_at=now,
            )
        )
        candidates = select(StorageOperation.id).where(
            eligible,
            StorageOperation.attempt_count < MAX_STORAGE_OPERATION_ATTEMPTS,
        )
        if operation_id is not None:
            candidates = candidates.where(StorageOperation.id == operation_id)
        candidate_ids = list(
            db.scalars(
                candidates.order_by(StorageOperation.created_at, StorageOperation.id)
            )
        )
        for candidate_id in candidate_ids:
            lease_token = str(uuid4())
            claimed = db.execute(
                update(StorageOperation)
                .where(
                    StorageOperation.id == candidate_id,
                    eligible,
                    StorageOperation.attempt_count
                    < MAX_STORAGE_OPERATION_ATTEMPTS,
                )
                .values(
                    status="processing",
                    attempt_count=StorageOperation.attempt_count + 1,
                    lease_token=lease_token,
                    lease_expires_at=now + STORAGE_OPERATION_LEASE,
                    next_attempt_at=None,
                    error_category=None,
                    updated_at=now,
                )
            )
            if claimed.rowcount != 1:
                continue
            db.commit()
            operation = db.get(StorageOperation, candidate_id)
            if operation is None:
                continue
            return StorageOperationClaim(
                id=operation.id,
                document_id=operation.document_id,
                provider=operation.provider,
                storage_key=operation.storage_key,
                operation_type=operation.operation_type,
                actor_id=operation.actor_id,
                lease_token=lease_token,
                attempt_count=operation.attempt_count,
            )
        db.commit()
    return None


def _error_category(error: Exception) -> str:
    if isinstance(error, (TimeoutError, StorageTimeoutError)):
        return "timeout"
    if isinstance(error, StorageProviderUnavailableError):
        return "provider_unavailable"
    if isinstance(error, StorageError):
        return "storage_error"
    return "internal_error"


def _execute_claimed_operation(
    session_factory: sessionmaker[Session],
    providers: StorageProviderRegistry,
    claim: StorageOperationClaim,
) -> bool:
    if claim.operation_type not in {"upload_cleanup", "delete"}:
        mark_storage_operation_retryable(
            session_factory,
            claim.id,
            claim.lease_token,
            "unsupported_operation",
        )
        return False
    try:
        storage = providers.get(claim.provider)
        storage.delete(claim.storage_key)
    except InvalidStorageKeyError:
        mark_storage_operation_retryable(
            session_factory,
            claim.id,
            claim.lease_token,
            "invalid_storage_key",
        )
        logger.error(
            "Storage cleanup failed for operation %s (invalid_storage_key)",
            claim.id,
        )
        return False
    except StorageObjectNotFoundError:
        pass
    except Exception as error:
        mark_storage_operation_retryable(
            session_factory,
            claim.id,
            claim.lease_token,
            _error_category(error),
        )
        logger.error(
            "Storage cleanup failed for operation %s (%s)",
            claim.id,
            _error_category(error),
        )
        return False

    try:
        with session_factory() as db:
            operation = db.get(StorageOperation, claim.id)
            if (
                operation is None
                or operation.status != "processing"
                or operation.lease_token != claim.lease_token
            ):
                return False
            document = db.get(Document, claim.document_id)
            if claim.operation_type == "delete" and document is not None:
                actor_id = claim.actor_id
                if actor_id is not None and db.get(User, actor_id) is None:
                    actor_id = None
                record_audit(
                    db,
                    actor_id,
                    "document.deleted",
                    "document",
                    document.id,
                    {"name": document.name, "size_bytes": document.size_bytes},
                )
            if document is not None:
                db.delete(document)
            operation.status = "completed"
            operation.completed_at = utcnow_naive()
            operation.updated_at = operation.completed_at
            operation.lease_token = None
            operation.lease_expires_at = None
            operation.error_category = None
            db.commit()
        return True
    except SQLAlchemyError:
        logger.error("Could not finalize storage operation %s (database_error)", claim.id)
        return False


def process_storage_operation(
    session_factory: sessionmaker[Session],
    providers: StorageProviderRegistry,
    operation_id: str,
) -> bool:
    claim = claim_storage_operation(session_factory, operation_id)
    if claim is None:
        with session_factory() as db:
            operation = db.get(StorageOperation, operation_id)
            return operation is not None and operation.status == "completed"
    return _execute_claimed_operation(session_factory, providers, claim)


def recover_storage_operations(
    session_factory: sessionmaker[Session],
    providers: StorageProviderRegistry,
    *,
    limit: int = 25,
) -> tuple[int, int]:
    processed = 0
    completed = 0
    for _ in range(max(0, limit)):
        claim = claim_storage_operation(session_factory)
        if claim is None:
            break
        processed += 1
        if _execute_claimed_operation(session_factory, providers, claim):
            completed += 1
    return processed, completed
