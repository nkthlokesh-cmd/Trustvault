import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import AuditChainLock, AuditEvent

AUDIT_GENESIS_HASH = "0" * 64


def _normalize_timestamp(created_at: datetime) -> datetime:
    if created_at.utcoffset() is not None:
        return created_at.astimezone(timezone.utc).replace(tzinfo=None)
    return created_at


@dataclass(frozen=True)
class AuditChainVerification:
    is_valid: bool
    event_count: int
    first_invalid_event_id: int | None = None
    failure_reason: str | None = None


def _event_hash(
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str,
    created_at: datetime,
    metadata_json: str,
    previous_hash: str,
) -> str:
    event_data = json.dumps(
        {
            "action": action,
            "actor_id": actor_id,
            "created_at": _normalize_timestamp(created_at).isoformat(),
            "metadata_json": metadata_json,
            "previous_hash": previous_hash,
            "target_id": target_id,
            "target_type": target_type,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(event_data.encode("utf-8")).hexdigest()


def verify_audit_chain(events: Iterable[AuditEvent]) -> AuditChainVerification:
    ordered_events = list(events)
    for previous, current in zip(ordered_events, ordered_events[1:]):
        if current.id <= previous.id:
            return AuditChainVerification(
                False, len(ordered_events), current.id, "event_order"
            )

    previous_hash = AUDIT_GENESIS_HASH
    for event in ordered_events:
        if not hmac.compare_digest(event.previous_hash, previous_hash):
            return AuditChainVerification(
                False, len(ordered_events), event.id, "broken_link"
            )

        expected_hash = _event_hash(
            event.actor_id,
            event.action,
            event.target_type,
            event.target_id,
            event.created_at,
            event.metadata_json,
            event.previous_hash,
        )
        if not hmac.compare_digest(event.event_hash, expected_hash):
            return AuditChainVerification(
                False, len(ordered_events), event.id, "event_hash"
            )
        previous_hash = event.event_hash

    return AuditChainVerification(True, len(ordered_events))


def record_audit(
    db: Session,
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str,
    metadata: dict[str, object],
) -> None:
    lock_result = db.execute(
        update(AuditChainLock)
        .where(AuditChainLock.id == 1)
        .values(id=AuditChainLock.id)
    )
    if lock_result.rowcount != 1:
        raise RuntimeError("Audit chain lock row is missing")

    previous = db.scalar(
        select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)
    )
    previous_hash = previous.event_hash if previous else AUDIT_GENESIS_HASH
    created_at = datetime.now(timezone.utc)
    metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    db.add(
        AuditEvent(
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            created_at=created_at,
            metadata_json=metadata_json,
            previous_hash=previous_hash,
            event_hash=_event_hash(
                actor_id,
                action,
                target_type,
                target_id,
                created_at,
                metadata_json,
                previous_hash,
            ),
        )
    )
