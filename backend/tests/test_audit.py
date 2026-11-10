from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import URL, delete, select

from app.audit import (
    AUDIT_GENESIS_HASH,
    _event_hash,
    record_audit,
    verify_audit_chain,
)
from app.main import create_app
from app.models import AuditChainLock, AuditEvent


def test_event_hash_treats_naive_timestamp_as_utc():
    naive_timestamp = datetime(2024, 1, 2, 3, 4, 5, 123456)
    aware_timestamp = naive_timestamp.replace(tzinfo=timezone.utc)

    naive_hash = _event_hash(
        None, "test.action", "test", "one", naive_timestamp, "{}", AUDIT_GENESIS_HASH
    )
    aware_hash = _event_hash(
        None, "test.action", "test", "one", aware_timestamp, "{}", AUDIT_GENESIS_HASH
    )

    assert naive_hash == aware_hash


def test_event_hash_converts_other_timezones_to_utc():
    utc_timestamp = datetime(2024, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)
    other_timezone_timestamp = datetime(
        2024,
        1,
        2,
        8,
        34,
        5,
        123456,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )

    utc_hash = _event_hash(
        None, "test.action", "test", "one", utc_timestamp, "{}", AUDIT_GENESIS_HASH
    )
    other_timezone_hash = _event_hash(
        None,
        "test.action",
        "test",
        "one",
        other_timezone_timestamp,
        "{}",
        AUDIT_GENESIS_HASH,
    )

    assert utc_hash == other_timezone_hash


def test_verify_audit_chain_accepts_existing_naive_utc_event():
    event = AuditEvent(
        id=1,
        actor_id=None,
        action="test.legacy",
        target_type="test",
        target_id="legacy",
        created_at=datetime(2024, 1, 1, 12, 0, 0),
        metadata_json='{"source":"legacy"}',
        previous_hash=AUDIT_GENESIS_HASH,
        event_hash="a2b93ef8481d8e7e62fa6b243948bd48480e4075416b9b67039f846353abe988",
    )

    result = verify_audit_chain([event])

    assert result.is_valid is True
    assert result.event_count == 1


@pytest.fixture
def audit_app(tmp_path: Path):
    database_url = URL.create(
        "sqlite", database=str(tmp_path / "audit-chain.sqlite")
    ).render_as_string(hide_password=False)
    app = create_app(
        database_url,
        cookie_secure=False,
        storage_directory=str(tmp_path / "private-storage"),
    )
    with TestClient(app):
        yield app


def test_concurrent_audit_writers_preserve_chain_order(audit_app):
    app = audit_app
    writer_count = 12
    barrier = Barrier(writer_count)

    def append_event(index: int) -> None:
        with app.state.session_factory() as db:
            barrier.wait(timeout=10)
            record_audit(
                db,
                None,
                "test.concurrent",
                "test",
                str(index),
                {"index": index},
            )
            db.commit()

    with ThreadPoolExecutor(max_workers=writer_count) as executor:
        list(executor.map(append_event, range(writer_count)))

    with app.state.session_factory() as db:
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        result = verify_audit_chain(events)

    assert len(events) == writer_count
    assert result.is_valid is True
    assert result.event_count == writer_count


def test_audit_rollback_releases_lock_without_recording_event(audit_app):
    app = audit_app
    with app.state.session_factory() as db:
        record_audit(db, None, "test.committed", "test", "one", {})
        db.commit()
        committed = db.scalar(
            select(AuditEvent).where(AuditEvent.action == "test.committed")
        )
        assert committed is not None
        committed_hash = committed.event_hash

        record_audit(db, None, "test.rolled_back", "test", "two", {})
        db.rollback()

        record_audit(db, None, "test.after_rollback", "test", "three", {})
        db.commit()
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))

    assert [event.action for event in events] == [
        "test.committed",
        "test.after_rollback",
    ]
    assert events[0].event_hash == committed_hash
    assert verify_audit_chain(events).is_valid is True


def test_audit_append_fails_closed_when_lock_row_is_missing(audit_app):
    app = audit_app
    with app.state.session_factory() as db:
        db.execute(delete(AuditChainLock).where(AuditChainLock.id == 1))
        db.commit()

        with pytest.raises(RuntimeError, match="Audit chain lock row is missing"):
            record_audit(db, None, "test.unserialized", "test", "one", {})
        db.rollback()

        assert db.scalar(select(AuditEvent)) is None
