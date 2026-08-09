from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent_continuity.kernel.audit import AuditAnchorV1
from agent_continuity.kernel.canonical import (
    canonical_bytes,
    canonical_loads,
    record_id,
    validate_logical_time,
)
from agent_continuity.kernel.model import RecordId, StoredRecord
from agent_continuity.kernel.records import make_record
from agent_continuity.store.base import AuditEventDraft, StoreIntegrityError
from agent_continuity.store.sqlite import SQLiteStateStore

LOGICAL_TIME = validate_logical_time("2026-08-09T12:00:00Z")


def _record(value: str) -> StoredRecord:
    return make_record("Example/v1", {"value": value})


def _event(record: StoredRecord) -> AuditEventDraft:
    return AuditEventDraft(
        kind="checkpoint",
        subject_id=record.record_id,
        logical_time=LOGICAL_TIME,
        details={"record_id": record.record_id},
    )


def _store(path: Path) -> SQLiteStateStore:
    return SQLiteStateStore(path, store_id="store-test")


def _drop_immutable_triggers(connection: sqlite3.Connection, table: str) -> None:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?",
        (table,),
    ).fetchall()
    assert rows
    for (name,) in rows:
        connection.execute(f'DROP TRIGGER "{name}"')


def test_full_audit_and_matching_external_anchor_pass(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")

    with _store(path) as store:
        first_receipt = store.commit(
            records=(first,),
            event=_event(first),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=first.record_id,
        )
        store.commit(
            records=(second,),
            event=_event(second),
            head_name="checkpoint",
            expected_head=first_receipt.head,
            new_head_id=second.record_id,
        )
        anchor = store.make_anchor(
            created_at=validate_logical_time("2026-08-09T12:01:00Z"),
            label="release-candidate",
        )
        verification = store.verify_audit(anchor)

    assert anchor.store_id == "store-test"
    assert anchor.audit_sequence == 2
    assert verification.valid is True
    assert verification.supplied_anchor_matched is True
    assert verification.audit_head_id == anchor.audit_head_id


def test_audit_event_mutation_is_detected_without_echoing_bytes(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("first")
    with _store(path) as store:
        store.commit(
            records=(record,),
            event=_event(record),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )

    with sqlite3.connect(path) as connection:
        _drop_immutable_triggers(connection, "audit_events")
        connection.execute(
            "UPDATE audit_events SET canonical_bytes = ? WHERE sequence = 1",
            (b'{"tampered":true}',),
        )

    with _store(path) as store:
        verification = store.verify_audit()
    assert verification.valid is False
    assert verification.supplied_anchor_matched is False


def test_record_mutation_breaks_load_and_full_audit(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("first")
    with _store(path) as store:
        store.commit(
            records=(record,),
            event=_event(record),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )

    with sqlite3.connect(path) as connection:
        _drop_immutable_triggers(connection, "records")
        connection.execute(
            "UPDATE records SET canonical_bytes = ? WHERE record_id = ?",
            (b'{"value":"tampered"}', record.record_id),
        )

    with _store(path) as store:
        with pytest.raises(StoreIntegrityError):
            store.load_record(record.record_id)
        assert store.verify_audit().valid is False


def test_anchor_detects_history_truncation_after_known_head(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")
    with _store(path) as store:
        first_receipt = store.commit(
            records=(first,),
            event=_event(first),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=first.record_id,
        )
        store.commit(
            records=(second,),
            event=_event(second),
            head_name="checkpoint",
            expected_head=first_receipt.head,
            new_head_id=second.record_id,
        )
        anchor = store.make_anchor(
            created_at=validate_logical_time("2026-08-09T12:01:00Z"), label=None
        )

    with sqlite3.connect(path) as connection:
        _drop_immutable_triggers(connection, "audit_events")
        first_event = connection.execute(
            "SELECT event_id FROM audit_events WHERE sequence = 1"
        ).fetchone()
        assert first_event is not None
        connection.execute(
            "UPDATE heads SET record_id = ?, audit_event_id = ?, audit_sequence = 1",
            (first.record_id, first_event[0]),
        )
        connection.execute("DELETE FROM audit_events WHERE sequence = 2")

    with _store(path) as store:
        verification = store.verify_audit(anchor)
    assert verification.valid is False
    assert verification.supplied_anchor_matched is False


def test_audit_replay_rejects_future_record_reference(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")
    with _store(path) as store:
        first_receipt = store.commit(
            records=(first,),
            event=_event(first),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=first.record_id,
        )
        store.commit(
            records=(second,),
            event=_event(second),
            head_name="checkpoint",
            expected_head=first_receipt.head,
            new_head_id=second.record_id,
        )

    with sqlite3.connect(path) as connection:
        _drop_immutable_triggers(connection, "audit_events")
        rows = connection.execute(
            "SELECT sequence, canonical_bytes FROM audit_events ORDER BY sequence"
        ).fetchall()
        assert len(rows) == 2
        first_payload = canonical_loads(bytes(rows[0][1]))
        second_payload = canonical_loads(bytes(rows[1][1]))

        first_payload["record_ids"] = sorted(
            [first.record_id, second.record_id]
        )
        first_updates = first_payload["head_updates"]
        assert isinstance(first_updates, list)
        assert isinstance(first_updates[0], dict)
        first_updates[0]["new_record_id"] = second.record_id
        first_event_id = record_id("AuditEvent/v1", "v1", first_payload)

        second_payload["previous_event_id"] = first_event_id
        second_updates = second_payload["head_updates"]
        assert isinstance(second_updates, list)
        assert isinstance(second_updates[0], dict)
        second_updates[0]["expected"] = {
            "audit_event_id": first_event_id,
            "audit_sequence": 1,
            "record_id": second.record_id,
        }
        second_event_id = record_id("AuditEvent/v1", "v1", second_payload)

        connection.execute(
            "UPDATE audit_events SET event_id = ?, canonical_bytes = ? "
            "WHERE sequence = 1",
            (first_event_id, canonical_bytes(first_payload)),
        )
        connection.execute(
            "UPDATE audit_events SET event_id = ?, previous_event_id = ?, "
            "canonical_bytes = ? WHERE sequence = 2",
            (
                second_event_id,
                first_event_id,
                canonical_bytes(second_payload),
            ),
        )
        connection.execute(
            "UPDATE heads SET record_id = ?, audit_event_id = ?, "
            "audit_sequence = 2 WHERE name = 'checkpoint'",
            (second.record_id, second_event_id),
        )

    with _store(path) as store:
        assert store.verify_audit().valid is False


def test_foreign_or_rewritten_anchor_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("first")
    with _store(path) as store:
        store.commit(
            records=(record,),
            event=_event(record),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )
        anchor = store.make_anchor(
            created_at=validate_logical_time("2026-08-09T12:01:00Z"), label=None
        )
        foreign = AuditAnchorV1(
            store_id="store-foreign",
            audit_sequence=anchor.audit_sequence,
            audit_head_id=anchor.audit_head_id,
            created_at=anchor.created_at,
            label=anchor.label,
        )
        rewritten = AuditAnchorV1(
            store_id=anchor.store_id,
            audit_sequence=anchor.audit_sequence,
            audit_head_id=RecordId("sha256:" + "f" * 64),
            created_at=anchor.created_at,
            label=anchor.label,
        )
        assert store.verify_audit(foreign).valid is False
        assert store.verify_audit(rewritten).valid is False
