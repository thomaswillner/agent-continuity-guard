from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from agent_continuity.kernel.canonical import (
    canonical_bytes,
    canonical_loads,
    digest_bytes,
    record_id,
    validate_logical_time,
)
from agent_continuity.kernel.model import RecordId, StoredRecord
from agent_continuity.kernel.records import make_record
from agent_continuity.store import (
    AuditAnchorV1,
    AuditEventDraft,
    SQLiteStateStore,
    StoreIntegrityError,
)
from tests.helpers.state_store import open_test_store

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


def _store(
    path: Path,
    *,
    trusted_anchor: AuditAnchorV1 | None = None,
) -> SQLiteStateStore:
    return open_test_store(path, trusted_anchor=trusted_anchor)


def _drop_immutable_triggers(connection: sqlite3.Connection, table: str) -> None:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?",
        (table,),
    ).fetchall()
    assert rows
    for (name,) in rows:
        connection.execute(f'DROP TRIGGER "{name}"')


@contextmanager
def _mutable_table(
    connection: sqlite3.Connection, table: str
) -> Iterator[None]:
    rows = connection.execute(
        "SELECT name, sql FROM sqlite_schema "
        "WHERE type = 'trigger' AND tbl_name = ? ORDER BY name",
        (table,),
    ).fetchall()
    assert rows and all(sql is not None for _name, sql in rows)
    for name, _sql in rows:
        connection.execute(f'DROP TRIGGER "{name}"')
    try:
        yield
    finally:
        for _name, sql in rows:
            connection.execute(str(sql))


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

    with sqlite3.connect(path) as connection:  # noqa: SIM117
        with _mutable_table(connection, "audit_events"):
            connection.execute(
                "UPDATE audit_events SET canonical_bytes = ? WHERE sequence = 1",
                (b'{"tampered":true}',),
            )

    with pytest.raises(StoreIntegrityError):
        _store(path)


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

    with sqlite3.connect(path) as connection, _mutable_table(connection, "records"):
        connection.execute(
            "UPDATE records SET canonical_bytes = ? WHERE record_id = ?",
            (b'{"value":"tampered"}', record.record_id),
        )

    with pytest.raises(StoreIntegrityError):
        _store(path)


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

    with sqlite3.connect(path) as connection:  # noqa: SIM117
        with _mutable_table(connection, "audit_events"):
            first_event = connection.execute(
                "SELECT event_id FROM audit_events WHERE sequence = 1"
            ).fetchone()
            assert first_event is not None
            connection.execute(
                "UPDATE heads SET record_id = ?, audit_event_id = ?, "
                "audit_sequence = 1",
                (first.record_id, first_event[0]),
            )
            connection.execute("DELETE FROM audit_events WHERE sequence = 2")

    with pytest.raises(StoreIntegrityError):
        _store(path, trusted_anchor=anchor)


def test_trusted_anchor_blocks_write_after_anchored_history_truncation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")
    third = _record("third")
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
            label=None,
        )

    with _store(path, trusted_anchor=anchor) as store:
        with sqlite3.connect(path) as connection:  # noqa: SIM117
            with _mutable_table(connection, "audit_events"):
                rows = connection.execute(
                    "SELECT sequence, canonical_bytes FROM audit_events "
                    "ORDER BY sequence"
                ).fetchall()
                first_payload = canonical_loads(bytes(rows[0][1]))
                second_payload = canonical_loads(bytes(rows[1][1]))
                first_payload["details"] = {
                    **first_payload["details"],
                    "flag": True,
                }
                rewritten_first = record_id("AuditEvent/v1", "v1", first_payload)
                second_payload["previous_event_id"] = rewritten_first
                updates = second_payload["head_updates"]
                assert isinstance(updates, list) and isinstance(updates[0], dict)
                expected = updates[0]["expected"]
                assert isinstance(expected, dict)
                expected["audit_event_id"] = rewritten_first
                rewritten_second = record_id("AuditEvent/v1", "v1", second_payload)
                connection.execute(
                    "UPDATE audit_events SET event_id = ?, canonical_bytes = ? "
                    "WHERE sequence = 1",
                    (rewritten_first, canonical_bytes(first_payload)),
                )
                connection.execute(
                    "UPDATE audit_events SET event_id = ?, previous_event_id = ?, "
                    "canonical_bytes = ? WHERE sequence = 2",
                    (
                        rewritten_second,
                        rewritten_first,
                        canonical_bytes(second_payload),
                    ),
                )
                connection.execute(
                    "UPDATE heads SET audit_event_id = ? WHERE name = 'checkpoint'",
                    (rewritten_second,),
                )

        with pytest.raises(StoreIntegrityError):
            store.commit(
                records=(third,),
                event=_event(third),
                head_name="checkpoint",
                expected_head=first_receipt.head,
                new_head_id=third.record_id,
            )

    with _store(path) as structurally_valid:
        assert structurally_valid.verify_audit().valid is True
    with pytest.raises(StoreIntegrityError):
        _store(path, trusted_anchor=anchor)


@pytest.mark.parametrize(
    "mutation_sql",
    [
        "DROP TRIGGER records_no_update",
        "CREATE INDEX unexpected_record_type ON records(record_type)",
        "CREATE TABLE unexpected(value TEXT) STRICT",
        "ALTER TABLE heads ADD COLUMN unexpected TEXT",
        (
            "DROP TRIGGER records_no_update; "
            "CREATE TRIGGER records_no_update BEFORE UPDATE ON records "
            "BEGIN SELECT RAISE(ABORT, 'different SQL'); END"
        ),
    ],
)
def test_existing_schema_is_validated_before_constructor_mutation(
    tmp_path: Path,
    mutation_sql: str,
) -> None:
    path = tmp_path / "state.sqlite3"
    with _store(path):
        pass
    with sqlite3.connect(path) as connection:
        connection.executescript(mutation_sql)
    before = path.read_bytes()
    before_digest = hashlib.sha256(before).hexdigest()

    with pytest.raises(StoreIntegrityError):
        _store(path)

    assert hashlib.sha256(path.read_bytes()).hexdigest() == before_digest


def test_reopen_rejects_tampered_record_before_returning_store(
    tmp_path: Path,
) -> None:
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
    with sqlite3.connect(path) as connection, _mutable_table(connection, "records"):
        connection.execute(
            "UPDATE records SET canonical_bytes = ? WHERE record_id = ?",
            (b'{"value":"tampered"}', record.record_id),
        )

    with pytest.raises(StoreIntegrityError):
        _store(path)


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

    with sqlite3.connect(path) as connection:  # noqa: SIM117
        with _mutable_table(connection, "audit_events"):
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

    with pytest.raises(StoreIntegrityError):
        _store(path)


def test_audit_replay_rejects_post_genesis_local_value_after_anchor(
    tmp_path: Path,
) -> None:
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
        anchor = store.make_anchor(
            created_at=validate_logical_time("2026-08-09T12:01:00Z"),
            label=None,
        )
        store.commit(
            records=(second,),
            event=_event(second),
            head_name="checkpoint",
            expected_head=first_receipt.head,
            new_head_id=second.record_id,
        )

    late_bytes = b"late goal"
    late_digest = digest_bytes(late_bytes)
    with sqlite3.connect(path) as connection:  # noqa: SIM117
        with _mutable_table(connection, "audit_events"):
            connection.execute(
                "INSERT INTO sensitive_local_values(digest, kind, value) "
                "VALUES (?, 'goal_text', ?)",
                (late_digest, sqlite3.Binary(late_bytes)),
            )
            row = connection.execute(
                "SELECT canonical_bytes FROM audit_events WHERE sequence = 2"
            ).fetchone()
            assert row is not None
            payload = canonical_loads(bytes(row[0]))
            payload["local_values"] = [
                {"digest": late_digest, "kind": "goal_text"}
            ]
            rewritten_event_id = record_id("AuditEvent/v1", "v1", payload)
            connection.execute(
                "UPDATE audit_events SET event_id = ?, canonical_bytes = ? "
                "WHERE sequence = 2",
                (rewritten_event_id, canonical_bytes(payload)),
            )
            connection.execute(
                "UPDATE heads SET audit_event_id = ? WHERE name = 'checkpoint'",
                (rewritten_event_id,),
            )

    with pytest.raises(StoreIntegrityError):
        _store(path, trusted_anchor=anchor)


def test_audit_replay_rejects_missing_link(tmp_path: Path) -> None:
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

        with sqlite3.connect(path) as connection:  # noqa: SIM117
            with _mutable_table(connection, "audit_events"):
                row = connection.execute(
                    "SELECT canonical_bytes FROM audit_events WHERE sequence = 2"
                ).fetchone()
                assert row is not None
                payload = canonical_loads(bytes(row[0]))
                payload["previous_event_id"] = None
                event_id = record_id("AuditEvent/v1", "v1", payload)
                connection.execute(
                    "UPDATE audit_events SET event_id = ?, "
                    "previous_event_id = NULL, canonical_bytes = ? "
                    "WHERE sequence = 2",
                    (event_id, canonical_bytes(payload)),
                )
                connection.execute(
                    "UPDATE heads SET audit_event_id = ? WHERE name = 'checkpoint'",
                    (event_id,),
                )

        verification = store.verify_audit()
        assert verification.valid is False
        assert verification.supplied_anchor_matched is False

    with pytest.raises(StoreIntegrityError):
        _store(path)


def test_audit_replay_rejects_reordered_event_payloads(tmp_path: Path) -> None:
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

        with sqlite3.connect(path) as connection:  # noqa: SIM117
            with _mutable_table(connection, "audit_events"):
                rows = connection.execute(
                    "SELECT sequence, canonical_bytes FROM audit_events "
                    "ORDER BY sequence"
                ).fetchall()
                assert len(rows) == 2
                connection.execute(
                    "UPDATE audit_events SET canonical_bytes = ? WHERE sequence = 1",
                    (rows[1][1],),
                )
                connection.execute(
                    "UPDATE audit_events SET canonical_bytes = ? WHERE sequence = 2",
                    (rows[0][1],),
                )

        verification = store.verify_audit()
        assert verification.valid is False
        assert verification.supplied_anchor_matched is False

    with pytest.raises(StoreIntegrityError):
        _store(path)


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
