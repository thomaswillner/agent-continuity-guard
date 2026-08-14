from __future__ import annotations

import copy
import json
import pickle
import sqlite3
from dataclasses import FrozenInstanceError, asdict, fields, replace
from pathlib import Path
from typing import Any

import pytest

from agent_continuity.kernel.canonical import digest_bytes, validate_logical_time
from agent_continuity.kernel.model import RecordId, StoredRecord
from agent_continuity.kernel.records import make_record
from agent_continuity.store import (
    AuditEventDraft,
    HeadState,
    HeadUpdate,
    MemoryStateStore,
    SensitiveLocalValueDraft,
    SQLiteStateStore,
    StoreConflictError,
    StoreIntegrityError,
    StoreValidationError,
)
from tests.helpers.state_store import open_test_store

LOGICAL_TIME = validate_logical_time("2026-08-09T12:00:00Z")


def _record(value: str) -> StoredRecord:
    return make_record("Example/v1", {"value": value})


def _event(
    subject_id: RecordId, details: dict[str, Any] | None = None
) -> AuditEventDraft:
    return AuditEventDraft(
        kind="checkpoint",
        subject_id=subject_id,
        logical_time=LOGICAL_TIME,
        details={} if details is None else details,
    )


def _open_store(
    path: Path,
    *,
    fault_injector: Any = None,
) -> SQLiteStateStore:
    return open_test_store(
        path,
        store_id="store-test",
        fault_injector=fault_injector,
    )


def _table_count(path: Path, table: str) -> int:
    with sqlite3.connect(path) as connection:
        value = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    assert value is not None
    return int(value[0])


def _durable_store_rows(path: Path) -> dict[str, list[tuple[Any, ...]]]:
    with sqlite3.connect(path) as connection:
        return {
            table: connection.execute(f"SELECT * FROM {table}").fetchall()
            for table in (
                "records",
                "sensitive_local_values",
                "audit_events",
                "heads",
            )
        }


def test_audit_event_draft_preserves_public_dataclass_semantics() -> None:
    record = _record("public-dataclass")
    first_digest = digest_bytes(b"first")
    second_digest = digest_bytes(b"second")
    caller_details: dict[str, Any] = {"items": [{"digest": first_digest}]}
    event = _event(record.record_id, caller_details)

    assert tuple(item.name for item in fields(event)) == (
        "kind",
        "subject_id",
        "logical_time",
        "details",
    )
    assert asdict(event) == {
        "kind": "checkpoint",
        "subject_id": record.record_id,
        "logical_time": LOGICAL_TIME,
        "details": {"items": [{"digest": first_digest}]},
    }
    assert event.__match_args__ == (
        "kind",
        "subject_id",
        "logical_time",
        "details",
    )
    match event:
        case AuditEventDraft(kind, subject_id, logical_time, details):
            assert (kind, subject_id, logical_time, details) == (
                "checkpoint",
                record.record_id,
                LOGICAL_TIME,
                {"items": [{"digest": first_digest}]},
            )

    assert replace(event) == event
    replacement_details: dict[str, Any] = {
        "items": [{"digest": second_digest}]
    }
    replacement = replace(event, details=replacement_details)
    replacement_details["items"][0]["digest"] = first_digest
    caller_details["items"][0]["digest"] = second_digest
    first_read = event.details
    second_read = event.details
    first_read["items"][0]["digest"] = second_digest  # type: ignore[index]

    assert first_read is not second_read
    assert first_read["items"] is not second_read["items"]
    assert event.details == {"items": [{"digest": first_digest}]}
    assert replacement.details == {"items": [{"digest": second_digest}]}


def test_copy_deepcopy_and_pickle_reconstruct_public_audit_snapshot(
    tmp_path: Path,
) -> None:
    path = tmp_path / "public-dataclass-reconstruction.sqlite3"
    record = _record("public-dataclass-reconstruction")
    original_digest = digest_bytes(b"reconstruction-original")
    mutated_digest = digest_bytes(b"reconstruction-mutated")
    event = _event(
        record.record_id,
        {"items": [{"digest": original_digest}]},
    )
    reconstructions = (
        copy.copy(event),
        copy.deepcopy(event),
        pickle.loads(pickle.dumps(event)),
    )

    for reconstructed in reconstructions:
        assert reconstructed is not event
        assert reconstructed == event
        assert asdict(reconstructed) == asdict(event)
        first_read = reconstructed.details
        second_read = reconstructed.details
        first_read["items"][0]["digest"] = mutated_digest  # type: ignore[index]
        assert first_read is not second_read
        assert first_read["items"] is not second_read["items"]
        assert reconstructed.details == {
            "items": [{"digest": original_digest}]
        }
        assert event.details == {"items": [{"digest": original_digest}]}

    with _open_store(path) as store:
        receipt = store.commit(
            records=(record,),
            event=event,
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )
        for reconstructed in reconstructions:
            retry = store.commit(
                records=(record,),
                event=reconstructed,
                head_name="checkpoint",
                expected_head=None,
                new_head_id=record.record_id,
            )
            assert retry == receipt
        assert store.read_audit_head() is not None
        assert store.read_audit_head().audit_sequence == 1  # type: ignore[union-attr]


def test_public_dataclass_copies_cannot_change_persisted_exact_retry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "public-dataclass.sqlite3"
    record = _record("public-dataclass-persistence")
    original_digest = digest_bytes(b"original")
    mutated_digest = digest_bytes(b"mutated")
    caller_details: dict[str, Any] = {"items": [{"digest": original_digest}]}
    event = _event(record.record_id, caller_details)

    caller_details["items"][0]["digest"] = mutated_digest
    event.details["items"][0]["digest"] = mutated_digest  # type: ignore[index]
    event_dict = asdict(event)
    event_dict["details"]["items"][0]["digest"] = mutated_digest

    with _open_store(path) as store:
        receipt = store.commit(
            records=(record,),
            event=event,
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )
        retry = store.commit(
            records=(record,),
            event=replace(event),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )

        assert retry == receipt
        assert store.read_audit_head() is not None
        assert store.read_audit_head().audit_sequence == 1  # type: ignore[union-attr]

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT canonical_bytes FROM audit_events WHERE sequence = 1"
        ).fetchone()
    assert row is not None
    assert json.loads(bytes(row[0]))["details"] == {
        "items": [{"digest": original_digest}]
    }


def test_genesis_commit_persists_only_approved_typed_local_values(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("genesis")
    local_bytes = b"caller approved narrative"
    local_digest = digest_bytes(local_bytes)
    drafts = (
        SensitiveLocalValueDraft(
            digest=local_digest,
            kind="goal_text",
            value=local_bytes,
            caller_approved=True,
        ),
        SensitiveLocalValueDraft(
            digest=local_digest,
            kind="criterion_text",
            value=local_bytes,
            caller_approved=True,
        ),
    )

    with _open_store(path) as store:
        receipt = store.commit(
            records=(record,),
            local_values=drafts,
            event=_event(record.record_id, {"digest": local_digest}),
            head_name="session:test:checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )

        assert receipt.head == store.read_head("session:test:checkpoint")
        assert receipt.inserted_record_ids == (record.record_id,)
        assert store.load_record(record.record_id) == record
        assert store.verify_audit().valid is True

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT digest, kind, value FROM sensitive_local_values ORDER BY kind"
        ).fetchall()
        audit_bytes = connection.execute(
            "SELECT canonical_bytes FROM audit_events"
        ).fetchone()
    assert rows == [
        (local_digest, "criterion_text", local_bytes),
        (local_digest, "goal_text", local_bytes),
    ]
    assert audit_bytes is not None
    assert local_bytes not in bytes(audit_bytes[0])


@pytest.mark.parametrize(
    "draft",
    [
        SensitiveLocalValueDraft(
            digest=digest_bytes(b"value"),
            kind="goal_text",
            value=b"value",
            caller_approved=False,
        ),
        SensitiveLocalValueDraft(
            digest=digest_bytes(b"value"),
            kind="transcript",
            value=b"value",
            caller_approved=True,
        ),
        SensitiveLocalValueDraft(
            digest=digest_bytes(b"different"),
            kind="goal_text",
            value=b"value",
            caller_approved=True,
        ),
    ],
)
def test_local_value_validation_fails_before_any_transaction_effect(
    tmp_path: Path,
    draft: SensitiveLocalValueDraft,
) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("genesis")

    with _open_store(path) as store:
        with pytest.raises(StoreValidationError):
            store.commit(
                records=(record,),
                local_values=(draft,),
                event=_event(record.record_id),
                head_name="checkpoint",
                expected_head=None,
                new_head_id=record.record_id,
            )
        assert store.read_audit_head() is None

    assert _table_count(path, "records") == 0
    assert _table_count(path, "sensitive_local_values") == 0
    assert _table_count(path, "audit_events") == 0
    assert _table_count(path, "heads") == 0


def test_invalid_audit_logical_time_is_rejected_at_draft_boundary() -> None:
    record = _record("invalid-time")

    with pytest.raises(StoreValidationError):
        AuditEventDraft(
            kind="checkpoint",
            subject_id=record.record_id,
            logical_time="2026-08-09 12:00:00",  # type: ignore[arg-type]
            details={},
        )


@pytest.mark.parametrize(
    "details",
    [
        {"raw": "caller narrative"},
        {"prompt": digest_bytes(b"prompt")},
        {"items": [{"source": digest_bytes(b"source")}]},
        {"authorization": "secret-value"},
        {"count": 1.5},
        {"code": "bad\ncode"},
        {"code": "PRIVATE_SOURCE_EXCERPT"},
        {"status": "PRIVATE_STATUS_EXCERPT"},
    ],
)
def test_audit_details_reject_unclassified_string_bytes(
    details: dict[str, Any],
) -> None:
    record = _record("private-details")

    with pytest.raises(StoreValidationError):
        _event(record.record_id, details)


@pytest.mark.parametrize(
    ("key", "sentinel"),
    [
        ("code", "PRIVATE_SOURCE_EXCERPT"),
        ("status", "PRIVATE_STATUS_EXCERPT"),
    ],
)
def test_audit_draft_returns_fresh_details_without_changing_commit_identity(
    tmp_path: Path,
    key: str,
    sentinel: str,
) -> None:
    path = tmp_path / f"{key}.sqlite3"
    record = _record(f"private-{key}")

    with _open_store(path) as store:
        before_bytes = path.read_bytes()
        before_rows = _durable_store_rows(path)
        event = _event(record.record_id)
        exposed = event.details
        exposed[key] = sentinel
        assert event.details == {}
        receipt = store.commit(
            records=(record,),
            event=event,
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )
        retry = store.commit(
            records=(record,),
            event=_event(record.record_id),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )
        assert retry == receipt
        assert store.read_audit_head() is not None
        assert store.read_audit_head().audit_sequence == 1  # type: ignore[union-attr]
        assert _durable_store_rows(path) != before_rows
        assert path.read_bytes() != before_bytes
        assert store.verify_audit().valid is True

    assert sentinel.encode("utf-8") not in path.read_bytes()


def test_public_collections_reject_duplicate_identities_before_transaction(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("duplicate")
    local = SensitiveLocalValueDraft(
        digest=digest_bytes(b"goal"),
        kind="goal_text",
        value=b"goal",
        caller_approved=True,
    )
    with pytest.raises(StoreValidationError):
        _event(
            record.record_id,
            {"digests": [record.record_id, record.record_id]},
        )

    with _open_store(path) as store:
        with pytest.raises(StoreValidationError):
            store.commit(
                records=(record, record),
                event=_event(record.record_id),
                head_name="checkpoint",
                expected_head=None,
                new_head_id=record.record_id,
            )
        with pytest.raises(StoreValidationError):
            store.commit(
                records=(record,),
                local_values=(local, local),
                event=_event(record.record_id),
                head_name="checkpoint",
                expected_head=None,
                new_head_id=record.record_id,
            )
        assert store.read_audit_head() is None


def test_missing_audit_subject_rolls_back_before_commit(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("present")
    missing = RecordId("sha256:" + "d" * 64)

    with _open_store(path) as store:
        with pytest.raises(StoreIntegrityError):
            store.commit(
                records=(record,),
                event=_event(missing),
                head_name="checkpoint",
                expected_head=None,
                new_head_id=record.record_id,
            )
        assert store.read_audit_head() is None

    for table in ("records", "sensitive_local_values", "audit_events", "heads"):
        assert _table_count(path, table) == 0


def test_atomic_multi_head_commit_returns_ordered_immutable_receipt(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")
    before_digest = digest_bytes(b"before")
    after_digest = digest_bytes(b"after")
    caller_details: dict[str, Any] = {"items": [{"digest": before_digest}]}
    event = _event(first.record_id, caller_details)
    caller_details["items"] = [{"digest": after_digest}]

    with _open_store(path) as store:
        receipt = store.commit_many(
            records=(second, first),
            event=event,
            head_updates=(
                HeadUpdate("head:a", None, first.record_id),
                HeadUpdate("head:b", None, second.record_id),
            ),
        )

        assert tuple(name for name, _head in receipt.heads) == ("head:a", "head:b")
        assert receipt.inserted_record_ids == tuple(
            sorted((first.record_id, second.record_id))
        )
        first_head = store.read_head("head:a")
        second_head = store.read_head("head:b")
        assert first_head is not None
        assert second_head is not None
        assert first_head.audit_event_id == second_head.audit_event_id
        assert first_head.audit_sequence == second_head.audit_sequence == 1
        with pytest.raises(FrozenInstanceError):
            first_head.audit_sequence = 2  # type: ignore[misc]
        with pytest.raises(TypeError):
            receipt.heads[0] = receipt.heads[1]  # type: ignore[index]

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT canonical_bytes FROM audit_events WHERE sequence = 1"
        ).fetchone()
    assert row is not None
    payload = json.loads(bytes(row[0]))
    assert payload["details"] == {"items": [{"digest": before_digest}]}


def test_duplicate_head_update_names_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("value")
    updates = (
        HeadUpdate("head:a", None, RecordId("sha256:" + "1" * 64)),
        HeadUpdate("head:a", None, RecordId("sha256:" + "2" * 64)),
    )

    with _open_store(path) as store:
        with pytest.raises(StoreValidationError):
            store.commit_many(
                records=(record,),
                event=_event(record.record_id),
                head_updates=updates,
            )
        assert store.read_audit_head() is None


def test_unsorted_public_collections_are_normalized_before_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")
    details = {
        "digests": [second.record_id, first.record_id],
        "items": [
            {"record_id": second.record_id},
            {"record_id": first.record_id},
        ],
    }

    with _open_store(path) as store:
        receipt = store.commit_many(
            records=(second, first),
            event=_event(first.record_id, details),
            head_updates=(
                HeadUpdate("head:b", None, second.record_id),
                HeadUpdate("head:a", None, first.record_id),
            ),
        )

    assert tuple(name for name, _head in receipt.heads) == ("head:a", "head:b")
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT canonical_bytes FROM audit_events WHERE sequence = 1"
        ).fetchone()
    assert row is not None
    payload = json.loads(bytes(row[0]))
    assert payload["details"] == {
        "digests": sorted((first.record_id, second.record_id)),
        "items": [
            {"record_id": first.record_id},
            {"record_id": second.record_id},
        ],
    }


def test_stale_multi_head_cas_and_missing_new_record_are_atomic(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")
    third = _record("third")

    with _open_store(path) as store:
        genesis = store.commit_many(
            records=(first, second),
            event=_event(first.record_id),
            head_updates=(
                HeadUpdate("head:a", None, first.record_id),
                HeadUpdate("head:b", None, second.record_id),
            ),
        )
        expected = dict(genesis.heads)
        stale = HeadState(
            record_id=expected["head:b"].record_id,
            audit_event_id=RecordId("sha256:" + "f" * 64),
            audit_sequence=expected["head:b"].audit_sequence,
        )

        with pytest.raises(StoreConflictError):
            store.commit_many(
                records=(third,),
                event=_event(third.record_id),
                head_updates=(
                    HeadUpdate("head:a", expected["head:a"], third.record_id),
                    HeadUpdate("head:b", stale, third.record_id),
                ),
            )
        assert store.read_head("head:a") == expected["head:a"]
        assert store.read_head("head:b") == expected["head:b"]
        assert store.read_audit_head() is not None
        assert store.read_audit_head().audit_sequence == 1  # type: ignore[union-attr]

        missing_id = RecordId("sha256:" + "e" * 64)
        with pytest.raises(StoreIntegrityError):
            store.commit(
                records=(third,),
                event=_event(third.record_id),
                head_name="head:a",
                expected_head=expected["head:a"],
                new_head_id=missing_id,
            )
        assert store.read_head("head:a") == expected["head:a"]
        assert store.read_audit_head() is not None
        assert store.read_audit_head().audit_sequence == 1  # type: ignore[union-attr]


def test_reinserting_identical_record_is_idempotent_but_byte_drift_blocks(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")

    with _open_store(path) as store:
        first_receipt = store.commit(
            records=(first,),
            event=_event(first.record_id),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=first.record_id,
        )
        second_receipt = store.commit(
            records=(first, second),
            event=_event(second.record_id),
            head_name="checkpoint",
            expected_head=first_receipt.head,
            new_head_id=second.record_id,
        )
        assert second_receipt.inserted_record_ids == (second.record_id,)

        forged = StoredRecord(
            record_id=first.record_id,
            record_type=first.record_type,
            schema_version=first.schema_version,
            canonical_bytes=b'{"value":"drift"}',
        )
        with pytest.raises(StoreIntegrityError):
            store.commit(
                records=(forged,),
                event=_event(first.record_id),
                head_name="checkpoint",
                expected_head=second_receipt.head,
                new_head_id=first.record_id,
            )
        assert store.read_head("checkpoint") == second_receipt.head


@pytest.mark.parametrize(
    "stage",
    ["after_records", "after_audit", "after_head", "before_commit"],
)
def test_precommit_faults_roll_back_every_table(tmp_path: Path, stage: str) -> None:
    path = tmp_path / f"{stage}.sqlite3"
    record = _record(stage)

    def inject(observed: str) -> None:
        if observed == stage:
            raise RuntimeError(stage)

    with _open_store(path, fault_injector=inject) as store:
        with pytest.raises(RuntimeError, match=stage):
            store.commit(
                records=(record,),
                event=_event(record.record_id),
                head_name="checkpoint",
                expected_head=None,
                new_head_id=record.record_id,
            )
        assert store.read_audit_head() is None

    for table in ("records", "sensitive_local_values", "audit_events", "heads"):
        assert _table_count(path, table) == 0


def test_before_commit_target_drift_has_zero_durable_effects(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    target = path.parent.parent / f"{path.parent.name}-{path.name}-target"
    retained_target = target.with_name(target.name + "-retained")
    record = _record("before-commit-target-drift")
    drifted = False

    def inject(stage: str) -> None:
        nonlocal drifted
        if stage != "before_commit":
            return
        target.rename(retained_target)
        target.mkdir(mode=0o700)
        (target / ".git").mkdir(mode=0o700)
        drifted = True

    with _open_store(path, fault_injector=inject) as store:
        before_bytes = path.read_bytes()
        before_rows = _durable_store_rows(path)
        try:
            with pytest.raises(StoreIntegrityError):
                store.commit(
                    records=(record,),
                    event=_event(record.record_id),
                    head_name="checkpoint",
                    expected_head=None,
                    new_head_id=record.record_id,
                )
        finally:
            if drifted:
                (target / ".git").rmdir()
                target.rmdir()
                retained_target.rename(target)

        assert path.read_bytes() == before_bytes
        assert _durable_store_rows(path) == before_rows
        assert store.read_audit_head() is None
        assert store.read_head("checkpoint") is None

    with _open_store(path) as reopened:
        assert reopened.read_audit_head() is None
        assert reopened.read_head("checkpoint") is None
        assert reopened.verify_audit().valid is True

    for table in ("records", "sensitive_local_values", "audit_events", "heads"):
        assert _table_count(path, table) == 0


def test_after_commit_fault_reconciles_and_exact_retry_is_idempotent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("after")
    raised = False

    def inject(stage: str) -> None:
        nonlocal raised
        if stage == "after_commit" and not raised:
            raised = True
            raise RuntimeError(stage)

    event = _event(record.record_id)
    update = HeadUpdate("checkpoint", None, record.record_id)
    with _open_store(path, fault_injector=inject) as store:
        first = store.commit_many(
            records=(record,), event=event, head_updates=(update,)
        )
        second = store.commit_many(
            records=(record,), event=event, head_updates=(update,)
        )
        assert second == first
        assert store.read_audit_head() is not None
        assert store.read_audit_head().audit_sequence == 1  # type: ignore[union-attr]

    assert _table_count(path, "audit_events") == 1


def test_exact_retry_survives_unrelated_later_audit_event(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")
    first_event = _event(first.record_id)
    first_update = HeadUpdate("head:a", None, first.record_id)

    with _open_store(path) as store:
        original = store.commit_many(
            records=(first,),
            event=first_event,
            head_updates=(first_update,),
        )
        store.commit_many(
            records=(second,),
            event=_event(second.record_id),
            head_updates=(HeadUpdate("head:b", None, second.record_id),),
        )

        retried = store.commit_many(
            records=(first,),
            event=first_event,
            head_updates=(first_update,),
        )

        assert retried == original
        assert store.read_audit_head() is not None
        assert store.read_audit_head().audit_sequence == 2  # type: ignore[union-attr]


def test_sensitive_local_values_are_genesis_only(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = _record("first")
    second = _record("second")
    late_local = SensitiveLocalValueDraft(
        digest=digest_bytes(b"late goal"),
        kind="goal_text",
        value=b"late goal",
        caller_approved=True,
    )

    with _open_store(path) as store:
        genesis = store.commit(
            records=(first,),
            event=_event(first.record_id),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=first.record_id,
        )
        with pytest.raises(StoreValidationError):
            store.commit(
                records=(second,),
                local_values=(late_local,),
                event=_event(second.record_id),
                head_name="checkpoint",
                expected_head=genesis.head,
                new_head_id=second.record_id,
            )
        assert store.read_head("checkpoint") == genesis.head
        assert store.read_audit_head() is not None
        assert store.read_audit_head().audit_sequence == 1  # type: ignore[union-attr]

    assert _table_count(path, "sensitive_local_values") == 0


def test_store_reopen_rehashes_records_and_rejects_schema_drift(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    record = _record("reopen")
    with _open_store(path) as store:
        receipt = store.commit(
            records=(record,),
            event=_event(record.record_id),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )

    with _open_store(path) as reopened:
        assert reopened.read_head("checkpoint") == receipt.head
        assert reopened.load_record(record.record_id) == record
        assert reopened.verify_audit().valid is True

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE metadata SET value = ? WHERE key = 'schema_version'", (b"2",)
        )
    unsupported_bytes = path.read_bytes()
    with pytest.raises(StoreIntegrityError):
        _open_store(path)
    assert path.read_bytes() == unsupported_bytes


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
@pytest.mark.parametrize(
    "table",
    ["records", "sensitive_local_values", "audit_events"],
)
def test_immutable_tables_reject_update_and_delete(
    tmp_path: Path,
    table: str,
    operation: str,
) -> None:
    path = tmp_path / f"{table}-{operation}.sqlite3"
    record = _record("immutable")
    local = SensitiveLocalValueDraft(
        digest=digest_bytes(b"local"),
        kind="goal_text",
        value=b"local",
        caller_approved=True,
    )
    with _open_store(path) as store:
        store.commit(
            records=(record,),
            local_values=(local,),
            event=_event(record.record_id),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )

    sql = (
        f"UPDATE {table} SET "
        + {
            "records": "record_type = record_type",
            "sensitive_local_values": "kind = kind",
            "audit_events": "canonical_bytes = canonical_bytes",
        }[table]
        if operation == "UPDATE"
        else f"DELETE FROM {table}"
    )
    with sqlite3.connect(path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(sql)


def test_memory_store_implements_same_public_commit_contract() -> None:
    record = _record("memory")
    with MemoryStateStore(store_id="memory-test") as store:
        receipt = store.commit(
            records=(record,),
            event=_event(record.record_id),
            head_name="checkpoint",
            expected_head=None,
            new_head_id=record.record_id,
        )
        assert store.read_head("checkpoint") == receipt.head
        assert store.load_record(record.record_id) == record
        assert store.verify_audit().valid is True
