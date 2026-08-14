from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import traceback
from dataclasses import replace
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from agent_continuity import (
    AlreadyInitialized,
    CheckpointReceipt,
    Continuity,
    Profile,
    TransitionRefused,
)
from agent_continuity.capture import CaptureSnapshot, GitTargetAdapter
from agent_continuity.kernel.canonical import digest_bytes
from agent_continuity.kernel.model import LogicalTime
from agent_continuity.store import SQLiteStateStore
from tests.helpers.git_repo import make_git_repo, repository_write_manifest


class FixedClock:
    def __init__(self, value: str) -> None:
        self._value = LogicalTime(value)

    def now(self) -> LogicalTime:
        return self._value


class CaptureSequence:
    def __init__(self, snapshots: tuple[CaptureSnapshot, ...]) -> None:
        self._snapshots = snapshots
        self._index = 0
        self._lock = Lock()

    def capture(self, instruction_paths: tuple[bytes, ...]) -> CaptureSnapshot:
        assert instruction_paths == (b"AGENTS.md",)
        with self._lock:
            if self._index >= len(self._snapshots):
                raise AssertionError("unexpected capture")
            snapshot = self._snapshots[self._index]
            self._index += 1
            return snapshot


class ProcessBarrierAdapter:
    def __init__(self, target: str, barrier: Any) -> None:
        self._adapter = GitTargetAdapter(target)
        self._barrier = barrier
        self._captures = 0

    def capture(self, instruction_paths: tuple[bytes, ...]) -> CaptureSnapshot:
        assert instruction_paths == (b"AGENTS.md",)
        snapshot = self._adapter.capture(instruction_paths)
        self._captures += 1
        if self._captures == 3:
            self._barrier.wait(timeout=15)
        return snapshot

    def close(self) -> None:
        self._adapter.close()


def _process_checkpoint(
    target: str,
    state_home: str,
    barrier: Any,
    results: Any,
    writer: int,
) -> None:
    adapter = ProcessBarrierAdapter(target, barrier)
    try:
        continuity = Continuity.open(
            target,
            state_home=state_home,
            session_key="process-race",
            clock=FixedClock(f"2026-08-14T12:00:0{writer + 1}Z"),
            target_adapter=adapter,
        )
        receipt = continuity.checkpoint(f"concurrent reason bytes {writer}")
        results.put(
            (
                "receipt",
                receipt.checkpoint_id,
                receipt.audit_event_id,
                receipt.audit_sequence,
            )
        )
    except Exception as error:
        results.put(("error", type(error).__name__, str(error)))
    finally:
        adapter.close()


def _process_identical_checkpoint(
    target: str,
    state_home: str,
    barrier: Any,
    results: Any,
) -> None:
    adapter = ProcessBarrierAdapter(target, barrier)
    try:
        receipt = Continuity.open(
            target,
            state_home=state_home,
            session_key="identical-process-race",
            clock=FixedClock("2026-08-14T12:00:01Z"),
            target_adapter=adapter,
        ).checkpoint()
        results.put(
            (
                "receipt",
                receipt.checkpoint_id,
                receipt.audit_event_id,
                receipt.audit_sequence,
            )
        )
    except Exception as error:
        results.put(("error", type(error).__name__, str(error)))
    finally:
        adapter.close()


def _process_initialize_winner(
    target: str,
    state_home: str,
    results: Any,
) -> None:
    try:
        receipt = Continuity.open(
            target,
            state_home=state_home,
            session_key="late-genesis-race",
            clock=FixedClock("2026-08-14T12:00:00Z"),
        ).initialize("winner goal", (), instruction_paths=("AGENTS.md",))
        results.put(("receipt", receipt.checkpoint_id))
    except Exception as error:
        results.put(("error", type(error).__name__, str(error)))


def _snapshot(tmp_path: Path) -> tuple[Path, CaptureSnapshot]:
    repo = make_git_repo(tmp_path)
    with GitTargetAdapter(repo.root) as adapter:
        snapshot = adapter.capture((b"AGENTS.md",))
    return repo.root, snapshot


def _changed(snapshot: CaptureSnapshot, marker: bytes) -> CaptureSnapshot:
    target = replace(snapshot.target, inventory_digest=digest_bytes(marker))
    return replace(snapshot, target=target)


def _continuity(
    target: Path,
    state_home: Path,
    snapshots: tuple[CaptureSnapshot, ...],
    *,
    session_key: str = "integration",
) -> Continuity:
    return Continuity.open(
        target,
        state_home=state_home,
        session_key=session_key,
        clock=FixedClock("2026-08-14T12:00:00Z"),
        target_adapter=CaptureSequence(snapshots),
    )


def _database(state_home: Path) -> Path:
    databases = tuple(state_home.glob("*.sqlite3"))
    assert len(databases) == 1
    return databases[0]


def _checkpoint_rows(database: Path) -> list[tuple[str, dict[str, object]]]:
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT record_id, canonical_bytes FROM records "
            "WHERE record_type = 'Checkpoint' ORDER BY rowid"
        ).fetchall()
    return [(str(identity), json.loads(bytes(raw))) for identity, raw in rows]


def _store_projection(database: Path) -> tuple[bytes, int, tuple[object, ...]]:
    with sqlite3.connect(database) as connection:
        heads = tuple(
            connection.execute(
                "SELECT name, record_id, audit_event_id, audit_sequence "
                "FROM heads ORDER BY name"
            )
        )
        audit = tuple(
            connection.execute(
                "SELECT sequence, event_id, canonical_bytes "
                "FROM audit_events ORDER BY sequence"
            )
        )
    return database.read_bytes(), database.stat().st_mtime_ns, (heads, audit)


def test_checkpoint_appends_one_parent_linked_checkpoint_and_reason_digest(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    continuity = _continuity(target, state_home, (snapshot,) * 6)
    initial = continuity.initialize(
        "stable goal", ("criterion",), instruction_paths=("AGENTS.md",)
    )
    before_target = repository_write_manifest(target)
    reason = "raw checkpoint reason must not persist"

    receipt = continuity.checkpoint(reason)

    assert type(receipt) is CheckpointReceipt
    assert receipt.verdict.value == "pass"
    assert receipt.transition_allowed is True
    assert receipt.audit_sequence == initial.audit_sequence + 1
    assert repository_write_manifest(target) == before_target
    database = _database(state_home)
    rows = _checkpoint_rows(database)
    assert len(rows) == 2
    parent_id, parent = rows[0]
    child_id, child = rows[1]
    assert parent_id == initial.checkpoint_id
    assert child_id == receipt.checkpoint_id
    assert child["parent_checkpoint_id"] == parent_id
    assert child["audit_parent_id"] == initial.audit_event_id
    for field in (
        "acceptance_criteria",
        "accepted_decision_ids",
        "actor_ids",
        "assignment_authority",
        "authority_scopes",
        "constraint_digests",
        "evidence_ids",
        "goal_id",
        "initialization_intent_id",
        "instruction_id",
        "invalidation_ids",
        "open_assignment_ids",
        "pending_work",
        "policy_id",
        "ruleset_id",
        "target_id",
        "unresolved",
    ):
        assert child[field] == parent[field]
    with sqlite3.connect(database) as connection:
        audit_rows = connection.execute(
            "SELECT canonical_bytes FROM audit_events ORDER BY sequence"
        ).fetchall()
        heads = connection.execute("SELECT name FROM heads ORDER BY name").fetchall()
    assert len(audit_rows) == 2
    assert heads == [("session:integration:checkpoint",)]
    child_audit = json.loads(bytes(audit_rows[-1][0]))
    assert child_audit["kind"] == "checkpoint"
    assert child_audit["subject_id"] == receipt.checkpoint_id
    assert child_audit["previous_event_id"] == initial.audit_event_id
    assert child_audit["details"]["digest"] == digest_bytes(reason.encode())
    invocation_digests = child_audit["details"]["digests"]
    assert len(invocation_digests) == 1
    assert invocation_digests[0].startswith("sha256:")
    assert len(invocation_digests[0]) == 71
    assert reason.encode() not in database.read_bytes()


@pytest.mark.parametrize("gate", ["ab", "ac"])
def test_checkpoint_refuses_capture_mismatch_without_state_or_target_write(
    tmp_path: Path, gate: str
) -> None:
    target, snapshot = _snapshot(tmp_path)
    changed = _changed(snapshot, gate.encode())
    state_home = tmp_path / "state"
    continuity = _continuity(
        target,
        state_home,
        (snapshot,) * 3
        + ((snapshot, changed) if gate == "ab" else (snapshot, snapshot, changed)),
    )
    continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))
    database = _database(state_home)
    before_store = _store_projection(database)
    before_target = repository_write_manifest(target)

    with pytest.raises(TransitionRefused) as captured:
        continuity.checkpoint("refused reason bytes")

    assert captured.value.result.verdict.value == "unknown"
    assert captured.value.result.transition_allowed is False
    assert _store_projection(database) == before_store
    assert repository_write_manifest(target) == before_target
    assert b"refused reason bytes" not in database.read_bytes()


def test_checkpoint_reason_validation_precedes_capture_or_write(tmp_path: Path) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    continuity = _continuity(target, state_home, (snapshot,) * 3)
    continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))
    database = _database(state_home)
    before = _store_projection(database)

    with pytest.raises(TypeError):
        continuity.checkpoint(7)  # type: ignore[arg-type]

    assert _store_projection(database) == before


def test_two_cross_process_checkpoint_writers_retry_from_fresh_parent(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    initial = _continuity(
        target,
        state_home,
        (snapshot,) * 3,
        session_key="process-race",
    ).initialize("goal", (), instruction_paths=("AGENTS.md",))
    before_target = repository_write_manifest(target)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    results = context.Queue()
    processes = tuple(
        context.Process(
            target=_process_checkpoint,
            args=(str(target), str(state_home), barrier, results, index),
        )
        for index in range(2)
    )

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=45)
        assert process.exitcode == 0
    observed = tuple(sorted(results.get(timeout=5) for _process in processes))

    assert tuple(item[0] for item in observed) == ("receipt", "receipt")
    assert {item[3] for item in observed} == {2, 3}
    rows = _checkpoint_rows(_database(state_home))
    assert len(rows) == 3
    by_id = {identity: payload for identity, payload in rows}
    sequence_to_id = {item[3]: item[1] for item in observed}
    sequence_to_audit_id = {item[3]: item[2] for item in observed}
    assert by_id[sequence_to_id[2]]["parent_checkpoint_id"] == initial.checkpoint_id
    assert by_id[sequence_to_id[3]]["parent_checkpoint_id"] == sequence_to_id[2]
    assert by_id[sequence_to_id[3]]["audit_parent_id"] == sequence_to_audit_id[2]
    assert repository_write_manifest(target) == before_target
    assert b"concurrent reason bytes" not in _database(state_home).read_bytes()


def test_identical_cross_process_checkpoint_calls_append_distinct_children(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    initial = _continuity(
        target,
        state_home,
        (snapshot,) * 3,
        session_key="identical-process-race",
    ).initialize("goal", (), instruction_paths=("AGENTS.md",))
    before_target = repository_write_manifest(target)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    results = context.Queue()
    processes = tuple(
        context.Process(
            target=_process_identical_checkpoint,
            args=(os.fspath(target), os.fspath(state_home), barrier, results),
        )
        for _index in range(2)
    )

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=45)
        assert process.exitcode == 0
    observed = tuple(sorted(results.get(timeout=5) for _process in processes))

    assert tuple(item[0] for item in observed) == ("receipt", "receipt")
    assert {item[3] for item in observed} == {2, 3}
    sequence_to_checkpoint = {item[3]: item[1] for item in observed}
    sequence_to_audit = {item[3]: item[2] for item in observed}
    rows = _checkpoint_rows(_database(state_home))
    assert len(rows) == 3
    by_id = {identity: payload for identity, payload in rows}
    assert (
        by_id[sequence_to_checkpoint[2]]["parent_checkpoint_id"]
        == initial.checkpoint_id
    )
    assert (
        by_id[sequence_to_checkpoint[3]]["parent_checkpoint_id"]
        == sequence_to_checkpoint[2]
    )
    assert (
        by_id[sequence_to_checkpoint[3]]["audit_parent_id"]
        == sequence_to_audit[2]
    )
    assert repository_write_manifest(target) == before_target


def test_checkpoint_refusal_never_exposes_reason_or_target_path(tmp_path: Path) -> None:
    target, snapshot = _snapshot(tmp_path)
    changed = _changed(snapshot, b"sanitize")
    state_home = tmp_path / "state"
    reason = "raw-refusal-reason-marker"
    continuity = _continuity(
        target,
        state_home,
        (snapshot,) * 3 + (snapshot, changed),
    )
    continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))

    with pytest.raises(TransitionRefused) as captured:
        continuity.checkpoint(reason)

    rendered = "".join(traceback.format_exception(captured.value))
    assert reason not in rendered
    assert os.fspath(target) not in rendered


def test_checkpoint_refuses_compiled_policy_drift_without_store_write(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    _continuity(target, state_home, (snapshot,) * 3).initialize(
        "goal", (), instruction_paths=("AGENTS.md",)
    )
    database = _database(state_home)
    before = _store_projection(database)
    changed_policy = Continuity.open(
        target,
        state_home=state_home,
        session_key="integration",
        clock=FixedClock("2026-08-14T12:00:01Z"),
        target_adapter=CaptureSequence((snapshot, snapshot)),
        profile=Profile.STRICT,
    )

    with pytest.raises(TransitionRefused) as captured:
        changed_policy.checkpoint()

    assert captured.value.result.verdict.value == "unknown"
    assert captured.value.result.transition_allowed is False
    assert _store_projection(database) == before


def test_initialize_reconciles_genesis_committed_before_local_value_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    context = multiprocessing.get_context("spawn")
    original_commit = SQLiteStateStore.commit
    triggered = False

    def commit_after_winner(
        store: SQLiteStateStore,
        **kwargs: Any,
    ) -> Any:
        nonlocal triggered
        if not triggered and kwargs["event"].kind == "initialize":
            triggered = True
            results = context.Queue()
            process = context.Process(
                target=_process_initialize_winner,
                args=(os.fspath(target), os.fspath(state_home), results),
            )
            process.start()
            process.join(timeout=30)
            assert process.exitcode == 0
            assert results.get(timeout=5)[0] == "receipt"
        return original_commit(store, **kwargs)

    monkeypatch.setattr(SQLiteStateStore, "commit", commit_after_winner)
    continuity = _continuity(
        target,
        state_home,
        (snapshot,) * 3,
        session_key="late-genesis-race",
    )

    with pytest.raises(AlreadyInitialized):
        continuity.initialize("loser goal", (), instruction_paths=("AGENTS.md",))

    with sqlite3.connect(_database(state_home)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone() == (1,)
