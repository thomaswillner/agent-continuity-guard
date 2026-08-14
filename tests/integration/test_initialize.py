from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Lock

import pytest

from agent_continuity import (
    AlreadyInitialized,
    CheckpointReceipt,
    Continuity,
    Profile,
    PromotionMode,
    TransitionRefused,
)
from agent_continuity.capture import CaptureSnapshot, GitTargetAdapter
from agent_continuity.kernel.canonical import digest_bytes, record_id
from agent_continuity.kernel.model import LogicalTime
from agent_continuity.kernel.records import (
    build_unresolved_item,
    build_work_item,
)
from tests.helpers.git_repo import (
    make_git_repo,
    repository_write_manifest,
)


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
    clock: str = "2026-08-14T12:00:00Z",
    profile: Profile | None = None,
    promotion_mode: PromotionMode | None = None,
    session_key: str = "integration",
) -> Continuity:
    return Continuity.open(
        target,
        state_home=state_home,
        session_key=session_key,
        clock=FixedClock(clock),
        target_adapter=CaptureSequence(snapshots),
        profile=profile,
        promotion_mode=promotion_mode,
    )


def _database(state_home: Path) -> Path:
    databases = tuple(state_home.glob("*.sqlite3"))
    assert len(databases) == 1
    return databases[0]


def _records(database: Path) -> dict[str, tuple[str, bytes]]:
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT record_type, record_id, canonical_bytes FROM records"
        ).fetchall()
    return {
        str(record_type): (str(identity), bytes(raw))
        for record_type, identity, raw in rows
    }


def _payload(raw: bytes) -> dict[str, object]:
    value = json.loads(raw)
    assert isinstance(value, dict)
    return value


def test_initialize_commits_exact_genesis_records_receipt_and_local_values(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "external-state"
    goal = "goal-text-must-remain-local"
    criteria = (
        "criterion-one-must-remain-local",
        "criterion-two-must-remain-local",
    )
    before = repository_write_manifest(target)

    receipt = _continuity(
        target, state_home, (snapshot, snapshot, snapshot)
    ).initialize(goal, criteria, instruction_paths=("AGENTS.md",))

    assert type(receipt) is CheckpointReceipt
    assert receipt.verdict.value == "pass"
    assert receipt.transition_allowed is True
    assert repository_write_manifest(target) == before

    database = _database(state_home)
    records = _records(database)
    assert set(records) == {
        "Actor",
        "Checkpoint",
        "Criterion",
        "Goal",
        "InitializationIntent",
        "InstructionManifest",
        "PathScope",
        "Policy",
        "Ruleset",
        "TargetIdentity",
    }
    checkpoint_id, checkpoint_raw = records["Checkpoint"]
    checkpoint = _payload(checkpoint_raw)
    intent_id, intent_raw = records["InitializationIntent"]
    intent = _payload(intent_raw)
    goal_id, goal_raw = records["Goal"]
    policy_id, policy_raw = records["Policy"]
    actor_id, actor_raw = records["Actor"]
    ruleset_id, ruleset_raw = records["Ruleset"]

    assert receipt.checkpoint_id == checkpoint_id
    assert receipt.target_id == snapshot.target.record().record_id
    assert checkpoint_id == record_id("Checkpoint", "v1", checkpoint)
    assert intent_id == record_id("InitializationIntent", "v1", intent)
    assert goal_id == record_id("Goal", "v1", _payload(goal_raw))
    assert actor_id == record_id("Actor", "v1", _payload(actor_raw))
    assert ruleset_id == record_id("Ruleset", "v1", _payload(ruleset_raw))
    assert policy_id == record_id("Policy", "v1", _payload(policy_raw))
    assert checkpoint["initialization_intent_id"] == intent_id
    assert checkpoint["target_id"] == receipt.target_id
    assert checkpoint["goal_id"] == goal_id
    assert checkpoint["instruction_id"] == records["InstructionManifest"][0]
    assert checkpoint["policy_id"] == policy_id
    assert checkpoint["ruleset_id"] == ruleset_id
    assert checkpoint["actor_ids"] == [actor_id]
    assert checkpoint["assignment_authority"] == "read_only"
    assert checkpoint["authority_scopes"] == [{"kind": "tree", "path": None}]
    assert checkpoint["evidence_ids"] == []
    assert checkpoint["invalidation_ids"] == []
    assert checkpoint["accepted_decision_ids"] == []
    assert checkpoint["pending_work"] == []
    assert checkpoint["unresolved"] == []
    assert checkpoint["open_assignment_ids"] == []
    assert checkpoint["audit_parent_id"] is None
    assert checkpoint["parent_checkpoint_id"] is None
    assert checkpoint["created_at"] == "2026-08-14T12:00:00Z"
    assert intent == {
        "criterion_ids": [
            item["criterion_id"] for item in checkpoint["acceptance_criteria"]
        ],
        "goal_id": goal_id,
        "instruction_id": records["InstructionManifest"][0],
        "policy_id": policy_id,
        "ruleset_id": ruleset_id,
        "session_key": "integration",
        "target_id": receipt.target_id,
    }
    assert [item["ordinal"] for item in checkpoint["acceptance_criteria"]] == [0, 1]
    assert _payload(records["TargetIdentity"][1]) == _payload(
        snapshot.target.record().canonical_bytes
    )
    assert records["InstructionManifest"] == (
        snapshot.instruction_record().record_id,
        snapshot.instruction_record().canonical_bytes,
    )

    deterministic_bytes = b"\n".join(raw for _identity, raw in records.values())
    assert goal.encode() not in deterministic_bytes
    assert all(item.encode() not in deterministic_bytes for item in criteria)
    assert b"# Synthetic instructions\n" not in deterministic_bytes
    assert str(target).encode() not in deterministic_bytes

    with sqlite3.connect(database) as connection:
        local_rows = connection.execute(
            "SELECT kind, value FROM sensitive_local_values ORDER BY kind, value"
        ).fetchall()
        audit_rows = connection.execute(
            "SELECT sequence, event_id, canonical_bytes FROM audit_events"
        ).fetchall()
        heads = connection.execute(
            "SELECT record_id, audit_event_id, audit_sequence FROM heads"
        ).fetchall()
    assert local_rows == [
        ("criterion_text", criteria[0].encode()),
        ("criterion_text", criteria[1].encode()),
        ("goal_text", goal.encode()),
    ]
    assert len(audit_rows) == 1
    assert heads == [(receipt.checkpoint_id, receipt.audit_event_id, 1)]
    assert receipt.audit_sequence == 1
    assert receipt.audit_event_id == audit_rows[0][1]
    assert goal.encode() not in bytes(audit_rows[0][2])
    assert all(item.encode() not in bytes(audit_rows[0][2]) for item in criteria)


@pytest.mark.parametrize("gate", ["ab", "ac"])
def test_initialize_refuses_capture_mismatch_without_store_or_target_write(
    tmp_path: Path, gate: str
) -> None:
    target, snapshot = _snapshot(tmp_path)
    changed = _changed(snapshot, gate.encode())
    snapshots = (
        (snapshot, changed)
        if gate == "ab"
        else (snapshot, snapshot, changed)
    )
    state_home = tmp_path / "must-not-exist"
    before = repository_write_manifest(target)

    with pytest.raises(TransitionRefused) as captured:
        _continuity(target, state_home, snapshots).initialize(
            "blocked goal", (), instruction_paths=("AGENTS.md",)
        )

    assert captured.value.result.transition_allowed is False
    assert not state_home.exists()
    assert repository_write_manifest(target) == before


def test_observe_profile_cannot_bypass_atomic_capture_mismatch(tmp_path: Path) -> None:
    target, snapshot = _snapshot(tmp_path)
    changed = _changed(snapshot, b"observe-mismatch")
    state_home = tmp_path / "must-not-exist"

    with pytest.raises(TransitionRefused) as captured:
        _continuity(
            target,
            state_home,
            (snapshot, changed),
            profile=Profile.OBSERVE,
        ).initialize("blocked goal", (), instruction_paths=("AGENTS.md",))

    assert captured.value.result.transition_allowed is False
    assert not state_home.exists()


def test_identical_initialize_is_exactly_idempotent_and_changed_intent_refuses(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    continuity = _continuity(target, state_home, (snapshot,) * 9)

    first = continuity.initialize(
        "stable goal", ("criterion",), instruction_paths=("AGENTS.md",)
    )
    second = continuity.initialize(
        "stable goal", ("criterion",), instruction_paths=("AGENTS.md",)
    )
    with pytest.raises(AlreadyInitialized):
        continuity.initialize(
            "changed goal", ("criterion",), instruction_paths=("AGENTS.md",)
        )

    assert second == first
    with sqlite3.connect(_database(state_home)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM heads").fetchone() == (1,)


def test_concurrent_identical_initialize_reconciles_to_one_exact_receipt(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    first = _continuity(
        target,
        state_home,
        (snapshot,) * 3,
        clock="2026-08-14T12:00:00Z",
    )
    second = _continuity(
        target,
        state_home,
        (snapshot,) * 3,
        clock="2026-08-14T12:00:01Z",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        receipts = tuple(
            executor.map(
                lambda continuity: continuity.initialize(
                    "goal", ("criterion",), instruction_paths=("AGENTS.md",)
                ),
                (first, second),
            )
        )

    assert receipts[0] == receipts[1]
    with sqlite3.connect(_database(state_home)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM heads").fetchone() == (1,)


def test_facade_policy_overrides_are_recompiled_into_effective_identity(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    baseline_home = tmp_path / "baseline"
    override_home = tmp_path / "override"

    _continuity(target, baseline_home, (snapshot,) * 3).initialize(
        "goal", (), instruction_paths=("AGENTS.md",)
    )
    _continuity(
        target,
        override_home,
        (snapshot,) * 3,
        profile=Profile.STRICT,
        promotion_mode=PromotionMode.REVIEW,
    ).initialize("goal", (), instruction_paths=("AGENTS.md",))

    baseline_id, baseline_raw = _records(_database(baseline_home))["Policy"]
    override_id, override_raw = _records(_database(override_home))["Policy"]
    assert baseline_id != override_id
    assert _payload(baseline_raw)["profile"] == "guard"
    assert _payload(baseline_raw)["promotion_mode"] == "automatic"
    assert _payload(override_raw)["profile"] == "strict"
    assert _payload(override_raw)["promotion_mode"] == "review"


def test_future_checkpoint_item_builders_bind_pure_record_identity() -> None:
    digest = digest_bytes(b"future checkpoint item")

    work = build_work_item(
        kind="task",
        status_code="pending",
        digest=digest,
    )
    unresolved = build_unresolved_item(code="unknown", digest=None)

    assert work.record().record_id == work.work_item_id
    assert unresolved.record().record_id == unresolved.unresolved_id


def test_distinct_session_keys_have_independent_atomic_genesis(tmp_path: Path) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"

    first = _continuity(
        target,
        state_home,
        (snapshot,) * 3,
        session_key="first",
    ).initialize("first goal", (), instruction_paths=("AGENTS.md",))
    second = _continuity(
        target,
        state_home,
        (snapshot,) * 3,
        session_key="second",
    ).initialize("second goal", (), instruction_paths=("AGENTS.md",))

    assert first.audit_sequence == second.audit_sequence == 1
    assert first.checkpoint_id != second.checkpoint_id
    assert len(tuple(state_home.glob("*.sqlite3"))) == 2
