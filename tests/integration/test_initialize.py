from __future__ import annotations

import copy
import json
import multiprocessing
import os
import sqlite3
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Lock
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

from agent_continuity import (
    AlreadyInitialized,
    CheckpointReceipt,
    Continuity,
    ContinuityRequestError,
    Profile,
    PromotionMode,
    TransitionRefused,
)
from agent_continuity.capture import CaptureSnapshot, GitTargetAdapter
from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    canonical_loads,
    digest_bytes,
    record_id,
)
from agent_continuity.kernel.model import (
    AssignmentAuthority,
    LogicalTime,
    RecordId,
)
from agent_continuity.kernel.paths import (
    PathIdentityV1,
    PathScopeKind,
    PathScopeV1,
    path_scope_payload,
)
from agent_continuity.kernel.records import (
    ActorV1,
    CriterionV1,
    ProducerIdentity,
    RulesetV1,
    actor_payload,
    build_actor,
    build_checkpoint,
    build_criterion,
    build_unresolved_item,
    build_work_item,
    checkpoint_payload,
    ruleset_payload,
)
from agent_continuity.store.paths import StatePathError
from tests.helpers.git_repo import (
    GitRepo,
    make_git_repo,
    repository_write_manifest,
)
from tools import verify_schemas


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
        snapshot = self._adapter.capture(instruction_paths)
        self._captures += 1
        if self._captures == 3:
            self._barrier.wait(timeout=15)
        return snapshot


def _process_initialize(
    target: str,
    state_home: str,
    barrier: Any,
    results: Any,
    goal: str,
) -> None:
    try:
        continuity = Continuity.open(
            target,
            state_home=state_home,
            session_key="process-race",
            clock=FixedClock("2026-08-14T12:00:00Z"),
            target_adapter=ProcessBarrierAdapter(target, barrier),
        )
        receipt = continuity.initialize(
            goal,
            ("criterion",),
            instruction_paths=("AGENTS.md",),
        )
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


def _schema_documents() -> dict[str, dict[str, Any]]:
    root = Path(__file__).parents[2] / "schemas" / "v1"
    return {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in root.glob("*.schema.json")
    }


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


@pytest.mark.parametrize("changed", [False, True])
def test_two_process_initialization_race_is_exact_and_atomic(
    tmp_path: Path,
    changed: bool,
) -> None:
    target, _snapshot_value = _snapshot(tmp_path)
    state_home = tmp_path / "process-state"
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    results = context.Queue()
    goals = ("same goal", "changed goal" if changed else "same goal")
    processes = tuple(
        context.Process(
            target=_process_initialize,
            args=(str(target), str(state_home), barrier, results, goal),
        )
        for goal in goals
    )

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0
    observed = tuple(sorted(results.get(timeout=5) for _process in processes))

    if changed:
        assert tuple(item[0] for item in observed) == ("error", "receipt")
        assert observed[0][1:] == (
            "AlreadyInitialized",
            "session already has a different initialization intent",
        )
    else:
        assert observed[0][0] == observed[1][0] == "receipt"
        assert observed[0][1:] == observed[1][1:]
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


@pytest.mark.parametrize("linked", [False, True])
def test_initialize_rejects_state_under_pinned_git_common_directory(
    tmp_path: Path,
    linked: bool,
) -> None:
    primary_base = tmp_path / "primary"
    primary_base.mkdir()
    primary = make_git_repo(primary_base)
    target = primary.root
    if linked:
        linked_root = tmp_path / "linked"
        primary.git(
            "worktree",
            "add",
            "-q",
            "-b",
            "linked-state-guard",
            os.fspath(linked_root),
        )
        target = GitRepo(linked_root).root
    state_home = primary.git_dir / "must-not-create-state"

    continuity = Continuity.open(target, state_home=state_home)
    with pytest.raises(StatePathError):
        continuity.initialize(
            "goal",
            (),
            instruction_paths=("AGENTS.md",),
        )

    assert not state_home.exists()


def test_custom_adapter_still_rejects_state_overlapping_target(tmp_path: Path) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = target / "must-not-create-state"

    with pytest.raises(StatePathError):
        _continuity(target, state_home, (snapshot,) * 3).initialize(
            "goal",
            (),
            instruction_paths=("AGENTS.md",),
        )

    assert not state_home.exists()


@pytest.mark.parametrize("record_type", ["actor", "ruleset"])
def test_schema_admission_rejects_runtime_rejected_unsorted_identifiers(
    record_type: str,
) -> None:
    digest_a = RecordId("sha256:" + "a" * 64)
    digest_b = RecordId("sha256:" + "b" * 64)
    schemas = _schema_documents()
    if record_type == "actor":
        producer = ProducerIdentity(
            "agent-continuity-guard",
            "0.1.0.dev0",
            digest_a,
        )
        with pytest.raises(CanonicalJSONError):
            ActorV1(
                digest_a,
                producer,
                AssignmentAuthority.READ_ONLY,
                (digest_b, digest_a),
            )
        valid = build_actor(
            producer=producer,
            authority=AssignmentAuthority.READ_ONLY,
            scope_ids=(digest_a, digest_b),
        )
        schema_name = "actor.schema.json"
        invalid = {
            **actor_payload(valid),
            "scope_ids": [digest_b, digest_a],
        }
    else:
        with pytest.raises(CanonicalJSONError):
            RulesetV1(digest_a, (digest_b, digest_a))
        valid = RulesetV1(
            record_id("Ruleset", "v1", {"rule_ids": [digest_a, digest_b]}),
            (digest_a, digest_b),
        )
        schema_name = "ruleset.schema.json"
        invalid = {"rule_ids": [digest_b, digest_a]}

    valid_payload = (
        actor_payload(valid)
        if record_type == "actor"
        else ruleset_payload(valid)
    )
    verify_schemas.validate_schema_instance(
        schema_name,
        valid_payload,
        schemas,
    )
    with pytest.raises(verify_schemas.SchemaVerificationError):
        verify_schemas.validate_schema_instance(schema_name, invalid, schemas)


def _semantic_checkpoint_payload() -> dict[str, Any]:
    record_ids = tuple(
        RecordId("sha256:" + component * 64) for component in "123456789abc"
    )
    criteria = (
        build_criterion(ordinal=0, digest=digest_bytes(b"criterion-a")),
        build_criterion(ordinal=1, digest=digest_bytes(b"criterion-b")),
    )
    work = (
        build_work_item(
            kind="implement",
            status_code="pending",
            digest=digest_bytes(b"work-a"),
        ),
        build_work_item(
            kind="verify",
            status_code="pending",
            digest=digest_bytes(b"work-b"),
        ),
    )
    unresolved = (
        build_unresolved_item(code="question-a", digest=digest_bytes(b"answer-a")),
        build_unresolved_item(code="question-b", digest=digest_bytes(b"answer-b")),
    )
    scopes = (
        PathScopeV1(path=None, kind=PathScopeKind.TREE),
        PathScopeV1(
            path=PathIdentityV1.from_bytes("posix-bytes", b"owned/file"),
            kind=PathScopeKind.FILE,
        ),
    )
    ordered_scopes = tuple(
        sorted(scopes, key=lambda scope: canonical_bytes(path_scope_payload(scope)))
    )
    checkpoint = build_checkpoint(
        parent_checkpoint_id=None,
        target_id=record_ids[0],
        goal_id=record_ids[1],
        acceptance_criteria=criteria,
        constraint_digests=(record_ids[2], record_ids[3]),
        instruction_id=record_ids[4],
        policy_id=record_ids[5],
        ruleset_id=record_ids[6],
        actor_ids=(record_ids[0], record_ids[1]),
        evidence_ids=(record_ids[2], record_ids[3]),
        invalidation_ids=(record_ids[4], record_ids[5]),
        accepted_decision_ids=(record_ids[6], record_ids[7]),
        pending_work=tuple(sorted(work, key=lambda item: item.work_item_id)),
        unresolved=tuple(sorted(unresolved, key=lambda item: item.unresolved_id)),
        assignment_authority=AssignmentAuthority.READ_ONLY,
        authority_scopes=ordered_scopes,
        open_assignment_ids=(record_ids[8], record_ids[9]),
        audit_parent_id=None,
        initialization_intent_id=record_ids[10],
        created_at=LogicalTime("2026-08-14T12:00:00Z"),
    )
    return checkpoint_payload(checkpoint)


_CHECKPOINT_ORDERED_ID_FIELDS = (
    "constraint_digests",
    "actor_ids",
    "evidence_ids",
    "invalidation_ids",
    "accepted_decision_ids",
    "open_assignment_ids",
)


@pytest.mark.parametrize("field", _CHECKPOINT_ORDERED_ID_FIELDS)
def test_checkpoint_schema_admission_rejects_unsorted_identifier_fields(
    field: str,
) -> None:
    schemas = _schema_documents()
    invalid = copy.deepcopy(_semantic_checkpoint_payload())
    invalid[field].reverse()
    verify_schemas.schema_validator("checkpoint.schema.json", schemas).validate(
        invalid
    )

    with pytest.raises(verify_schemas.SchemaVerificationError):
        verify_schemas.validate_schema_instance(
            "checkpoint.schema.json",
            invalid,
            schemas,
        )


@pytest.mark.parametrize("field", _CHECKPOINT_ORDERED_ID_FIELDS)
def test_checkpoint_schema_admission_rejects_duplicate_identifier_fields(
    field: str,
) -> None:
    schemas = _schema_documents()
    invalid = copy.deepcopy(_semantic_checkpoint_payload())
    invalid[field][1] = invalid[field][0]

    with pytest.raises(ValidationError):
        verify_schemas.validate_schema_instance(
            "checkpoint.schema.json",
            invalid,
            schemas,
        )


@pytest.mark.parametrize(
    "case",
    [
        "criteria_noncontiguous",
        "criteria_duplicate_identity",
        "criterion_forged_identity",
        "work_unsorted",
        "work_duplicate_identity",
        "work_forged_identity",
        "unresolved_unsorted",
        "unresolved_duplicate_identity",
        "unresolved_forged_identity",
        "authority_scopes_unsorted",
        "authority_scope_invalid_identity",
    ],
)
def test_checkpoint_schema_admission_rejects_runtime_semantic_mismatch(
    case: str,
) -> None:
    schemas = _schema_documents()
    invalid = copy.deepcopy(_semantic_checkpoint_payload())
    forged = "sha256:" + "f" * 64
    if case == "criteria_noncontiguous":
        invalid["acceptance_criteria"][1]["ordinal"] = 2
    elif case == "criteria_duplicate_identity":
        invalid["acceptance_criteria"][1]["criterion_id"] = invalid[
            "acceptance_criteria"
        ][0]["criterion_id"]
    elif case == "criterion_forged_identity":
        invalid["acceptance_criteria"][0]["criterion_id"] = forged
    elif case == "work_unsorted":
        invalid["pending_work"].reverse()
    elif case == "work_duplicate_identity":
        invalid["pending_work"][1]["work_item_id"] = invalid["pending_work"][0][
            "work_item_id"
        ]
    elif case == "work_forged_identity":
        invalid["pending_work"][0]["work_item_id"] = forged
    elif case == "unresolved_unsorted":
        invalid["unresolved"].reverse()
    elif case == "unresolved_duplicate_identity":
        invalid["unresolved"][1]["unresolved_id"] = invalid["unresolved"][0][
            "unresolved_id"
        ]
    elif case == "unresolved_forged_identity":
        invalid["unresolved"][0]["unresolved_id"] = forged
    elif case == "authority_scopes_unsorted":
        invalid["authority_scopes"].reverse()
    elif case == "authority_scope_invalid_identity":
        scope = next(
            item for item in invalid["authority_scopes"] if item["path"] is not None
        )
        scope["path"]["segment_offsets"] = [1]
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError(case)
    verify_schemas.schema_validator("checkpoint.schema.json", schemas).validate(
        invalid
    )

    with pytest.raises(verify_schemas.SchemaVerificationError):
        verify_schemas.validate_schema_instance(
            "checkpoint.schema.json",
            invalid,
            schemas,
        )


def test_checkpoint_schema_admission_accepts_runtime_valid_payload() -> None:
    verify_schemas.validate_schema_instance(
        "checkpoint.schema.json",
        _semantic_checkpoint_payload(),
        _schema_documents(),
    )


def test_canonical_loader_blocks_float_before_mathematical_integer_schema() -> None:
    schemas = _schema_documents()
    digest = "sha256:" + "1" * 64
    raw = ('{"digest":"' + digest + '","ordinal":1.0}').encode()
    parsed = json.loads(raw)
    assert Draft202012Validator(
        schemas["criterion.schema.json"]
    ).is_valid(parsed)

    with pytest.raises(CanonicalJSONError):
        canonical_loads(raw)
    with pytest.raises(CanonicalJSONError):
        CriterionV1(RecordId(digest), 1.0, digest)  # type: ignore[arg-type]


@pytest.mark.parametrize("child", ["criterion", "work", "unresolved"])
def test_checkpoint_rejects_forged_nested_child_identity(child: str) -> None:
    digest = digest_bytes(b"checkpoint child")
    criterion = build_criterion(ordinal=0, digest=digest)
    work = build_work_item(kind="task", status_code="pending", digest=digest)
    unresolved = build_unresolved_item(code="unknown", digest=digest)
    scope = PathScopeV1(path=None, kind=PathScopeKind.TREE)
    checkpoint = build_checkpoint(
        parent_checkpoint_id=None,
        target_id=RecordId(digest),
        goal_id=RecordId(digest),
        acceptance_criteria=(criterion,),
        constraint_digests=(),
        instruction_id=RecordId(digest),
        policy_id=RecordId(digest),
        ruleset_id=RecordId(digest),
        actor_ids=(RecordId(digest),),
        evidence_ids=(),
        invalidation_ids=(),
        accepted_decision_ids=(),
        pending_work=(work,),
        unresolved=(unresolved,),
        assignment_authority=AssignmentAuthority.READ_ONLY,
        authority_scopes=(scope,),
        open_assignment_ids=(),
        audit_parent_id=None,
        initialization_intent_id=RecordId(digest),
        created_at=LogicalTime("2026-08-14T12:00:00Z"),
    )
    forged = RecordId("sha256:" + "f" * 64)
    changes: dict[str, object]
    if child == "criterion":
        changes = {
            "acceptance_criteria": (
                replace(criterion, criterion_id=forged),
            )
        }
    elif child == "work":
        changes = {"pending_work": (replace(work, work_item_id=forged),)}
    else:
        changes = {
            "unresolved": (
                replace(unresolved, unresolved_id=forged),
            )
        }

    with pytest.raises(CanonicalJSONError):
        replace(checkpoint, **changes)


def test_missing_target_path_maps_to_fully_sanitized_request_error(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "raw-missing-target-marker"

    with pytest.raises(ContinuityRequestError) as captured:
        Continuity.open(missing)

    error = captured.value
    rendered = "\n".join(
        (
            str(error),
            repr(error),
            "".join(traceback.format_exception(error)),
        )
    )
    assert str(missing) not in rendered
    assert missing.name not in rendered
    assert error.__cause__ is None
    assert error.__context__ is None
