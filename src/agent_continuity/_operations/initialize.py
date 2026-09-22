"""Private three-observation admission and idempotent genesis commit."""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Final

from agent_continuity.capture import CaptureSnapshot
from agent_continuity.capture.coordinator import snapshot_findings
from agent_continuity.kernel.canonical import (
    canonical_bytes,
    canonical_loads,
    digest_bytes,
)
from agent_continuity.kernel.evaluation import EvaluationResult, Verdict, evaluate
from agent_continuity.kernel.model import RecordId, StoredRecord
from agent_continuity.kernel.paths import PathScopeKind, PathScopeV1, path_scope_payload
from agent_continuity.kernel.records import (
    CheckpointReceipt,
    ProducerIdentity,
    build_actor,
    build_checkpoint,
    build_criterion,
    build_goal,
    build_initialization_intent,
    build_ruleset,
    make_record,
)
from agent_continuity.policy import LoadedPolicy
from agent_continuity.store import (
    AuditEventDraft,
    SensitiveLocalValueDraft,
    SQLiteStateStore,
    StoreConflictError,
    StoreValidationError,
)

from .session import (
    _ContinuityRuntime,
    database_lock,
    open_store_with_bounded_reconciliation,
)

_PRODUCER_NAME: Final = "agent-continuity-guard"
_PRODUCER_VERSION: Final = "0.1.0.dev0"


def _exceptions() -> tuple[type[Exception], type[Exception]]:
    from agent_continuity.api import AlreadyInitialized, TransitionRefused

    return AlreadyInitialized, TransitionRefused


def _producer_identity() -> ProducerIdentity:
    digest = digest_bytes(
        canonical_bytes({"name": _PRODUCER_NAME, "version": _PRODUCER_VERSION})
    )
    return ProducerIdentity(_PRODUCER_NAME, _PRODUCER_VERSION, digest)


def _instruction_bytes(
    instruction_paths: Sequence[str | os.PathLike[str]],
) -> tuple[bytes, ...]:
    if isinstance(instruction_paths, (str, bytes, os.PathLike)):
        raise TypeError("instruction_paths must be a sequence of paths")
    result: list[bytes] = []
    for value in instruction_paths:
        if not isinstance(value, (str, os.PathLike)):
            raise TypeError("instruction path is invalid")
        result.append(os.fsencode(value))
    return tuple(result)


def _local_values(
    goal: bytes,
    criteria: tuple[bytes, ...],
) -> tuple[SensitiveLocalValueDraft, ...]:
    values = {
        (digest_bytes(value), kind): SensitiveLocalValueDraft(
            digest=digest_bytes(value),
            kind=kind,
            value=value,
            caller_approved=True,
        )
        for kind, value in (
            ("goal_text", goal),
            *(("criterion_text", item) for item in criteria),
        )
    }
    return tuple(values[key] for key in sorted(values))


def _forced_refusal(result: EvaluationResult) -> EvaluationResult:
    if not result.transition_allowed:
        return result
    verdict = result.verdict if result.verdict is not Verdict.PASS else Verdict.UNKNOWN
    return EvaluationResult(verdict, False, result.findings)


def _snapshot_matches_policy(
    snapshot: CaptureSnapshot, loaded_policy: LoadedPolicy
) -> bool:
    typed_snapshot = snapshot
    if loaded_policy.source.startswith("target"):
        return typed_snapshot.target_policy_digest == loaded_policy.source_digest
    if loaded_policy.source.startswith("builtin"):
        return typed_snapshot.target_policy_digest is None
    return True


def initialize(
    runtime: _ContinuityRuntime,
    goal: str,
    acceptance_criteria: Sequence[str],
    *,
    instruction_paths: Sequence[str | os.PathLike[str]] = (),
) -> CheckpointReceipt:
    _, TransitionRefused = _exceptions()
    if type(goal) is not str or isinstance(acceptance_criteria, (str, bytes)):
        raise TypeError("goal and acceptance criteria are invalid")
    criteria_text = tuple(acceptance_criteria)
    if any(type(item) is not str for item in criteria_text):
        raise TypeError("acceptance criterion is invalid")
    goal_bytes = goal.encode("utf-8", errors="strict")
    criterion_bytes = tuple(
        item.encode("utf-8", errors="strict") for item in criteria_text
    )
    requested = _instruction_bytes(instruction_paths)
    policy = runtime.loaded_policy.compiled

    snapshot_a = runtime.target_adapter.capture(requested)
    snapshot_b = runtime.target_adapter.capture(requested)
    evaluation = evaluate(snapshot_findings(snapshot_a, snapshot_b, policy.profile))
    if (
        snapshot_b != snapshot_a
        or not _snapshot_matches_policy(snapshot_a, runtime.loaded_policy)
        or not _snapshot_matches_policy(snapshot_b, runtime.loaded_policy)
    ):
        raise TransitionRefused(_forced_refusal(evaluation))
    if not evaluation.transition_allowed:
        raise TransitionRefused(evaluation)

    target_record = snapshot_a.target.record()
    instruction_record = snapshot_a.instruction_record()
    goal_record = build_goal(digest_bytes(goal_bytes))
    criteria = tuple(
        build_criterion(ordinal=index, digest=digest_bytes(value))
        for index, value in enumerate(criterion_bytes)
    )
    ruleset = build_ruleset(())
    root_scope = PathScopeV1(path=None, kind=PathScopeKind.TREE)
    scope_record = make_record("PathScope", path_scope_payload(root_scope))
    actor = build_actor(
        producer=_producer_identity(),
        authority=policy.max_assignment_authority,
        scope_ids=(scope_record.record_id,),
    )
    intent = build_initialization_intent(
        session_key=runtime.session_key,
        target_id=target_record.record_id,
        goal_id=goal_record.goal_id,
        criterion_ids=tuple(item.criterion_id for item in criteria),
        instruction_id=instruction_record.record_id,
        policy_id=policy.policy_id,
        ruleset_id=ruleset.ruleset_id,
    )
    checkpoint = build_checkpoint(
        parent_checkpoint_id=None,
        target_id=target_record.record_id,
        goal_id=goal_record.goal_id,
        acceptance_criteria=criteria,
        constraint_digests=(),
        instruction_id=instruction_record.record_id,
        policy_id=policy.policy_id,
        ruleset_id=ruleset.ruleset_id,
        actor_ids=(actor.actor_id,),
        evidence_ids=(),
        invalidation_ids=(),
        accepted_decision_ids=(),
        pending_work=(),
        unresolved=(),
        assignment_authority=policy.max_assignment_authority,
        authority_scopes=(root_scope,),
        open_assignment_ids=(),
        audit_parent_id=None,
        initialization_intent_id=intent.intent_id,
        created_at=runtime.clock.now(),
    )
    records: tuple[StoredRecord, ...] = (
        target_record,
        instruction_record,
        policy.record(),
        scope_record,
        goal_record.record(),
        *(item.record() for item in criteria),
        ruleset.record(),
        actor.record(),
        intent.record(),
        checkpoint.record(),
    )

    snapshot_c = runtime.target_adapter.capture(requested)
    if snapshot_c != snapshot_a or not _snapshot_matches_policy(
        snapshot_c, runtime.loaded_policy
    ):
        changed = evaluate(snapshot_findings(snapshot_a, snapshot_c, policy.profile))
        raise TransitionRefused(_forced_refusal(changed))

    database_identity = digest_bytes(
        canonical_bytes(
            {
                "physical_root_fingerprint": (
                    snapshot_a.target.physical_root_fingerprint
                ),
                "session_key": runtime.session_key,
            }
        )
    )
    database_suffix = database_identity.removeprefix("sha256:")
    database_name = f"session-{database_suffix}.sqlite3"
    store_id = f"session-{database_suffix}"
    head_name = f"session:{runtime.session_key}:checkpoint"
    event = AuditEventDraft(
        kind="initialize",
        subject_id=checkpoint.checkpoint_id,
        logical_time=checkpoint.created_at,
        details={"record_id": intent.intent_id},
    )
    with (
        database_lock(runtime, database_name),
        open_store_with_bounded_reconciliation(
            runtime,
            database_name=database_name,
            store_id=store_id,
        ) as store,
    ):
        if store.read_head(head_name) is not None:
            receipt = _reconcile_existing(
                store,
                head_name=head_name,
                intent_record=intent.record(),
                evaluation=evaluation,
            )
        else:
            try:
                committed = store.commit(
                    records=records,
                    local_values=_local_values(goal_bytes, criterion_bytes),
                    event=event,
                    head_name=head_name,
                    expected_head=None,
                    new_head_id=checkpoint.checkpoint_id,
                )
            except StoreConflictError:
                receipt = _reconcile_existing(
                    store,
                    head_name=head_name,
                    intent_record=intent.record(),
                    evaluation=evaluation,
                )
            except StoreValidationError as error:
                if (
                    str(error)
                    != "sensitive-local values are allowed only during genesis"
                    or store.read_head(head_name) is None
                ):
                    raise
                receipt = _reconcile_existing(
                    store,
                    head_name=head_name,
                    intent_record=intent.record(),
                    evaluation=evaluation,
                )
            else:
                receipt = CheckpointReceipt(
                    checkpoint_id=committed.head.record_id,
                    target_id=target_record.record_id,
                    audit_event_id=committed.head.audit_event_id,
                    audit_sequence=committed.head.audit_sequence,
                    verdict=evaluation.verdict,
                    transition_allowed=evaluation.transition_allowed,
                )
    runtime.database_name = database_name
    runtime.instruction_paths = requested
    return receipt


def _reconcile_existing(
    store: SQLiteStateStore,
    *,
    head_name: str,
    intent_record: StoredRecord,
    evaluation: EvaluationResult,
) -> CheckpointReceipt:
    AlreadyInitialized, _ = _exceptions()
    head = store.read_head(head_name)
    if head is None:
        raise StoreConflictError(
            "initialization head disappeared during reconciliation"
        )
    checkpoint_record = store.load_record(head.record_id)
    checkpoint = canonical_loads(checkpoint_record.canonical_bytes)
    existing_intent_id = checkpoint.get("initialization_intent_id")
    target_id = checkpoint.get("target_id")
    if type(existing_intent_id) is not str or type(target_id) is not str:
        raise StoreConflictError("existing initialization record is invalid")
    existing_intent = store.load_record(RecordId(existing_intent_id))
    if existing_intent != intent_record:
        raise AlreadyInitialized(
            "session already has a different initialization intent"
        )
    return CheckpointReceipt(
        checkpoint_id=head.record_id,
        target_id=RecordId(target_id),
        audit_event_id=head.audit_event_id,
        audit_sequence=head.audit_sequence,
        verdict=evaluation.verdict,
        transition_allowed=evaluation.transition_allowed,
    )
