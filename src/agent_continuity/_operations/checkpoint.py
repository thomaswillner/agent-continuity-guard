"""Private checkpoint capture, bounded CAS retry, and receipt construction."""

from __future__ import annotations

import secrets
from typing import Final

from agent_continuity.capture.coordinator import evaluate_checkpoint_capture
from agent_continuity.kernel.canonical import digest_bytes
from agent_continuity.kernel.checkpoint import build_subsequent_checkpoint
from agent_continuity.kernel.records import CheckpointReceipt, build_ruleset
from agent_continuity.store import (
    AuditEventDraft,
    StoreConflictError,
    StoreIntegrityError,
)

from .initialize import _forced_refusal, _snapshot_matches_policy
from .session import (
    _ContinuityRuntime,
    capture_matches_checkpoint,
    database_lock,
    discover_database_name,
    load_checkpoint_record,
    load_instruction_paths,
    open_session_store,
)

_CHECKPOINT_ATTEMPTS: Final = 3


def _continuity_request_error() -> type[Exception]:
    from agent_continuity.api import ContinuityRequestError

    return ContinuityRequestError


def _transition_refused() -> type[Exception]:
    from agent_continuity.api import TransitionRefused

    return TransitionRefused


def checkpoint(
    runtime: _ContinuityRuntime, reason: str | None = None
) -> CheckpointReceipt:
    if reason is not None and type(reason) is not str:
        raise TypeError("checkpoint reason must be text or null")
    reason_digest = None if reason is None else digest_bytes(reason.encode("utf-8"))
    invocation_digest = digest_bytes(secrets.token_bytes(32))
    policy = runtime.loaded_policy.compiled
    ruleset_id = build_ruleset(()).ruleset_id
    for attempt in range(_CHECKPOINT_ATTEMPTS):
        database_name = discover_database_name(runtime)
        conflicted = False
        with (
            database_lock(runtime, database_name),
            open_session_store(runtime, read_only=False) as store,
        ):
            head = store.read_head(runtime.head_name)
            if head is None:
                raise _continuity_request_error()("continuity session is unavailable")
            parent = load_checkpoint_record(store, head.record_id)
            if parent is None:
                raise StoreIntegrityError("checkpoint head record is absent")
            checkpoint_parent = parent
            instruction_paths = load_instruction_paths(
                store,
                checkpoint_parent.instruction_id,
            )
            runtime.instruction_paths = instruction_paths
            snapshot_a = runtime.target_adapter.capture(instruction_paths)
            snapshot_b = runtime.target_adapter.capture(instruction_paths)
            evaluation = evaluate_checkpoint_capture(
                checkpoint_parent,
                snapshot_a,
                snapshot_b,
                policy.profile,
                policy_id=policy.policy_id,
                ruleset_id=ruleset_id,
            )
            if (
                snapshot_b != snapshot_a
                or not capture_matches_checkpoint(
                    checkpoint_parent,
                    snapshot_a,
                )
                or not _snapshot_matches_policy(snapshot_a, runtime.loaded_policy)
                or not _snapshot_matches_policy(snapshot_b, runtime.loaded_policy)
            ):
                evaluation = _forced_refusal(evaluation)
            if not evaluation.transition_allowed:
                raise _transition_refused()(evaluation)
            child = build_subsequent_checkpoint(
                checkpoint_parent,
                audit_parent_id=head.audit_event_id,
                created_at=runtime.clock.now(),
            )
            snapshot_c = runtime.target_adapter.capture(instruction_paths)
            if snapshot_c != snapshot_a or not _snapshot_matches_policy(
                snapshot_c, runtime.loaded_policy
            ):
                changed = evaluate_checkpoint_capture(
                    checkpoint_parent,
                    snapshot_a,
                    snapshot_c,
                    policy.profile,
                    policy_id=policy.policy_id,
                    ruleset_id=ruleset_id,
                )
                raise _transition_refused()(_forced_refusal(changed))
            event = AuditEventDraft(
                kind="checkpoint",
                subject_id=child.checkpoint_id,
                logical_time=child.created_at,
                details={
                    "digests": [invocation_digest],
                    **({} if reason_digest is None else {"digest": reason_digest}),
                },
            )
            try:
                committed = store.commit(
                    records=(child.record(),),
                    event=event,
                    head_name=runtime.head_name,
                    expected_head=head,
                    new_head_id=child.checkpoint_id,
                )
            except StoreConflictError:
                conflicted = True
            else:
                return CheckpointReceipt(
                    checkpoint_id=committed.head.record_id,
                    target_id=child.target_id,
                    audit_event_id=committed.head.audit_event_id,
                    audit_sequence=committed.head.audit_sequence,
                    verdict=evaluation.verdict,
                    transition_allowed=evaluation.transition_allowed,
                )
        if not conflicted:
            break
        if attempt + 1 == _CHECKPOINT_ATTEMPTS:
            raise StoreConflictError("checkpoint head changed during retry")
    raise StoreConflictError("checkpoint transition did not commit")
