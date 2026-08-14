"""Thin public orchestration facade for continuity initialization."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Final

from agent_continuity.adapters import Clock, SystemClock
from agent_continuity.capture import GitTargetAdapter, TargetAdapter
from agent_continuity.capture.coordinator import snapshot_findings
from agent_continuity.kernel.canonical import (
    canonical_bytes,
    canonical_loads,
    digest_bytes,
)
from agent_continuity.kernel.evaluation import (
    EvaluationResult,
    Profile,
    Verdict,
    evaluate,
)
from agent_continuity.kernel.model import PromotionMode, RecordId, StoredRecord
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
from agent_continuity.policy import LoadedPolicy, apply_facade_overrides, load_policy
from agent_continuity.store import (
    AuditEventDraft,
    SensitiveLocalValueDraft,
    SQLiteStateStore,
    StoreConflictError,
    StoreIntegrityError,
    open_external_state_root,
    resolve_state_home,
)
from agent_continuity.store.paths import StatePathError

_DATABASE_LOCKS: dict[tuple[Path, str], Lock] = {}
_DATABASE_LOCKS_GUARD = Lock()
_PRODUCER_NAME: Final = "agent-continuity-guard"
_PRODUCER_VERSION: Final = "0.1.0.dev0"
_STORE_OPEN_ATTEMPTS: Final = 100
_STORE_OPEN_MAX_DELAY_SECONDS: Final = 0.05

__all__ = [
    "AlreadyInitialized",
    "CheckpointReceipt",
    "Continuity",
    "ContinuityError",
    "ContinuityRequestError",
    "TransitionRefused",
]


class ContinuityError(RuntimeError):
    """Base class for public continuity orchestration failures."""


class ContinuityRequestError(ContinuityError, ValueError):
    """Caller input is invalid; message and exception links are sanitized."""


class TransitionRefused(ContinuityError):
    """Current observations do not admit a protected state transition."""

    def __init__(self, result: EvaluationResult) -> None:
        super().__init__("continuity transition refused")
        self.result = result


class AlreadyInitialized(ContinuityError):
    """Session genesis exists with a different initialization intent."""


def _database_lock(state_home: Path, name: str) -> Lock:
    key = (state_home, name)
    with _DATABASE_LOCKS_GUARD:
        return _DATABASE_LOCKS.setdefault(key, Lock())


@contextmanager
def _open_store_with_bounded_reconciliation(
    *,
    target: Path,
    git_directory: Path | None,
    state_home: Path,
    database_name: str,
    store_id: str,
) -> Iterator[SQLiteStateStore]:
    """Adopt a concurrently created store or fail closed after a fixed bound."""

    for attempt in range(_STORE_OPEN_ATTEMPTS):
        state_root = None
        try:
            state_root = open_external_state_root(
                target,
                git_directory,
                state_home,
            )
            store = SQLiteStateStore(
                state_root,
                database_name=database_name,
                store_id=store_id,
            )
        except (StatePathError, StoreIntegrityError):
            if state_root is not None:
                state_root.close()
            if attempt + 1 == _STORE_OPEN_ATTEMPTS:
                raise
            delay = min(
                0.001 * (attempt + 1),
                _STORE_OPEN_MAX_DELAY_SECONDS,
            )
            time.sleep(delay)
            continue
        try:
            yield store
        finally:
            store.close()
        return
    raise AssertionError("bounded store-open loop did not terminate")


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


class Continuity:
    """Public facade that hides capture ordering and genesis transactions."""

    def __init__(
        self,
        *,
        target: Path,
        git_directory: Path | None,
        state_home: Path,
        session_key: str,
        clock: Clock,
        target_adapter: TargetAdapter,
        loaded_policy: LoadedPolicy,
    ) -> None:
        self._target = target
        self._git_directory = git_directory
        self._state_home = state_home
        self._session_key = session_key
        self._clock = clock
        self._adapter = target_adapter
        self._loaded_policy = loaded_policy

    @classmethod
    def open(
        cls,
        target: str | Path,
        *,
        profile: Profile | None = None,
        promotion_mode: PromotionMode | None = None,
        state_home: str | Path | None = None,
        policy: str | Path | None = None,
        session_key: str = "default",
        clock: Clock | None = None,
        target_adapter: TargetAdapter | None = None,
    ) -> Continuity:
        target_path: Path | None = None
        try:
            candidate = Path(target)
            resolved = candidate.resolve(strict=True)
            if resolved.is_dir():
                target_path = resolved
        except (OSError, RuntimeError, TypeError, ValueError):
            pass
        if target_path is None:
            raise ContinuityRequestError("continuity target is unavailable")
        selected_policy = load_policy(
            target=target_path,
            explicit=None if policy is None else Path(policy),
        )
        selected_policy = apply_facade_overrides(
            selected_policy,
            profile=profile,
            promotion_mode=promotion_mode,
        )
        # Validation occurs in the pure model before any state path is created.
        build_initialization_intent(
            session_key=session_key,
            target_id=RecordId("sha256:" + "1" * 64),
            goal_id=RecordId("sha256:" + "2" * 64),
            criterion_ids=(),
            instruction_id=RecordId("sha256:" + "3" * 64),
            policy_id=selected_policy.compiled.policy_id,
            ruleset_id=RecordId("sha256:" + "4" * 64),
        )
        adapter = (
            GitTargetAdapter(target_path)
            if target_adapter is None
            else target_adapter
        )
        git_directory = (
            adapter.git_common_directory
            if isinstance(adapter, GitTargetAdapter)
            else None
        )
        return cls(
            target=target_path,
            git_directory=git_directory,
            state_home=resolve_state_home(state_home),
            session_key=session_key,
            clock=SystemClock() if clock is None else clock,
            target_adapter=adapter,
            loaded_policy=selected_policy,
        )

    def initialize(
        self,
        goal: str,
        acceptance_criteria: Sequence[str],
        *,
        instruction_paths: Sequence[str | os.PathLike[str]] = (),
    ) -> CheckpointReceipt:
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
        policy = self._loaded_policy.compiled

        snapshot_a = self._adapter.capture(requested)
        snapshot_b = self._adapter.capture(requested)
        evaluation = evaluate(
            snapshot_findings(snapshot_a, snapshot_b, policy.profile)
        )
        if snapshot_b != snapshot_a:
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
            session_key=self._session_key,
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
            created_at=self._clock.now(),
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

        snapshot_c = self._adapter.capture(requested)
        if snapshot_c != snapshot_a:
            changed = evaluate(
                snapshot_findings(snapshot_a, snapshot_c, policy.profile)
            )
            raise TransitionRefused(_forced_refusal(changed))

        database_identity = digest_bytes(
            canonical_bytes(
                {
                    "physical_root_fingerprint": (
                        snapshot_a.target.physical_root_fingerprint
                    ),
                    "session_key": self._session_key,
                }
            )
        )
        database_suffix = database_identity.removeprefix("sha256:")
        database_name = f"session-{database_suffix}.sqlite3"
        store_id = f"session-{database_suffix}"
        head_name = f"session:{self._session_key}:checkpoint"
        event = AuditEventDraft(
            kind="initialize",
            subject_id=checkpoint.checkpoint_id,
            logical_time=checkpoint.created_at,
            details={"record_id": intent.intent_id},
        )
        with (
            _database_lock(self._state_home, database_name),
            _open_store_with_bounded_reconciliation(
                target=self._target,
                git_directory=self._git_directory,
                state_home=self._state_home,
                database_name=database_name,
                store_id=store_id,
            ) as store,
        ):
            if store.read_head(head_name) is not None:
                return self._reconcile_existing(
                    store,
                    head_name=head_name,
                    intent_record=intent.record(),
                    evaluation=evaluation,
                )
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
                return self._reconcile_existing(
                    store,
                    head_name=head_name,
                    intent_record=intent.record(),
                    evaluation=evaluation,
                )
        return CheckpointReceipt(
            checkpoint_id=committed.head.record_id,
            target_id=target_record.record_id,
            audit_event_id=committed.head.audit_event_id,
            audit_sequence=committed.head.audit_sequence,
            verdict=evaluation.verdict,
            transition_allowed=evaluation.transition_allowed,
        )

    @staticmethod
    def _reconcile_existing(
        store: SQLiteStateStore,
        *,
        head_name: str,
        intent_record: StoredRecord,
        evaluation: EvaluationResult,
    ) -> CheckpointReceipt:
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
