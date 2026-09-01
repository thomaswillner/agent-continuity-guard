"""Thin public orchestration facade for continuity initialization."""

from __future__ import annotations

import os
import re
import secrets
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Final, cast

from agent_continuity.adapters import Clock, SystemClock
from agent_continuity.capture import (
    CaptureRequestError,
    CaptureSnapshot,
    GitTargetAdapter,
    TargetAdapter,
)
from agent_continuity.capture.coordinator import (
    evaluate_checkpoint_capture,
    snapshot_findings,
)
from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    canonical_loads,
    digest_bytes,
)
from agent_continuity.kernel.checkpoint import (
    build_subsequent_checkpoint,
    checkpoint_from_record,
    instruction_paths_from_record,
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
    CheckpointV1,
    ProducerIdentity,
    build_actor,
    build_checkpoint,
    build_criterion,
    build_goal,
    build_initialization_intent,
    build_ruleset,
    make_record,
)
from agent_continuity.policy import (
    LoadedPolicy,
    apply_facade_overrides,
    load_policy,
    load_target_policy,
)
from agent_continuity.store import (
    AuditEventDraft,
    SensitiveLocalValueDraft,
    SQLiteStateStore,
    StoreConflictError,
    StoreIntegrityError,
    StoreValidationError,
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
_CHECKPOINT_ATTEMPTS: Final = 3
_SESSION_DATABASE_RE = re.compile(r"^session-[0-9a-f]{64}\.sqlite3$")

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


@contextmanager
def _open_existing_store(
    *,
    target: Path,
    git_directory: Path | None,
    state_home: Path,
    database_name: str,
    read_only: bool,
) -> Iterator[SQLiteStateStore]:
    """Open an existing session store without admitting store creation."""

    if not os.path.lexists(state_home):
        raise ContinuityRequestError("continuity session is unavailable")
    state_root = None
    store = None
    missing = False
    try:
        state_root = open_external_state_root(target, git_directory, state_home)
        store = SQLiteStateStore(
            state_root,
            database_name=database_name,
            store_id=None,
            read_only=read_only,
        )
    except StoreValidationError:
        missing = True
        if state_root is not None:
            state_root.close()
    if missing or store is None:
        raise ContinuityRequestError("continuity session is unavailable")
    try:
        yield store
    finally:
        store.close()


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
    snapshot: CaptureSnapshot,
    loaded_policy: LoadedPolicy,
) -> bool:
    if loaded_policy.source.startswith("target"):
        return snapshot.target_policy_digest == loaded_policy.source_digest
    if loaded_policy.source.startswith("builtin"):
        return snapshot.target_policy_digest is None
    return True


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
        self._database_name: str | None = None
        self._instruction_paths: tuple[bytes, ...] | None = None

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
        try:
            admitted_adapter = GitTargetAdapter(target)
        except CaptureRequestError:
            admitted_adapter = None
        if admitted_adapter is None:
            raise ContinuityRequestError("continuity target is unavailable")
        target_path = admitted_adapter.root
        if policy is None:
            selected_policy = load_target_policy(
                admitted_adapter.read_target_policy()
            )
        else:
            selected_policy = load_policy(
                target=target_path,
                explicit=Path(policy),
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
        adapter = admitted_adapter if target_adapter is None else target_adapter
        git_directory = admitted_adapter.git_common_directory
        if target_adapter is not None:
            admitted_adapter.close()
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
        if (
            snapshot_b != snapshot_a
            or not _snapshot_matches_policy(snapshot_a, self._loaded_policy)
            or not _snapshot_matches_policy(snapshot_b, self._loaded_policy)
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
        if snapshot_c != snapshot_a or not _snapshot_matches_policy(
            snapshot_c, self._loaded_policy
        ):
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
                receipt = self._reconcile_existing(
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
                    receipt = self._reconcile_existing(
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
                    receipt = self._reconcile_existing(
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
        self._database_name = database_name
        self._instruction_paths = requested
        return receipt

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

    @property
    def _head_name(self) -> str:
        return f"session:{self._session_key}:checkpoint"

    def _discover_database_name(self) -> str:
        if self._database_name is not None:
            return self._database_name
        if not os.path.lexists(self._state_home):
            raise ContinuityRequestError("continuity session is unavailable")
        with open_external_state_root(
            self._target,
            self._git_directory,
            self._state_home,
        ) as state_root:
            candidates = tuple(
                sorted(
                    name
                    for name in os.listdir(state_root.dir_fd)
                    if _SESSION_DATABASE_RE.fullmatch(name) is not None
                )
            )
        matches: list[str] = []
        for database_name in candidates:
            with _open_existing_store(
                target=self._target,
                git_directory=self._git_directory,
                state_home=self._state_home,
                database_name=database_name,
                read_only=True,
            ) as store:
                if store.read_head(self._head_name) is not None:
                    matches.append(database_name)
        if not matches:
            raise ContinuityRequestError("continuity session is unavailable")
        if len(matches) != 1:
            raise StoreIntegrityError("continuity session mapping is ambiguous")
        self._database_name = matches[0]
        return matches[0]

    @contextmanager
    def _open_session_store(
        self,
        *,
        read_only: bool = True,
    ) -> Iterator[SQLiteStateStore]:
        database_name = self._discover_database_name()
        missing = False
        with _open_existing_store(
            target=self._target,
            git_directory=self._git_directory,
            state_home=self._state_home,
            database_name=database_name,
            read_only=read_only,
        ) as store:
            if store.read_head(self._head_name) is None:
                missing = True
            else:
                yield store
        if missing:
            raise ContinuityRequestError("continuity session is unavailable")

    @staticmethod
    def _load_checkpoint_record(
        store: SQLiteStateStore,
        checkpoint_id: RecordId,
    ) -> object:
        missing = False
        invalid = False
        checkpoint = None
        try:
            record = store.load_record(checkpoint_id)
        except KeyError:
            missing = True
        else:
            try:
                checkpoint = checkpoint_from_record(record)
            except (CanonicalJSONError, KeyError, TypeError, ValueError):
                invalid = True
        if missing:
            return None
        if invalid or checkpoint is None:
            raise StoreIntegrityError("checkpoint record is invalid")
        return checkpoint

    @classmethod
    def _select_checkpoint(
        cls,
        store: SQLiteStateStore,
        *,
        head_name: str,
        selector: str,
    ) -> object:
        head = store.read_head(head_name)
        if head is None:
            return None
        selected_id = head.record_id if selector == "latest" else RecordId(selector)
        current = cls._load_checkpoint_record(store, head.record_id)
        seen: set[RecordId] = set()
        while current is not None:
            checkpoint = cast(CheckpointV1, current)
            if checkpoint.checkpoint_id == selected_id:
                return checkpoint
            if (
                checkpoint.parent_checkpoint_id is None
                or checkpoint.checkpoint_id in seen
            ):
                return None
            seen.add(checkpoint.checkpoint_id)
            current = cls._load_checkpoint_record(
                store,
                checkpoint.parent_checkpoint_id,
            )
        return None

    @staticmethod
    def _load_instruction_paths(
        store: SQLiteStateStore,
        instruction_id: RecordId,
    ) -> tuple[bytes, ...]:
        missing = False
        invalid = False
        paths = None
        try:
            record = store.load_record(instruction_id)
        except KeyError:
            missing = True
        else:
            try:
                paths = instruction_paths_from_record(record)
            except (CanonicalJSONError, KeyError, TypeError, ValueError):
                invalid = True
        if missing or invalid or paths is None:
            raise StoreIntegrityError("instruction record is invalid")
        return paths

    @staticmethod
    def _capture_matches_checkpoint(
        checkpoint: object,
        snapshot: object,
    ) -> bool:
        typed_checkpoint = cast(CheckpointV1, checkpoint)
        typed_snapshot = cast(CaptureSnapshot, snapshot)
        return (
            typed_snapshot.target.record().record_id == typed_checkpoint.target_id
            and typed_snapshot.instruction_record().record_id
            == typed_checkpoint.instruction_id
        )

    def checkpoint(self, reason: str | None = None) -> CheckpointReceipt:
        if reason is not None and type(reason) is not str:
            raise TypeError("checkpoint reason must be text or null")
        reason_digest = None if reason is None else digest_bytes(reason.encode("utf-8"))
        invocation_digest = digest_bytes(secrets.token_bytes(32))
        policy = self._loaded_policy.compiled
        ruleset_id = build_ruleset(()).ruleset_id
        for attempt in range(_CHECKPOINT_ATTEMPTS):
            database_name = self._discover_database_name()
            conflicted = False
            with (
                _database_lock(self._state_home, database_name),
                self._open_session_store(read_only=False) as store,
            ):
                head = store.read_head(self._head_name)
                if head is None:
                    raise ContinuityRequestError("continuity session is unavailable")
                parent = self._load_checkpoint_record(store, head.record_id)
                if parent is None:
                    raise StoreIntegrityError("checkpoint head record is absent")
                checkpoint_parent = cast(CheckpointV1, parent)
                instruction_paths = self._load_instruction_paths(
                    store,
                    checkpoint_parent.instruction_id,
                )
                self._instruction_paths = instruction_paths
                snapshot_a = self._adapter.capture(instruction_paths)
                snapshot_b = self._adapter.capture(instruction_paths)
                evaluation = evaluate_checkpoint_capture(
                    checkpoint_parent,
                    snapshot_a,
                    snapshot_b,
                    policy.profile,
                    policy_id=policy.policy_id,
                    ruleset_id=ruleset_id,
                )
                if snapshot_b != snapshot_a or not self._capture_matches_checkpoint(
                    checkpoint_parent,
                    snapshot_a,
                ) or not _snapshot_matches_policy(
                    snapshot_a, self._loaded_policy
                ) or not _snapshot_matches_policy(
                    snapshot_b, self._loaded_policy
                ):
                    evaluation = _forced_refusal(evaluation)
                if not evaluation.transition_allowed:
                    raise TransitionRefused(evaluation)
                child = build_subsequent_checkpoint(
                    checkpoint_parent,
                    audit_parent_id=head.audit_event_id,
                    created_at=self._clock.now(),
                )
                snapshot_c = self._adapter.capture(instruction_paths)
                if snapshot_c != snapshot_a or not _snapshot_matches_policy(
                    snapshot_c, self._loaded_policy
                ):
                    changed = evaluate_checkpoint_capture(
                        checkpoint_parent,
                        snapshot_a,
                        snapshot_c,
                        policy.profile,
                        policy_id=policy.policy_id,
                        ruleset_id=ruleset_id,
                    )
                    raise TransitionRefused(_forced_refusal(changed))
                event = AuditEventDraft(
                    kind="checkpoint",
                    subject_id=child.checkpoint_id,
                    logical_time=child.created_at,
                    details={
                        "digests": [invocation_digest],
                        **(
                            {}
                            if reason_digest is None
                            else {"digest": reason_digest}
                        ),
                    },
                )
                try:
                    committed = store.commit(
                        records=(child.record(),),
                        event=event,
                        head_name=self._head_name,
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

    def verify(self, checkpoint: str = "latest") -> EvaluationResult:
        valid_selector = type(checkpoint) is str and checkpoint == "latest"
        if type(checkpoint) is str and checkpoint != "latest":
            try:
                from agent_continuity.kernel.records import require_digest

                require_digest(checkpoint)
            except (TypeError, ValueError):
                valid_selector = False
            else:
                valid_selector = True
        if not valid_selector:
            raise ContinuityRequestError("checkpoint selection is invalid")
        with self._open_session_store() as store:
            selected = self._select_checkpoint(
                store,
                head_name=self._head_name,
                selector=checkpoint,
            )
            if selected is None:
                raise ContinuityRequestError("checkpoint is unavailable")
            typed_checkpoint = cast(CheckpointV1, selected)
            instruction_paths = self._load_instruction_paths(
                store,
                typed_checkpoint.instruction_id,
            )
            self._instruction_paths = instruction_paths
            snapshot_a = self._adapter.capture(instruction_paths)
            snapshot_b = self._adapter.capture(instruction_paths)
            result = evaluate_checkpoint_capture(
                typed_checkpoint,
                snapshot_a,
                snapshot_b,
                self._loaded_policy.compiled.profile,
                policy_id=self._loaded_policy.compiled.policy_id,
                ruleset_id=build_ruleset(()).ruleset_id,
            )
            if snapshot_b != snapshot_a or not self._capture_matches_checkpoint(
                typed_checkpoint,
                snapshot_a,
            ) or not _snapshot_matches_policy(
                snapshot_a, self._loaded_policy
            ) or not _snapshot_matches_policy(
                snapshot_b, self._loaded_policy
            ):
                return _forced_refusal(result)
            return result
