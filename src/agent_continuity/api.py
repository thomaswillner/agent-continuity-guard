"""Thin public orchestration facade for continuity initialization."""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from agent_continuity._operations.checkpoint import checkpoint as checkpoint_operation
from agent_continuity._operations.initialize import initialize as initialize_operation
from agent_continuity._operations.resume import resume as resume_operation
from agent_continuity._operations.session import (
    _ContinuityRuntime,
    open_session_store,
)
from agent_continuity._operations.verify import verify as verify_operation
from agent_continuity.adapters import Clock, SystemClock
from agent_continuity.capture import (
    CaptureRequestError,
    GitTargetAdapter,
    TargetAdapter,
)
from agent_continuity.kernel.evaluation import EvaluationResult, Profile
from agent_continuity.kernel.model import PromotionMode, RecordId
from agent_continuity.kernel.records import (
    CheckpointReceipt,
    build_initialization_intent,
)
from agent_continuity.kernel.resume import ResumeContext
from agent_continuity.policy import (
    LoadedPolicy,
    apply_facade_overrides,
    load_policy,
    load_target_policy,
)
from agent_continuity.store import (
    SQLiteStateStore,
    StoreIntegrityError,
    resolve_state_home,
)

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
        self._runtime = _ContinuityRuntime(
            target=target,
            git_directory=git_directory,
            state_home=state_home,
            session_key=session_key,
            clock=clock,
            target_adapter=target_adapter,
            loaded_policy=loaded_policy,
        )

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
        continuity = cls(
            target=target_path,
            git_directory=git_directory,
            state_home=resolve_state_home(state_home),
            session_key=session_key,
            clock=SystemClock() if clock is None else clock,
            target_adapter=adapter,
            loaded_policy=selected_policy,
        )
        continuity._runtime.policy_path = None if policy is None else Path(policy)
        continuity._runtime.profile_override = profile
        continuity._runtime.promotion_mode_override = promotion_mode
        return continuity

    def initialize(
        self,
        goal: str,
        acceptance_criteria: Sequence[str],
        *,
        instruction_paths: Sequence[str | os.PathLike[str]] = (),
    ) -> CheckpointReceipt:
        return initialize_operation(
            self._runtime,
            goal,
            acceptance_criteria,
            instruction_paths=instruction_paths,
        )


    @contextmanager
    def _open_session_store(
        self,
        *,
        read_only: bool = True,
    ) -> Iterator[SQLiteStateStore]:
        with open_session_store(self._runtime, read_only=read_only) as store:
            yield store

    def checkpoint(self, reason: str | None = None) -> CheckpointReceipt:
        return checkpoint_operation(self._runtime, reason)


    def verify(self, checkpoint: str = "latest") -> EvaluationResult:
        return verify_operation(self._runtime, checkpoint)

    def resume(self, checkpoint: str = "latest") -> ResumeContext:
        integrity_message: str | None = None
        try:
            return resume_operation(self._runtime, checkpoint)
        except StoreIntegrityError as error:
            integrity_message = str(error)
        if integrity_message is not None:
            raise StoreIntegrityError(integrity_message) from None
        raise AssertionError("unreachable resume integrity state")
