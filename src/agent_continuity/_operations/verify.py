"""Private pure read-only continuity verification use case."""

from __future__ import annotations

from agent_continuity.capture.coordinator import evaluate_checkpoint_capture
from agent_continuity.kernel.evaluation import EvaluationResult
from agent_continuity.kernel.records import build_ruleset

from .initialize import _forced_refusal, _snapshot_matches_policy
from .session import (
    _ContinuityRuntime,
    capture_matches_checkpoint,
    load_instruction_paths,
    open_session_store,
    select_checkpoint,
)


def _continuity_request_error() -> type[Exception]:
    from agent_continuity.api import ContinuityRequestError

    return ContinuityRequestError


def verify(runtime: _ContinuityRuntime, checkpoint: str = "latest") -> EvaluationResult:
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
        raise _continuity_request_error()("checkpoint selection is invalid")
    with open_session_store(
        runtime,
    ) as store:
        selected = select_checkpoint(
            store,
            head_name=runtime.head_name,
            selector=checkpoint,
        )
        if selected is None:
            raise _continuity_request_error()("checkpoint is unavailable")
        typed_checkpoint = selected
        instruction_paths = load_instruction_paths(
            store,
            typed_checkpoint.instruction_id,
        )
        runtime.instruction_paths = instruction_paths
        snapshot_a = runtime.target_adapter.capture(instruction_paths)
        snapshot_b = runtime.target_adapter.capture(instruction_paths)
        result = evaluate_checkpoint_capture(
            typed_checkpoint,
            snapshot_a,
            snapshot_b,
            runtime.loaded_policy.compiled.profile,
            policy_id=runtime.loaded_policy.compiled.policy_id,
            ruleset_id=build_ruleset(()).ruleset_id,
        )
        if (
            snapshot_b != snapshot_a
            or not capture_matches_checkpoint(
                typed_checkpoint,
                snapshot_a,
            )
            or not _snapshot_matches_policy(snapshot_a, runtime.loaded_policy)
            or not _snapshot_matches_policy(snapshot_b, runtime.loaded_policy)
        ):
            return _forced_refusal(result)
        return result
