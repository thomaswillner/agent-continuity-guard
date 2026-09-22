from __future__ import annotations

import inspect

import agent_continuity
import agent_continuity.api as api
from agent_continuity.kernel.canonical import canonical_bytes
from agent_continuity.kernel.checkpoint import verification_result_payload
from agent_continuity.kernel.evaluation import EvaluationResult, Verdict
from agent_continuity.kernel.records import (
    CheckpointReceipt,
    checkpoint_receipt_payload,
)

_PACKAGE_EXPORTS = [
    "AlreadyInitialized",
    "CheckpointReceipt",
    "Continuity",
    "ContinuityError",
    "ContinuityRequestError",
    "Profile",
    "PromotionMode",
    "TransitionRefused",
]
_API_EXPORTS = [
    "AlreadyInitialized",
    "CheckpointReceipt",
    "Continuity",
    "ContinuityError",
    "ContinuityRequestError",
    "TransitionRefused",
]
_CONTINUITY_SIGNATURES = {
    "Continuity": "(*, target: 'Path', git_directory: 'Path | None', state_home: 'Path', session_key: 'str', clock: 'Clock', target_adapter: 'TargetAdapter', loaded_policy: 'LoadedPolicy') -> 'None'",  # noqa: E501
    "open": "(target: 'str | Path', *, profile: 'Profile | None' = None, promotion_mode: 'PromotionMode | None' = None, state_home: 'str | Path | None' = None, policy: 'str | Path | None' = None, session_key: 'str' = 'default', clock: 'Clock | None' = None, target_adapter: 'TargetAdapter | None' = None) -> 'Continuity'",  # noqa: E501
    "initialize": "(self, goal: 'str', acceptance_criteria: 'Sequence[str]', *, instruction_paths: 'Sequence[str | os.PathLike[str]]' = ()) -> 'CheckpointReceipt'",  # noqa: E501
    "checkpoint": "(self, reason: 'str | None' = None) -> 'CheckpointReceipt'",
    "verify": "(self, checkpoint: 'str' = 'latest') -> 'EvaluationResult'",
}
_EXCEPTION_MROS = {
    "ContinuityError": (
        "agent_continuity.api.ContinuityError",
        "builtins.RuntimeError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ),
    "ContinuityRequestError": (
        "agent_continuity.api.ContinuityRequestError",
        "agent_continuity.api.ContinuityError",
        "builtins.RuntimeError",
        "builtins.ValueError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ),
    "TransitionRefused": (
        "agent_continuity.api.TransitionRefused",
        "agent_continuity.api.ContinuityError",
        "builtins.RuntimeError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ),
    "AlreadyInitialized": (
        "agent_continuity.api.AlreadyInitialized",
        "agent_continuity.api.ContinuityError",
        "builtins.RuntimeError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ),
}


def _mro_names(value: type[BaseException]) -> tuple[str, ...]:
    return tuple(f"{item.__module__}.{item.__qualname__}" for item in value.__mro__)


def test_existing_package_and_api_exports_are_exact_ordered_lists() -> None:
    assert type(agent_continuity.__all__) is list
    assert agent_continuity.__all__ == _PACKAGE_EXPORTS
    assert type(api.__all__) is list
    assert api.__all__ == _API_EXPORTS
    assert "ResumeContext" not in agent_continuity.__all__
    assert "ResumeContext" not in api.__all__


def test_continuity_existing_signatures_and_only_allowed_delta_are_frozen() -> None:
    observed = {
        "Continuity": str(inspect.signature(api.Continuity)),
        **{
            name: str(inspect.signature(getattr(api.Continuity, name)))
            for name in ("open", "initialize", "checkpoint", "verify")
        },
    }
    assert observed == _CONTINUITY_SIGNATURES

    public_methods = {
        name
        for name, value in inspect.getmembers(api.Continuity)
        if not name.startswith("_") and inspect.isfunction(value)
    }
    assert public_methods in (
        {"checkpoint", "initialize", "verify"},
        {"checkpoint", "initialize", "resume", "verify"},
    )
    if "resume" in public_methods:
        assert str(inspect.signature(api.Continuity.resume)) == (
            "(self, checkpoint: 'str' = 'latest') -> 'ResumeContext'"
        )


def test_continuity_exception_identities_and_mros_are_frozen() -> None:
    for name, expected in _EXCEPTION_MROS.items():
        value = getattr(api, name)
        assert getattr(agent_continuity, name) is value
        assert _mro_names(value) == expected


def test_checkpoint_receipt_canonical_payload_is_frozen() -> None:
    receipt = CheckpointReceipt(
        checkpoint_id="sha256:" + "1" * 64,
        target_id="sha256:" + "2" * 64,
        audit_event_id="sha256:" + "3" * 64,
        audit_sequence=7,
        verdict=Verdict.PASS,
        transition_allowed=True,
    )
    expected = {
        "audit_event_id": "sha256:" + "3" * 64,
        "audit_sequence": 7,
        "checkpoint_id": "sha256:" + "1" * 64,
        "target_id": "sha256:" + "2" * 64,
        "transition_allowed": True,
        "verdict": "pass",
    }

    assert checkpoint_receipt_payload(receipt) == expected
    assert canonical_bytes(expected) == (
        b'{"audit_event_id":"sha256:'
        + b"3" * 64
        + b'","audit_sequence":7,"checkpoint_id":"sha256:'
        + b"1" * 64
        + b'","target_id":"sha256:'
        + b"2" * 64
        + b'","transition_allowed":true,"verdict":"pass"}'
    )


def test_verification_result_canonical_payload_is_frozen() -> None:
    result = EvaluationResult(Verdict.PASS, True, ())
    expected = {
        "findings": [],
        "schema": "VerificationResult/v1",
        "transition_allowed": True,
        "verdict": "pass",
    }

    assert verification_result_payload(result) == expected
    assert canonical_bytes(expected) == (
        b'{"findings":[],"schema":"VerificationResult/v1",'
        b'"transition_allowed":true,"verdict":"pass"}'
    )
