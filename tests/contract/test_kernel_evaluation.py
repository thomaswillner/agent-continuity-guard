from __future__ import annotations

from itertools import permutations

import pytest

from agent_continuity.kernel.canonical import CanonicalJSONError, canonical_bytes
from agent_continuity.kernel.evaluation import (
    EvaluationCase,
    EvaluationResult,
    Profile,
    Verdict,
    evaluate,
    evaluation_result_payload,
)
from agent_continuity.kernel.findings import Finding
from agent_continuity.kernel.model import RecordId


def finding(
    verdict: Verdict,
    *,
    code: str = "example",
    integrity_failure: bool = False,
    message_id: str = "acg.example",
    parameters: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        code=code,
        verdict=verdict,
        subject_id=RecordId("sha256:" + "1" * 64),
        message_id=message_id,
        parameters={} if parameters is None else parameters,  # type: ignore[arg-type]
        integrity_failure=integrity_failure,
    )


def test_no_findings_is_pass_and_allowed_for_every_profile() -> None:
    for profile in Profile:
        result = evaluate(EvaluationCase(profile=profile, findings=()))
        assert result.verdict is Verdict.PASS
        assert result.transition_allowed is True
        assert result.findings == ()


@pytest.mark.parametrize(
    ("profile", "verdict", "allowed"),
    [
        (Profile.OBSERVE, Verdict.PASS, True),
        (Profile.OBSERVE, Verdict.WARN, True),
        (Profile.OBSERVE, Verdict.UNKNOWN, True),
        (Profile.OBSERVE, Verdict.BLOCK, True),
        (Profile.GUARD, Verdict.PASS, True),
        (Profile.GUARD, Verdict.WARN, True),
        (Profile.GUARD, Verdict.UNKNOWN, False),
        (Profile.GUARD, Verdict.BLOCK, False),
        (Profile.STRICT, Verdict.PASS, True),
        (Profile.STRICT, Verdict.WARN, False),
        (Profile.STRICT, Verdict.UNKNOWN, False),
        (Profile.STRICT, Verdict.BLOCK, False),
    ],
)
def test_profile_decision_table(
    profile: Profile, verdict: Verdict, allowed: bool
) -> None:
    result = evaluate(EvaluationCase(profile, (finding(verdict),)))
    assert result.verdict is verdict
    assert result.transition_allowed is allowed


@pytest.mark.parametrize("profile", list(Profile))
def test_integrity_failure_refuses_under_every_profile(profile: Profile) -> None:
    result = evaluate(
        EvaluationCase(
            profile,
            (finding(Verdict.WARN, integrity_failure=True),),
        )
    )

    assert result.verdict is Verdict.WARN
    assert result.transition_allowed is False


def test_finding_order_does_not_change_evaluation_or_canonical_output() -> None:
    findings = (
        finding(Verdict.BLOCK, code="zeta"),
        finding(Verdict.WARN, code="alpha"),
        finding(Verdict.UNKNOWN, code="middle"),
    )
    expected = evaluate(EvaluationCase(Profile.GUARD, findings))
    expected_bytes = canonical_bytes(evaluation_result_payload(expected))

    for ordered in permutations(findings):
        result = evaluate(EvaluationCase(Profile.GUARD, ordered))
        assert result == expected
        assert canonical_bytes(evaluation_result_payload(result)) == expected_bytes


def test_highest_ranked_finding_controls_verdict() -> None:
    result = evaluate(
        EvaluationCase(
            Profile.OBSERVE,
            (
                finding(Verdict.WARN, code="warning"),
                finding(Verdict.BLOCK, code="blocking"),
                finding(Verdict.UNKNOWN, code="unknown"),
            ),
        )
    )

    assert result.verdict is Verdict.BLOCK
    assert [item.verdict for item in result.findings] == [
        Verdict.WARN,
        Verdict.UNKNOWN,
        Verdict.BLOCK,
    ]


def test_total_finding_sort_is_invariant_when_primary_fields_tie() -> None:
    tied = (
        finding(
            Verdict.WARN,
            message_id="acg.example.zeta",
            parameters={"value": 2},
        ),
        finding(
            Verdict.WARN,
            message_id="acg.example.alpha",
            parameters={"value": 2},
        ),
        finding(
            Verdict.WARN,
            message_id="acg.example.alpha",
            parameters={"value": 1},
            integrity_failure=True,
        ),
    )
    expected: bytes | None = None
    for ordered in permutations(tied):
        result = evaluate(EvaluationCase(Profile.OBSERVE, ordered))
        encoded = canonical_bytes(evaluation_result_payload(result))
        if expected is None:
            expected = encoded
        assert encoded == expected


def test_finding_defensively_freezes_nested_parameters() -> None:
    original: dict[str, object] = {
        "outer": {"items": ["first"]},
        "top": "original",
    }
    value = finding(Verdict.WARN, parameters=original)
    before = canonical_bytes(evaluation_result_payload(evaluate(
        EvaluationCase(Profile.GUARD, (value,))
    )))

    original["top"] = "mutated"
    nested_original = original["outer"]
    assert isinstance(nested_original, dict)
    nested_original["items"] = ["changed"]
    exposed = value.parameters
    exposed["top"] = "mutated-copy"
    nested_exposed = exposed["outer"]
    assert isinstance(nested_exposed, dict)
    nested_exposed["items"] = ["changed-copy"]

    after = canonical_bytes(evaluation_result_payload(evaluate(
        EvaluationCase(Profile.GUARD, (value,))
    )))
    assert after == before
    assert value.parameters == {
        "outer": {"items": ["first"]},
        "top": "original",
    }


def test_evaluation_frozen_records_reject_mutable_or_untyped_containers() -> None:
    value = finding(Verdict.WARN)
    with pytest.raises(CanonicalJSONError):
        EvaluationCase(Profile.GUARD, [value])  # type: ignore[arg-type]
    with pytest.raises(CanonicalJSONError):
        EvaluationCase("guard", (value,))  # type: ignore[arg-type]
    with pytest.raises(CanonicalJSONError):
        EvaluationResult(Verdict.WARN, True, [value])  # type: ignore[arg-type]
