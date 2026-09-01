"""Pure deterministic verdict aggregation and profile enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from .canonical import CanonicalJSONError, canonical_bytes
from .model import JsonObject

if TYPE_CHECKING:
    from .findings import Finding
    from .invalidation import EvidenceEvaluationInput


class Verdict(StrEnum):
    PASS = "pass"
    WARN = "warn"
    UNKNOWN = "unknown"
    BLOCK = "block"


VERDICT_RANK = {
    Verdict.PASS: 0,
    Verdict.WARN: 1,
    Verdict.UNKNOWN: 2,
    Verdict.BLOCK: 3,
}


class Profile(StrEnum):
    OBSERVE = "observe"
    GUARD = "guard"
    STRICT = "strict"


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    profile: Profile
    findings: tuple[Finding, ...]
    evidence_input: EvidenceEvaluationInput | None = None

    def __post_init__(self) -> None:
        from .findings import Finding

        if type(self.profile) is not Profile:
            raise CanonicalJSONError("evaluation profile is invalid")
        if type(self.findings) is not tuple or any(
            type(item) is not Finding for item in self.findings
        ):
            raise CanonicalJSONError("evaluation findings must be an immutable tuple")
        if self.evidence_input is not None:
            from .invalidation import EvidenceEvaluationInput

            if type(self.evidence_input) is not EvidenceEvaluationInput:
                raise CanonicalJSONError("evaluation evidence input is invalid")


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    verdict: Verdict
    transition_allowed: bool
    findings: tuple[Finding, ...]

    def __post_init__(self) -> None:
        from .findings import Finding

        if type(self.verdict) is not Verdict:
            raise CanonicalJSONError("evaluation verdict is invalid")
        if type(self.transition_allowed) is not bool:
            raise CanonicalJSONError("transition_allowed must be Boolean")
        if type(self.findings) is not tuple or any(
            type(item) is not Finding for item in self.findings
        ):
            raise CanonicalJSONError("evaluation findings must be an immutable tuple")


def evaluate(case: EvaluationCase) -> EvaluationResult:
    from .findings import finding_payload, findings_from_invalidations
    from .invalidation import evaluate_invalidations

    supplied_findings = case.findings
    if case.evidence_input is not None:
        supplied_findings += findings_from_invalidations(
            evaluate_invalidations(
                case.evidence_input.evidence,
                case.evidence_input.context,
            )
        )
    findings = tuple(
        sorted(
            supplied_findings,
            key=lambda item: (
                VERDICT_RANK[item.verdict],
                canonical_bytes(finding_payload(item)),
            ),
        )
    )
    verdict = max(
        (item.verdict for item in findings),
        key=VERDICT_RANK.__getitem__,
        default=Verdict.PASS,
    )
    if any(item.integrity_failure for item in findings):
        allowed = False
    elif case.profile is Profile.OBSERVE:
        allowed = True
    elif case.profile is Profile.GUARD:
        allowed = verdict in {Verdict.PASS, Verdict.WARN}
    else:
        allowed = verdict is Verdict.PASS
    return EvaluationResult(verdict, allowed, findings)


def evaluation_result_payload(result: EvaluationResult) -> JsonObject:
    from .findings import finding_payload

    return {
        "findings": [finding_payload(item) for item in result.findings],
        "schema": "EvaluationResult/v1",
        "transition_allowed": result.transition_allowed,
        "verdict": result.verdict.value,
    }
