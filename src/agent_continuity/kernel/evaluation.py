"""Pure deterministic verdict aggregation and profile enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from .model import JsonObject

if TYPE_CHECKING:
    from .findings import Finding


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


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    verdict: Verdict
    transition_allowed: bool
    findings: tuple[Finding, ...]


def evaluate(case: EvaluationCase) -> EvaluationResult:
    findings = tuple(
        sorted(
            case.findings,
            key=lambda item: (
                VERDICT_RANK[item.verdict],
                item.code,
                str(item.subject_id),
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
