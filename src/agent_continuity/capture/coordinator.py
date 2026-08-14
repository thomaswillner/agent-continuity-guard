"""Capture comparison translated into pure kernel findings."""

from __future__ import annotations

from agent_continuity.kernel.evaluation import (
    EvaluationCase,
    EvaluationResult,
    Profile,
    Verdict,
    evaluate,
)
from agent_continuity.kernel.findings import Finding
from agent_continuity.kernel.model import RecordId
from agent_continuity.kernel.records import CheckpointV1

from .base import CaptureSnapshot


def snapshot_findings(
    snapshot_a: CaptureSnapshot,
    snapshot_b: CaptureSnapshot,
    profile: Profile,
) -> EvaluationCase:
    findings: list[Finding] = []
    subject_id = snapshot_a.target.record().record_id
    if not snapshot_a.target.is_clean or not snapshot_b.target.is_clean:
        findings.append(
            Finding(
                code="target.dirty",
                verdict=Verdict.UNKNOWN,
                subject_id=subject_id,
                message_id="acg.target.dirty",
                parameters={},
            )
        )
    if snapshot_a != snapshot_b:
        findings.append(
            Finding(
                code="capture.unstable",
                verdict=Verdict.UNKNOWN,
                subject_id=subject_id,
                message_id="acg.capture.unstable",
                parameters={},
            )
        )
    return EvaluationCase(profile=profile, findings=tuple(findings))


def evaluate_checkpoint_capture(
    checkpoint: CheckpointV1,
    snapshot_a: CaptureSnapshot,
    snapshot_b: CaptureSnapshot,
    profile: Profile,
    *,
    policy_id: RecordId,
    ruleset_id: RecordId,
) -> EvaluationResult:
    """Evaluate capture stability, cleanliness, and checkpoint identity binding."""

    case = snapshot_findings(snapshot_a, snapshot_b, profile)
    findings = list(case.findings)
    identity_matches = (
        snapshot_a.target.record().record_id == checkpoint.target_id
        and snapshot_a.instruction_record().record_id == checkpoint.instruction_id
        and policy_id == checkpoint.policy_id
        and ruleset_id == checkpoint.ruleset_id
    )
    if not identity_matches and not any(
        finding.code == "capture.unstable" for finding in findings
    ):
        findings.append(
            Finding(
                code="capture.unstable",
                verdict=Verdict.UNKNOWN,
                subject_id=checkpoint.checkpoint_id,
                message_id="acg.capture.unstable",
                parameters={},
            )
        )
    return evaluate(EvaluationCase(profile=profile, findings=tuple(findings)))
