"""Capture comparison translated into pure kernel findings."""

from __future__ import annotations

from agent_continuity.kernel.evaluation import EvaluationCase, Profile, Verdict
from agent_continuity.kernel.findings import Finding

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

