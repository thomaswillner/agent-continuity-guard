"""Capture comparison translated into pure kernel findings."""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, cast

from agent_continuity.kernel.evaluation import (
    EvaluationCase,
    EvaluationResult,
    Profile,
    Verdict,
    evaluate,
)
from agent_continuity.kernel.findings import Finding
from agent_continuity.kernel.model import RecordId
from agent_continuity.kernel.paths import PathIdentityV1
from agent_continuity.kernel.records import CheckpointV1

from .base import (
    CapturedView,
    CaptureSnapshot,
    CaptureUnknownError,
    TargetAdapter,
    _LiveCapture,
)


class _LiveTargetAdapter(Protocol):
    def _capture_live(
        self, required_paths: Sequence[PathIdentityV1]
    ) -> _LiveCapture: ...


class CaptureCoordinator:
    """Promote one stable live observation after at most one retry."""

    def __init__(self, adapter: TargetAdapter) -> None:
        self._adapter = adapter

    def capture_stable(
        self,
        required_paths: Sequence[PathIdentityV1] = (),
    ) -> CapturedView:
        required = tuple(required_paths)
        live_method = getattr(self._adapter, "_capture_live", None)
        if not callable(live_method):
            self._adapter.capture(tuple(path.raw_bytes() for path in required))
            raise CaptureUnknownError(
                "target adapter cannot promote a stable live-worktree view"
            )
        live_adapter = cast(_LiveTargetAdapter, self._adapter)
        for attempt in range(2):
            try:
                first = live_adapter._capture_live(required)
                second = live_adapter._capture_live(required)
            except CaptureUnknownError:
                if attempt == 0:
                    continue
                raise
            if first == second:
                ephemeral = self._materialize(second)
                return CapturedView(
                    snapshot=second.snapshot,
                    files=second.files,
                    ephemeral_root=ephemeral,
                )
        raise CaptureUnknownError("target remained unstable after one retry")

    def _materialize(self, captured: _LiveCapture) -> Path | None:
        if not captured.required_contents:
            return None
        root = Path(tempfile.mkdtemp(prefix="acg-capture-"))
        target_root = getattr(self._adapter, "root", None)
        if isinstance(target_root, Path) and root.is_relative_to(target_root):
            shutil.rmtree(root)
            raise CaptureUnknownError("ephemeral capture root overlaps target")
        root_fd = os.open(root, os.O_RDONLY)
        try:
            for path, content in captured.required_contents.items():
                current = os.dup(root_fd)
                components = path.raw_bytes().split(b"/")
                try:
                    for component in components[:-1]:
                        with contextlib.suppress(FileExistsError):
                            os.mkdir(component, 0o700, dir_fd=current)
                        next_descriptor = os.open(
                            component,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY,
                            dir_fd=current,
                        )
                        os.close(current)
                        current = next_descriptor
                    descriptor = os.open(
                        components[-1],
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o400,
                        dir_fd=current,
                    )
                    try:
                        offset = 0
                        while offset < len(content):
                            offset += os.write(descriptor, content[offset:])
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(current)
            os.fsync(root_fd)
        except BaseException:
            shutil.rmtree(root)
            raise
        finally:
            os.close(root_fd)
        return root


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
