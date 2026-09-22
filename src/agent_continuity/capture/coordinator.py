"""Capture comparison translated into pure kernel findings."""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from agent_continuity.kernel.canonical import digest_bytes
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
    CaptureRequestError,
    CaptureSnapshot,
    CaptureUnknownError,
    TargetAdapter,
    _LiveCapture,
)


class _LiveTargetAdapter(Protocol):
    def _capture_live(
        self, required_paths: Sequence[PathIdentityV1]
    ) -> _LiveCapture: ...


def _target_projection_matches(
    candidate: CaptureSnapshot,
    live: CaptureSnapshot,
) -> bool:
    """Compare all target fields that share a representation across capture modes."""

    expected = candidate.target
    observed = live.target
    shared = (
        "adapter_id",
        "adapter_version",
        "sanitized_remote_identity_digest",
        "head_oid",
        "tree_oid",
        "index_manifest_digest",
        "ignore_provenance_digest",
        "platform_id",
        "filesystem_id",
        "physical_root_fingerprint",
    )
    return (
        all(getattr(expected, field) == getattr(observed, field) for field in shared)
        and candidate.instructions == live.instructions
        and candidate.target_policy_digest == live.target_policy_digest
    )


@dataclass(frozen=True, slots=True)
class _ResumeCapture:
    view: CapturedView
    checkpoint_snapshot: CaptureSnapshot | None
    citation_contents: Mapping[PathIdentityV1, bytes]
    missing_citation_paths: frozenset[PathIdentityV1]
    observation_incomplete: bool = False


def _discard_materialization_root(root: Path) -> None:
    """Remove an unreturned capture root before ownership can be lost."""

    cleanup_error: OSError | None = None
    for _attempt in range(2):
        try:
            shutil.rmtree(root)
        except OSError as error:
            cleanup_error = error
            continue
        if not root.exists():
            return
    if root.exists():
        raise CaptureUnknownError("ephemeral capture cleanup failed") from cleanup_error


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

    def capture_for_resume(
        self,
        *,
        instruction_paths: Sequence[PathIdentityV1],
        citation_paths: Sequence[PathIdentityV1],
    ) -> _ResumeCapture:
        """Capture one stable census while keeping path roles separate."""

        instructions = tuple(instruction_paths)
        citations = tuple(citation_paths)
        instruction_raw = tuple(item.raw_bytes() for item in instructions)
        citation_raw = tuple(item.raw_bytes() for item in citations)
        if len(set(instruction_raw)) != len(instruction_raw):
            raise CaptureUnknownError("instruction paths must be unique")
        if len(set(citation_raw)) != len(citation_raw):
            raise CaptureUnknownError("citation paths must be unique")
        live_method = getattr(self._adapter, "_capture_live", None)
        if not callable(live_method):
            self._adapter.capture(instruction_raw)
            raise CaptureUnknownError(
                "target adapter cannot promote a stable resume view"
            )
        live_adapter = cast(_LiveTargetAdapter, self._adapter)
        for attempt in range(2):
            try:
                census = live_adapter._capture_live(())
                census_by_raw = {path.raw_bytes(): path for path in census.files}
                requested = tuple(
                    census_by_raw[raw]
                    for raw in dict.fromkeys((*instruction_raw, *citation_raw))
                    if raw in census_by_raw
                )
                first = live_adapter._capture_live(requested)
                second = live_adapter._capture_live(requested)
            except (CaptureUnknownError, CaptureRequestError):
                if attempt == 0:
                    continue
                raise CaptureUnknownError(
                    "target remained unstable after one retry"
                ) from None

            first_by_raw = {path.raw_bytes(): path for path in first.files}
            second_by_raw = {path.raw_bytes(): path for path in second.files}
            stable = (
                census.snapshot.target
                == first.snapshot.target
                == second.snapshot.target
                and census.snapshot.target_policy_digest
                == first.snapshot.target_policy_digest
                == second.snapshot.target_policy_digest
                and census.files == first.files == second.files
                and all(
                    first.required_contents.get(first_by_raw[raw])
                    == second.required_contents.get(second_by_raw[raw])
                    for raw in (*instruction_raw, *citation_raw)
                    if raw in first_by_raw and raw in second_by_raw
                )
                and all(
                    (raw in census_by_raw)
                    == (raw in first_by_raw)
                    == (raw in second_by_raw)
                    for raw in (*instruction_raw, *citation_raw)
                )
            )
            if not stable:
                if attempt == 0:
                    continue
                break

            instruction_by_raw = {
                item.path.raw_bytes(): item for item in second.snapshot.instructions
            }
            projected_instructions = tuple(
                instruction_by_raw[raw]
                for raw in instruction_raw
                if raw in instruction_by_raw
            )
            contents: dict[PathIdentityV1, bytes] = {}
            missing: set[PathIdentityV1] = set()
            for citation, raw in zip(citations, citation_raw, strict=True):
                observed = second_by_raw.get(raw)
                if observed is None:
                    missing.add(citation)
                    continue
                content = second.required_contents.get(observed)
                observation = second.files.get(observed)
                if (
                    content is None
                    or observation is None
                    or digest_bytes(content) != observation.content_digest
                ):
                    stable = False
                    break
                contents[citation] = content
            if not stable:
                if attempt == 0:
                    continue
                break

            retained = {
                second_by_raw[raw]: second.required_contents[second_by_raw[raw]]
                for raw in dict.fromkeys((*instruction_raw, *citation_raw))
                if raw in second_by_raw
                and second_by_raw[raw] in second.required_contents
            }
            projected = _LiveCapture(
                snapshot=CaptureSnapshot(
                    target=second.snapshot.target,
                    instructions=projected_instructions,
                    target_policy_digest=second.snapshot.target_policy_digest,
                ),
                files=second.files,
                required_contents=MappingProxyType(retained),
            )
            checkpoint_snapshot: CaptureSnapshot | None = None
            instructions_complete = all(raw in second_by_raw for raw in instruction_raw)
            if instructions_complete:
                try:
                    candidate = self._adapter.capture(instruction_raw)
                except (CaptureUnknownError, CaptureRequestError):
                    if citations:
                        return _ResumeCapture(
                            view=CapturedView(
                                snapshot=projected.snapshot,
                                files=projected.files,
                                ephemeral_root=self._materialize(projected),
                            ),
                            checkpoint_snapshot=None,
                            citation_contents=MappingProxyType(contents),
                            missing_citation_paths=frozenset(missing),
                            observation_incomplete=True,
                        )
                    if attempt == 0:
                        continue
                    break
                common_identity_matches = _target_projection_matches(
                    candidate,
                    projected.snapshot,
                )
                if not common_identity_matches:
                    if attempt == 0:
                        continue
                    break
                checkpoint_snapshot = candidate
            return _ResumeCapture(
                view=CapturedView(
                    snapshot=projected.snapshot,
                    files=projected.files,
                    ephemeral_root=self._materialize(projected),
                ),
                checkpoint_snapshot=checkpoint_snapshot,
                citation_contents=MappingProxyType(contents),
                missing_citation_paths=frozenset(missing),
            )
        raise CaptureUnknownError("target remained unstable after one retry")

    def _materialize(self, captured: _LiveCapture) -> Path | None:
        if not captured.required_contents:
            return None
        root: Path | None = None
        root_fd = -1
        try:
            root = Path(tempfile.mkdtemp(prefix="acg-capture-"))
            target_root = getattr(self._adapter, "root", None)
            if isinstance(target_root, Path) and root.is_relative_to(target_root):
                raise CaptureUnknownError("ephemeral capture root overlaps target")
            root_fd = os.open(root, os.O_RDONLY)
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
            os.close(root_fd)
            root_fd = -1
            return root
        except CaptureUnknownError:
            if root is not None:
                _discard_materialization_root(root)
            raise
        except OSError as error:
            if root is not None:
                with contextlib.suppress(CaptureUnknownError):
                    _discard_materialization_root(root)
            raise CaptureUnknownError(
                "ephemeral capture could not be materialized"
            ) from error
        except BaseException:
            if root is not None:
                _discard_materialization_root(root)
            raise
        finally:
            if root_fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(root_fd)


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
