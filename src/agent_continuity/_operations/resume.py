"""Private one-connection, read-only verified resume operation."""

from __future__ import annotations

import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from agent_continuity.capture import (
    CaptureRequestError,
    CaptureUnknownError,
    TargetIdentityV1,
)
from agent_continuity.capture.coordinator import CaptureCoordinator
from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_loads,
    digest_bytes,
)
from agent_continuity.kernel.capabilities import CapabilityClaimV1, CapabilityStatus
from agent_continuity.kernel.citation import CitationV1
from agent_continuity.kernel.evaluation import EvaluationCase, Verdict, evaluate
from agent_continuity.kernel.evidence import (
    EvidenceAuthority,
    EvidenceV1,
    InvalidatorKind,
)
from agent_continuity.kernel.findings import Finding, findings_from_invalidations
from agent_continuity.kernel.invalidation import (
    CitationObservation,
    EvidenceState,
    Invalidation,
    InvalidationContext,
    evaluate_invalidations,
)
from agent_continuity.kernel.model import Digest, JsonObject, LogicalTime, RecordId
from agent_continuity.kernel.paths import PathIdentityV1
from agent_continuity.kernel.records import (
    CheckpointV1,
    make_record,
    require_digest,
)
from agent_continuity.kernel.resume import ResumeContext, build_resume_context
from agent_continuity.policy import (
    LoadedPolicy,
    PolicyError,
    apply_facade_overrides,
    load_policy,
    load_target_policy,
)
from agent_continuity.store import StoreIntegrityError

from .session import (
    _ContinuityRuntime,
    checkpoint_lineage_ids,
    load_actor_producer_ids,
    load_citation_records,
    load_evidence_graph,
    load_goal_record,
    load_initialization_ruleset,
    load_instruction_paths,
    open_session_store,
    select_checkpoint,
)


def _payload_string(payload: JsonObject, field: str) -> str:
    value = payload.get(field)
    if type(value) is not str:
        raise StoreIntegrityError("target identity record is invalid")
    return value


def _load_target_identity(
    store: object, record_id: RecordId
) -> TargetIdentityV1 | None:
    try:
        stored = store.load_record(record_id)  # type: ignore[attr-defined]
    except (KeyError, StoreIntegrityError):
        return None
    try:
        if stored.record_type != "TargetIdentity" or stored.schema_version != "v1":
            raise StoreIntegrityError("target identity record is invalid")
        payload = canonical_loads(stored.canonical_bytes)
        fields = {
            "adapter_id",
            "adapter_version",
            "capabilities",
            "filesystem_id",
            "git_object_manifest_digest",
            "head_oid",
            "ignore_provenance_digest",
            "index_manifest_digest",
            "inventory_digest",
            "physical_root_fingerprint",
            "platform_id",
            "sanitized_remote_identity_digest",
            "status_digest",
            "tree_oid",
            "worktree_manifest_digest",
        }
        if set(payload) != fields:
            raise StoreIntegrityError("target identity record is invalid")
        raw_capabilities = payload["capabilities"]
        if type(raw_capabilities) is not dict:
            raise StoreIntegrityError("target identity record is invalid")
        capabilities = tuple(
            CapabilityClaimV1(
                name=name,
                status=cast(CapabilityStatus, _payload_string(value, "status")),
                adapter_id=_payload_string(value, "adapter_id"),
                adapter_version=_payload_string(value, "adapter_version"),
                evidence_digest=(
                    None
                    if value.get("evidence_digest") is None
                    else Digest(_payload_string(value, "evidence_digest"))
                ),
            )
            for name, value in sorted(raw_capabilities.items())
            if type(name) is str and type(value) is dict
        )
        if len(capabilities) != len(raw_capabilities):
            raise StoreIntegrityError("target identity record is invalid")
        remote = payload["sanitized_remote_identity_digest"]
        target = TargetIdentityV1(
            adapter_id=_payload_string(payload, "adapter_id"),
            adapter_version=_payload_string(payload, "adapter_version"),
            sanitized_remote_identity_digest=(
                None
                if remote is None
                else Digest(
                    _payload_string(payload, "sanitized_remote_identity_digest")
                )
            ),
            head_oid=_payload_string(payload, "head_oid"),
            tree_oid=_payload_string(payload, "tree_oid"),
            index_manifest_digest=Digest(
                _payload_string(payload, "index_manifest_digest")
            ),
            worktree_manifest_digest=Digest(
                _payload_string(payload, "worktree_manifest_digest")
            ),
            inventory_digest=Digest(_payload_string(payload, "inventory_digest")),
            status_digest=Digest(_payload_string(payload, "status_digest")),
            git_object_manifest_digest=Digest(
                _payload_string(payload, "git_object_manifest_digest")
            ),
            ignore_provenance_digest=Digest(
                _payload_string(payload, "ignore_provenance_digest")
            ),
            platform_id=_payload_string(payload, "platform_id"),
            filesystem_id=_payload_string(payload, "filesystem_id"),
            physical_root_fingerprint=Digest(
                _payload_string(payload, "physical_root_fingerprint")
            ),
            capabilities=capabilities,
        )
        if (
            stored.record_id != record_id
            or make_record("TargetIdentity", payload) != stored
            or target.record() != stored
        ):
            raise StoreIntegrityError("target identity record is invalid")
        return target
    except StoreIntegrityError:
        raise
    except (CanonicalJSONError, KeyError, TypeError, ValueError) as error:
        raise StoreIntegrityError("target identity record is invalid") from error


def _continuity_request_error() -> type[Exception]:
    from agent_continuity.api import ContinuityRequestError

    return ContinuityRequestError


def _validate_selector(checkpoint: str) -> None:
    valid = type(checkpoint) is str and checkpoint == "latest"
    if type(checkpoint) is str and checkpoint != "latest":
        try:
            require_digest(checkpoint)
        except (TypeError, ValueError):
            valid = False
        else:
            valid = True
    if not valid:
        raise _continuity_request_error()("checkpoint selection is invalid") from None


def _resume_finding(code: str, checkpoint: CheckpointV1) -> Finding:
    return Finding(
        code=code,
        verdict=Verdict.BLOCK,
        subject_id=checkpoint.checkpoint_id,
        message_id=f"acg.{code}",
        parameters={},
        integrity_failure=True,
    )


def _citation_observations(
    citations: Mapping[RecordId, CitationV1],
    contents: Mapping[PathIdentityV1, bytes],
    missing: frozenset[PathIdentityV1],
) -> dict[RecordId, CitationObservation]:
    content_by_raw = {path.raw_bytes(): value for path, value in contents.items()}
    missing_raw = frozenset(path.raw_bytes() for path in missing)
    observations: dict[RecordId, CitationObservation] = {}
    for citation_id, citation in citations.items():
        raw = citation.path.raw_bytes()
        if raw in missing_raw:
            observations[citation_id] = CitationObservation(
                citation_id=citation_id,
                available=False,
                stable=True,
                file_digest=None,
                span_digest=None,
                unknown_code="citation.path_missing",
            )
            continue
        content = content_by_raw.get(raw)
        if content is None:
            observations[citation_id] = CitationObservation(
                citation_id=citation_id,
                available=False,
                stable=False,
                file_digest=None,
                span_digest=None,
                unknown_code="evidence.observation_unavailable",
            )
            continue
        span_digest = None
        if citation.byte_start is not None and citation.byte_end is not None:
            if citation.byte_end > len(content):
                observations[citation_id] = CitationObservation(
                    citation_id=citation_id,
                    available=False,
                    stable=True,
                    file_digest=None,
                    span_digest=None,
                    unknown_code="evidence.observation_unavailable",
                )
                continue
            span_digest = digest_bytes(content[citation.byte_start : citation.byte_end])
        observations[citation_id] = CitationObservation(
            citation_id=citation_id,
            available=True,
            stable=True,
            file_digest=digest_bytes(content),
            span_digest=span_digest,
            unknown_code=None,
        )
    return observations


def _bind_citations_and_propagate(
    evidence: Mapping[RecordId, EvidenceV1],
    citations: Mapping[RecordId, CitationV1],
    evaluated: tuple[Invalidation, ...],
) -> tuple[Invalidation, ...]:
    values = {item.evidence_id: item for item in evaluated}
    for evidence_id in sorted(evidence):
        record = evidence[evidence_id]
        for invalidator in record.invalidators:
            if (
                not invalidator.required
                or invalidator.kind is not InvalidatorKind.CITATION
            ):
                continue
            citation = citations[invalidator.subject_id]
            expected = (
                citation.span_digest
                if citation.span_digest is not None
                else citation.file_digest
            )
            if record.subject_digest != expected:
                values[evidence_id] = Invalidation(
                    evidence_id,
                    EvidenceState.INVALIDATED,
                    (
                        "citation.span_changed"
                        if citation.span_digest is not None
                        else "citation.file_changed"
                    ),
                    (invalidator.subject_id,),
                    (evidence_id,),
                )
                break
    for _attempt in range(len(evidence)):
        changed = False
        for evidence_id in sorted(evidence):
            if values[evidence_id].state is EvidenceState.INVALIDATED:
                continue
            dependencies = tuple(
                invalidator.subject_id
                for invalidator in evidence[evidence_id].invalidators
                if invalidator.required
                and invalidator.kind is InvalidatorKind.EVIDENCE_DEPENDENCY
                and invalidator.subject_id in values
                and values[invalidator.subject_id].state is EvidenceState.INVALIDATED
            )
            if not dependencies:
                continue
            paths = tuple(
                (
                    evidence_id,
                    *values[dependency_id].transitive_path,
                )
                for dependency_id in dependencies
            )
            replacement = Invalidation(
                evidence_id,
                EvidenceState.INVALIDATED,
                "evidence.dependency_invalid",
                dependencies,
                min(paths),
            )
            if replacement != values[evidence_id]:
                values[evidence_id] = replacement
                changed = True
        if not changed:
            break
    return tuple(values[evidence_id] for evidence_id in sorted(values))


def _evidence_dependencies(record: EvidenceV1) -> tuple[RecordId, ...]:
    return tuple(
        invalidator.subject_id
        for invalidator in record.invalidators
        if invalidator.required
        and invalidator.kind is InvalidatorKind.EVIDENCE_DEPENDENCY
    )


def _dependency_cycles(
    evidence: Mapping[RecordId, EvidenceV1],
) -> tuple[tuple[RecordId, ...], ...]:
    adjacency = {
        evidence_id: tuple(
            dependency_id
            for dependency_id in _evidence_dependencies(record)
            if dependency_id in evidence
        )
        for evidence_id, record in evidence.items()
    }
    cyclic: list[tuple[RecordId, ...]] = []
    for evidence_id in sorted(evidence):
        reachable = {evidence_id}
        frontier = [evidence_id]
        while frontier:
            current = frontier.pop()
            for dependency_id in adjacency[current]:
                if dependency_id not in reachable:
                    reachable.add(dependency_id)
                    frontier.append(dependency_id)
        component = tuple(
            candidate
            for candidate in sorted(reachable)
            if evidence_id in _reachable_evidence(candidate, adjacency)
        )
        if (
            len(component) > 1 or evidence_id in adjacency[evidence_id]
        ) and component not in cyclic:
            cyclic.append(component)
    return tuple(cyclic)


def _reachable_evidence(
    start: RecordId,
    adjacency: Mapping[RecordId, tuple[RecordId, ...]],
) -> frozenset[RecordId]:
    reached = {start}
    frontier = [start]
    while frontier:
        current = frontier.pop()
        for dependency_id in adjacency[current]:
            if dependency_id not in reached:
                reached.add(dependency_id)
                frontier.append(dependency_id)
    return frozenset(reached)


def _propagate_evidence_dependencies(
    evidence: Mapping[RecordId, EvidenceV1],
    direct: Mapping[RecordId, Invalidation],
) -> tuple[Invalidation, ...]:
    """Propagate direct outcomes without re-evaluating another record's basis."""

    values = dict(direct)
    cyclic: set[RecordId] = set()
    for component in _dependency_cycles(evidence):
        member_ids = frozenset(component)
        cyclic.update(component)
        for evidence_id in component:
            causes = tuple(
                sorted(
                    dependency_id
                    for dependency_id in _evidence_dependencies(evidence[evidence_id])
                    if dependency_id in member_ids
                )
            )
            values[evidence_id] = Invalidation(
                evidence_id,
                EvidenceState.UNKNOWN,
                "evidence.dependency_cycle",
                causes,
                (
                    evidence_id,
                    *(item for item in component if item != evidence_id),
                ),
            )
    for _attempt in range(len(evidence)):
        changed = False
        for evidence_id in sorted(evidence):
            if evidence_id in cyclic:
                continue
            current = values[evidence_id]
            if current.state is EvidenceState.INVALIDATED:
                continue
            dependencies = _evidence_dependencies(evidence[evidence_id])
            invalid = tuple(
                dependency_id
                for dependency_id in dependencies
                if dependency_id in values
                and values[dependency_id].state is EvidenceState.INVALIDATED
            )
            unknown = tuple(
                dependency_id
                for dependency_id in dependencies
                if dependency_id not in values
                or values[dependency_id].state is EvidenceState.UNKNOWN
                or evidence[dependency_id].authority is EvidenceAuthority.ADVISORY
            )
            replacement: Invalidation | None = None
            if invalid:
                paths = tuple(
                    (
                        evidence_id,
                        *(values[dependency_id].transitive_path or (dependency_id,)),
                    )
                    for dependency_id in invalid
                )
                replacement = Invalidation(
                    evidence_id,
                    EvidenceState.INVALIDATED,
                    "evidence.dependency_invalid",
                    invalid,
                    min(paths),
                )
            elif current.state is EvidenceState.UNKNOWN:
                continue
            elif unknown:
                paths = tuple(
                    (
                        evidence_id,
                        *(
                            values[dependency_id].transitive_path
                            if dependency_id in values
                            else (dependency_id,)
                        ),
                    )
                    for dependency_id in unknown
                )
                replacement = Invalidation(
                    evidence_id,
                    EvidenceState.UNKNOWN,
                    "evidence.dependency_unknown",
                    unknown,
                    min(paths),
                )
            if replacement is not None and replacement != current:
                values[evidence_id] = replacement
                changed = True
        if not changed:
            break
    return tuple(values[evidence_id] for evidence_id in sorted(values))


def _evaluate_evidence(
    *,
    logical_time: LogicalTime,
    evidence: Mapping[RecordId, EvidenceV1],
    checkpoint_lineage: frozenset[RecordId],
    selected_checkpoint_id: RecordId,
    target: TargetIdentityV1,
    producer_ids: frozenset[RecordId],
    citations: Mapping[RecordId, CitationObservation],
) -> tuple[Invalidation, ...]:
    if not evidence:
        return ()
    direct: dict[RecordId, Invalidation] = {}
    for evidence_id in sorted(evidence):
        record = evidence[evidence_id]
        basis = (
            record.checkpoint_id
            if record.checkpoint_id in checkpoint_lineage
            else selected_checkpoint_id
        )
        context = InvalidationContext(
            logical_time=logical_time,
            target=target,
            checkpoint_id=basis,
            producer_ids=producer_ids,
            citations=citations,
        )
        outcome = evaluate_invalidations({evidence_id: record}, context)[0]
        dependencies = _evidence_dependencies(record)
        if outcome.code == "evidence.dependency_unknown" and all(
            dependency_id in evidence for dependency_id in dependencies
        ):
            outcome = Invalidation(evidence_id, EvidenceState.CURRENT, "", (), ())
        direct[evidence_id] = outcome
    return _propagate_evidence_dependencies(evidence, direct)


def _cleanup_capture_root(root: Path) -> None:
    failed = False
    for _attempt in range(2):
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
            continue
        break
    if root.exists() or failed:
        raise CaptureUnknownError("capture cleanup failed")


def _observe_current_policy(runtime: _ContinuityRuntime) -> LoadedPolicy | None:
    try:
        if runtime.policy_path is None:
            from agent_continuity.capture import GitTargetAdapter

            with GitTargetAdapter(runtime.target) as admitted_adapter:
                loaded = load_target_policy(admitted_adapter.read_target_policy())
        else:
            loaded = load_policy(
                target=runtime.target,
                explicit=runtime.policy_path,
            )
        return apply_facade_overrides(
            loaded,
            profile=runtime.profile_override,
            promotion_mode=runtime.promotion_mode_override,
        )
    except (PolicyError, CaptureRequestError, CaptureUnknownError):
        return None


def resume(runtime: _ContinuityRuntime, checkpoint: str = "latest") -> ResumeContext:
    """Return a verified compact context without mutating target or state."""

    _validate_selector(checkpoint)
    ephemeral_root = None
    with open_session_store(runtime, read_only=True) as store:
        with store._read_snapshot():
            audit = store.verify_audit()
            if not audit.valid:
                raise StoreIntegrityError("StateStore audit verification failed")
            current_head = store.read_head(runtime.head_name)
            if current_head is None:
                raise _continuity_request_error()(
                    "continuity session is unavailable"
                ) from None
            selected = select_checkpoint(
                store,
                head_name=runtime.head_name,
                selector=checkpoint,
            )
            if selected is None:
                raise _continuity_request_error()("checkpoint is unavailable") from None
            goal = load_goal_record(store, selected.goal_id)
            initialization_intent = load_initialization_ruleset(
                store, selected.initialization_intent_id
            )
            stored_target = _load_target_identity(store, selected.target_id)
            producer_ids = load_actor_producer_ids(store, selected.actor_ids)
            evidence = load_evidence_graph(store, selected.evidence_ids)
            citations = load_citation_records(store, evidence)
            lineage = checkpoint_lineage_ids(store, selected)
            instruction_bytes = load_instruction_paths(store, selected.instruction_id)
        instruction_paths = tuple(
            PathIdentityV1.from_bytes("git-path-bytes", value)
            for value in instruction_bytes
        )
        findings: list[Finding] = []
        current_policy = _observe_current_policy(runtime)
        if selected.checkpoint_id != current_head.record_id:
            findings.append(_resume_finding("resume.checkpoint_stale", selected))
        if (
            current_policy is None
            or current_policy.compiled.policy_id != selected.policy_id
        ):
            findings.append(_resume_finding("resume.policy_changed", selected))
        if initialization_intent.ruleset_id != selected.ruleset_id:
            findings.append(_resume_finding("resume.ruleset_changed", selected))
        evaluation_profile = (
            runtime.loaded_policy.compiled.profile
            if current_policy is None
            else current_policy.compiled.profile
        )
        citation_paths_by_raw = {
            citation.path.raw_bytes(): citation.path for citation in citations.values()
        }
        invalidations: tuple[Invalidation, ...] = ()
        try:
            captured = CaptureCoordinator(runtime.target_adapter).capture_for_resume(
                instruction_paths=instruction_paths,
                citation_paths=tuple(
                    citation_paths_by_raw[key] for key in sorted(citation_paths_by_raw)
                ),
            )
            captured_policy = _observe_current_policy(runtime)
            if (
                captured_policy is None
                or captured_policy.compiled.policy_id != selected.policy_id
            ) and all(item.code != "resume.policy_changed" for item in findings):
                findings.append(_resume_finding("resume.policy_changed", selected))
            ephemeral_root = captured.view.ephemeral_root
            snapshot = captured.view.snapshot
            checkpoint_snapshot = captured.checkpoint_snapshot
            target_changed = (
                checkpoint_snapshot.target.record().record_id != selected.target_id
                if checkpoint_snapshot is not None
                else any(path not in captured.view.files for path in instruction_paths)
            )
            if target_changed:
                findings.append(_resume_finding("resume.target_changed", selected))
            if snapshot.instruction_record().record_id != selected.instruction_id:
                findings.append(
                    _resume_finding("resume.instructions_changed", selected)
                )
            citation_observations = _citation_observations(
                citations,
                captured.citation_contents,
                captured.missing_citation_paths,
            )
            logical_time = runtime.clock.now()
            evaluated_invalidations = _evaluate_evidence(
                logical_time=logical_time,
                evidence=evidence,
                checkpoint_lineage=lineage,
                selected_checkpoint_id=selected.checkpoint_id,
                target=(
                    checkpoint_snapshot.target
                    if checkpoint_snapshot is not None
                    else stored_target or snapshot.target
                ),
                producer_ids=producer_ids,
                citations=citation_observations,
            )
            invalidations = _bind_citations_and_propagate(
                evidence,
                citations,
                evaluated_invalidations,
            )
            if captured.observation_incomplete and all(
                item.state is EvidenceState.CURRENT for item in invalidations
            ):
                findings.append(
                    Finding(
                        "evidence.observation_unavailable",
                        Verdict.UNKNOWN,
                        selected.checkpoint_id,
                        "acg.evidence.observation_unavailable",
                        {},
                    )
                )
            evaluation = evaluate(
                EvaluationCase(
                    profile=evaluation_profile,
                    findings=(
                        *findings,
                        *findings_from_invalidations(invalidations),
                    ),
                )
            )
            return build_resume_context(
                selected,
                evaluation,
                goal_digest=goal.digest,
                invalidations=invalidations,
            )
        except (CaptureRequestError, CaptureUnknownError):
            unknown = Finding(
                "evidence.observation_unavailable",
                Verdict.UNKNOWN,
                selected.checkpoint_id,
                "acg.evidence.observation_unavailable",
                {},
            )
            evaluation = evaluate(
                EvaluationCase(
                    profile=evaluation_profile,
                    findings=(*findings, unknown),
                )
            )
            return build_resume_context(
                selected,
                evaluation,
                goal_digest=goal.digest,
                invalidations=(),
            )
        finally:
            if ephemeral_root is not None:
                _cleanup_capture_root(ephemeral_root)
