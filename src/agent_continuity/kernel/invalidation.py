"""Pure deterministic direct and transitive Evidence/v1 invalidation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from .canonical import CanonicalJSONError, validate_logical_time
from .evidence import (
    EvidenceAuthority,
    EvidenceCompleteness,
    EvidenceV1,
    InvalidatorKind,
    InvalidatorV1,
)
from .model import Digest, LogicalTime, RecordId, StoredRecord
from .records import (
    make_record,
    producer_identity_payload,
    require_digest,
)

if TYPE_CHECKING:
    class TargetIdentityV1(Protocol):
        """Type-only kernel view of the read-only target identity contract."""

        def record(self) -> StoredRecord: ...


class EvidenceState(StrEnum):
    CURRENT = "current"
    INVALIDATED = "invalidated"
    UNKNOWN = "unknown"


_INVALIDATION_CODES = frozenset(
    {
        "citation.path_missing",
        "citation.file_changed",
        "citation.span_changed",
        "evidence.expired",
        "evidence.target_mismatch",
        "evidence.checkpoint_mismatch",
        "evidence.producer_mismatch",
        "evidence.dependency_invalid",
        "evidence.dependency_unknown",
        "evidence.dependency_cycle",
        "evidence.observation_unavailable",
    }
)


@dataclass(frozen=True, slots=True)
class Invalidation:
    evidence_id: RecordId
    state: EvidenceState
    code: str
    direct_cause_ids: tuple[RecordId, ...]
    transitive_path: tuple[RecordId, ...]

    def __post_init__(self) -> None:
        require_digest(self.evidence_id)
        if type(self.state) is not EvidenceState:
            raise CanonicalJSONError("evidence state is invalid")
        if self.state is EvidenceState.CURRENT:
            if self.code or self.direct_cause_ids or self.transitive_path:
                raise CanonicalJSONError(
                    "current evidence cannot carry invalidation data"
                )
            return
        if self.code not in _INVALIDATION_CODES:
            raise CanonicalJSONError("invalidation code is invalid")
        _require_ids(self.direct_cause_ids, ordered=True, field="direct causes")
        _require_ids(self.transitive_path, ordered=False, field="transitive path")
        if not self.transitive_path or self.transitive_path[0] != self.evidence_id:
            raise CanonicalJSONError("invalidation path must begin at its evidence")


@dataclass(frozen=True, slots=True)
class CitationObservation:
    citation_id: RecordId
    available: bool
    stable: bool
    file_digest: Digest | None
    span_digest: Digest | None
    unknown_code: str | None

    def __post_init__(self) -> None:
        require_digest(self.citation_id)
        if type(self.available) is not bool or type(self.stable) is not bool:
            raise CanonicalJSONError("citation observation flags must be Boolean")
        for value in (self.file_digest, self.span_digest):
            if value is not None:
                require_digest(value)
        if self.unknown_code is not None and (
            type(self.unknown_code) is not str or not self.unknown_code
        ):
            raise CanonicalJSONError("citation unknown code is invalid")


@dataclass(frozen=True, slots=True)
class InvalidationContext:
    logical_time: LogicalTime
    target: TargetIdentityV1
    checkpoint_id: RecordId
    producer_ids: frozenset[RecordId]
    citations: Mapping[RecordId, CitationObservation]

    def __post_init__(self) -> None:
        validate_logical_time(self.logical_time)
        target_record = self.target.record()
        if target_record.record_type != "TargetIdentity":
            raise CanonicalJSONError("invalidation target is invalid")
        require_digest(self.checkpoint_id)
        if type(self.producer_ids) is not frozenset:
            raise CanonicalJSONError("producer identifiers must be a frozenset")
        for producer_id in self.producer_ids:
            require_digest(producer_id)
        if not isinstance(self.citations, Mapping):
            raise CanonicalJSONError("citation observations must be a mapping")
        for citation_id, observation in self.citations.items():
            require_digest(citation_id)
            if type(observation) is not CitationObservation:
                raise CanonicalJSONError("citation observation is invalid")
            if citation_id != observation.citation_id:
                raise CanonicalJSONError(
                    "citation observation identity is inconsistent"
                )


@dataclass(frozen=True, slots=True)
class EvidenceEvaluationInput:
    evidence: Mapping[RecordId, EvidenceV1]
    context: InvalidationContext

    def __post_init__(self) -> None:
        _validate_inputs(self.evidence, self.context)


def _require_ids(
    values: tuple[RecordId, ...],
    *,
    ordered: bool,
    field: str,
) -> None:
    if type(values) is not tuple:
        raise CanonicalJSONError(f"{field} must be an exact tuple")
    if len(values) != len(set(values)):
        raise CanonicalJSONError(f"{field} must be unique")
    if ordered and values != tuple(sorted(values)):
        raise CanonicalJSONError(f"{field} must be sorted")
    for value in values:
        require_digest(value)


def _validate_inputs(
    evidence: Mapping[RecordId, EvidenceV1],
    context: InvalidationContext,
) -> None:
    if not isinstance(evidence, Mapping):
        raise CanonicalJSONError("evidence graph must be a mapping")
    if type(context) is not InvalidationContext:
        raise CanonicalJSONError("invalidation context is invalid")
    for evidence_id, record in evidence.items():
        require_digest(evidence_id)
        if type(record) is not EvidenceV1:
            raise CanonicalJSONError("evidence graph value is invalid")
        if record.evidence_id != evidence_id:
            raise CanonicalJSONError("evidence graph identity is inconsistent")


def _current(evidence_id: RecordId) -> Invalidation:
    return Invalidation(evidence_id, EvidenceState.CURRENT, "", (), ())


def _outcome(
    evidence_id: RecordId,
    state: EvidenceState,
    code: str,
    causes: tuple[RecordId, ...] = (),
    path: tuple[RecordId, ...] | None = None,
) -> Invalidation:
    ordered_causes = tuple(sorted(set(causes)))
    return Invalidation(
        evidence_id,
        state,
        code,
        ordered_causes,
        (evidence_id,) if path is None else path,
    )


def _digests_differ(expected: Digest, observed: Digest) -> bool:
    """Comparison seam used by the planted critical mutation proof."""

    return expected != observed


def _producer_id(record: EvidenceV1) -> RecordId:
    return make_record(
        "ProducerIdentity", producer_identity_payload(record.producer)
    ).record_id


def _citation_outcome(
    record: EvidenceV1,
    invalidator: InvalidatorV1,
    context: InvalidationContext,
) -> Invalidation:
    observation = context.citations.get(invalidator.subject_id)
    if observation is None or not observation.stable:
        return _outcome(
            record.evidence_id,
            EvidenceState.UNKNOWN,
            "evidence.observation_unavailable",
            (invalidator.subject_id,),
        )
    if not observation.available:
        if observation.unknown_code == "citation.path_missing":
            return _outcome(
                record.evidence_id,
                EvidenceState.INVALIDATED,
                "citation.path_missing",
                (invalidator.subject_id,),
            )
        return _outcome(
            record.evidence_id,
            EvidenceState.UNKNOWN,
            "evidence.observation_unavailable",
            (invalidator.subject_id,),
        )
    if observation.unknown_code is not None:
        return _outcome(
            record.evidence_id,
            EvidenceState.UNKNOWN,
            "evidence.observation_unavailable",
            (invalidator.subject_id,),
        )
    if observation.span_digest is not None:
        if _digests_differ(record.subject_digest, observation.span_digest):
            return _outcome(
                record.evidence_id,
                EvidenceState.INVALIDATED,
                "citation.span_changed",
                (invalidator.subject_id,),
            )
        return _current(record.evidence_id)
    if observation.file_digest is None:
        return _outcome(
            record.evidence_id,
            EvidenceState.UNKNOWN,
            "evidence.observation_unavailable",
            (invalidator.subject_id,),
        )
    if _digests_differ(record.subject_digest, observation.file_digest):
        return _outcome(
            record.evidence_id,
            EvidenceState.INVALIDATED,
            "citation.file_changed",
            (invalidator.subject_id,),
        )
    return _current(record.evidence_id)


def _evaluate_direct(
    record: EvidenceV1,
    context: InvalidationContext,
) -> Invalidation:
    if record.completeness is not EvidenceCompleteness.COMPLETE:
        return _outcome(
            record.evidence_id,
            EvidenceState.UNKNOWN,
            "evidence.observation_unavailable",
        )
    if record.expires_at is not None and context.logical_time >= record.expires_at:
        return _outcome(
            record.evidence_id,
            EvidenceState.INVALIDATED,
            "evidence.expired",
        )
    target_id = context.target.record().record_id
    if record.target_id != target_id:
        return _outcome(
            record.evidence_id,
            EvidenceState.INVALIDATED,
            "evidence.target_mismatch",
            (target_id,),
        )
    if record.checkpoint_id != context.checkpoint_id:
        return _outcome(
            record.evidence_id,
            EvidenceState.INVALIDATED,
            "evidence.checkpoint_mismatch",
            (context.checkpoint_id,),
        )
    producer_id = _producer_id(record)
    if producer_id not in context.producer_ids:
        return _outcome(
            record.evidence_id,
            EvidenceState.INVALIDATED,
            "evidence.producer_mismatch",
            (producer_id,),
        )

    observations: list[Invalidation] = []
    for invalidator in record.invalidators:
        if not invalidator.required:
            continue
        if invalidator.kind is InvalidatorKind.CITATION:
            observations.append(_citation_outcome(record, invalidator, context))
        elif invalidator.kind is InvalidatorKind.TARGET:
            if invalidator.subject_id != target_id:
                observations.append(
                    _outcome(
                        record.evidence_id,
                        EvidenceState.INVALIDATED,
                        "evidence.target_mismatch",
                        (invalidator.subject_id,),
                    )
                )
        elif invalidator.kind is InvalidatorKind.CHECKPOINT:
            if invalidator.subject_id != context.checkpoint_id:
                observations.append(
                    _outcome(
                        record.evidence_id,
                        EvidenceState.INVALIDATED,
                        "evidence.checkpoint_mismatch",
                        (invalidator.subject_id,),
                    )
                )
        elif invalidator.kind is InvalidatorKind.PRODUCER:
            if invalidator.subject_id not in context.producer_ids:
                observations.append(
                    _outcome(
                        record.evidence_id,
                        EvidenceState.INVALIDATED,
                        "evidence.producer_mismatch",
                        (invalidator.subject_id,),
                    )
                )
        elif invalidator.kind is InvalidatorKind.POLICY:
            observations.append(
                _outcome(
                    record.evidence_id,
                    EvidenceState.UNKNOWN,
                    "evidence.observation_unavailable",
                    (invalidator.subject_id,),
                )
            )

    invalidated = sorted(
        (item for item in observations if item.state is EvidenceState.INVALIDATED),
        key=lambda item: (item.code, item.direct_cause_ids),
    )
    if invalidated:
        return invalidated[0]
    unknown = sorted(
        (item for item in observations if item.state is EvidenceState.UNKNOWN),
        key=lambda item: (item.code, item.direct_cause_ids),
    )
    return unknown[0] if unknown else _current(record.evidence_id)


def _dependencies(record: EvidenceV1) -> tuple[RecordId, ...]:
    return tuple(
        invalidator.subject_id
        for invalidator in record.invalidators
        if invalidator.required
        and invalidator.kind is InvalidatorKind.EVIDENCE_DEPENDENCY
    )


def _strongly_connected_components(
    evidence: Mapping[RecordId, EvidenceV1],
) -> tuple[tuple[RecordId, ...], ...]:
    nodes = tuple(sorted(evidence))
    adjacency = {
        node: tuple(
            sorted(
                dependency
                for dependency in _dependencies(evidence[node])
                if dependency in evidence
            )
        )
        for node in nodes
    }
    visited: set[RecordId] = set()
    finish_order: list[RecordId] = []
    for root in nodes:
        if root in visited:
            continue
        visited.add(root)
        stack: list[tuple[RecordId, int]] = [(root, 0)]
        while stack:
            node, index = stack[-1]
            neighbours = adjacency[node]
            if index < len(neighbours):
                neighbour = neighbours[index]
                stack[-1] = (node, index + 1)
                if neighbour not in visited:
                    visited.add(neighbour)
                    stack.append((neighbour, 0))
            else:
                finish_order.append(node)
                stack.pop()

    reverse: dict[RecordId, list[RecordId]] = {node: [] for node in nodes}
    for node, dependencies in adjacency.items():
        for dependency in dependencies:
            reverse[dependency].append(node)
    components: list[tuple[RecordId, ...]] = []
    assigned: set[RecordId] = set()
    for root in reversed(finish_order):
        if root in assigned:
            continue
        assigned.add(root)
        members: list[RecordId] = []
        component_stack = [root]
        while component_stack:
            node = component_stack.pop()
            members.append(node)
            for neighbour in reversed(sorted(reverse[node])):
                if neighbour not in assigned:
                    assigned.add(neighbour)
                    component_stack.append(neighbour)
        components.append(tuple(sorted(members)))
    return tuple(sorted(components))


def _mark_cycles_unknown(
    evidence: Mapping[RecordId, EvidenceV1],
    direct: dict[RecordId, Invalidation],
    components: tuple[tuple[RecordId, ...], ...],
) -> frozenset[RecordId]:
    cyclic: set[RecordId] = set()
    for component in components:
        is_cycle = len(component) > 1 or component[0] in _dependencies(
            evidence[component[0]]
        )
        if not is_cycle:
            continue
        member_set = frozenset(component)
        cyclic.update(component)
        for evidence_id in component:
            causes = tuple(
                dependency
                for dependency in _dependencies(evidence[evidence_id])
                if dependency in member_set
            )
            direct[evidence_id] = _outcome(
                evidence_id,
                EvidenceState.UNKNOWN,
                "evidence.dependency_cycle",
                causes,
                (evidence_id, *(item for item in component if item != evidence_id)),
            )
    return frozenset(cyclic)


def _dependency_path(
    evidence_id: RecordId,
    dependency_id: RecordId,
    dependency: Invalidation | None,
) -> tuple[RecordId, ...]:
    if dependency is None or not dependency.transitive_path:
        return (evidence_id, dependency_id)
    return (evidence_id, *dependency.transitive_path)


def _propagate_to_fixed_point(
    evidence: Mapping[RecordId, EvidenceV1],
    direct: dict[RecordId, Invalidation],
    cyclic: frozenset[RecordId],
) -> tuple[Invalidation, ...]:
    values = dict(direct)
    for _attempt in range(len(evidence)):
        updated = dict(values)
        changed = False
        for evidence_id in sorted(evidence):
            if evidence_id in cyclic:
                continue
            current = values[evidence_id]
            if current.state is EvidenceState.INVALIDATED:
                continue
            invalid_dependencies: list[RecordId] = []
            unknown_dependencies: list[RecordId] = []
            for dependency_id in _dependencies(evidence[evidence_id]):
                dependency = values.get(dependency_id)
                dependency_record = evidence.get(dependency_id)
                if (
                    dependency is not None
                    and dependency.state is EvidenceState.INVALIDATED
                ):
                    invalid_dependencies.append(dependency_id)
                elif (
                    dependency is None
                    or dependency.state is EvidenceState.UNKNOWN
                    or dependency_record is None
                    or dependency_record.authority is EvidenceAuthority.ADVISORY
                ):
                    unknown_dependencies.append(dependency_id)
            if invalid_dependencies:
                paths = tuple(
                    _dependency_path(
                        evidence_id,
                        dependency_id,
                        values.get(dependency_id),
                    )
                    for dependency_id in invalid_dependencies
                )
                replacement = _outcome(
                    evidence_id,
                    EvidenceState.INVALIDATED,
                    "evidence.dependency_invalid",
                    tuple(invalid_dependencies),
                    min(paths),
                )
            elif current.state is EvidenceState.UNKNOWN:
                continue
            elif unknown_dependencies:
                paths = tuple(
                    _dependency_path(
                        evidence_id,
                        dependency_id,
                        values.get(dependency_id),
                    )
                    for dependency_id in unknown_dependencies
                )
                replacement = _outcome(
                    evidence_id,
                    EvidenceState.UNKNOWN,
                    "evidence.dependency_unknown",
                    tuple(unknown_dependencies),
                    min(paths),
                )
            else:
                continue
            if replacement != current:
                updated[evidence_id] = replacement
                changed = True
        values = updated
        if not changed:
            break
    return tuple(values[evidence_id] for evidence_id in sorted(values))


def evaluate_invalidations(
    evidence: Mapping[RecordId, EvidenceV1],
    context: InvalidationContext,
) -> tuple[Invalidation, ...]:
    """Evaluate direct proof changes and propagate them through required edges."""

    _validate_inputs(evidence, context)
    direct = {
        evidence_id: _evaluate_direct(record, context)
        for evidence_id, record in sorted(evidence.items())
    }
    components = _strongly_connected_components(evidence)
    cyclic = _mark_cycles_unknown(evidence, direct, components)
    return _propagate_to_fixed_point(evidence, direct, cyclic)
