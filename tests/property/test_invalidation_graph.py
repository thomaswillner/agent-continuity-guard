from __future__ import annotations

from collections.abc import Iterable
from itertools import permutations

import pytest

from agent_continuity.capture import TargetIdentityV1
from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from agent_continuity.kernel.evidence import (
    EvidenceAuthority,
    EvidenceCompleteness,
    EvidenceKind,
    EvidenceV1,
    InvalidatorKind,
    InvalidatorV1,
    evidence_v1,
    invalidator_payload,
)
from agent_continuity.kernel.invalidation import (
    EvidenceState,
    InvalidationContext,
    evaluate_invalidations,
)
from agent_continuity.kernel.model import LogicalTime, RecordId
from agent_continuity.kernel.records import (
    FactV1,
    ProducerIdentity,
    make_record,
    producer_identity_payload,
)

NOW = LogicalTime("2026-09-01T00:00:10Z")
CHECKPOINT = RecordId(digest_bytes(b"property-checkpoint"))
PRODUCER = ProducerIdentity("property-producer", "1", digest_bytes(b"producer"))
PRODUCER_ID = make_record(
    "ProducerIdentity", producer_identity_payload(PRODUCER)
).record_id


def _target() -> TargetIdentityV1:
    digest = digest_bytes(b"property-target")
    return TargetIdentityV1(
        adapter_id="property-adapter",
        adapter_version="1",
        sanitized_remote_identity_digest=None,
        head_oid="a" * 40,
        tree_oid="b" * 40,
        index_manifest_digest=digest,
        worktree_manifest_digest=digest,
        inventory_digest=digest,
        status_digest=digest,
        git_object_manifest_digest=digest,
        ignore_provenance_digest=digest,
        platform_id="property-platform",
        filesystem_id="property-filesystem",
        physical_root_fingerprint=digest,
        capabilities=(),
    )


TARGET = _target()
TARGET_ID = TARGET.record().record_id
CONTEXT = InvalidationContext(
    logical_time=NOW,
    target=TARGET,
    checkpoint_id=CHECKPOINT,
    producer_ids=frozenset({PRODUCER_ID}),
    citations={},
)


def _ordered(values: Iterable[InvalidatorV1]) -> tuple[InvalidatorV1, ...]:
    return tuple(
        sorted(values, key=lambda item: canonical_bytes(invalidator_payload(item)))
    )


def _evidence(
    label: str,
    dependencies: tuple[RecordId, ...] = (),
    *,
    expires_at: LogicalTime | None = None,
) -> EvidenceV1:
    return evidence_v1(
        kind=EvidenceKind.STRUCTURED_CLAIM,
        subject_digest=digest_bytes(f"subject:{label}".encode()),
        authority=EvidenceAuthority.DETERMINISTIC,
        producer=PRODUCER,
        target_id=TARGET_ID,
        checkpoint_id=CHECKPOINT,
        observed_at=LogicalTime("2026-09-01T00:00:00Z"),
        expires_at=expires_at,
        completeness=EvidenceCompleteness.COMPLETE,
        terminal_status=None,
        declared_output_digest=None,
        observed_output_digest=None,
        collected_check_count=None,
        pagination_complete=None,
        payload_digest=digest_bytes(f"payload:{label}".encode()),
        facts=(FactV1(("property", label), True),),
        invalidators=_ordered(
            InvalidatorV1(
                InvalidatorKind.EVIDENCE_DEPENDENCY,
                dependency,
                required=True,
            )
            for dependency in dependencies
        ),
    )


def _diamond() -> tuple[dict[str, EvidenceV1], dict[RecordId, EvidenceV1]]:
    root = _evidence("root", expires_at=NOW)
    left = _evidence("left", (root.evidence_id,))
    right = _evidence("right", (root.evidence_id,))
    top = _evidence("top", (left.evidence_id, right.evidence_id))
    unrelated = _evidence("unrelated")
    named = {
        "left": left,
        "right": right,
        "root": root,
        "top": top,
        "unrelated": unrelated,
    }
    return named, {value.evidence_id: value for value in named.values()}


@pytest.mark.parametrize(
    "order",
    permutations(("left", "right", "root", "top", "unrelated")),
)
def test_diamond_propagation_is_insertion_order_invariant_and_unique(
    order: tuple[str, ...],
) -> None:
    named, _graph = _diamond()
    graph = {named[label].evidence_id: named[label] for label in order}

    result = evaluate_invalidations(graph, CONTEXT)
    by_id = {item.evidence_id: item for item in result}

    assert tuple(item.evidence_id for item in result) == tuple(sorted(graph))
    assert len(result) == len(set(item.evidence_id for item in result))
    for label in ("root", "left", "right", "top"):
        assert by_id[named[label].evidence_id].state is EvidenceState.INVALIDATED
    assert by_id[named["unrelated"].evidence_id].state is EvidenceState.CURRENT
    assert by_id[named["top"].evidence_id].direct_cause_ids == tuple(
        sorted((named["left"].evidence_id, named["right"].evidence_id))
    )


@pytest.mark.parametrize("length", [2, 3, 7, 20])
def test_bounded_fixed_point_reaches_every_node_in_a_dependency_chain(
    length: int,
) -> None:
    chain = [_evidence("chain-0", expires_at=NOW)]
    for index in range(1, length):
        chain.append(_evidence(f"chain-{index}", (chain[-1].evidence_id,)))
    graph = {item.evidence_id: item for item in reversed(chain)}

    result = {item.evidence_id: item for item in evaluate_invalidations(graph, CONTEXT)}

    assert all(item.state is EvidenceState.INVALIDATED for item in result.values())
    assert result[chain[-1].evidence_id].transitive_path == tuple(
        item.evidence_id for item in reversed(chain)
    )


def _forge_cycle_record(
    template: EvidenceV1,
    evidence_id: RecordId,
    dependency_id: RecordId,
) -> EvidenceV1:
    forged = object.__new__(EvidenceV1)
    for field in EvidenceV1.__dataclass_fields__:
        object.__setattr__(forged, field, getattr(template, field))
    object.__setattr__(forged, "evidence_id", evidence_id)
    object.__setattr__(
        forged,
        "invalidators",
        (
            InvalidatorV1(
                InvalidatorKind.EVIDENCE_DEPENDENCY,
                dependency_id,
                required=True,
            ),
        ),
    )
    return forged


def test_dependency_cycle_is_unknown_instead_of_passing_or_looping() -> None:
    first_id = RecordId(digest_bytes(b"cycle-first"))
    second_id = RecordId(digest_bytes(b"cycle-second"))
    first = _forge_cycle_record(_evidence("cycle-first-template"), first_id, second_id)
    second = _forge_cycle_record(
        _evidence("cycle-second-template"), second_id, first_id
    )

    result = {
        item.evidence_id: item
        for item in evaluate_invalidations(
            {second_id: second, first_id: first},
            CONTEXT,
        )
    }

    assert result[first_id].state is EvidenceState.UNKNOWN
    assert result[second_id].state is EvidenceState.UNKNOWN
    assert result[first_id].code == "evidence.dependency_cycle"
    assert result[second_id].code == "evidence.dependency_cycle"
