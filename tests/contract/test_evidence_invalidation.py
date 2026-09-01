from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from agent_continuity.capture import TargetIdentityV1
from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from agent_continuity.kernel.citation import citation_v1
from agent_continuity.kernel.evaluation import (
    EvaluationCase,
    Profile,
    Verdict,
    evaluate,
)
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
    CitationObservation,
    EvidenceEvaluationInput,
    EvidenceState,
    Invalidation,
    InvalidationContext,
    evaluate_invalidations,
)
from agent_continuity.kernel.model import Digest, LogicalTime, RecordId
from agent_continuity.kernel.records import (
    FactV1,
    ProducerIdentity,
    make_record,
    producer_identity_payload,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "content_rot"
NOW = LogicalTime("2026-09-01T00:00:10Z")
CHECKPOINT = RecordId(digest_bytes(b"checkpoint-current"))
PRODUCER = ProducerIdentity("fixture-producer", "1", digest_bytes(b"producer"))


def _target(label: bytes = b"target-current") -> TargetIdentityV1:
    digest = digest_bytes(label)
    return TargetIdentityV1(
        adapter_id="fixture-adapter",
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
        platform_id="fixture-platform",
        filesystem_id="fixture-filesystem",
        physical_root_fingerprint=digest,
        capabilities=(),
    )


TARGET = _target()
TARGET_ID = TARGET.record().record_id
PRODUCER_ID = make_record(
    "ProducerIdentity", producer_identity_payload(PRODUCER)
).record_id


def _ordered_invalidators(
    values: tuple[InvalidatorV1, ...],
) -> tuple[InvalidatorV1, ...]:
    return tuple(
        sorted(
            values,
            key=lambda item: canonical_bytes(invalidator_payload(item)),
        )
    )


def _evidence(
    label: str,
    *,
    authority: EvidenceAuthority = EvidenceAuthority.DETERMINISTIC,
    target_id: RecordId = TARGET_ID,
    checkpoint_id: RecordId = CHECKPOINT,
    producer: ProducerIdentity = PRODUCER,
    expires_at: LogicalTime | None = None,
    completeness: EvidenceCompleteness = EvidenceCompleteness.COMPLETE,
    subject_digest: Digest | None = None,
    invalidators: tuple[InvalidatorV1, ...] = (),
) -> EvidenceV1:
    return evidence_v1(
        kind=EvidenceKind.STRUCTURED_CLAIM,
        subject_digest=(
            digest_bytes(f"subject:{label}".encode())
            if subject_digest is None
            else subject_digest
        ),
        authority=authority,
        producer=producer,
        target_id=target_id,
        checkpoint_id=checkpoint_id,
        observed_at=LogicalTime("2026-09-01T00:00:00Z"),
        expires_at=expires_at,
        completeness=completeness,
        terminal_status=None,
        declared_output_digest=None,
        observed_output_digest=None,
        collected_check_count=None,
        pagination_complete=None,
        payload_digest=digest_bytes(f"payload:{label}".encode()),
        facts=(FactV1(("fixture", label), True),),
        invalidators=_ordered_invalidators(invalidators),
    )


def _context(
    *,
    logical_time: LogicalTime = NOW,
    target: TargetIdentityV1 = TARGET,
    checkpoint_id: RecordId = CHECKPOINT,
    producer_ids: frozenset[RecordId] = frozenset({PRODUCER_ID}),
    citations: Mapping[RecordId, CitationObservation] | None = None,
) -> InvalidationContext:
    return InvalidationContext(
        logical_time=logical_time,
        target=target,
        checkpoint_id=checkpoint_id,
        producer_ids=producer_ids,
        citations={} if citations is None else citations,
    )


def _by_id(values: tuple[Invalidation, ...]) -> dict[RecordId, Invalidation]:
    return {value.evidence_id: value for value in values}


def _fixture_span() -> tuple[bytes, bytes, int, int]:
    document = (FIXTURE_ROOT / "document.bin").read_bytes()
    manifest = json.loads((FIXTURE_ROOT / "citations.json").read_text())
    path = manifest["path"].encode("ascii")
    start = manifest["span"]["byte_start"]
    end = manifest["span"]["byte_end"]
    assert document[start:end] == b"trusted=value"
    return document, path, start, end


def _cited_span_graph() -> tuple[
    dict[RecordId, EvidenceV1], InvalidationContext, dict[str, RecordId]
]:
    document, path, start, end = _fixture_span()
    citation = citation_v1(path, document, start, end)
    citation_id = citation.record().record_id
    assert citation.span_digest is not None
    span = _evidence(
        "span",
        subject_digest=citation.span_digest,
        invalidators=(
            InvalidatorV1(InvalidatorKind.CITATION, citation_id, required=True),
        ),
    )
    derived = _evidence(
        "derived",
        invalidators=(
            InvalidatorV1(
                InvalidatorKind.EVIDENCE_DEPENDENCY,
                span.evidence_id,
                required=True,
            ),
        ),
    )
    unrelated = _evidence("unrelated")
    context = _context(
        citations={
            citation_id: CitationObservation(
                citation_id=citation_id,
                available=True,
                stable=True,
                file_digest=citation.file_digest,
                span_digest=citation.span_digest,
                unknown_code=None,
            )
        }
    )
    return (
        {
            span.evidence_id: span,
            derived.evidence_id: derived,
            unrelated.evidence_id: unrelated,
        },
        context,
        {
            "citation": citation_id,
            "derived": derived.evidence_id,
            "span": span.evidence_id,
            "unrelated": unrelated.evidence_id,
        },
    )


def _replace_cited_bytes(
    context: InvalidationContext,
    replacement: bytes,
) -> InvalidationContext:
    document, path, start, end = _fixture_span()
    changed = document[:start] + replacement + document[end:]
    current = citation_v1(path, changed, start, start + len(replacement))
    citation_id = next(iter(context.citations))
    return replace(
        context,
        citations={
            citation_id: CitationObservation(
                citation_id=citation_id,
                available=True,
                stable=True,
                file_digest=current.file_digest,
                span_digest=current.span_digest,
                unknown_code=None,
            )
        },
    )


def _change_unrelated_file(context: InvalidationContext) -> InvalidationContext:
    document, path, start, end = _fixture_span()
    changed = document + b"unrelated=changed\n"
    current = citation_v1(path, changed, start, end)
    citation_id = next(iter(context.citations))
    return replace(
        context,
        citations={
            citation_id: CitationObservation(
                citation_id=citation_id,
                available=True,
                stable=True,
                file_digest=current.file_digest,
                span_digest=current.span_digest,
                unknown_code=None,
            )
        },
    )


def _assert_changed_cited_span_invalidates_only_dependants() -> None:
    graph, context, ids = _cited_span_graph()
    result = _by_id(
        evaluate_invalidations(graph, _replace_cited_bytes(context, b"unsafe-value"))
    )
    assert result[ids["span"]].state is EvidenceState.INVALIDATED
    assert result[ids["span"]].code == "citation.span_changed"
    assert result[ids["derived"]].state is EvidenceState.INVALIDATED
    assert result[ids["derived"]].code == "evidence.dependency_invalid"
    assert result[ids["unrelated"]].state is EvidenceState.CURRENT


def test_changed_cited_span_invalidates_only_its_dependants() -> None:
    _assert_changed_cited_span_invalidates_only_dependants()


def test_unrelated_file_change_does_not_invalidate_span_citation() -> None:
    graph, context, ids = _cited_span_graph()
    result = _by_id(evaluate_invalidations(graph, _change_unrelated_file(context)))

    assert result[ids["span"]].state is EvidenceState.CURRENT
    assert result[ids["derived"]].state is EvidenceState.CURRENT


def test_whole_file_citation_change_and_missing_path_are_distinct() -> None:
    document, path, _start, _end = _fixture_span()
    citation = citation_v1(path, document)
    citation_id = citation.record().record_id
    evidence = _evidence(
        "whole-file",
        subject_digest=citation.file_digest,
        invalidators=(
            InvalidatorV1(InvalidatorKind.CITATION, citation_id, required=True),
        ),
    )
    changed = citation_v1(path, document + b"changed\n")
    changed_context = _context(
        citations={
            citation_id: CitationObservation(
                citation_id,
                True,
                True,
                changed.file_digest,
                None,
                None,
            )
        }
    )
    missing_context = _context(
        citations={
            citation_id: CitationObservation(
                citation_id,
                False,
                True,
                None,
                None,
                "citation.path_missing",
            )
        }
    )

    changed_result = evaluate_invalidations(
        {evidence.evidence_id: evidence}, changed_context
    )[0]
    missing_result = evaluate_invalidations(
        {evidence.evidence_id: evidence}, missing_context
    )[0]
    assert (changed_result.state, changed_result.code) == (
        EvidenceState.INVALIDATED,
        "citation.file_changed",
    )
    assert (missing_result.state, missing_result.code) == (
        EvidenceState.INVALIDATED,
        "citation.path_missing",
    )


@pytest.mark.parametrize(
    ("include_observation", "available", "stable"),
    [
        (False, False, False),
        (True, False, True),
        (True, True, False),
    ],
)
def test_missing_unavailable_or_unstable_citation_observation_is_unknown(
    include_observation: bool,
    available: bool,
    stable: bool,
) -> None:
    graph, context, ids = _cited_span_graph()
    citation_id = ids["citation"]
    observation = CitationObservation(
        citation_id,
        available=available,
        stable=stable,
        file_digest=None,
        span_digest=None,
        unknown_code="fixture.observation_unavailable",
    )
    unavailable = replace(
        context,
        citations={citation_id: observation} if include_observation else {},
    )

    result = _by_id(evaluate_invalidations(graph, unavailable))[ids["span"]]
    assert (result.state, result.code) == (
        EvidenceState.UNKNOWN,
        "evidence.observation_unavailable",
    )


def test_expiry_boundary_is_invalid_at_exact_logical_time() -> None:
    boundary = LogicalTime("2026-09-01T00:00:10Z")
    evidence = _evidence("expiring", expires_at=boundary)

    at_boundary = evaluate_invalidations(
        {evidence.evidence_id: evidence}, _context(logical_time=boundary)
    )[0]
    before_boundary = evaluate_invalidations(
        {evidence.evidence_id: evidence},
        _context(logical_time=LogicalTime("2026-09-01T00:00:09Z")),
    )[0]
    assert (at_boundary.state, at_boundary.code) == (
        EvidenceState.INVALIDATED,
        "evidence.expired",
    )
    assert before_boundary.state is EvidenceState.CURRENT


@pytest.mark.parametrize(
    ("evidence_changes", "context_changes", "code"),
    [
        (
            {"target_id": RecordId(digest_bytes(b"old-target"))},
            {},
            "evidence.target_mismatch",
        ),
        (
            {"checkpoint_id": RecordId(digest_bytes(b"old-checkpoint"))},
            {},
            "evidence.checkpoint_mismatch",
        ),
        (
            {
                "producer": ProducerIdentity(
                    "retired-producer",
                    "1",
                    digest_bytes(b"retired"),
                )
            },
            {},
            "evidence.producer_mismatch",
        ),
    ],
)
def test_target_checkpoint_and_producer_mismatch_invalidate(
    evidence_changes: dict[str, object],
    context_changes: dict[str, object],
    code: str,
) -> None:
    evidence = _evidence("mismatch", **evidence_changes)  # type: ignore[arg-type]
    result = evaluate_invalidations(
        {evidence.evidence_id: evidence}, _context(**context_changes)  # type: ignore[arg-type]
    )[0]

    assert (result.state, result.code) == (EvidenceState.INVALIDATED, code)


def test_direct_invalidation_precedes_unknown_dependency() -> None:
    missing = RecordId(digest_bytes(b"missing-dependency"))
    unknown = _evidence(
        "missing-dependency",
        invalidators=(
            InvalidatorV1(
                InvalidatorKind.EVIDENCE_DEPENDENCY, missing, required=True
            ),
        ),
    )
    unknown_result = evaluate_invalidations(
        {unknown.evidence_id: unknown}, _context()
    )[0]
    assert (unknown_result.state, unknown_result.code) == (
        EvidenceState.UNKNOWN,
        "evidence.dependency_unknown",
    )

    expired = _evidence(
        "expired-with-missing-dependency",
        expires_at=NOW,
        invalidators=(
            InvalidatorV1(
                InvalidatorKind.EVIDENCE_DEPENDENCY, missing, required=True
            ),
        ),
    )

    result = evaluate_invalidations({expired.evidence_id: expired}, _context())[0]
    assert (result.state, result.code) == (
        EvidenceState.INVALIDATED,
        "evidence.expired",
    )


def test_required_advisory_dependency_cannot_satisfy_deterministic_evidence() -> None:
    advisory = _evidence("advisory", authority=EvidenceAuthority.ADVISORY)
    required = _evidence(
        "requires-deterministic",
        invalidators=(
            InvalidatorV1(
                InvalidatorKind.EVIDENCE_DEPENDENCY,
                advisory.evidence_id,
                required=True,
            ),
        ),
    )

    result = _by_id(
        evaluate_invalidations(
            {required.evidence_id: required, advisory.evidence_id: advisory},
            _context(),
        )
    )
    assert result[advisory.evidence_id].state is EvidenceState.CURRENT
    assert (result[required.evidence_id].state, result[required.evidence_id].code) == (
        EvidenceState.UNKNOWN,
        "evidence.dependency_unknown",
    )


def test_evaluation_emits_normalized_findings_from_invalidations() -> None:
    graph, context, ids = _cited_span_graph()
    evidence_input = EvidenceEvaluationInput(
        graph,
        _replace_cited_bytes(context, b"unsafe-value"),
    )

    result = evaluate(EvaluationCase(Profile.STRICT, (), evidence_input))

    assert result.verdict is Verdict.BLOCK
    assert result.transition_allowed is False
    assert [(finding.subject_id, finding.code) for finding in result.findings] == [
        (ids["span"], "citation.span_changed"),
        (ids["derived"], "evidence.dependency_invalid"),
    ]
    for finding in result.findings:
        assert finding.message_id == f"acg.{finding.code}"
        assert set(finding.parameters) == {"direct_cause_ids", "transitive_path"}


def test_mutation_reversed_digest_comparison_is_killed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_continuity.kernel import invalidation

    monkeypatch.setattr(
        invalidation,
        "_digests_differ",
        lambda expected, observed: expected == observed,
    )
    with pytest.raises(AssertionError):
        _assert_changed_cited_span_invalidates_only_dependants()
