"""Pure immutable ResumeContext/v1 construction and serialization."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import CanonicalJSONError, canonical_bytes
from .evaluation import EvaluationResult, Verdict
from .invalidation import EvidenceState, Invalidation
from .model import Digest, JsonObject, RecordId
from .records import (
    CheckpointV1,
    CriterionV1,
    UnresolvedItemV1,
    WorkItemV1,
    criterion_payload,
    require_digest,
    unresolved_item_payload,
    work_item_payload,
)

_FINDING_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


@dataclass(frozen=True, slots=True)
class ResumeContext:
    checkpoint_id: RecordId
    verdict: Verdict
    usable: bool
    target_id: RecordId
    goal_digest: Digest
    acceptance_criteria: tuple[CriterionV1, ...]
    constraint_digests: tuple[Digest, ...]
    accepted_decision_ids: tuple[RecordId, ...]
    pending_work: tuple[WorkItemV1, ...]
    unresolved: tuple[UnresolvedItemV1, ...]
    open_assignment_ids: tuple[RecordId, ...]
    current_evidence_ids: tuple[RecordId, ...]
    invalidations: tuple[Invalidation, ...]
    blocker_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.acceptance_criteria) is not tuple or any(
            type(item) is not CriterionV1 for item in self.acceptance_criteria
        ):
            raise CanonicalJSONError("resume criteria must be an exact model tuple")
        if type(self.pending_work) is not tuple or any(
            type(item) is not WorkItemV1 for item in self.pending_work
        ):
            raise CanonicalJSONError("resume work must be an exact model tuple")
        if type(self.unresolved) is not tuple or any(
            type(item) is not UnresolvedItemV1 for item in self.unresolved
        ):
            raise CanonicalJSONError(
                "resume unresolved items must be an exact model tuple"
            )
        if type(self.invalidations) is not tuple or any(
            type(item) is not Invalidation for item in self.invalidations
        ):
            raise CanonicalJSONError(
                "resume invalidations must be an exact model tuple"
            )
        string_fields = (
            (self.constraint_digests, "resume constraints"),
            (self.accepted_decision_ids, "resume decisions"),
            (self.open_assignment_ids, "resume assignments"),
            (self.current_evidence_ids, "resume current evidence"),
            (self.blocker_codes, "resume blockers"),
        )
        for string_values, string_field in string_fields:
            if type(string_values) is not tuple or any(
                type(item) is not str for item in string_values
            ):
                raise CanonicalJSONError(
                    f"{string_field} must be an exact string tuple"
                )
        if any(_FINDING_CODE_RE.fullmatch(code) is None for code in self.blocker_codes):
            raise CanonicalJSONError("resume blocker code is invalid")
        for value in (
            self.checkpoint_id,
            self.target_id,
            self.goal_digest,
            *self.constraint_digests,
            *self.accepted_decision_ids,
            *self.open_assignment_ids,
            *self.current_evidence_ids,
        ):
            require_digest(value)
        if type(self.verdict) is not Verdict or type(self.usable) is not bool:
            raise CanonicalJSONError("resume verdict is invalid")
        if tuple(item.ordinal for item in self.acceptance_criteria) != tuple(
            range(len(self.acceptance_criteria))
        ):
            raise CanonicalJSONError("resume criteria are not ordered")
        for string_values, string_field in string_fields:
            if string_values != tuple(sorted(string_values)) or len(
                string_values
            ) != len(set(string_values)):
                raise CanonicalJSONError(
                    f"{string_field} must be ordered and unique"
                )
        for _models, identifiers, field in (
            (
                self.pending_work,
                tuple(item.work_item_id for item in self.pending_work),
                "resume work",
            ),
            (
                self.unresolved,
                tuple(item.unresolved_id for item in self.unresolved),
                "resume unresolved items",
            ),
        ):
            if identifiers != tuple(sorted(identifiers)) or len(identifiers) != len(
                set(identifiers)
            ):
                raise CanonicalJSONError(f"{field} must be ordered and unique")
        invalidation_bytes = tuple(
            canonical_bytes(invalidation_payload(item)) for item in self.invalidations
        )
        if invalidation_bytes != tuple(sorted(invalidation_bytes)) or len(
            invalidation_bytes
        ) != len(set(invalidation_bytes)):
            raise CanonicalJSONError("resume invalidations must be ordered and unique")
        evidence_ids = tuple(item.evidence_id for item in self.invalidations)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise CanonicalJSONError("resume evidence identities must be unique")
        expected_current = tuple(
            sorted(
                item.evidence_id
                for item in self.invalidations
                if item.state is EvidenceState.CURRENT
            )
        )
        if self.current_evidence_ids != expected_current:
            raise CanonicalJSONError("resume current evidence is inconsistent")


def invalidation_payload(invalidation: Invalidation) -> JsonObject:
    return {
        "code": invalidation.code,
        "direct_cause_ids": list(invalidation.direct_cause_ids),
        "evidence_id": invalidation.evidence_id,
        "state": invalidation.state.value,
        "transitive_path": list(invalidation.transitive_path),
    }


def build_resume_context(
    checkpoint: CheckpointV1,
    evaluation: EvaluationResult,
    *,
    goal_digest: Digest,
    invalidations: tuple[Invalidation, ...],
) -> ResumeContext:
    require_digest(goal_digest)
    ordered_invalidations = tuple(
        sorted(
            invalidations,
            key=lambda item: canonical_bytes(invalidation_payload(item)),
        )
    )
    if len({item.evidence_id for item in ordered_invalidations}) != len(
        ordered_invalidations
    ):
        raise CanonicalJSONError("resume evidence identities must be unique")
    return ResumeContext(
        checkpoint_id=checkpoint.checkpoint_id,
        verdict=evaluation.verdict,
        usable=evaluation.transition_allowed,
        target_id=checkpoint.target_id,
        goal_digest=goal_digest,
        acceptance_criteria=checkpoint.acceptance_criteria,
        constraint_digests=checkpoint.constraint_digests,
        accepted_decision_ids=checkpoint.accepted_decision_ids,
        pending_work=checkpoint.pending_work,
        unresolved=checkpoint.unresolved,
        open_assignment_ids=checkpoint.open_assignment_ids,
        current_evidence_ids=tuple(
            sorted(
                item.evidence_id
                for item in ordered_invalidations
                if item.state is EvidenceState.CURRENT
            )
        ),
        invalidations=ordered_invalidations,
        blocker_codes=tuple(sorted({item.code for item in evaluation.findings})),
    )


def resume_context_payload(context: ResumeContext) -> JsonObject:
    return {
        "acceptance_criteria": [
            criterion_payload(item) for item in context.acceptance_criteria
        ],
        "accepted_decision_ids": list(context.accepted_decision_ids),
        "blocker_codes": list(context.blocker_codes),
        "checkpoint_id": context.checkpoint_id,
        "constraint_digests": list(context.constraint_digests),
        "current_evidence_ids": list(context.current_evidence_ids),
        "goal_digest": context.goal_digest,
        "invalidations": [invalidation_payload(item) for item in context.invalidations],
        "open_assignment_ids": list(context.open_assignment_ids),
        "pending_work": [work_item_payload(item) for item in context.pending_work],
        "schema": "ResumeContext/v1",
        "target_id": context.target_id,
        "unresolved": [unresolved_item_payload(item) for item in context.unresolved],
        "usable": context.usable,
        "verdict": context.verdict.value,
    }
