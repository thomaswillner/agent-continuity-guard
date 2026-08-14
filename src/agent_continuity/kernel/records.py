"""Strict public record helpers for the pure kernel."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import (
    CanonicalJSONError,
    canonical_bytes,
    record_id,
    validate_logical_time,
)
from .evaluation import Profile, Verdict
from .model import (
    ADAPTER_CAPABILITY_VOCABULARY_V1,
    DETECTOR_CODE_VOCABULARY_V1,
    AssignmentAuthority,
    Digest,
    JsonObject,
    JsonScalar,
    LogicalTime,
    PromotionMode,
    RecordId,
    ResourceLimitsV1,
    StoredRecord,
)
from .paths import PathScopeV1, path_scope_payload

_PUBLIC_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")
_FIELD_COMPONENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

SCHEMA_REGISTRY: dict[str, str] = {
    "Actor/v1": "actor.schema.json",
    "AuditAnchor/v1": "audit-anchor.schema.json",
    "AuditEvent/v1": "audit-event.schema.json",
    "AuditVerification/v1": "audit-verification.schema.json",
    "CapabilityClaim/v1": "capability-claim.schema.json",
    "Checkpoint/v1": "checkpoint.schema.json",
    "CheckpointReceipt/v1": "checkpoint-receipt.schema.json",
    "Criterion/v1": "criterion.schema.json",
    "EvaluationResult/v1": "evaluation-result.schema.json",
    "Fact/v1": "fact.schema.json",
    "Finding/v1": "finding.schema.json",
    "InstructionManifest/v1": "instruction-manifest.schema.json",
    "InitializationIntent/v1": "initialization-intent.schema.json",
    "PathIdentity/v1": "path-identity.schema.json",
    "PathScope/v1": "path-scope.schema.json",
    "Policy/v1": "policy.schema.json",
    "PolicyTemplate/v1": "policy-template.schema.json",
    "ProducerIdentity/v1": "producer-identity.schema.json",
    "Goal/v1": "goal.schema.json",
    "Ruleset/v1": "ruleset.schema.json",
    "TargetIdentity/v1": "target-identity.schema.json",
    "UnresolvedItem/v1": "unresolved-item.schema.json",
    "WorkItem/v1": "work-item.schema.json",
}


@dataclass(frozen=True, slots=True)
class CompiledPolicyV1:
    """Canonical Policy/v1 with identity derived from approved compiled fields."""

    policy_id: RecordId
    authoring_digest: Digest
    profile: Profile
    promotion_mode: PromotionMode
    limits: ResourceLimitsV1
    required_adapter_capabilities: tuple[str, ...]
    max_assignment_authority: AssignmentAuthority
    approval_operator_ids: tuple[RecordId, ...]
    rollback_operator_ids: tuple[RecordId, ...]
    evidence_expiry_seconds: int
    enabled_detectors: tuple[str, ...]
    severity_by_code: tuple[tuple[str, Verdict], ...]

    def __post_init__(self) -> None:
        require_digest(self.policy_id)
        require_digest(self.authoring_digest)
        if type(self.profile) is not Profile:
            raise CanonicalJSONError("compiled policy profile is invalid")
        if type(self.promotion_mode) is not PromotionMode:
            raise CanonicalJSONError("compiled policy promotion mode is invalid")
        if type(self.limits) is not ResourceLimitsV1:
            raise CanonicalJSONError("compiled policy limits are invalid")
        if type(self.max_assignment_authority) is not AssignmentAuthority:
            raise CanonicalJSONError("compiled policy assignment authority is invalid")
        _require_ordered_string_tuple(
            self.required_adapter_capabilities,
            field="required adapter capabilities",
        )
        if not set(self.required_adapter_capabilities).issubset(
            ADAPTER_CAPABILITY_VOCABULARY_V1
        ):
            raise CanonicalJSONError("policy adapter capability is unsupported")
        _require_ordered_digest_tuple(
            self.approval_operator_ids,
            field="approval operator identifiers",
        )
        _require_ordered_digest_tuple(
            self.rollback_operator_ids,
            field="rollback operator identifiers",
        )
        if (
            type(self.evidence_expiry_seconds) is not int
            or self.evidence_expiry_seconds < 1
        ):
            raise CanonicalJSONError("evidence expiry must be a positive integer")
        _require_ordered_string_tuple(
            self.enabled_detectors,
            field="enabled detectors",
        )
        if not set(self.enabled_detectors).issubset(DETECTOR_CODE_VOCABULARY_V1):
            raise CanonicalJSONError("policy detector is unsupported")
        if type(self.severity_by_code) is not tuple or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not Verdict
            for item in self.severity_by_code
        ):
            raise CanonicalJSONError("policy severities must be immutable pairs")
        severity_codes = tuple(item[0] for item in self.severity_by_code)
        if severity_codes != tuple(sorted(severity_codes)) or len(
            set(severity_codes)
        ) != len(severity_codes):
            raise CanonicalJSONError("policy severities must be ordered and unique")
        if any(
            verdict not in {Verdict.WARN, Verdict.BLOCK}
            for _code, verdict in self.severity_by_code
        ):
            raise CanonicalJSONError("policy severities must warn or block")
        if severity_codes != self.enabled_detectors:
            raise CanonicalJSONError("policy severities must cover enabled detectors")

    def record(self) -> StoredRecord:
        value = make_record("Policy", policy_payload(self))
        if value.record_id != self.policy_id:
            raise CanonicalJSONError("compiled policy identity is invalid")
        return value


def _require_ordered_string_tuple(value: tuple[str, ...], *, field: str) -> None:
    if type(value) is not tuple or any(type(item) is not str for item in value):
        raise CanonicalJSONError(f"{field} must be an exact string tuple")
    if value != tuple(sorted(value)) or len(set(value)) != len(value):
        raise CanonicalJSONError(f"{field} must be ordered and unique")


def _require_ordered_digest_tuple(value: tuple[RecordId, ...], *, field: str) -> None:
    _require_ordered_string_tuple(value, field=field)
    for item in value:
        require_digest(item)


def _require_digest_sequence(value: tuple[RecordId, ...], *, field: str) -> None:
    if type(value) is not tuple:
        raise CanonicalJSONError(f"{field} must be an exact tuple")
    if len(value) != len(set(value)):
        raise CanonicalJSONError(f"{field} must be unique")
    for item in value:
        require_digest(item)


def _require_ordered_model_ids(value: tuple[RecordId, ...], *, field: str) -> None:
    _require_ordered_digest_tuple(value, field=field)


def require_digest(value: str) -> None:
    if _DIGEST_RE.fullmatch(value) is None:
        raise CanonicalJSONError("digest must be lowercase SHA-256")


def require_public_component(value: str, *, field: str) -> None:
    if _PUBLIC_COMPONENT_RE.fullmatch(value) is None:
        raise CanonicalJSONError(f"{field} is not a bounded public identifier")


@dataclass(frozen=True, slots=True)
class ProducerIdentity:
    name: str
    version: str
    digest: Digest

    def __post_init__(self) -> None:
        require_public_component(self.name, field="producer name")
        require_public_component(self.version, field="producer version")
        require_digest(self.digest)


@dataclass(frozen=True, slots=True)
class FactV1:
    field_path: tuple[str, ...]
    value: JsonScalar

    def __post_init__(self) -> None:
        if type(self.field_path) is not tuple or any(
            type(item) is not str for item in self.field_path
        ):
            raise CanonicalJSONError("fact field path must be an exact string tuple")
        if not 1 <= len(self.field_path) <= 8:
            raise CanonicalJSONError("fact field path must have one to eight segments")
        if any(_FIELD_COMPONENT_RE.fullmatch(item) is None for item in self.field_path):
            raise CanonicalJSONError("fact field path contains an invalid segment")
        if self.value is not None and type(self.value) not in {bool, int, str}:
            raise CanonicalJSONError("fact value must be an exact JSON scalar")
        canonical_bytes(self.value)


@dataclass(frozen=True, slots=True)
class ActorV1:
    actor_id: RecordId
    producer: ProducerIdentity
    authority: AssignmentAuthority
    scope_ids: tuple[RecordId, ...]

    def __post_init__(self) -> None:
        require_digest(self.actor_id)
        if type(self.producer) is not ProducerIdentity:
            raise CanonicalJSONError("actor producer is invalid")
        if type(self.authority) is not AssignmentAuthority:
            raise CanonicalJSONError("actor authority is invalid")
        _require_ordered_digest_tuple(self.scope_ids, field="actor scope identifiers")

    def record(self) -> StoredRecord:
        value = make_record("Actor", actor_payload(self))
        if value.record_id != self.actor_id:
            raise CanonicalJSONError("actor identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class GoalV1:
    goal_id: RecordId
    digest: Digest

    def __post_init__(self) -> None:
        require_digest(self.goal_id)
        require_digest(self.digest)

    def record(self) -> StoredRecord:
        value = make_record("Goal", goal_payload(self))
        if value.record_id != self.goal_id:
            raise CanonicalJSONError("goal identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class RulesetV1:
    ruleset_id: RecordId
    rule_ids: tuple[RecordId, ...]

    def __post_init__(self) -> None:
        require_digest(self.ruleset_id)
        _require_ordered_digest_tuple(self.rule_ids, field="ruleset identifiers")

    def record(self) -> StoredRecord:
        value = make_record("Ruleset", ruleset_payload(self))
        if value.record_id != self.ruleset_id:
            raise CanonicalJSONError("ruleset identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class InitializationIntentV1:
    intent_id: RecordId
    session_key: str
    target_id: RecordId
    goal_id: RecordId
    criterion_ids: tuple[RecordId, ...]
    instruction_id: RecordId
    policy_id: RecordId
    ruleset_id: RecordId

    def __post_init__(self) -> None:
        require_digest(self.intent_id)
        require_public_component(self.session_key, field="initialization session key")
        for value in (
            self.target_id,
            self.goal_id,
            self.instruction_id,
            self.policy_id,
            self.ruleset_id,
        ):
            require_digest(value)
        _require_digest_sequence(
            self.criterion_ids,
            field="initialization criterion identifiers",
        )

    def record(self) -> StoredRecord:
        value = make_record("InitializationIntent", initialization_intent_payload(self))
        if value.record_id != self.intent_id:
            raise CanonicalJSONError("initialization intent identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class CriterionV1:
    criterion_id: RecordId
    ordinal: int
    digest: Digest

    def __post_init__(self) -> None:
        require_digest(self.criterion_id)
        if type(self.ordinal) is not int or self.ordinal < 0:
            raise CanonicalJSONError("criterion ordinal must be nonnegative")
        require_digest(self.digest)

    def record(self) -> StoredRecord:
        value = make_record("Criterion", criterion_record_payload(self))
        if value.record_id != self.criterion_id:
            raise CanonicalJSONError("criterion identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class WorkItemV1:
    work_item_id: RecordId
    kind: str
    status_code: str
    digest: Digest

    def __post_init__(self) -> None:
        require_digest(self.work_item_id)
        require_public_component(self.kind, field="work item kind")
        require_public_component(self.status_code, field="work item status")
        require_digest(self.digest)

    def record(self) -> StoredRecord:
        value = make_record("WorkItem", work_item_record_payload(self))
        if value.record_id != self.work_item_id:
            raise CanonicalJSONError("work item identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class UnresolvedItemV1:
    unresolved_id: RecordId
    code: str
    digest: Digest | None

    def __post_init__(self) -> None:
        require_digest(self.unresolved_id)
        require_public_component(self.code, field="unresolved item code")
        if self.digest is not None:
            require_digest(self.digest)

    def record(self) -> StoredRecord:
        value = make_record("UnresolvedItem", unresolved_item_record_payload(self))
        if value.record_id != self.unresolved_id:
            raise CanonicalJSONError("unresolved item identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class CheckpointV1:
    checkpoint_id: RecordId
    parent_checkpoint_id: RecordId | None
    target_id: RecordId
    goal_id: RecordId
    acceptance_criteria: tuple[CriterionV1, ...]
    constraint_digests: tuple[Digest, ...]
    instruction_id: RecordId
    policy_id: RecordId
    ruleset_id: RecordId
    actor_ids: tuple[RecordId, ...]
    evidence_ids: tuple[RecordId, ...]
    invalidation_ids: tuple[RecordId, ...]
    accepted_decision_ids: tuple[RecordId, ...]
    pending_work: tuple[WorkItemV1, ...]
    unresolved: tuple[UnresolvedItemV1, ...]
    assignment_authority: AssignmentAuthority
    authority_scopes: tuple[PathScopeV1, ...]
    open_assignment_ids: tuple[RecordId, ...]
    audit_parent_id: RecordId | None
    initialization_intent_id: RecordId
    created_at: LogicalTime

    def __post_init__(self) -> None:
        for value in (
            self.checkpoint_id,
            self.target_id,
            self.goal_id,
            self.instruction_id,
            self.policy_id,
            self.ruleset_id,
            self.initialization_intent_id,
        ):
            require_digest(value)
        for optional in (self.parent_checkpoint_id, self.audit_parent_id):
            if optional is not None:
                require_digest(optional)
        if type(self.acceptance_criteria) is not tuple or any(
            type(item) is not CriterionV1 for item in self.acceptance_criteria
        ):
            raise CanonicalJSONError("checkpoint criteria are invalid")
        if tuple(item.ordinal for item in self.acceptance_criteria) != tuple(
            range(len(self.acceptance_criteria))
        ):
            raise CanonicalJSONError("checkpoint criterion ordinals are invalid")
        criterion_ids = tuple(item.criterion_id for item in self.acceptance_criteria)
        if len(criterion_ids) != len(set(criterion_ids)):
            raise CanonicalJSONError("checkpoint criterion identities must be unique")
        _require_ordered_string_tuple(
            self.constraint_digests,
            field="checkpoint constraint digests",
        )
        for digest in self.constraint_digests:
            require_digest(digest)
        for field, values in (
            ("checkpoint actor identifiers", self.actor_ids),
            ("checkpoint evidence identifiers", self.evidence_ids),
            ("checkpoint invalidation identifiers", self.invalidation_ids),
            ("checkpoint decision identifiers", self.accepted_decision_ids),
            ("checkpoint assignment identifiers", self.open_assignment_ids),
        ):
            _require_ordered_digest_tuple(values, field=field)
        if type(self.pending_work) is not tuple or any(
            type(item) is not WorkItemV1 for item in self.pending_work
        ):
            raise CanonicalJSONError("checkpoint pending work is invalid")
        _require_ordered_model_ids(
            tuple(item.work_item_id for item in self.pending_work),
            field="checkpoint work item identifiers",
        )
        if type(self.unresolved) is not tuple or any(
            type(item) is not UnresolvedItemV1 for item in self.unresolved
        ):
            raise CanonicalJSONError("checkpoint unresolved items are invalid")
        _require_ordered_model_ids(
            tuple(item.unresolved_id for item in self.unresolved),
            field="checkpoint unresolved identifiers",
        )
        if type(self.assignment_authority) is not AssignmentAuthority:
            raise CanonicalJSONError("checkpoint assignment authority is invalid")
        if type(self.authority_scopes) is not tuple or any(
            type(item) is not PathScopeV1 for item in self.authority_scopes
        ):
            raise CanonicalJSONError("checkpoint authority scopes are invalid")
        scope_bytes = tuple(
            canonical_bytes(path_scope_payload(item)) for item in self.authority_scopes
        )
        if scope_bytes != tuple(sorted(scope_bytes)) or len(scope_bytes) != len(
            set(scope_bytes)
        ):
            raise CanonicalJSONError("checkpoint authority scopes must be ordered")
        validate_logical_time(self.created_at)

    def record(self) -> StoredRecord:
        value = make_record("Checkpoint", checkpoint_payload(self))
        if value.record_id != self.checkpoint_id:
            raise CanonicalJSONError("checkpoint identity is invalid")
        return value


@dataclass(frozen=True, slots=True)
class CheckpointReceipt:
    checkpoint_id: RecordId
    target_id: RecordId
    audit_event_id: RecordId
    audit_sequence: int
    verdict: Verdict
    transition_allowed: bool

    def __post_init__(self) -> None:
        for value in (self.checkpoint_id, self.target_id, self.audit_event_id):
            require_digest(value)
        if type(self.audit_sequence) is not int or self.audit_sequence <= 0:
            raise CanonicalJSONError("receipt audit sequence must be positive")
        if type(self.verdict) is not Verdict:
            raise CanonicalJSONError("receipt verdict is invalid")
        if type(self.transition_allowed) is not bool:
            raise CanonicalJSONError("receipt transition flag is invalid")


def make_record(
    record_type: str,
    payload: JsonObject,
    *,
    schema_version: str = "v1",
) -> StoredRecord:
    encoded = canonical_bytes(payload)
    return StoredRecord(
        record_id=record_id(record_type, schema_version, payload),
        record_type=record_type,
        schema_version=schema_version,
        canonical_bytes=encoded,
    )


def producer_identity_payload(producer: ProducerIdentity) -> JsonObject:
    return {
        "digest": producer.digest,
        "name": producer.name,
        "version": producer.version,
    }


def fact_payload(fact: FactV1) -> JsonObject:
    return {"field_path": list(fact.field_path), "value": fact.value}


def actor_payload(actor: ActorV1) -> JsonObject:
    return {
        "authority": actor.authority.value,
        "producer": producer_identity_payload(actor.producer),
        "scope_ids": list(actor.scope_ids),
    }


def goal_payload(goal: GoalV1) -> JsonObject:
    return {"digest": goal.digest}


def ruleset_payload(ruleset: RulesetV1) -> JsonObject:
    return {"rule_ids": list(ruleset.rule_ids)}


def initialization_intent_payload(intent: InitializationIntentV1) -> JsonObject:
    return {
        "criterion_ids": list(intent.criterion_ids),
        "goal_id": intent.goal_id,
        "instruction_id": intent.instruction_id,
        "policy_id": intent.policy_id,
        "ruleset_id": intent.ruleset_id,
        "session_key": intent.session_key,
        "target_id": intent.target_id,
    }


def criterion_record_payload(criterion: CriterionV1) -> JsonObject:
    return {"digest": criterion.digest, "ordinal": criterion.ordinal}


def criterion_payload(criterion: CriterionV1) -> JsonObject:
    return {
        "criterion_id": criterion.criterion_id,
        **criterion_record_payload(criterion),
    }


def work_item_record_payload(item: WorkItemV1) -> JsonObject:
    return {
        "digest": item.digest,
        "kind": item.kind,
        "status_code": item.status_code,
    }


def work_item_payload(item: WorkItemV1) -> JsonObject:
    return {"work_item_id": item.work_item_id, **work_item_record_payload(item)}


def unresolved_item_record_payload(item: UnresolvedItemV1) -> JsonObject:
    return {"code": item.code, "digest": item.digest}


def unresolved_item_payload(item: UnresolvedItemV1) -> JsonObject:
    return {
        "unresolved_id": item.unresolved_id,
        **unresolved_item_record_payload(item),
    }


def checkpoint_payload(checkpoint: CheckpointV1) -> JsonObject:
    return {
        "acceptance_criteria": [
            criterion_payload(item) for item in checkpoint.acceptance_criteria
        ],
        "accepted_decision_ids": list(checkpoint.accepted_decision_ids),
        "actor_ids": list(checkpoint.actor_ids),
        "assignment_authority": checkpoint.assignment_authority.value,
        "audit_parent_id": checkpoint.audit_parent_id,
        "authority_scopes": [
            path_scope_payload(item) for item in checkpoint.authority_scopes
        ],
        "constraint_digests": list(checkpoint.constraint_digests),
        "created_at": checkpoint.created_at,
        "evidence_ids": list(checkpoint.evidence_ids),
        "goal_id": checkpoint.goal_id,
        "initialization_intent_id": checkpoint.initialization_intent_id,
        "instruction_id": checkpoint.instruction_id,
        "invalidation_ids": list(checkpoint.invalidation_ids),
        "open_assignment_ids": list(checkpoint.open_assignment_ids),
        "parent_checkpoint_id": checkpoint.parent_checkpoint_id,
        "pending_work": [work_item_payload(item) for item in checkpoint.pending_work],
        "policy_id": checkpoint.policy_id,
        "ruleset_id": checkpoint.ruleset_id,
        "target_id": checkpoint.target_id,
        "unresolved": [unresolved_item_payload(item) for item in checkpoint.unresolved],
    }


def checkpoint_receipt_payload(receipt: CheckpointReceipt) -> JsonObject:
    return {
        "audit_event_id": receipt.audit_event_id,
        "audit_sequence": receipt.audit_sequence,
        "checkpoint_id": receipt.checkpoint_id,
        "target_id": receipt.target_id,
        "transition_allowed": receipt.transition_allowed,
        "verdict": receipt.verdict.value,
    }


_ZERO_RECORD_ID = RecordId("sha256:" + "0" * 64)


def build_actor(
    *,
    producer: ProducerIdentity,
    authority: AssignmentAuthority,
    scope_ids: tuple[RecordId, ...],
) -> ActorV1:
    placeholder = ActorV1(_ZERO_RECORD_ID, producer, authority, scope_ids)
    identity = make_record("Actor", actor_payload(placeholder)).record_id
    return ActorV1(identity, producer, authority, scope_ids)


def build_goal(digest: Digest) -> GoalV1:
    placeholder = GoalV1(_ZERO_RECORD_ID, digest)
    identity = make_record("Goal", goal_payload(placeholder)).record_id
    return GoalV1(identity, digest)


def build_ruleset(rule_ids: tuple[RecordId, ...]) -> RulesetV1:
    placeholder = RulesetV1(_ZERO_RECORD_ID, rule_ids)
    identity = make_record("Ruleset", ruleset_payload(placeholder)).record_id
    return RulesetV1(identity, rule_ids)


def build_initialization_intent(
    *,
    session_key: str,
    target_id: RecordId,
    goal_id: RecordId,
    criterion_ids: tuple[RecordId, ...],
    instruction_id: RecordId,
    policy_id: RecordId,
    ruleset_id: RecordId,
) -> InitializationIntentV1:
    placeholder = InitializationIntentV1(
        _ZERO_RECORD_ID,
        session_key,
        target_id,
        goal_id,
        criterion_ids,
        instruction_id,
        policy_id,
        ruleset_id,
    )
    identity = make_record(
        "InitializationIntent", initialization_intent_payload(placeholder)
    ).record_id
    return InitializationIntentV1(
        identity,
        session_key,
        target_id,
        goal_id,
        criterion_ids,
        instruction_id,
        policy_id,
        ruleset_id,
    )


def build_criterion(*, ordinal: int, digest: Digest) -> CriterionV1:
    placeholder = CriterionV1(_ZERO_RECORD_ID, ordinal, digest)
    identity = make_record("Criterion", criterion_record_payload(placeholder)).record_id
    return CriterionV1(identity, ordinal, digest)


def build_work_item(*, kind: str, status_code: str, digest: Digest) -> WorkItemV1:
    placeholder = WorkItemV1(_ZERO_RECORD_ID, kind, status_code, digest)
    identity = make_record("WorkItem", work_item_record_payload(placeholder)).record_id
    return WorkItemV1(identity, kind, status_code, digest)


def build_unresolved_item(*, code: str, digest: Digest | None) -> UnresolvedItemV1:
    placeholder = UnresolvedItemV1(_ZERO_RECORD_ID, code, digest)
    identity = make_record(
        "UnresolvedItem", unresolved_item_record_payload(placeholder)
    ).record_id
    return UnresolvedItemV1(identity, code, digest)


def build_checkpoint(
    *,
    parent_checkpoint_id: RecordId | None,
    target_id: RecordId,
    goal_id: RecordId,
    acceptance_criteria: tuple[CriterionV1, ...],
    constraint_digests: tuple[Digest, ...],
    instruction_id: RecordId,
    policy_id: RecordId,
    ruleset_id: RecordId,
    actor_ids: tuple[RecordId, ...],
    evidence_ids: tuple[RecordId, ...],
    invalidation_ids: tuple[RecordId, ...],
    accepted_decision_ids: tuple[RecordId, ...],
    pending_work: tuple[WorkItemV1, ...],
    unresolved: tuple[UnresolvedItemV1, ...],
    assignment_authority: AssignmentAuthority,
    authority_scopes: tuple[PathScopeV1, ...],
    open_assignment_ids: tuple[RecordId, ...],
    audit_parent_id: RecordId | None,
    initialization_intent_id: RecordId,
    created_at: LogicalTime,
) -> CheckpointV1:
    def construct(identity: RecordId) -> CheckpointV1:
        return CheckpointV1(
            checkpoint_id=identity,
            parent_checkpoint_id=parent_checkpoint_id,
            target_id=target_id,
            goal_id=goal_id,
            acceptance_criteria=acceptance_criteria,
            constraint_digests=constraint_digests,
            instruction_id=instruction_id,
            policy_id=policy_id,
            ruleset_id=ruleset_id,
            actor_ids=actor_ids,
            evidence_ids=evidence_ids,
            invalidation_ids=invalidation_ids,
            accepted_decision_ids=accepted_decision_ids,
            pending_work=pending_work,
            unresolved=unresolved,
            assignment_authority=assignment_authority,
            authority_scopes=authority_scopes,
            open_assignment_ids=open_assignment_ids,
            audit_parent_id=audit_parent_id,
            initialization_intent_id=initialization_intent_id,
            created_at=created_at,
        )

    placeholder = construct(_ZERO_RECORD_ID)
    identity = make_record("Checkpoint", checkpoint_payload(placeholder)).record_id
    return construct(identity)


def policy_payload(policy: CompiledPolicyV1) -> JsonObject:
    """Return approved persisted fields; raw TOML bytes are deliberately absent."""

    return {
        "approval_operator_ids": list(policy.approval_operator_ids),
        "authoring_digest": policy.authoring_digest,
        "enabled_detectors": list(policy.enabled_detectors),
        "evidence_expiry_seconds": policy.evidence_expiry_seconds,
        "limits": {
            "max_aggregate_bytes": policy.limits.max_aggregate_bytes,
            "max_analyzer_text_bytes": policy.limits.max_analyzer_text_bytes,
            "max_external_json_bytes": policy.limits.max_external_json_bytes,
            "max_file_bytes": policy.limits.max_file_bytes,
            "max_paths": policy.limits.max_paths,
        },
        "max_assignment_authority": policy.max_assignment_authority.value,
        "profile": policy.profile.value,
        "promotion_mode": policy.promotion_mode.value,
        "required_adapter_capabilities": list(policy.required_adapter_capabilities),
        "rollback_operator_ids": list(policy.rollback_operator_ids),
        "severity_by_code": {
            code: verdict.value for code, verdict in policy.severity_by_code
        },
    }
