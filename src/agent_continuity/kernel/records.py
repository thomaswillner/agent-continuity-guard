"""Strict public record helpers for the pure kernel."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import CanonicalJSONError, canonical_bytes, record_id
from .evaluation import Profile, Verdict
from .model import (
    AssignmentAuthority,
    Digest,
    JsonObject,
    JsonScalar,
    PromotionMode,
    RecordId,
    ResourceLimitsV1,
    StoredRecord,
)

_PUBLIC_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")
_FIELD_COMPONENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

SCHEMA_REGISTRY: dict[str, str] = {
    "AuditAnchor/v1": "audit-anchor.schema.json",
    "AuditEvent/v1": "audit-event.schema.json",
    "AuditVerification/v1": "audit-verification.schema.json",
    "CapabilityClaim/v1": "capability-claim.schema.json",
    "EvaluationResult/v1": "evaluation-result.schema.json",
    "Fact/v1": "fact.schema.json",
    "Finding/v1": "finding.schema.json",
    "InstructionManifest/v1": "instruction-manifest.schema.json",
    "PathIdentity/v1": "path-identity.schema.json",
    "PathScope/v1": "path-scope.schema.json",
    "Policy/v1": "policy.schema.json",
    "PolicyTemplate/v1": "policy-template.schema.json",
    "ProducerIdentity/v1": "producer-identity.schema.json",
    "TargetIdentity/v1": "target-identity.schema.json",
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
