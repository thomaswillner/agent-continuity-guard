"""Canonical public audit anchor and verification records."""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonical_bytes, canonical_loads, validate_logical_time
from .model import JsonObject, LogicalTime, RecordId
from .records import require_digest, require_public_component


def _normalized_optional_label(value: str | None) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise ValueError("audit anchor label must be exact text")
    require_public_component(value, field="audit anchor label")
    normalized = canonical_loads(canonical_bytes({"label": value}))["label"]
    if type(normalized) is not str:
        raise ValueError("audit anchor label is invalid")
    return normalized


def _validate_common(
    store_id: str, audit_sequence: int, audit_head_id: RecordId
) -> None:
    require_public_component(store_id, field="audit store ID")
    if type(audit_sequence) is not int or audit_sequence <= 0:
        raise ValueError("audit sequence must be a positive integer")
    if type(audit_head_id) is not str:
        raise ValueError("audit head ID must be exact text")
    require_digest(audit_head_id)


@dataclass(frozen=True, slots=True)
class AuditAnchorV1:
    store_id: str
    audit_sequence: int
    audit_head_id: RecordId
    created_at: LogicalTime
    label: str | None

    def __post_init__(self) -> None:
        _validate_common(self.store_id, self.audit_sequence, self.audit_head_id)
        validate_logical_time(self.created_at)
        object.__setattr__(self, "label", _normalized_optional_label(self.label))


@dataclass(frozen=True, slots=True)
class AuditVerification:
    store_id: str
    audit_sequence: int
    audit_head_id: RecordId
    supplied_anchor_matched: bool
    valid: bool

    def __post_init__(self) -> None:
        require_public_component(self.store_id, field="audit store ID")
        if type(self.audit_sequence) is not int or self.audit_sequence < 0:
            raise ValueError("audit verification sequence must be nonnegative")
        if type(self.audit_head_id) is not str:
            raise ValueError("audit verification head ID must be exact text")
        require_digest(self.audit_head_id)
        if (
            type(self.supplied_anchor_matched) is not bool
            or type(self.valid) is not bool
        ):
            raise ValueError("audit verification flags must be exact booleans")


def audit_anchor_payload(anchor: AuditAnchorV1) -> JsonObject:
    return {
        "audit_head_id": anchor.audit_head_id,
        "audit_sequence": anchor.audit_sequence,
        "created_at": anchor.created_at,
        "label": anchor.label,
        "store_id": anchor.store_id,
    }


def audit_verification_payload(verification: AuditVerification) -> JsonObject:
    return {
        "audit_head_id": verification.audit_head_id,
        "audit_sequence": verification.audit_sequence,
        "store_id": verification.store_id,
        "supplied_anchor_matched": verification.supplied_anchor_matched,
        "valid": verification.valid,
    }
