"""Strict Evidence/v1 records with deterministic invalidation inputs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from .canonical import canonical_bytes, record_id, validate_logical_time
from .model import (
    Digest,
    JsonObject,
    JsonScalar,
    JsonValue,
    LogicalTime,
    RecordId,
    StoredRecord,
)
from .records import (
    FactV1,
    ProducerIdentity,
    RecordSchemaError,
    make_record,
    require_digest,
)


class EvidenceAuthority(StrEnum):
    DETERMINISTIC = "deterministic"
    ADVISORY = "advisory"


class EvidenceKind(StrEnum):
    CITATION = "citation"
    COMMAND = "command"
    STRUCTURED_CLAIM = "structured_claim"
    TARGET = "target"
    HARNESS = "harness"


class EvidenceCompleteness(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    TRUNCATED = "truncated"
    UNAVAILABLE = "unavailable"


class InvalidatorKind(StrEnum):
    CITATION = "citation"
    EVIDENCE_DEPENDENCY = "evidence_dependency"
    TARGET = "target"
    CHECKPOINT = "checkpoint"
    PRODUCER = "producer"
    POLICY = "policy"


@dataclass(frozen=True, slots=True)
class InvalidatorV1:
    kind: InvalidatorKind
    subject_id: RecordId
    required: bool

    def __post_init__(self) -> None:
        if type(self.kind) is not InvalidatorKind:
            raise RecordSchemaError("invalidator kind is invalid")
        try:
            require_digest(self.subject_id)
        except ValueError as error:
            raise RecordSchemaError("invalidator subject is invalid") from error
        if type(self.required) is not bool:
            raise RecordSchemaError("invalidator required is invalid")


@dataclass(frozen=True, slots=True)
class EvidenceV1:
    evidence_id: RecordId
    kind: EvidenceKind
    subject_digest: Digest
    authority: EvidenceAuthority
    producer: ProducerIdentity
    target_id: RecordId
    checkpoint_id: RecordId
    observed_at: LogicalTime
    expires_at: LogicalTime | None
    completeness: EvidenceCompleteness
    terminal_status: int | None
    declared_output_digest: Digest | None
    observed_output_digest: Digest | None
    collected_check_count: int | None
    pagination_complete: bool | None
    payload_digest: Digest
    facts: tuple[FactV1, ...]
    invalidators: tuple[InvalidatorV1, ...]

    def __post_init__(self) -> None:
        validate_evidence(self)

    def record(self) -> StoredRecord:
        validate_evidence(self)
        return make_record("Evidence", evidence_payload(self))


def invalidator_payload(value: InvalidatorV1) -> JsonObject:
    return {
        "kind": value.kind.value,
        "required": value.required,
        "subject_id": value.subject_id,
    }


def _require_optional_digest(value: Digest | None, *, field: str) -> None:
    if value is None:
        return
    try:
        require_digest(value)
    except ValueError as error:
        raise RecordSchemaError(f"{field} is invalid") from error


def _require_canonical_items(
    values: tuple[object, ...],
    *,
    field: str,
    payload: Callable[[object], JsonObject],
) -> None:
    if type(values) is not tuple:
        raise RecordSchemaError(f"{field} must be an exact tuple")
    encoded = tuple(canonical_bytes(payload(value)) for value in values)
    if encoded != tuple(sorted(encoded)) or len(encoded) != len(set(encoded)):
        raise RecordSchemaError(f"{field} must be unique and canonically sorted")


def _validate_evidence_content(value: EvidenceV1) -> None:
    if type(value) is not EvidenceV1:
        raise RecordSchemaError("evidence is invalid")
    if type(value.kind) is not EvidenceKind:
        raise RecordSchemaError("evidence kind is invalid")
    if type(value.authority) is not EvidenceAuthority:
        raise RecordSchemaError("evidence authority is invalid")
    if type(value.producer) is not ProducerIdentity:
        raise RecordSchemaError("evidence producer is invalid")
    if type(value.completeness) is not EvidenceCompleteness:
        raise RecordSchemaError("evidence completeness is invalid")
    for field, digest in (
        ("evidence identifier", value.evidence_id),
        ("subject digest", value.subject_digest),
        ("target identifier", value.target_id),
        ("checkpoint identifier", value.checkpoint_id),
        ("payload digest", value.payload_digest),
    ):
        try:
            require_digest(digest)
        except ValueError as error:
            raise RecordSchemaError(f"evidence {field} is invalid") from error
    if type(value.observed_at) is not str:
        raise RecordSchemaError("evidence observation time is invalid")
    try:
        validate_logical_time(value.observed_at)
    except ValueError as error:
        raise RecordSchemaError("evidence observation time is invalid") from error
    if value.expires_at is not None:
        if type(value.expires_at) is not str:
            raise RecordSchemaError("evidence expiry is invalid")
        try:
            validate_logical_time(value.expires_at)
        except ValueError as error:
            raise RecordSchemaError("evidence expiry is invalid") from error
        if value.expires_at < value.observed_at:
            raise RecordSchemaError("evidence expiry precedes observation")
    if value.terminal_status is not None and type(value.terminal_status) is not int:
        raise RecordSchemaError("evidence terminal status is invalid")
    _require_optional_digest(
        value.declared_output_digest, field="evidence declared output digest"
    )
    _require_optional_digest(
        value.observed_output_digest, field="evidence observed output digest"
    )
    if value.collected_check_count is not None and (
        type(value.collected_check_count) is not int
        or value.collected_check_count < 0
    ):
        raise RecordSchemaError("evidence collected check count is invalid")
    if (
        value.pagination_complete is not None
        and type(value.pagination_complete) is not bool
    ):
        raise RecordSchemaError("evidence pagination completeness is invalid")
    if type(value.facts) is not tuple or any(
        type(fact) is not FactV1 for fact in value.facts
    ):
        raise RecordSchemaError("evidence facts are invalid")
    _require_canonical_items(
        value.facts,
        field="evidence facts",
        payload=lambda item: fact_payload(cast(FactV1, item)),
    )
    if value.authority is EvidenceAuthority.DETERMINISTIC and not value.facts:
        raise RecordSchemaError("deterministic evidence requires facts")
    if type(value.invalidators) is not tuple or any(
        type(invalidator) is not InvalidatorV1 for invalidator in value.invalidators
    ):
        raise RecordSchemaError("evidence invalidators are invalid")
    _require_canonical_items(
        value.invalidators,
        field="evidence invalidators",
        payload=lambda item: invalidator_payload(cast(InvalidatorV1, item)),
    )
    if (
        value.kind is EvidenceKind.COMMAND
        and value.completeness is EvidenceCompleteness.COMPLETE
        and (
            value.terminal_status is None
            or value.declared_output_digest is None
            or value.observed_output_digest is None
            or value.declared_output_digest != value.observed_output_digest
            or value.collected_check_count is None
            or value.collected_check_count <= 0
            or value.pagination_complete is not True
        )
    ):
        raise RecordSchemaError("complete command evidence receipt is invalid")


def validate_evidence(evidence: EvidenceV1) -> None:
    """Reject Evidence/v1 that lacks a deterministic identity or receipt."""

    _validate_evidence_content(evidence)
    expected = record_id("Evidence", "v1", evidence_payload(evidence))
    if evidence.evidence_id != expected:
        raise RecordSchemaError("evidence identity is invalid")


def fact_payload(value: FactV1) -> JsonObject:
    return {"field_path": list(value.field_path), "value": value.value}


def evidence_payload(evidence: EvidenceV1) -> JsonObject:
    _validate_evidence_content(evidence)
    return _evidence_payload_fields(
        kind=evidence.kind,
        subject_digest=evidence.subject_digest,
        authority=evidence.authority,
        producer=evidence.producer,
        target_id=evidence.target_id,
        checkpoint_id=evidence.checkpoint_id,
        observed_at=evidence.observed_at,
        expires_at=evidence.expires_at,
        completeness=evidence.completeness,
        terminal_status=evidence.terminal_status,
        declared_output_digest=evidence.declared_output_digest,
        observed_output_digest=evidence.observed_output_digest,
        collected_check_count=evidence.collected_check_count,
        pagination_complete=evidence.pagination_complete,
        payload_digest=evidence.payload_digest,
        facts=evidence.facts,
        invalidators=evidence.invalidators,
    )


def _evidence_payload_fields(
    *,
    kind: EvidenceKind,
    subject_digest: Digest,
    authority: EvidenceAuthority,
    producer: ProducerIdentity,
    target_id: RecordId,
    checkpoint_id: RecordId,
    observed_at: LogicalTime,
    expires_at: LogicalTime | None,
    completeness: EvidenceCompleteness,
    terminal_status: int | None,
    declared_output_digest: Digest | None,
    observed_output_digest: Digest | None,
    collected_check_count: int | None,
    pagination_complete: bool | None,
    payload_digest: Digest,
    facts: tuple[FactV1, ...],
    invalidators: tuple[InvalidatorV1, ...],
) -> JsonObject:
    return {
        "authority": authority.value,
        "checkpoint_id": checkpoint_id,
        "collected_check_count": collected_check_count,
        "completeness": completeness.value,
        "declared_output_digest": declared_output_digest,
        "expires_at": expires_at,
        "facts": [fact_payload(fact) for fact in facts],
        "invalidators": [
            invalidator_payload(invalidator) for invalidator in invalidators
        ],
        "kind": kind.value,
        "observed_at": observed_at,
        "observed_output_digest": observed_output_digest,
        "pagination_complete": pagination_complete,
        "payload_digest": payload_digest,
        "producer": {
            "digest": producer.digest,
            "name": producer.name,
            "version": producer.version,
        },
        "subject_digest": subject_digest,
        "target_id": target_id,
        "terminal_status": terminal_status,
    }


def evidence_v1(
    *,
    kind: EvidenceKind,
    subject_digest: Digest,
    authority: EvidenceAuthority,
    producer: ProducerIdentity,
    target_id: RecordId,
    checkpoint_id: RecordId,
    observed_at: LogicalTime,
    expires_at: LogicalTime | None,
    completeness: EvidenceCompleteness,
    terminal_status: int | None,
    declared_output_digest: Digest | None,
    observed_output_digest: Digest | None,
    collected_check_count: int | None,
    pagination_complete: bool | None,
    payload_digest: Digest,
    facts: tuple[FactV1, ...],
    invalidators: tuple[InvalidatorV1, ...],
) -> EvidenceV1:
    """Build proof-bearing Evidence/v1 with a derived canonical identity."""

    payload = _evidence_payload_fields(
        kind=kind,
        subject_digest=subject_digest,
        authority=authority,
        producer=producer,
        target_id=target_id,
        checkpoint_id=checkpoint_id,
        observed_at=observed_at,
        expires_at=expires_at,
        completeness=completeness,
        terminal_status=terminal_status,
        declared_output_digest=declared_output_digest,
        observed_output_digest=observed_output_digest,
        collected_check_count=collected_check_count,
        pagination_complete=pagination_complete,
        payload_digest=payload_digest,
        facts=facts,
        invalidators=invalidators,
    )
    identity = record_id("Evidence", "v1", payload)
    return EvidenceV1(
        identity,
        kind,
        subject_digest,
        authority,
        producer,
        target_id,
        checkpoint_id,
        observed_at,
        expires_at,
        completeness,
        terminal_status,
        declared_output_digest,
        observed_output_digest,
        collected_check_count,
        pagination_complete,
        payload_digest,
        facts,
        invalidators,
    )


def evidence_from_payload(payload: JsonObject) -> EvidenceV1:
    """Decode Evidence/v1 only from exact canonical fields and vocabularies."""

    expected = {
        "authority",
        "checkpoint_id",
        "collected_check_count",
        "completeness",
        "declared_output_digest",
        "expires_at",
        "facts",
        "invalidators",
        "kind",
        "observed_at",
        "observed_output_digest",
        "pagination_complete",
        "payload_digest",
        "producer",
        "subject_digest",
        "target_id",
        "terminal_status",
    }
    if set(payload) != expected:
        raise RecordSchemaError("evidence fields are invalid")
    producer_payload = payload["producer"]
    facts_payload = payload["facts"]
    invalidators_payload = payload["invalidators"]
    if type(producer_payload) is not dict or set(producer_payload) != {
        "digest",
        "name",
        "version",
    }:
        raise RecordSchemaError("evidence producer fields are invalid")
    if type(facts_payload) is not list or type(invalidators_payload) is not list:
        raise RecordSchemaError("evidence collections are invalid")
    try:
        facts = tuple(_fact_from_payload(item) for item in facts_payload)
        invalidators = tuple(
            _invalidator_from_payload(item) for item in invalidators_payload
        )
        return evidence_v1(
            kind=EvidenceKind(_string_field(payload, "kind")),
            subject_digest=Digest(_string_field(payload, "subject_digest")),
            authority=EvidenceAuthority(_string_field(payload, "authority")),
            producer=ProducerIdentity(
                _string_field(producer_payload, "name"),
                _string_field(producer_payload, "version"),
                Digest(_string_field(producer_payload, "digest")),
            ),
            target_id=RecordId(_string_field(payload, "target_id")),
            checkpoint_id=RecordId(_string_field(payload, "checkpoint_id")),
            observed_at=LogicalTime(_string_field(payload, "observed_at")),
            expires_at=(
                None
                if payload["expires_at"] is None
                else LogicalTime(_string_field(payload, "expires_at"))
            ),
            completeness=EvidenceCompleteness(_string_field(payload, "completeness")),
            terminal_status=_optional_integer_field(payload, "terminal_status"),
            declared_output_digest=(
                None
                if payload["declared_output_digest"] is None
                else Digest(_string_field(payload, "declared_output_digest"))
            ),
            observed_output_digest=(
                None
                if payload["observed_output_digest"] is None
                else Digest(_string_field(payload, "observed_output_digest"))
            ),
            collected_check_count=_optional_integer_field(
                payload, "collected_check_count"
            ),
            pagination_complete=_optional_bool_field(payload, "pagination_complete"),
            payload_digest=Digest(_string_field(payload, "payload_digest")),
            facts=facts,
            invalidators=invalidators,
        )
    except RecordSchemaError:
        raise
    except (TypeError, ValueError) as error:
        raise RecordSchemaError("evidence payload is invalid") from error


def _fact_from_payload(payload: object) -> FactV1:
    if type(payload) is not dict or set(payload) != {"field_path", "value"}:
        raise RecordSchemaError("evidence fact fields are invalid")
    field_path = payload["field_path"]
    if type(field_path) is not list:
        raise RecordSchemaError("evidence fact fields are invalid")
    if any(type(item) is not str for item in field_path):
        raise RecordSchemaError("evidence fact fields are invalid")
    value = payload["value"]
    if value is not None and type(value) not in {bool, int, str}:
        raise RecordSchemaError("evidence fact fields are invalid")
    return FactV1(tuple(field_path), cast(JsonScalar, value))


def _invalidator_from_payload(payload: object) -> InvalidatorV1:
    if type(payload) is not dict or set(payload) != {"kind", "required", "subject_id"}:
        raise RecordSchemaError("evidence invalidator fields are invalid")
    return InvalidatorV1(
        InvalidatorKind(_string_field(payload, "kind")),
        RecordId(_string_field(payload, "subject_id")),
        _bool_field(payload, "required"),
    )


def _string_field(payload: JsonObject, field: str) -> str:
    value = payload[field]
    if type(value) is not str:
        raise RecordSchemaError("evidence payload is invalid")
    return value


def _optional_integer_field(payload: JsonObject, field: str) -> int | None:
    value: JsonValue = payload[field]
    if value is None:
        return None
    if type(value) is not int:
        raise RecordSchemaError("evidence payload is invalid")
    return value


def _bool_field(payload: JsonObject, field: str) -> bool:
    value = payload[field]
    if type(value) is not bool:
        raise RecordSchemaError("evidence payload is invalid")
    return value


def _optional_bool_field(payload: JsonObject, field: str) -> bool | None:
    value: JsonValue = payload[field]
    if value is None:
        return None
    if type(value) is not bool:
        raise RecordSchemaError("evidence payload is invalid")
    return value
