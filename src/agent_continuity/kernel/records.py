"""Strict public record helpers for the pure kernel."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import CanonicalJSONError, canonical_bytes, record_id
from .model import Digest, JsonObject, JsonScalar, StoredRecord

_PUBLIC_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")
_FIELD_COMPONENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

SCHEMA_REGISTRY: dict[str, str] = {
    "CapabilityClaim/v1": "capability-claim.schema.json",
    "EvaluationResult/v1": "evaluation-result.schema.json",
    "Fact/v1": "fact.schema.json",
    "Finding/v1": "finding.schema.json",
    "InstructionManifest/v1": "instruction-manifest.schema.json",
    "PathIdentity/v1": "path-identity.schema.json",
    "PathScope/v1": "path-scope.schema.json",
    "ProducerIdentity/v1": "producer-identity.schema.json",
    "TargetIdentity/v1": "target-identity.schema.json",
}


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
        if not 1 <= len(self.field_path) <= 8:
            raise CanonicalJSONError("fact field path must have one to eight segments")
        if any(_FIELD_COMPONENT_RE.fullmatch(item) is None for item in self.field_path):
            raise CanonicalJSONError("fact field path contains an invalid segment")
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
