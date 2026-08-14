"""Core immutable types shared by the pure kernel."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NewType, TypeAlias

JsonScalar: TypeAlias = bool | int | str | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]

RecordId = NewType("RecordId", str)
Digest = NewType("Digest", str)
LogicalTime = NewType("LogicalTime", str)
SensitiveLocalText = NewType("SensitiveLocalText", str)


class AssignmentAuthority(StrEnum):
    """Authority declared for an external assignment actor."""

    READ_ONLY = "read_only"
    SCOPED_WRITE = "scoped_write"


class PromotionMode(StrEnum):
    """Operator policy for deterministic candidate promotion."""

    AUTOMATIC = "automatic"
    REVIEW = "review"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class ResourceLimitsV1:
    """Identity-bearing resource limits compiled from policy authoring."""

    max_paths: int
    max_file_bytes: int
    max_aggregate_bytes: int
    max_analyzer_text_bytes: int
    max_external_json_bytes: int

    def __post_init__(self) -> None:
        values = (
            self.max_paths,
            self.max_file_bytes,
            self.max_aggregate_bytes,
            self.max_analyzer_text_bytes,
            self.max_external_json_bytes,
        )
        if any(type(value) is not int or value < 1 for value in values):
            raise ValueError("resource limits must be positive exact integers")
        if self.max_analyzer_text_bytes > self.max_file_bytes:
            raise ValueError("analyzer limit cannot exceed file limit")
        if self.max_file_bytes > self.max_aggregate_bytes:
            raise ValueError("file limit cannot exceed aggregate limit")


@dataclass(frozen=True, slots=True)
class StoredRecord:
    """Canonical bytes and identity for one immutable record."""

    record_id: RecordId
    record_type: str
    schema_version: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class SensitiveLocalRef:
    """Secret-safe reference to caller-approved local narrative bytes."""

    digest: Digest
    kind: str
