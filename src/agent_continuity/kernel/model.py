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
