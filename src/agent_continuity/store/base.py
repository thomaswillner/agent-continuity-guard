"""Public immutable StateStore contracts and typed failures."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from agent_continuity.kernel.audit import AuditAnchorV1, AuditVerification
from agent_continuity.kernel.canonical import (
    canonical_bytes,
    canonical_loads,
    validate_logical_time,
)
from agent_continuity.kernel.model import (
    Digest,
    JsonObject,
    LogicalTime,
    RecordId,
    StoredRecord,
)
from agent_continuity.kernel.records import require_digest, require_public_component

_HEAD_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


class StateStoreError(RuntimeError):
    """Base class for deterministic StateStore failures."""


class StoreValidationError(StateStoreError, ValueError):
    """Caller input violates the public StateStore contract."""


class StoreConflictError(StateStoreError):
    """Expected-head compare-and-swap did not match current state."""


class StoreIntegrityError(StateStoreError):
    """Stored or supplied immutable bytes contradict their identity."""


FaultInjector = Callable[[str], None]


def require_record_id(value: RecordId, *, field: str) -> None:
    if type(value) is not str:
        raise StoreValidationError(f"{field} must be an exact record ID")
    try:
        require_digest(value)
    except ValueError as error:
        raise StoreValidationError(f"{field} must be a lowercase SHA-256 ID") from error


def require_head_name(value: str) -> None:
    if type(value) is not str or _HEAD_NAME_RE.fullmatch(value) is None:
        raise StoreValidationError("head name is not a bounded public identifier")


@dataclass(frozen=True, slots=True)
class HeadState:
    record_id: RecordId
    audit_event_id: RecordId
    audit_sequence: int

    def __post_init__(self) -> None:
        require_record_id(self.record_id, field="head record ID")
        require_record_id(self.audit_event_id, field="head audit event ID")
        if type(self.audit_sequence) is not int or self.audit_sequence <= 0:
            raise StoreValidationError("head audit sequence must be a positive integer")


@dataclass(frozen=True, slots=True)
class AuditHeadState:
    audit_event_id: RecordId
    audit_sequence: int

    def __post_init__(self) -> None:
        require_record_id(self.audit_event_id, field="audit head ID")
        if type(self.audit_sequence) is not int or self.audit_sequence <= 0:
            raise StoreValidationError("audit head sequence must be a positive integer")


@dataclass(frozen=True, slots=True)
class AuditEventDraft:
    kind: str
    subject_id: RecordId
    logical_time: LogicalTime
    details: JsonObject

    def __post_init__(self) -> None:
        try:
            require_public_component(self.kind, field="audit event kind")
        except ValueError as error:
            raise StoreValidationError("audit event kind is invalid") from error
        require_record_id(self.subject_id, field="audit subject ID")
        if type(self.logical_time) is not str:
            raise StoreValidationError("audit logical time must be canonical text")
        try:
            validate_logical_time(self.logical_time)
        except ValueError as error:
            raise StoreValidationError("audit logical time is invalid") from error
        if type(self.details) is not dict:
            raise StoreValidationError("audit details must be an exact JSON object")
        try:
            snapshot = canonical_loads(canonical_bytes(self.details))
        except ValueError as error:
            raise StoreValidationError(
                "audit details are not canonical JSON"
            ) from error
        object.__setattr__(self, "details", snapshot)


@dataclass(frozen=True, slots=True)
class SensitiveLocalValueDraft:
    digest: Digest
    kind: str
    value: bytes
    caller_approved: bool

    def __post_init__(self) -> None:
        if type(self.digest) is not str:
            raise StoreValidationError("local-value digest must be exact text")
        try:
            require_digest(self.digest)
        except ValueError as error:
            raise StoreValidationError("local-value digest is invalid") from error
        if type(self.kind) is not str:
            raise StoreValidationError("local-value kind must be exact text")
        if type(self.value) is not bytes:
            raise StoreValidationError("local value must be exact bytes")
        if type(self.caller_approved) is not bool:
            raise StoreValidationError("caller approval must be an exact boolean")
        object.__setattr__(self, "value", bytes(self.value))


@dataclass(frozen=True, slots=True)
class CommitReceipt:
    head: HeadState
    inserted_record_ids: tuple[RecordId, ...]

    def __post_init__(self) -> None:
        if type(self.head) is not HeadState:
            raise StoreValidationError("commit receipt head is invalid")
        _validate_record_id_tuple(self.inserted_record_ids)


@dataclass(frozen=True, slots=True)
class HeadUpdate:
    name: str
    expected: HeadState | None
    new_record_id: RecordId

    def __post_init__(self) -> None:
        require_head_name(self.name)
        if self.expected is not None and type(self.expected) is not HeadState:
            raise StoreValidationError("expected head must be HeadState or null")
        require_record_id(self.new_record_id, field="new head record ID")


@dataclass(frozen=True, slots=True)
class MultiHeadCommitReceipt:
    heads: tuple[tuple[str, HeadState], ...]
    inserted_record_ids: tuple[RecordId, ...]

    def __post_init__(self) -> None:
        if type(self.heads) is not tuple:
            raise StoreValidationError("receipt heads must be an exact tuple")
        names: list[str] = []
        for item in self.heads:
            if type(item) is not tuple or len(item) != 2:
                raise StoreValidationError("receipt head entry is invalid")
            name, head = item
            require_head_name(name)
            if type(head) is not HeadState:
                raise StoreValidationError("receipt head state is invalid")
            names.append(name)
        if names != sorted(names) or len(names) != len(set(names)):
            raise StoreValidationError("receipt heads must be unique and ordered")
        _validate_record_id_tuple(self.inserted_record_ids)


def _validate_record_id_tuple(values: tuple[RecordId, ...]) -> None:
    if type(values) is not tuple:
        raise StoreValidationError("record IDs must be an exact tuple")
    for value in values:
        require_record_id(value, field="inserted record ID")
    if tuple(sorted(values)) != values or len(values) != len(set(values)):
        raise StoreValidationError("record IDs must be unique and ordered")


class StateStore(Protocol):
    @property
    def store_id(self) -> str: ...

    def read_head(self, name: str) -> HeadState | None: ...

    def read_audit_head(self) -> AuditHeadState | None: ...

    def load_record(self, record_id: RecordId) -> StoredRecord: ...

    def commit(
        self,
        *,
        records: Sequence[StoredRecord],
        local_values: Sequence[SensitiveLocalValueDraft] = (),
        event: AuditEventDraft,
        head_name: str,
        expected_head: HeadState | None,
        new_head_id: RecordId,
    ) -> CommitReceipt: ...

    def commit_many(
        self,
        *,
        records: Sequence[StoredRecord],
        local_values: Sequence[SensitiveLocalValueDraft] = (),
        event: AuditEventDraft,
        head_updates: Sequence[HeadUpdate],
    ) -> MultiHeadCommitReceipt: ...

    def verify_audit(
        self, anchor: AuditAnchorV1 | None = None
    ) -> AuditVerification: ...

    def make_anchor(
        self,
        *,
        created_at: LogicalTime,
        label: str | None,
    ) -> AuditAnchorV1: ...
