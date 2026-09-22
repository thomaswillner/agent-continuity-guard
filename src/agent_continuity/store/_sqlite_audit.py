"""Private SQLite canonical audit replay and anchor invariant."""

from __future__ import annotations

import contextlib
import sqlite3
from typing import TYPE_CHECKING, cast

from agent_continuity.kernel.audit import AuditAnchorV1, AuditVerification
from agent_continuity.kernel.canonical import (
    canonical_loads,
    digest_bytes,
    record_id,
    validate_logical_time,
)
from agent_continuity.kernel.model import (
    Digest,
    JsonObject,
    JsonValue,
    LogicalTime,
    RecordId,
    StoredRecord,
)
from agent_continuity.kernel.records import require_digest, require_public_component

from ._sqlite_transactions import (
    _stored_head_update_entries,
    _validate_stored_record,
)
from .base import (
    AuditHeadState,
    HeadState,
    StoreIntegrityError,
    StoreValidationError,
    _normalize_audit_details,
    require_record_id,
)

_SCHEMA_VERSION = b"1"
_EMPTY_AUDIT_ID = RecordId("sha256:" + "0" * 64)
_ALLOWED_LOCAL_KINDS = frozenset({"criterion_text", "goal_text"})
_AUDIT_EVENT_KEYS = frozenset(
    {
        "details",
        "head_updates",
        "inserted_record_ids",
        "kind",
        "local_values",
        "logical_time",
        "previous_event_id",
        "record_ids",
        "sequence",
        "store_id",
        "subject_id",
    }
)


def _head_from_payload(value: object) -> HeadState | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != {
        "audit_event_id",
        "audit_sequence",
        "record_id",
    }:
        raise StoreIntegrityError("audit head payload is invalid")
    payload = cast(dict[str, object], value)
    try:
        return HeadState(
            record_id=RecordId(cast(str, payload["record_id"])),
            audit_event_id=RecordId(cast(str, payload["audit_event_id"])),
            audit_sequence=cast(int, payload["audit_sequence"]),
        )
    except (TypeError, ValueError) as error:
        raise StoreIntegrityError("audit head payload is invalid") from error


def _verified_audit_event_payload(
    raw_bytes: bytes,
    event_id_value: RecordId,
) -> JsonObject:
    try:
        require_digest(event_id_value)
        payload = canonical_loads(raw_bytes)
    except ValueError as error:
        raise StoreIntegrityError("audit event bytes are invalid") from error
    if set(payload) != _AUDIT_EVENT_KEYS:
        raise StoreIntegrityError("audit event fields are invalid")
    if record_id("AuditEvent/v1", "v1", payload) != event_id_value:
        raise StoreIntegrityError("audit event ID is invalid")
    return payload


class _SQLiteAuditMixin:
    """Own canonical event decoding, causal replay, reconciliation, and anchors."""

    if TYPE_CHECKING:
        _connection: sqlite3.Connection
        _trusted_anchor: AuditAnchorV1 | None
        store_id: str

        def _ensure_open(self) -> None: ...

    def _read_audit_head(self, connection: sqlite3.Connection) -> AuditHeadState | None:
        row = connection.execute(
            "SELECT event_id, sequence FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        try:
            return AuditHeadState(
                audit_event_id=RecordId(cast(str, row[0])),
                audit_sequence=cast(int, row[1]),
            )
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError("stored audit head is invalid") from error

    def read_audit_head(self) -> AuditHeadState | None:
        self._ensure_open()
        return self._read_audit_head(self._connection)

    def _verify_state(
        self,
        connection: sqlite3.Connection,
        *,
        anchor: AuditAnchorV1 | None,
    ) -> tuple[bool, AuditHeadState | None, bool]:
        audit_head: AuditHeadState | None = None
        try:
            metadata = {
                cast(str, key): bytes(value)
                for key, value in connection.execute(
                    "SELECT key, value FROM metadata"
                ).fetchall()
            }
            if metadata != {
                "schema_version": _SCHEMA_VERSION,
                "store_id": self.store_id.encode("utf-8"),
            }:
                raise StoreIntegrityError("metadata is inconsistent")
            records: dict[RecordId, StoredRecord] = {}
            for row in connection.execute(
                "SELECT record_id, record_type, schema_version, canonical_bytes "
                "FROM records ORDER BY record_id"
            ):
                candidate = StoredRecord(
                    record_id=RecordId(cast(str, row[0])),
                    record_type=cast(str, row[1]),
                    schema_version=cast(str, row[2]),
                    canonical_bytes=bytes(row[3]),
                )
                validated = _validate_stored_record(candidate)
                records[validated.record_id] = validated
            local_rows: dict[tuple[Digest, str], bytes] = {}
            for digest, kind, value in connection.execute(
                "SELECT digest, kind, value FROM sensitive_local_values "
                "ORDER BY digest, kind"
            ):
                digest_value = Digest(cast(str, digest))
                kind_value = cast(str, kind)
                require_digest(digest_value)
                if kind_value not in _ALLOWED_LOCAL_KINDS:
                    raise StoreIntegrityError("stored local-value kind is invalid")
                bytes_value = bytes(value)
                if digest_bytes(bytes_value) != digest_value:
                    raise StoreIntegrityError("stored local-value digest is invalid")
                local_rows[(digest_value, kind_value)] = bytes_value
            replayed_heads: dict[str, HeadState] = {}
            inserted_records: set[RecordId] = set()
            referenced_locals: set[tuple[Digest, str]] = set()
            previous_event_id: RecordId | None = None
            rows = connection.execute(
                "SELECT sequence, event_id, previous_event_id, canonical_bytes "
                "FROM audit_events ORDER BY sequence"
            ).fetchall()
            for expected_sequence, row in enumerate(rows, start=1):
                sequence, event_id_raw, previous_raw, raw_bytes = row
                if sequence != expected_sequence:
                    raise StoreIntegrityError("audit sequence is not contiguous")
                event_id_value = RecordId(cast(str, event_id_raw))
                require_digest(event_id_value)
                previous_value = (
                    None if previous_raw is None else RecordId(cast(str, previous_raw))
                )
                if previous_value != previous_event_id:
                    raise StoreIntegrityError("audit linkage is invalid")
                payload = _verified_audit_event_payload(
                    bytes(raw_bytes), event_id_value
                )
                if (
                    payload["sequence"] != sequence
                    or payload["previous_event_id"] != previous_value
                    or payload["store_id"] != self.store_id
                ):
                    raise StoreIntegrityError("audit event chain metadata is invalid")
                validate_logical_time(cast(str, payload["logical_time"]))
                require_public_component(
                    cast(str, payload["kind"]), field="audit event kind"
                )
                if (
                    type(payload["details"]) is not dict
                    or _normalize_audit_details(payload["details"])
                    != payload["details"]
                ):
                    raise StoreIntegrityError("audit event details are invalid")
                record_ids = self._verified_id_list(payload["record_ids"])
                inserted_ids = self._verified_id_list(payload["inserted_record_ids"])
                if not set(inserted_ids).issubset(record_ids):
                    raise StoreIntegrityError("inserted record IDs are not requested")
                if inserted_records.intersection(inserted_ids):
                    raise StoreIntegrityError("record is inserted by multiple events")
                event_available_records = inserted_records | set(inserted_ids)
                if not set(record_ids).issubset(event_available_records):
                    raise StoreIntegrityError(
                        "audit event references a record before insertion"
                    )
                subject = RecordId(cast(str, payload["subject_id"]))
                require_digest(subject)
                if subject not in event_available_records:
                    raise StoreIntegrityError(
                        "audit subject record is unavailable at event prefix"
                    )
                inserted_records.update(inserted_ids)
                local_values = payload["local_values"]
                if type(local_values) is not list:
                    raise StoreIntegrityError("audit local-value list is invalid")
                local_identities: list[tuple[Digest, str]] = []
                for item in local_values:
                    if type(item) is not dict or set(item) != {"digest", "kind"}:
                        raise StoreIntegrityError(
                            "audit local-value identity is invalid"
                        )
                    item_object = cast(dict[str, object], item)
                    identity = (
                        Digest(cast(str, item_object["digest"])),
                        cast(str, item_object["kind"]),
                    )
                    require_digest(identity[0])
                    if identity not in local_rows:
                        raise StoreIntegrityError("audit local-value row is absent")
                    local_identities.append(identity)
                if local_identities != sorted(set(local_identities)):
                    raise StoreIntegrityError("audit local values are not ordered")
                if sequence != 1 and local_identities:
                    raise StoreIntegrityError(
                        "sensitive-local values originate only at genesis"
                    )
                referenced_locals.update(local_identities)
                for (
                    name,
                    expected_payload,
                    new_record_payload,
                ) in _stored_head_update_entries(payload["head_updates"]):
                    expected = _head_from_payload(expected_payload)
                    if replayed_heads.get(name) != expected:
                        raise StoreIntegrityError("audit head CAS history is invalid")
                    new_record_id = RecordId(cast(str, new_record_payload))
                    require_record_id(new_record_id, field="audit new record ID")
                    if new_record_id not in event_available_records:
                        raise StoreIntegrityError(
                            "audit head record is unavailable at event prefix"
                        )
                    replayed_heads[name] = HeadState(
                        new_record_id, event_id_value, sequence
                    )
                previous_event_id = event_id_value
                audit_head = AuditHeadState(event_id_value, sequence)
            actual_heads = {
                cast(str, name): HeadState(
                    RecordId(cast(str, record_id_raw)),
                    RecordId(cast(str, event_id_raw)),
                    cast(int, sequence),
                )
                for name, record_id_raw, event_id_raw, sequence in connection.execute(
                    "SELECT name, record_id, audit_event_id, audit_sequence "
                    "FROM heads ORDER BY name"
                )
            }
            if actual_heads != replayed_heads:
                raise StoreIntegrityError("head projections do not match audit replay")
            if set(records) != inserted_records:
                raise StoreIntegrityError(
                    "record table does not match audit insertions"
                )
            if set(local_rows) != referenced_locals:
                raise StoreIntegrityError(
                    "sensitive-local table does not match audit references"
                )
            if audit_head is None and (records or local_rows or actual_heads):
                raise StoreIntegrityError("store data exists without audit history")
            anchor_matched = anchor is None
            if anchor is not None:
                if (
                    anchor.store_id != self.store_id
                    or audit_head is None
                    or audit_head.audit_sequence < anchor.audit_sequence
                ):
                    anchor_matched = False
                else:
                    anchor_row = connection.execute(
                        "SELECT event_id FROM audit_events WHERE sequence = ?",
                        (anchor.audit_sequence,),
                    ).fetchone()
                    anchor_matched = (
                        anchor_row is not None and anchor_row[0] == anchor.audit_head_id
                    )
            return anchor_matched, audit_head, anchor_matched
        except (sqlite3.Error, KeyError, TypeError, ValueError, StoreIntegrityError):
            with contextlib.suppress(StoreIntegrityError):
                audit_head = self._read_audit_head(connection)
            return False, audit_head, False

    @staticmethod
    def _verified_id_list(value: JsonValue) -> tuple[RecordId, ...]:
        if type(value) is not list:
            raise StoreIntegrityError("audit record ID list is invalid")
        result: list[RecordId] = []
        for item in value:
            record_id_value = RecordId(cast(str, item))
            require_digest(record_id_value)
            result.append(record_id_value)
        if result != sorted(set(result)):
            raise StoreIntegrityError("audit record IDs are not unique and ordered")
        return tuple(result)

    def verify_audit(self, anchor: AuditAnchorV1 | None = None) -> AuditVerification:
        self._ensure_open()
        if anchor is not None and type(anchor) is not AuditAnchorV1:
            raise StoreValidationError("anchor must be AuditAnchorV1 or null")
        effective_anchor = self._trusted_anchor if anchor is None else anchor
        valid, audit_head, anchor_matched = self._verify_state(
            self._connection, anchor=effective_anchor
        )
        if (
            self._trusted_anchor is not None
            and anchor is not None
            and anchor != self._trusted_anchor
        ):
            trusted_valid, trusted_head, trusted_matched = self._verify_state(
                self._connection, anchor=self._trusted_anchor
            )
            valid = valid and trusted_valid and trusted_matched
            if trusted_head != audit_head:
                valid = False
        if audit_head is None:
            return AuditVerification(
                store_id=self.store_id,
                audit_sequence=0,
                audit_head_id=_EMPTY_AUDIT_ID,
                supplied_anchor_matched=False,
                valid=valid and effective_anchor is None,
            )
        return AuditVerification(
            store_id=self.store_id,
            audit_sequence=audit_head.audit_sequence,
            audit_head_id=audit_head.audit_event_id,
            supplied_anchor_matched=(effective_anchor is not None and anchor_matched),
            valid=valid,
        )

    def make_anchor(
        self,
        *,
        created_at: LogicalTime,
        label: str | None,
    ) -> AuditAnchorV1:
        self._ensure_open()
        validate_logical_time(created_at)
        verification = self.verify_audit()
        if not verification.valid or verification.audit_sequence == 0:
            raise StoreIntegrityError("cannot anchor an empty or invalid audit chain")
        return AuditAnchorV1(
            store_id=self.store_id,
            audit_sequence=verification.audit_sequence,
            audit_head_id=verification.audit_head_id,
            created_at=created_at,
            label=label,
        )
