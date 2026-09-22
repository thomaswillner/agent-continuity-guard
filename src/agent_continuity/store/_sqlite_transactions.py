"""Private SQLite normalization and atomic transaction invariant."""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, cast

from agent_continuity.kernel.audit import AuditAnchorV1
from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    canonical_loads,
    digest_bytes,
    record_id,
)
from agent_continuity.kernel.model import (
    Digest,
    JsonObject,
    JsonValue,
    RecordId,
    StoredRecord,
)
from agent_continuity.kernel.records import require_digest

from .base import (
    AuditEventDraft,
    AuditHeadState,
    CommitReceipt,
    FaultInjector,
    HeadState,
    HeadUpdate,
    MultiHeadCommitReceipt,
    SensitiveLocalValueDraft,
    StoreConflictError,
    StoreIntegrityError,
    StoreValidationError,
    _normalize_audit_details,
    require_head_name,
    require_record_id,
)

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
_TRANSACTION_KEYS = (
    "details",
    "head_updates",
    "kind",
    "local_values",
    "logical_time",
    "record_ids",
    "store_id",
    "subject_id",
)


def _head_payload(head: HeadState | None) -> JsonObject | None:
    if head is None:
        return None
    return {
        "audit_event_id": head.audit_event_id,
        "audit_sequence": head.audit_sequence,
        "record_id": head.record_id,
    }


def _validate_stored_record(value: StoredRecord) -> StoredRecord:
    if type(value) is not StoredRecord:
        raise StoreValidationError("records must be exact StoredRecord values")
    if type(value.record_id) is not str:
        raise StoreIntegrityError("record ID is invalid")
    try:
        require_digest(value.record_id)
        if type(value.record_type) is not str or type(value.schema_version) is not str:
            raise CanonicalJSONError("record domains must be exact text")
        payload = canonical_loads(value.canonical_bytes)
        expected = record_id(value.record_type, value.schema_version, payload)
    except (TypeError, ValueError) as error:
        raise StoreIntegrityError("record bytes are not canonical") from error
    if expected != value.record_id:
        raise StoreIntegrityError("record bytes do not match record ID")
    return value


def _normalize_records(records: Sequence[StoredRecord]) -> tuple[StoredRecord, ...]:
    by_id: dict[RecordId, StoredRecord] = {}
    for item in records:
        record = _validate_stored_record(item)
        existing = by_id.get(record.record_id)
        if existing is not None:
            if existing != record:
                raise StoreIntegrityError("request contains conflicting record bytes")
            raise StoreValidationError("request record IDs must be unique")
        by_id[record.record_id] = record
    return tuple(by_id[key] for key in sorted(by_id))


def _normalize_local_values(
    values: Sequence[SensitiveLocalValueDraft],
) -> tuple[SensitiveLocalValueDraft, ...]:
    by_identity: dict[tuple[Digest, str], SensitiveLocalValueDraft] = {}
    for value in values:
        if type(value) is not SensitiveLocalValueDraft:
            raise StoreValidationError(
                "local values must be exact SensitiveLocalValueDraft values"
            )
        if not value.caller_approved:
            raise StoreValidationError("local value lacks explicit caller approval")
        if value.kind not in _ALLOWED_LOCAL_KINDS:
            raise StoreValidationError("local-value kind is not allowed in schema v1")
        if digest_bytes(value.value) != value.digest:
            raise StoreValidationError("local-value bytes do not match supplied digest")
        identity = (value.digest, value.kind)
        existing = by_identity.get(identity)
        if existing is not None:
            if existing.value != value.value:
                raise StoreIntegrityError(
                    "request contains conflicting local-value bytes"
                )
            raise StoreValidationError("local-value identities must be unique")
        by_identity[identity] = value
    return tuple(by_identity[key] for key in sorted(by_identity))


def _normalize_head_updates(updates: Sequence[HeadUpdate]) -> tuple[HeadUpdate, ...]:
    normalized = tuple(updates)
    if not normalized:
        raise StoreValidationError("commit requires at least one head update")
    if any(type(item) is not HeadUpdate for item in normalized):
        raise StoreValidationError("head updates must be exact HeadUpdate values")
    names = [item.name for item in normalized]
    if len(names) != len(set(names)):
        raise StoreValidationError("head update names must be unique")
    return tuple(sorted(normalized, key=lambda item: item.name))


def _head_update_payload(update: HeadUpdate) -> JsonObject:
    return {
        "expected": _head_payload(update.expected),
        "new_record_id": update.new_record_id,
    }


def _head_updates_payload(updates: tuple[HeadUpdate, ...]) -> JsonObject:
    return {update.name: _head_update_payload(update) for update in updates}


def _stored_head_update_entries(
    value: object,
) -> tuple[tuple[str, JsonValue, JsonValue], ...]:
    entries: list[tuple[str, JsonValue, JsonValue]] = []
    if type(value) is dict:
        if not value:
            raise StoreIntegrityError("audit head updates are invalid")
        updates = cast(dict[str, object], value)
        for name in sorted(updates):
            item = updates[name]
            if type(item) is not dict or set(item) != {
                "expected",
                "new_record_id",
            }:
                raise StoreIntegrityError("audit head update is invalid")
            require_head_name(name)
            item_object = cast(dict[str, object], item)
            entries.append(
                (
                    name,
                    cast(JsonValue, item_object["expected"]),
                    cast(JsonValue, item_object["new_record_id"]),
                )
            )
        return tuple(entries)
    if type(value) is not list or not value:
        raise StoreIntegrityError("audit head updates are invalid")
    for item in value:
        if type(item) is not dict or set(item) != {
            "expected",
            "name",
            "new_record_id",
        }:
            raise StoreIntegrityError("audit head update is invalid")
        item_object = cast(dict[str, object], item)
        name = cast(str, item_object["name"])
        require_head_name(name)
        entries.append(
            (
                name,
                cast(JsonValue, item_object["expected"]),
                cast(JsonValue, item_object["new_record_id"]),
            )
        )
    names = [name for name, _expected, _new_record_id in entries]
    if names != sorted(names) or len(names) != len(set(names)):
        raise StoreIntegrityError("audit head updates are not ordered")
    return tuple(entries)


def _local_value_payload(value: SensitiveLocalValueDraft) -> JsonObject:
    return {"digest": value.digest, "kind": value.kind}


class _SQLiteTransactionsMixin:
    """Own normalized BEGIN/COMMIT, CAS, retry, rollback, and reconciliation."""

    if TYPE_CHECKING:
        _connection: sqlite3.Connection
        _read_only: bool
        _memory: bool
        _trusted_anchor: AuditAnchorV1 | None
        _fault_injector: FaultInjector | None
        store_id: str

        def _ensure_open(self) -> None: ...
        def _assert_database_live(self) -> None: ...
        def _connect(
            self,
            *,
            read_only: bool,
            initialize_journal: bool,
        ) -> sqlite3.Connection: ...
        def _read_audit_head(
            self, connection: sqlite3.Connection
        ) -> AuditHeadState | None: ...
        def _verify_state(
            self,
            connection: sqlite3.Connection,
            *,
            anchor: AuditAnchorV1 | None,
        ) -> tuple[bool, AuditHeadState | None, bool]: ...

    @contextmanager
    def _read_snapshot(self) -> Iterator[None]:
        """Pin a coherent SQLite snapshot for one bounded observational operation."""

        self._ensure_open()
        if self._connection.in_transaction:
            raise StoreIntegrityError("SQLite read snapshot is already active")
        try:
            self._connection.execute("BEGIN")
            yield
            self._connection.execute("COMMIT")
        except sqlite3.Error:
            if self._connection.in_transaction:
                with contextlib.suppress(sqlite3.Error):
                    self._connection.execute("ROLLBACK")
            raise StoreIntegrityError("SQLite read snapshot failed") from None
        except Exception:
            if self._connection.in_transaction:
                with contextlib.suppress(sqlite3.Error):
                    self._connection.execute("ROLLBACK")
            raise

    def _fault(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)

    def _read_head(self, connection: sqlite3.Connection, name: str) -> HeadState | None:
        row = connection.execute(
            "SELECT record_id, audit_event_id, audit_sequence "
            "FROM heads WHERE name = ?",
            (name,),
        ).fetchone()
        if row is None:
            return None
        try:
            return HeadState(
                record_id=RecordId(cast(str, row[0])),
                audit_event_id=RecordId(cast(str, row[1])),
                audit_sequence=cast(int, row[2]),
            )
        except (TypeError, ValueError) as error:
            raise StoreIntegrityError("stored head is invalid") from error

    def read_head(self, name: str) -> HeadState | None:
        self._ensure_open()
        require_head_name(name)
        return self._read_head(self._connection, name)

    @staticmethod
    def _load_record_from_connection(
        connection: sqlite3.Connection, record_id_value: RecordId
    ) -> StoredRecord:
        row = connection.execute(
            "SELECT record_type, schema_version, canonical_bytes "
            "FROM records WHERE record_id = ?",
            (record_id_value,),
        ).fetchone()
        if row is None:
            raise KeyError(record_id_value)
        record = StoredRecord(
            record_id=record_id_value,
            record_type=cast(str, row[0]),
            schema_version=cast(str, row[1]),
            canonical_bytes=bytes(row[2]),
        )
        return _validate_stored_record(record)

    def load_record(self, record_id_value: RecordId) -> StoredRecord:
        self._ensure_open()
        require_record_id(record_id_value, field="record ID")
        return self._load_record_from_connection(self._connection, record_id_value)

    def _transaction_signature(
        self,
        *,
        records: tuple[StoredRecord, ...],
        local_values: tuple[SensitiveLocalValueDraft, ...],
        event: AuditEventDraft,
        head_updates: tuple[HeadUpdate, ...],
    ) -> JsonObject:
        return {
            "details": _normalize_audit_details(event.details),
            "head_updates": _head_updates_payload(head_updates),
            "kind": event.kind,
            "local_values": [_local_value_payload(item) for item in local_values],
            "logical_time": event.logical_time,
            "record_ids": [item.record_id for item in records],
            "store_id": self.store_id,
            "subject_id": event.subject_id,
        }

    @staticmethod
    def _event_signature(payload: JsonObject) -> JsonObject:
        signature = {key: payload[key] for key in _TRANSACTION_KEYS}
        signature["head_updates"] = {
            name: {"expected": expected, "new_record_id": new_record_id}
            for name, expected, new_record_id in _stored_head_update_entries(
                payload["head_updates"]
            )
        }
        return signature

    def _existing_retry_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        signature: JsonObject,
        head_updates: tuple[HeadUpdate, ...],
    ) -> MultiHeadCommitReceipt | None:
        rows = connection.execute(
            "SELECT sequence, event_id, canonical_bytes FROM audit_events "
            "ORDER BY sequence DESC"
        ).fetchall()
        for row in rows:
            try:
                sequence = cast(int, row[0])
                event_id_value = RecordId(cast(str, row[1]))
                from ._sqlite_audit import _verified_audit_event_payload

                payload = _verified_audit_event_payload(bytes(row[2]), event_id_value)
                if self._event_signature(payload) != signature:
                    continue
                inserted_raw = payload["inserted_record_ids"]
                if type(inserted_raw) is not list:
                    raise StoreIntegrityError("stored retry record IDs are invalid")
                inserted = tuple(RecordId(cast(str, item)) for item in inserted_raw)
                heads: list[tuple[str, HeadState]] = []
                for update in head_updates:
                    current = self._read_head(connection, update.name)
                    expected_current = HeadState(
                        record_id=update.new_record_id,
                        audit_event_id=event_id_value,
                        audit_sequence=sequence,
                    )
                    if current != expected_current:
                        break
                    heads.append((update.name, expected_current))
                else:
                    return MultiHeadCommitReceipt(tuple(heads), inserted)
            except (KeyError, TypeError, ValueError) as error:
                raise StoreIntegrityError("stored retry event is invalid") from error
        return None

    @staticmethod
    def _insert_records(
        connection: sqlite3.Connection,
        records: tuple[StoredRecord, ...],
    ) -> tuple[RecordId, ...]:
        inserted: list[RecordId] = []
        for record in records:
            row = connection.execute(
                "SELECT record_type, schema_version, canonical_bytes "
                "FROM records WHERE record_id = ?",
                (record.record_id,),
            ).fetchone()
            if row is not None:
                existing = StoredRecord(
                    record_id=record.record_id,
                    record_type=cast(str, row[0]),
                    schema_version=cast(str, row[1]),
                    canonical_bytes=bytes(row[2]),
                )
                if existing != record:
                    raise StoreIntegrityError(
                        "stored record bytes contradict record ID"
                    )
                continue
            connection.execute(
                "INSERT INTO records("
                "record_id, record_type, schema_version, canonical_bytes"
                ") "
                "VALUES (?, ?, ?, ?)",
                (
                    record.record_id,
                    record.record_type,
                    record.schema_version,
                    sqlite3.Binary(record.canonical_bytes),
                ),
            )
            inserted.append(record.record_id)
        return tuple(inserted)

    @staticmethod
    def _insert_local_values(
        connection: sqlite3.Connection,
        values: tuple[SensitiveLocalValueDraft, ...],
    ) -> None:
        for value in values:
            row = connection.execute(
                "SELECT value FROM sensitive_local_values "
                "WHERE digest = ? AND kind = ?",
                (value.digest, value.kind),
            ).fetchone()
            if row is not None:
                if bytes(row[0]) != value.value:
                    raise StoreIntegrityError(
                        "stored local-value bytes contradict digest and kind"
                    )
                continue
            connection.execute(
                "INSERT INTO sensitive_local_values(digest, kind, value) "
                "VALUES (?, ?, ?)",
                (value.digest, value.kind, sqlite3.Binary(value.value)),
            )

    def _build_event_payload(
        self,
        *,
        signature: JsonObject,
        inserted_record_ids: tuple[RecordId, ...],
        previous_event_id: RecordId | None,
        sequence: int,
    ) -> JsonObject:
        payload = dict(signature)
        payload.update(
            {
                "inserted_record_ids": list(inserted_record_ids),
                "previous_event_id": previous_event_id,
                "sequence": sequence,
            }
        )
        return payload

    def commit(
        self,
        *,
        records: Sequence[StoredRecord],
        local_values: Sequence[SensitiveLocalValueDraft] = (),
        event: AuditEventDraft,
        head_name: str,
        expected_head: HeadState | None,
        new_head_id: RecordId,
    ) -> CommitReceipt:
        update = HeadUpdate(head_name, expected_head, new_head_id)
        receipt = self.commit_many(
            records=records,
            local_values=local_values,
            event=event,
            head_updates=(update,),
        )
        return CommitReceipt(receipt.heads[0][1], receipt.inserted_record_ids)

    def commit_many(
        self,
        *,
        records: Sequence[StoredRecord],
        local_values: Sequence[SensitiveLocalValueDraft] = (),
        event: AuditEventDraft,
        head_updates: Sequence[HeadUpdate],
    ) -> MultiHeadCommitReceipt:
        self._ensure_open()
        if self._read_only:
            raise StoreValidationError("read-only SQLite store rejects transactions")
        self._assert_database_live()
        if type(event) is not AuditEventDraft:
            raise StoreValidationError("event must be an exact AuditEventDraft")
        normalized_records = _normalize_records(records)
        normalized_local_values = _normalize_local_values(local_values)
        normalized_updates = _normalize_head_updates(head_updates)
        signature = self._transaction_signature(
            records=normalized_records,
            local_values=normalized_local_values,
            event=event,
            head_updates=normalized_updates,
        )
        committed = False
        receipt: MultiHeadCommitReceipt | None = None
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            valid, _head, _anchor_matched = self._verify_state(
                self._connection, anchor=self._trusted_anchor
            )
            if not valid or (self._trusted_anchor is not None and not _anchor_matched):
                raise StoreIntegrityError("StateStore audit verification failed")
            retry = self._existing_retry_receipt(
                self._connection,
                signature=signature,
                head_updates=normalized_updates,
            )
            if retry is not None:
                self._connection.execute("ROLLBACK")
                return retry
            if normalized_local_values and self._read_audit_head(self._connection):
                raise StoreValidationError(
                    "sensitive-local values are allowed only during genesis"
                )
            for update in normalized_updates:
                if self._read_head(self._connection, update.name) != update.expected:
                    raise StoreConflictError(
                        "expected head does not match current state"
                    )
            inserted = self._insert_records(self._connection, normalized_records)
            self._insert_local_values(self._connection, normalized_local_values)
            subject_exists = self._connection.execute(
                "SELECT 1 FROM records WHERE record_id = ?",
                (event.subject_id,),
            ).fetchone()
            if subject_exists is None:
                raise StoreIntegrityError("audit subject record is absent")
            self._fault("after_records")
            for update in normalized_updates:
                exists = self._connection.execute(
                    "SELECT 1 FROM records WHERE record_id = ?",
                    (update.new_record_id,),
                ).fetchone()
                if exists is None:
                    raise StoreIntegrityError("new head record is absent")
            previous = self._read_audit_head(self._connection)
            sequence = 1 if previous is None else previous.audit_sequence + 1
            previous_event_id = None if previous is None else previous.audit_event_id
            event_payload = self._build_event_payload(
                signature=signature,
                inserted_record_ids=inserted,
                previous_event_id=previous_event_id,
                sequence=sequence,
            )
            event_id_value = record_id("AuditEvent/v1", "v1", event_payload)
            event_bytes = canonical_bytes(event_payload)
            self._connection.execute(
                "INSERT INTO audit_events("
                "sequence, event_id, previous_event_id, canonical_bytes"
                ") "
                "VALUES (?, ?, ?, ?)",
                (
                    sequence,
                    event_id_value,
                    previous_event_id,
                    sqlite3.Binary(event_bytes),
                ),
            )
            self._fault("after_audit")
            heads: list[tuple[str, HeadState]] = []
            for update in normalized_updates:
                head = HeadState(update.new_record_id, event_id_value, sequence)
                self._connection.execute(
                    "INSERT INTO heads("
                    "name, record_id, audit_event_id, audit_sequence"
                    ") "
                    "VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET "
                    "record_id=excluded.record_id, "
                    "audit_event_id=excluded.audit_event_id, "
                    "audit_sequence=excluded.audit_sequence",
                    (
                        update.name,
                        head.record_id,
                        head.audit_event_id,
                        head.audit_sequence,
                    ),
                )
                heads.append((update.name, head))
            self._fault("after_head")
            receipt = MultiHeadCommitReceipt(tuple(heads), inserted)
            self._fault("before_commit")
            self._assert_database_live()
            self._connection.execute("COMMIT")
            committed = True
        except Exception:
            if not committed and self._connection.in_transaction:
                with contextlib.suppress(sqlite3.Error):
                    self._connection.execute("ROLLBACK")
            raise
        assert receipt is not None
        post_commit_error: Exception | None = None
        try:
            self._fault("after_commit")
        except Exception as error:  # reconciliation decides whether commit succeeded
            post_commit_error = error
        if self._reconcile_committed(receipt, normalized_records):
            return receipt
        if post_commit_error is not None:
            raise StoreIntegrityError(
                "post-commit fault could not be reconciled"
            ) from post_commit_error
        raise StoreIntegrityError("committed transaction failed readback verification")

    def _reconcile_committed(
        self,
        receipt: MultiHeadCommitReceipt,
        supplied_records: tuple[StoredRecord, ...],
    ) -> bool:
        connection = (
            self._connection
            if self._memory
            else self._connect(read_only=False, initialize_journal=False)
        )
        try:
            valid, audit_head, _anchor_matched = self._verify_state(
                connection, anchor=self._trusted_anchor
            )
            if (
                not valid
                or audit_head is None
                or (self._trusted_anchor is not None and not _anchor_matched)
            ):
                return False
            receipt_audit_ids = {head.audit_event_id for _name, head in receipt.heads}
            receipt_sequences = {head.audit_sequence for _name, head in receipt.heads}
            if receipt_audit_ids != {
                audit_head.audit_event_id
            } or receipt_sequences != {audit_head.audit_sequence}:
                return False
            if any(
                self._read_head(connection, name) != head
                for name, head in receipt.heads
            ):
                return False
            for record in supplied_records:
                if (
                    self._load_record_from_connection(connection, record.record_id)
                    != record
                ):
                    return False
            return True
        except (KeyError, sqlite3.Error, StoreIntegrityError):
            return False
        finally:
            if connection is not self._connection:
                connection.close()
