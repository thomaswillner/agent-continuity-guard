"""Atomic SQLite StateStore with immutable records and linked audit events."""

from __future__ import annotations

import contextlib
import os
import re
import sqlite3
import stat
from collections.abc import Sequence
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import cast

from agent_continuity.kernel.audit import AuditAnchorV1, AuditVerification
from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
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
from .paths import ExternalStateRoot, StatePathError

_SCHEMA_VERSION = b"1"
_EMPTY_AUDIT_ID = RecordId("sha256:" + "0" * 64)
_ALLOWED_LOCAL_KINDS = frozenset({"criterion_text", "goal_text"})
_DATABASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
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


def _schema_sql() -> str:
    return (
        resources.files("agent_continuity.store")
        .joinpath("schema.sql")
        .read_text(encoding="utf-8")
    )


def _schema_identity(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, str, str, str | None], ...]:
    return tuple(
        (
            cast(str, object_type),
            cast(str, name),
            cast(str, table_name),
            None if sql is None else cast(str, sql),
        )
        for object_type, name, table_name, sql in connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "ORDER BY type, name"
        )
    )


@lru_cache(maxsize=1)
def _expected_schema_identity() -> tuple[tuple[str, str, str, str | None], ...]:
    reference = sqlite3.connect(":memory:", isolation_level=None)
    try:
        reference.executescript(_schema_sql())
        return _schema_identity(reference)
    finally:
        reference.close()


def _validate_frozen_schema(connection: sqlite3.Connection) -> None:
    try:
        actual = _schema_identity(connection)
    except sqlite3.Error as error:
        raise StoreIntegrityError("SQLite schema cannot be inspected") from error
    if actual != _expected_schema_identity():
        raise StoreIntegrityError("SQLite schema identity is not frozen schema v1")


def _head_payload(head: HeadState | None) -> JsonObject | None:
    if head is None:
        return None
    return {
        "audit_event_id": head.audit_event_id,
        "audit_sequence": head.audit_sequence,
        "record_id": head.record_id,
    }


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


def _local_value_payload(value: SensitiveLocalValueDraft) -> JsonObject:
    return {"digest": value.digest, "kind": value.kind}


class SQLiteStateStore:
    """Schema-v1 SQLite implementation of the public StateStore protocol."""

    def __init__(
        self,
        state_root: ExternalStateRoot,
        *,
        database_name: str,
        store_id: str | None = None,
        fault_injector: FaultInjector | None = None,
        trusted_anchor: AuditAnchorV1 | None = None,
    ) -> None:
        if type(state_root) is not ExternalStateRoot:
            raise StoreValidationError(
                "filesystem SQLite store requires a pinned ExternalStateRoot"
            )
        if (
            type(database_name) is not str
            or _DATABASE_NAME_RE.fullmatch(database_name) is None
            or database_name in {".", ".."}
        ):
            raise StoreValidationError("SQLite database name is invalid")
        if trusted_anchor is not None and type(trusted_anchor) is not AuditAnchorV1:
            raise StoreValidationError("trusted anchor must be AuditAnchorV1 or null")
        self._validate_supplied_store_id(store_id)
        self._state_root: ExternalStateRoot | None = state_root
        self._database_name = database_name
        self._path = state_root.path / database_name
        self._database_fd = -1
        self._database_identity: tuple[int, int] | None = None
        self._memory = False
        self._fault_injector = fault_injector
        self._trusted_anchor = trusted_anchor
        self._closed = False
        self._connection: sqlite3.Connection
        created = False
        try:
            self._assert_root_live(construction=True)
            try:
                self._database_fd = self._open_database_descriptor(create=False)
            except FileNotFoundError:
                if store_id is None:
                    raise StoreValidationError(
                        "new SQLite store requires a store ID"
                    ) from None
                if trusted_anchor is not None:
                    raise StoreIntegrityError(
                        "new SQLite store cannot satisfy a trusted anchor"
                    ) from None
                self._database_fd = self._open_database_descriptor(create=True)
                created = True
            self._capture_database_identity()
            self._validate_sidecars()
            if created:
                self._connection = self._connect(
                    read_only=False, initialize_journal=True
                )
                self._connection.executescript(_schema_sql())
                self._store_id = self._initialize_metadata(
                    store_id, allow_initialize=True
                )
                _validate_frozen_schema(self._connection)
                valid, _head, _matched = self._verify_state(
                    self._connection, anchor=None
                )
                if not valid:
                    raise StoreIntegrityError(
                        "new SQLite StateStore failed self-validation"
                    )
            else:
                read_only = self._connect(read_only=True, initialize_journal=False)
                try:
                    _validate_frozen_schema(read_only)
                    self._store_id = self._initialize_metadata_on(
                        read_only, store_id, allow_initialize=False
                    )
                    valid, _head, matched = self._verify_state(
                        read_only, anchor=trusted_anchor
                    )
                    if not valid or (trusted_anchor is not None and not matched):
                        raise StoreIntegrityError(
                            "existing SQLite StateStore failed full verification"
                        )
                finally:
                    read_only.close()
                self._assert_database_live()
                self._connection = self._connect(
                    read_only=False, initialize_journal=False
                )
                _validate_frozen_schema(self._connection)
                valid, _head, matched = self._verify_state(
                    self._connection, anchor=trusted_anchor
                )
                if not valid or (trusted_anchor is not None and not matched):
                    raise StoreIntegrityError(
                        "existing SQLite StateStore changed during open"
                    )
            self._assert_database_live()
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            if created:
                with contextlib.suppress(
                    OSError, StatePathError, StoreIntegrityError
                ):
                    self._assert_database_live()
                    os.unlink(database_name, dir_fd=state_root.dir_fd)
            self._close_handles()
            self._closed = True
            raise

    def _initialize_memory_store(
        self,
        *,
        store_id: str,
        fault_injector: FaultInjector | None,
    ) -> None:
        self._validate_supplied_store_id(store_id)
        self._state_root = None
        self._database_name = ":memory:"
        self._path = Path(":memory:")
        self._database_fd = -1
        self._database_identity = None
        self._memory = True
        self._fault_injector = fault_injector
        self._trusted_anchor = None
        self._closed = False
        self._connection = sqlite3.connect(
            ":memory:", isolation_level=None, timeout=5.0
        )
        try:
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.executescript(_schema_sql())
            self._store_id = self._initialize_metadata(
                store_id, allow_initialize=True
            )
            _validate_frozen_schema(self._connection)
            valid, _head, _matched = self._verify_state(
                self._connection, anchor=None
            )
            if not valid:
                raise StoreIntegrityError("memory StateStore failed self-validation")
        except Exception:
            self._connection.close()
            self._closed = True
            raise

    @property
    def store_id(self) -> str:
        return self._store_id

    @property
    def path(self) -> Path:
        return self._path

    @staticmethod
    def _validate_supplied_store_id(supplied_store_id: str | None) -> None:
        if supplied_store_id is None:
            return
        if type(supplied_store_id) is not str:
            raise StoreValidationError("store ID must be exact text")
        try:
            require_public_component(supplied_store_id, field="store ID")
        except ValueError as error:
            raise StoreValidationError("store ID is invalid") from error

    def _assert_root_live(self, *, construction: bool = False) -> None:
        root = self._state_root
        if root is None:
            return
        try:
            root._assert_live()
        except (OSError, StatePathError) as error:
            failure = (
                StoreValidationError
                if construction
                else StoreIntegrityError
            )
            raise failure("external state root is no longer trusted") from error

    def _open_database_descriptor(self, *, create: bool) -> int:
        root = self._state_root
        assert root is not None
        if not hasattr(os, "O_NOFOLLOW"):
            raise StoreValidationError("no-follow SQLite access is unsupported")
        flags = os.O_RDWR if create else os.O_RDONLY
        flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            return os.open(
                self._database_name,
                flags,
                0o600,
                dir_fd=root.dir_fd,
            )
        except FileNotFoundError:
            raise
        except OSError as error:
            raise StoreIntegrityError(
                "SQLite database could not be opened descriptor-relative"
            ) from error

    @staticmethod
    def _validate_database_metadata(metadata: os.stat_result) -> None:
        if not stat.S_ISREG(metadata.st_mode):
            raise StoreIntegrityError("SQLite database is not a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise StoreIntegrityError("SQLite database mode must be 0600")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise StoreIntegrityError("SQLite database owner is invalid")
        if metadata.st_nlink != 1:
            raise StoreIntegrityError("SQLite database must have one link")

    def _capture_database_identity(self) -> None:
        metadata = os.fstat(self._database_fd)
        self._validate_database_metadata(metadata)
        self._database_identity = (metadata.st_dev, metadata.st_ino)

    def _assert_database_live(self) -> None:
        if self._memory:
            return
        self._assert_root_live()
        root = self._state_root
        assert root is not None
        if self._database_fd < 0 or self._database_identity is None:
            raise StoreIntegrityError("SQLite database descriptor is closed")
        descriptor_metadata = os.fstat(self._database_fd)
        self._validate_database_metadata(descriptor_metadata)
        locator_metadata = os.stat(
            self._database_name,
            dir_fd=root.dir_fd,
            follow_symlinks=False,
        )
        self._validate_database_metadata(locator_metadata)
        if (
            descriptor_metadata.st_dev,
            descriptor_metadata.st_ino,
        ) != self._database_identity or (
            locator_metadata.st_dev,
            locator_metadata.st_ino,
        ) != self._database_identity:
            raise StoreIntegrityError("SQLite database identity changed")
        self._validate_sidecars()

    def _validate_sidecars(self) -> None:
        root = self._state_root
        if root is None:
            return
        for suffix in ("-journal", "-shm", "-wal"):
            name = self._database_name + suffix
            try:
                metadata = os.stat(name, dir_fd=root.dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            self._validate_database_metadata(metadata)

    def _connect(
        self,
        *,
        read_only: bool,
        initialize_journal: bool,
    ) -> sqlite3.Connection:
        self._assert_database_live()
        database = (
            self._path.as_uri() + "?mode=ro"
            if read_only
            else os.fspath(self._path)
        )
        connection = sqlite3.connect(
            database,
            isolation_level=None,
            timeout=5.0,
            uri=read_only,
        )
        try:
            self._configure_connection(
                connection,
                read_only=read_only,
                initialize_journal=initialize_journal,
            )
            self._assert_database_live()
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _configure_connection(
        connection: sqlite3.Connection,
        *,
        read_only: bool,
        initialize_journal: bool,
    ) -> None:
        connection.execute("PRAGMA foreign_keys=ON")
        if read_only:
            connection.execute("PRAGMA query_only=ON")
        else:
            connection.execute("PRAGMA synchronous=FULL")
        if initialize_journal:
            mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
            if mode is None or str(mode[0]).lower() != "delete":
                raise StoreIntegrityError("SQLite journal mode is not DELETE")
        elif not read_only:
            mode = connection.execute("PRAGMA journal_mode").fetchone()
            if mode is None or str(mode[0]).lower() != "delete":
                raise StoreIntegrityError("SQLite journal mode is not DELETE")

    def _initialize_metadata(
        self,
        supplied_store_id: str | None,
        *,
        allow_initialize: bool,
    ) -> str:
        return self._initialize_metadata_on(
            self._connection,
            supplied_store_id,
            allow_initialize=allow_initialize,
        )

    @staticmethod
    def _initialize_metadata_on(
        connection: sqlite3.Connection,
        supplied_store_id: str | None,
        *,
        allow_initialize: bool,
    ) -> str:
        rows = {
            cast(str, key): bytes(value)
            for key, value in connection.execute(
                "SELECT key, value FROM metadata"
            ).fetchall()
        }
        if not rows:
            if not allow_initialize or supplied_store_id is None:
                raise StoreIntegrityError("SQLite metadata is absent")
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    (
                        ("schema_version", sqlite3.Binary(_SCHEMA_VERSION)),
                        ("store_id", sqlite3.Binary(supplied_store_id.encode("utf-8"))),
                    ),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            return supplied_store_id
        if set(rows) != {"schema_version", "store_id"}:
            raise StoreIntegrityError("SQLite metadata keys are invalid")
        if rows["schema_version"] != _SCHEMA_VERSION:
            raise StoreIntegrityError("unsupported SQLite StateStore schema version")
        try:
            stored_id = rows["store_id"].decode("utf-8", errors="strict")
            require_public_component(stored_id, field="store ID")
        except (UnicodeDecodeError, ValueError) as error:
            raise StoreIntegrityError("stored SQLite store ID is invalid") from error
        if supplied_store_id is not None and supplied_store_id != stored_id:
            raise StoreIntegrityError(
                "supplied store ID does not match stored identity"
            )
        return stored_id

    def _ensure_open(self) -> None:
        if self._closed:
            raise StoreValidationError("SQLite StateStore is closed")

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._close_handles()
            self._closed = True

    def _close_handles(self) -> None:
        if self._database_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self._database_fd)
            self._database_fd = -1
        if self._state_root is not None:
            self._state_root.close()

    def __enter__(self) -> SQLiteStateStore:
        self._ensure_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

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
        return {key: payload[key] for key in _TRANSACTION_KEYS}

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
                payload = canonical_loads(bytes(row[2]))
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
            if not valid or (
                self._trusted_anchor is not None and not _anchor_matched
            ):
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
                or (
                    self._trusted_anchor is not None and not _anchor_matched
                )
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
                payload = canonical_loads(bytes(raw_bytes))
                if set(payload) != _AUDIT_EVENT_KEYS:
                    raise StoreIntegrityError("audit event fields are invalid")
                if record_id("AuditEvent/v1", "v1", payload) != event_id_value:
                    raise StoreIntegrityError("audit event ID is invalid")
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
                updates = payload["head_updates"]
                if type(updates) is not dict or not updates:
                    raise StoreIntegrityError("audit head updates are invalid")
                update_names: list[str] = []
                for name in sorted(updates):
                    item = updates[name]
                    if type(item) is not dict or set(item) != {
                        "expected",
                        "new_record_id",
                    }:
                        raise StoreIntegrityError("audit head update is invalid")
                    item_object = cast(dict[str, object], item)
                    require_head_name(name)
                    expected = _head_from_payload(item_object["expected"])
                    if replayed_heads.get(name) != expected:
                        raise StoreIntegrityError("audit head CAS history is invalid")
                    new_record_id = RecordId(cast(str, item_object["new_record_id"]))
                    require_record_id(new_record_id, field="audit new record ID")
                    if new_record_id not in event_available_records:
                        raise StoreIntegrityError(
                            "audit head record is unavailable at event prefix"
                        )
                    replayed_heads[name] = HeadState(
                        new_record_id, event_id_value, sequence
                    )
                    update_names.append(name)
                if update_names != sorted(set(update_names)) or not update_names:
                    raise StoreIntegrityError("audit head updates are not ordered")
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
            supplied_anchor_matched=(
                effective_anchor is not None and anchor_matched
            ),
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
