"""Private SQLite lifecycle and trusted-descriptor invariant."""

from __future__ import annotations

import contextlib
import os
import re
import sqlite3
import stat
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, cast

from agent_continuity.kernel.audit import AuditAnchorV1
from agent_continuity.kernel.records import require_public_component

from .base import (
    AuditHeadState,
    FaultInjector,
    StoreIntegrityError,
    StoreValidationError,
)
from .paths import ExternalStateRoot, StatePathError

if TYPE_CHECKING:
    from .sqlite import SQLiteStateStore

_SCHEMA_VERSION = b"1"
_DATABASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


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
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
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


class _SQLiteLifecycleMixin:
    """Own database identity, connection configuration, metadata, and closure."""

    if TYPE_CHECKING:

        def _verify_state(
            self,
            connection: sqlite3.Connection,
            *,
            anchor: AuditAnchorV1 | None,
        ) -> tuple[bool, AuditHeadState | None, bool]: ...

    def __init__(
        self,
        state_root: ExternalStateRoot,
        *,
        database_name: str,
        store_id: str | None = None,
        fault_injector: FaultInjector | None = None,
        trusted_anchor: AuditAnchorV1 | None = None,
        read_only: bool = False,
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
        if type(read_only) is not bool:
            raise StoreValidationError("read-only mode must be an exact boolean")
        self._validate_supplied_store_id(store_id)
        self._state_root: ExternalStateRoot | None = state_root
        self._database_name = database_name
        self._path = state_root.path / database_name
        self._database_fd = -1
        self._database_identity: tuple[int, int] | None = None
        self._memory = False
        self._fault_injector = fault_injector
        self._trusted_anchor = trusted_anchor
        self._read_only = read_only
        self._closed = False
        self._connection: sqlite3.Connection
        created = False
        try:
            self._assert_root_live(construction=True)
            try:
                self._database_fd = self._open_database_descriptor(create=False)
            except FileNotFoundError:
                if read_only or store_id is None:
                    raise StoreValidationError(
                        "read-only or unidentified SQLite store must already exist"
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
                verified = self._connect(read_only=True, initialize_journal=False)
                try:
                    _validate_frozen_schema(verified)
                    self._store_id = self._initialize_metadata_on(
                        verified, store_id, allow_initialize=False
                    )
                    valid, _head, matched = self._verify_state(
                        verified, anchor=trusted_anchor
                    )
                    if not valid or (trusted_anchor is not None and not matched):
                        raise StoreIntegrityError(
                            "existing SQLite StateStore failed full verification"
                        )
                except Exception:
                    verified.close()
                    raise
                if read_only:
                    self._connection = verified
                else:
                    verified.close()
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
                with contextlib.suppress(OSError, StatePathError, StoreIntegrityError):
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
        self._read_only = False
        self._closed = False
        self._connection = sqlite3.connect(
            ":memory:", isolation_level=None, timeout=5.0
        )
        try:
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.executescript(_schema_sql())
            self._store_id = self._initialize_metadata(store_id, allow_initialize=True)
            _validate_frozen_schema(self._connection)
            valid, _head, _matched = self._verify_state(self._connection, anchor=None)
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
            failure = StoreValidationError if construction else StoreIntegrityError
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
            if self._read_only:
                raise StoreIntegrityError(
                    "read-only SQLite store refuses recovery sidecars"
                )

    def _connect(
        self,
        *,
        read_only: bool,
        initialize_journal: bool,
    ) -> sqlite3.Connection:
        self._assert_database_live()
        database = (
            self._path.as_uri() + "?mode=ro" if read_only else os.fspath(self._path)
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
        return cast("SQLiteStateStore", self)

    def __exit__(self, *_args: object) -> None:
        self.close()
