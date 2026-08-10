"""Test-owned constructors for the public filesystem StateStore seam."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_continuity.kernel.canonical import canonical_bytes, record_id
from agent_continuity.kernel.model import JsonObject, RecordId, StoredRecord
from agent_continuity.store import (
    AuditAnchorV1,
    HeadState,
    SQLiteStateStore,
    open_external_state_root,
)

# Generated and verified by the public StateStore at pinned commit
# dafa14fcf485b2aedc2ecc6ef83ecd5f0c40da9d. Literals keep compatibility
# tests independent of Git history and of the implementation under test.
LEGACY_ARRAY_EVENT_ID = RecordId(
    "sha256:a4b1ca5b06eb2d468914a2c331184cf81f44f85d04c9e157e45dc0a1e57dc37f"
)
LEGACY_ARRAY_RECORDS = (
    StoredRecord(
        record_id=RecordId(
            "sha256:008552eac0ffff2ecaffb457c2e5f4a8464e70cded82e0c557b71e083fe79f01"
        ),
        record_type="Example/v1",
        schema_version="v1",
        canonical_bytes=b'{"value":"legacy-second"}',
    ),
    StoredRecord(
        record_id=RecordId(
            "sha256:779154f4d6c1f7089a1ae8eb4a25cbc4a459482b6d645f2ee56f23eb626e0bd0"
        ),
        record_type="Example/v1",
        schema_version="v1",
        canonical_bytes=b'{"value":"legacy-first"}',
    ),
)


def legacy_array_event_payload() -> JsonObject:
    """Return fresh canonical legacy AuditEvent/v1 payload data."""

    second, first = LEGACY_ARRAY_RECORDS
    return {
        "details": {
            "flag": True,
            "items": [{"record_id": second.record_id}],
        },
        "head_updates": [
            {
                "expected": None,
                "name": "head:a",
                "new_record_id": first.record_id,
            },
            {
                "expected": None,
                "name": "head:b",
                "new_record_id": second.record_id,
            },
        ],
        "inserted_record_ids": [second.record_id, first.record_id],
        "kind": "checkpoint",
        "local_values": [],
        "logical_time": "2026-08-09T12:00:00Z",
        "previous_event_id": None,
        "record_ids": [second.record_id, first.record_id],
        "sequence": 1,
        "store_id": "store-test",
        "subject_id": first.record_id,
    }


@dataclass(frozen=True, slots=True)
class LegacyArrayStoreFixture:
    event_id: RecordId
    event_bytes: bytes
    records: tuple[StoredRecord, ...]
    heads: tuple[tuple[str, HeadState], ...]


def open_test_store(
    path: Path,
    *,
    store_id: str = "store-test",
    fault_injector: Any = None,
    trusted_anchor: AuditAnchorV1 | None = None,
) -> SQLiteStateStore:
    """Open one store through a test-owned guarded target and pinned root."""

    target = path.parent.parent / f"{path.parent.name}-{path.name}-target"
    git_directory = target / ".git"
    target.mkdir(mode=0o700, exist_ok=True)
    git_directory.mkdir(mode=0o700, exist_ok=True)
    root = open_external_state_root(target, git_directory, path.parent)
    return SQLiteStateStore(
        root,
        database_name=path.name,
        store_id=store_id,
        fault_injector=fault_injector,
        trusted_anchor=trusted_anchor,
    )


def write_legacy_array_store(
    path: Path,
    *,
    payload: JsonObject | None = None,
    event_id: RecordId | None = None,
) -> LegacyArrayStoreFixture:
    """Write exact frozen-v1 rows using the legacy array event representation."""

    with open_test_store(path):
        pass
    event_payload = legacy_array_event_payload() if payload is None else payload
    event_bytes = canonical_bytes(event_payload)
    derived_event_id = record_id("AuditEvent/v1", "v1", event_payload)
    if payload is None:
        assert derived_event_id == LEGACY_ARRAY_EVENT_ID
    stored_event_id = derived_event_id if event_id is None else event_id
    raw_updates = event_payload["head_updates"]
    assert isinstance(raw_updates, list)
    projected: dict[str, RecordId] = {}
    for raw_update in raw_updates:
        assert isinstance(raw_update, dict)
        name = raw_update.get("name")
        new_record_id = raw_update.get("new_record_id")
        assert isinstance(name, str)
        assert isinstance(new_record_id, str)
        projected[name] = RecordId(new_record_id)
    heads = tuple(
        (
            name,
            HeadState(
                record_id=projected[name],
                audit_event_id=stored_event_id,
                audit_sequence=1,
            ),
        )
        for name in sorted(projected)
    )
    with sqlite3.connect(path) as connection:
        connection.executemany(
            "INSERT INTO records("
            "record_id, record_type, schema_version, canonical_bytes"
            ") VALUES (?, ?, ?, ?)",
            (
                (
                    item.record_id,
                    item.record_type,
                    item.schema_version,
                    sqlite3.Binary(item.canonical_bytes),
                )
                for item in LEGACY_ARRAY_RECORDS
            ),
        )
        connection.execute(
            "INSERT INTO audit_events("
            "sequence, event_id, previous_event_id, canonical_bytes"
            ") VALUES (1, ?, ?, ?)",
            (
                stored_event_id,
                event_payload["previous_event_id"],
                sqlite3.Binary(event_bytes),
            ),
        )
        connection.executemany(
            "INSERT INTO heads("
            "name, record_id, audit_event_id, audit_sequence"
            ") VALUES (?, ?, ?, ?)",
            (
                (name, head.record_id, head.audit_event_id, head.audit_sequence)
                for name, head in heads
            ),
        )
    return LegacyArrayStoreFixture(
        event_id=stored_event_id,
        event_bytes=event_bytes,
        records=LEGACY_ARRAY_RECORDS,
        heads=heads,
    )
