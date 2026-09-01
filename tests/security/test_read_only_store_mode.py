from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from agent_continuity import Continuity
from agent_continuity.kernel.canonical import validate_logical_time
from agent_continuity.kernel.records import make_record
from agent_continuity.store import (
    AuditEventDraft,
    SQLiteStateStore,
    StoreIntegrityError,
    StoreValidationError,
    open_external_state_root,
)
from tests.helpers.git_repo import make_git_repo

Metadata = tuple[int, int, int, int, int, int, int, int]
StateSnapshot = tuple[Metadata, tuple[tuple[str, Metadata, bytes], ...]]


def _metadata(path: Path) -> Metadata:
    value = path.lstat()
    return (
        stat.S_IMODE(value.st_mode),
        value.st_ino,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _state_snapshot(state_home: Path) -> StateSnapshot:
    entries = tuple(
        (path.name, _metadata(path), path.read_bytes())
        for path in sorted(
            state_home.iterdir(),
            key=lambda item: os.fsencode(item.name),
        )
    )
    return _metadata(state_home), entries


def _database(state_home: Path) -> Path:
    databases = tuple(state_home.glob("*.sqlite3"))
    assert len(databases) == 1
    return databases[0]


def _open_store(
    target: Path,
    state_home: Path,
    database: Path,
    *,
    read_only: bool,
) -> SQLiteStateStore:
    root = open_external_state_root(target, target / ".git", state_home)
    return SQLiteStateStore(
        root,
        database_name=database.name,
        store_id=None,
        read_only=read_only,
    )


def _run_cli(*arguments: str) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, "-m", "agent_continuity.cli", *arguments],
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": os.fspath(Path.cwd() / "src")},
        timeout=30,
    )
    assert result.returncode == 0, result.stdout
    assert result.stderr == b""
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


def _initialized_store(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = make_git_repo(tmp_path)
    state_home = tmp_path / "external-state"
    Continuity.open(repo.root, state_home=state_home).initialize(
        "goal",
        (),
        instruction_paths=("AGENTS.md",),
    )
    return repo.root, state_home, _database(state_home)


def test_explicit_read_only_store_rejects_transactions_without_state_change(
    tmp_path: Path,
) -> None:
    target, state_home, database = _initialized_store(tmp_path)
    before = _state_snapshot(state_home)
    next_record = make_record("Example/v1", {"value": "must-not-commit"})

    with _open_store(target, state_home, database, read_only=True) as store:
        assert store.read_audit_head() is not None
        with pytest.raises(StoreValidationError, match="read-only"):
            store.commit(
                records=(next_record,),
                event=AuditEventDraft(
                    kind="checkpoint",
                    subject_id=next_record.record_id,
                    logical_time=validate_logical_time("2026-08-14T12:00:00Z"),
                    details={"record_id": next_record.record_id},
                ),
                head_name="must-not-write",
                expected_head=None,
                new_head_id=next_record.record_id,
            )

    assert _state_snapshot(state_home) == before


def test_verify_audit_and_anchor_store_access_preserve_full_state_metadata(
    tmp_path: Path,
) -> None:
    target, state_home, _database_path = _initialized_store(tmp_path)
    common = (
        "--target",
        os.fspath(target),
        "--state-home",
        os.fspath(state_home),
    )
    commands = (
        ("verify", *common),
        ("verify-audit", *common),
        (
            "audit-anchor",
            "export",
            *common,
            "--output",
            os.fspath(tmp_path / "anchor.json"),
        ),
    )

    for command in commands:
        before = _state_snapshot(state_home)
        _run_cli(*command)
        assert _state_snapshot(state_home) == before
        assert all(
            not Path(os.fspath(_database(state_home)) + suffix).exists()
            for suffix in ("-journal", "-wal", "-shm")
        )


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_read_only_store_refuses_sidecars_without_touching_them(
    tmp_path: Path,
    suffix: str,
) -> None:
    target, state_home, database = _initialized_store(tmp_path)
    sidecar = Path(os.fspath(database) + suffix)
    sidecar.write_bytes(b"")
    sidecar.chmod(0o600)
    before = _state_snapshot(state_home)

    with pytest.raises(StoreIntegrityError, match="sidecar"):
        _open_store(target, state_home, database, read_only=True)

    assert _state_snapshot(state_home) == before


def test_read_only_store_preserves_real_hot_crash_recovery_journal(
    tmp_path: Path,
) -> None:
    target, state_home, database = _initialized_store(tmp_path)
    crash = """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1], isolation_level=None)
connection.execute("PRAGMA journal_mode=DELETE")
connection.execute("PRAGMA synchronous=FULL")
connection.execute("PRAGMA cache_size=1")
connection.execute("BEGIN IMMEDIATE")
connection.execute(
    "UPDATE metadata SET value = ? WHERE key = 'store_id'",
    (b"uncommitted-crash-value",),
)
for index in range(2000):
    connection.execute(
        "INSERT INTO records(record_id, record_type, schema_version, canonical_bytes) "
        "VALUES (?, 'Crash/v1', 'v1', ?)",
        (f"crash-{index:04d}", b"{}"),
    )
os._exit(0)
"""
    subprocess.run(
        [sys.executable, "-c", crash, os.fspath(database)],
        check=True,
        timeout=30,
    )
    journal = Path(os.fspath(database) + "-journal")
    assert journal.exists()
    assert journal.stat().st_size > 0
    before = _state_snapshot(state_home)

    with pytest.raises(StoreIntegrityError, match="sidecar"):
        _open_store(target, state_home, database, read_only=True)

    assert _state_snapshot(state_home) == before
