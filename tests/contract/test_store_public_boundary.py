from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

import agent_continuity.store as store
from agent_continuity.kernel.canonical import validate_logical_time
from agent_continuity.kernel.records import make_record

TASK4_TESTS = (
    Path(__file__),
    Path(__file__).parents[1] / "integration" / "test_sqlite_store.py",
    Path(__file__).parents[1] / "security" / "test_audit_tamper.py",
    Path(__file__).parents[1] / "helpers" / "state_store.py",
)
REQUIRED_STORE_EXPORTS = frozenset(
    {
        "AuditAnchorV1",
        "AuditEventDraft",
        "AuditVerification",
        "ExternalStateRoot",
        "HeadState",
        "HeadUpdate",
        "MemoryStateStore",
        "SQLiteStateStore",
        "SensitiveLocalValueDraft",
        "StoreConflictError",
        "StoreIntegrityError",
        "StoreValidationError",
        "open_external_state_root",
    }
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=path.name)


def _private_store_imports(path: Path) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("agent_continuity.store."):
                    violations.append(
                        f"{path.name}:{node.lineno}: private store import"
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("agent_continuity.store.") or module == (
                "agent_continuity.kernel.audit"
            ):
                violations.append(f"{path.name}:{node.lineno}: private store import")
    return violations


def test_task4_tests_use_only_public_store_boundary() -> None:
    violations = [
        violation
        for path in TASK4_TESTS
        for violation in _private_store_imports(path)
    ]

    assert violations == []


def test_store_exports_complete_public_task4_contract() -> None:
    assert set(store.__all__) >= REQUIRED_STORE_EXPORTS
    for name in REQUIRED_STORE_EXPORTS:
        assert getattr(store, name) is not None


def test_sqlite_store_rejects_unpinned_path_constructor(tmp_path: Path) -> None:
    with pytest.raises(store.StoreValidationError):
        store.SQLiteStateStore(  # type: ignore[arg-type]
            tmp_path / "state.sqlite3",
            database_name="state.sqlite3",
            store_id="store-test",
        )


def test_sqlite_store_consumes_live_pinned_external_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    git_directory = target / ".git"
    state_home = tmp_path / "state"
    git_directory.mkdir(parents=True)

    root = store.open_external_state_root(target, git_directory, state_home)
    with store.SQLiteStateStore(
        root,
        database_name="state.sqlite3",
        store_id="store-test",
    ) as state:
        assert state.path == state_home / "state.sqlite3"
        assert state.verify_audit().valid is True

    assert root.dir_fd == -1


def test_closed_root_cannot_construct_filesystem_store(tmp_path: Path) -> None:
    target = tmp_path / "target"
    git_directory = target / ".git"
    state_home = tmp_path / "state"
    git_directory.mkdir(parents=True)
    root = store.open_external_state_root(target, git_directory, state_home)
    root.close()

    with pytest.raises(store.StoreValidationError):
        store.SQLiteStateStore(
            root,
            database_name="state.sqlite3",
            store_id="store-test",
        )


def _commit_genesis(state: store.SQLiteStateStore) -> None:
    record = make_record("Example/v1", {"value": "genesis"})
    state.commit(
        records=(record,),
        event=store.AuditEventDraft(
            kind="checkpoint",
            subject_id=record.record_id,
            logical_time=validate_logical_time("2026-08-09T12:00:00Z"),
            details={"record_id": record.record_id},
        ),
        head_name="checkpoint",
        expected_head=None,
        new_head_id=record.record_id,
    )


@pytest.mark.parametrize("drift", ["root_mode", "target_identity"])
def test_filesystem_guard_is_revalidated_before_write(
    tmp_path: Path,
    drift: str,
) -> None:
    target = tmp_path / "target"
    git_directory = target / ".git"
    state_home = tmp_path / "state"
    git_directory.mkdir(parents=True)
    root = store.open_external_state_root(target, git_directory, state_home)
    state = store.SQLiteStateStore(
        root,
        database_name="state.sqlite3",
        store_id="store-test",
    )
    try:
        if drift == "root_mode":
            os.chmod(state_home, 0o755)
        else:
            target.rename(tmp_path / "original-target")
            (target / ".git").mkdir(parents=True)
        with pytest.raises(store.StoreIntegrityError):
            _commit_genesis(state)
    finally:
        if drift == "root_mode":
            os.chmod(state_home, 0o700)
        state.close()


@pytest.mark.parametrize("suffix", ["", "-journal"])
def test_sqlite_locator_and_sidecars_refuse_symlinks_without_touching_target(
    tmp_path: Path,
    suffix: str,
) -> None:
    target = tmp_path / "target"
    git_directory = target / ".git"
    state_home = tmp_path / "state"
    git_directory.mkdir(parents=True)
    database = state_home / "state.sqlite3"
    if suffix:
        root = store.open_external_state_root(target, git_directory, state_home)
        with store.SQLiteStateStore(
            root,
            database_name="state.sqlite3",
            store_id="store-test",
        ):
            pass
    else:
        state_home.mkdir(mode=0o700)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"unchanged")
    os.symlink(outside, Path(os.fspath(database) + suffix))
    root = store.open_external_state_root(target, git_directory, state_home)

    with pytest.raises(store.StoreIntegrityError):
        store.SQLiteStateStore(
            root,
            database_name="state.sqlite3",
            store_id="store-test",
        )

    assert outside.read_bytes() == b"unchanged"
