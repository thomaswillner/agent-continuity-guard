from __future__ import annotations

import ast
import inspect
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
PUBLIC_STORE_EXPORTS = [
    "AuditAnchorV1",
    "AuditEventDraft",
    "AuditHeadState",
    "AuditVerification",
    "CommitReceipt",
    "ExternalStateRoot",
    "HeadState",
    "HeadUpdate",
    "MemoryStateStore",
    "MultiHeadCommitReceipt",
    "SQLiteStateStore",
    "SensitiveLocalValueDraft",
    "StateStore",
    "StateStoreError",
    "StoreConflictError",
    "StoreIntegrityError",
    "StoreValidationError",
    "open_external_state_root",
    "resolve_state_home",
]
STORE_SIGNATURES = {
    "ExternalStateRoot": "(path: 'Path', dir_fd: 'int', *, target_path: 'Path', target_fd: 'int', git_path: 'Path | None', git_fd: 'int', _token: 'object') -> 'None'",  # noqa: E501
    "SQLiteStateStore": "(state_root: 'ExternalStateRoot', *, database_name: 'str', store_id: 'str | None' = None, fault_injector: 'FaultInjector | None' = None, trusted_anchor: 'AuditAnchorV1 | None' = None, read_only: 'bool' = False) -> 'None'",  # noqa: E501
    "MemoryStateStore": "(*, store_id: 'str', fault_injector: 'FaultInjector | None' = None) -> 'None'",  # noqa: E501
    "open_external_state_root": "(target: 'Path', git_directory: 'Path | None', state_home: 'Path') -> 'ExternalStateRoot'",  # noqa: E501
    "resolve_state_home": "(override: 'str | Path | None') -> 'Path'",
}
STORE_METHOD_SIGNATURES = {
    "read_head": "(self, name: 'str') -> 'HeadState | None'",
    "read_audit_head": "(self) -> 'AuditHeadState | None'",
    "load_record": "(self, record_id_value: 'RecordId') -> 'StoredRecord'",
    "commit": "(self, *, records: 'Sequence[StoredRecord]', local_values: 'Sequence[SensitiveLocalValueDraft]' = (), event: 'AuditEventDraft', head_name: 'str', expected_head: 'HeadState | None', new_head_id: 'RecordId') -> 'CommitReceipt'",  # noqa: E501
    "commit_many": "(self, *, records: 'Sequence[StoredRecord]', local_values: 'Sequence[SensitiveLocalValueDraft]' = (), event: 'AuditEventDraft', head_updates: 'Sequence[HeadUpdate]') -> 'MultiHeadCommitReceipt'",  # noqa: E501
    "verify_audit": "(self, anchor: 'AuditAnchorV1 | None' = None) -> 'AuditVerification'",  # noqa: E501
    "make_anchor": "(self, *, created_at: 'LogicalTime', label: 'str | None') -> 'AuditAnchorV1'",  # noqa: E501
    "close": "(self) -> 'None'",
    "__enter__": "(self) -> 'SQLiteStateStore'",
    "__exit__": "(self, *_args: 'object') -> 'None'",
}
PROTOCOL_METHOD_SIGNATURES = {
    **{
        key: value
        for key, value in STORE_METHOD_SIGNATURES.items()
        if key not in {"close", "__enter__", "__exit__"}
    },
    "load_record": "(self, record_id: 'RecordId') -> 'StoredRecord'",
}
STORE_EXCEPTION_MROS = {
    "StateStoreError": (
        "agent_continuity.store.base.StateStoreError",
        "builtins.RuntimeError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ),
    "StoreValidationError": (
        "agent_continuity.store.base.StoreValidationError",
        "agent_continuity.store.base.StateStoreError",
        "builtins.RuntimeError",
        "builtins.ValueError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ),
    "StoreConflictError": (
        "agent_continuity.store.base.StoreConflictError",
        "agent_continuity.store.base.StateStoreError",
        "builtins.RuntimeError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ),
    "StoreIntegrityError": (
        "agent_continuity.store.base.StoreIntegrityError",
        "agent_continuity.store.base.StateStoreError",
        "builtins.RuntimeError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ),
}


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
    assert type(store.__all__) is list
    assert store.__all__ == PUBLIC_STORE_EXPORTS
    for name in PUBLIC_STORE_EXPORTS:
        assert getattr(store, name) is not None


def test_store_public_signatures_properties_and_exception_mros_are_frozen() -> None:
    for name, expected in STORE_SIGNATURES.items():
        assert str(inspect.signature(getattr(store, name))) == expected
    for concrete in (store.SQLiteStateStore, store.MemoryStateStore):
        for name, expected in STORE_METHOD_SIGNATURES.items():
            assert str(inspect.signature(getattr(concrete, name))) == expected
        assert isinstance(inspect.getattr_static(concrete, "store_id"), property)
    assert isinstance(inspect.getattr_static(store.SQLiteStateStore, "path"), property)
    for name, expected in PROTOCOL_METHOD_SIGNATURES.items():
        assert str(inspect.signature(getattr(store.StateStore, name))) == expected
    assert isinstance(inspect.getattr_static(store.StateStore, "store_id"), property)
    for name, expected in STORE_EXCEPTION_MROS.items():
        value = getattr(store, name)
        assert tuple(
            f"{item.__module__}.{item.__qualname__}" for item in value.__mro__
        ) == expected


def test_store_context_managers_close_idempotently_even_on_body_error(
    tmp_path: Path,
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

    with pytest.raises(RuntimeError, match="body-marker"), state as entered:
        assert entered is state
        raise RuntimeError("body-marker")

    state.close()
    assert root.dir_fd == -1
    with pytest.raises(store.StoreValidationError, match="SQLite StateStore is closed"):
        state.read_head("checkpoint")


def test_external_state_root_context_manager_closes_on_body_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    git_directory = target / ".git"
    state_home = tmp_path / "state"
    git_directory.mkdir(parents=True)
    root = store.open_external_state_root(target, git_directory, state_home)

    with pytest.raises(RuntimeError, match="root-body-marker"), root as entered:
        assert entered is root
        raise RuntimeError("root-body-marker")

    root.close()
    assert root.dir_fd == -1


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
