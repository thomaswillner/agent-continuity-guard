"""Test-owned constructors for the public filesystem StateStore seam."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_continuity.store import (
    AuditAnchorV1,
    SQLiteStateStore,
    open_external_state_root,
)


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
