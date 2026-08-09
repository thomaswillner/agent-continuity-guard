"""Ephemeral in-memory StateStore adapter for deterministic tests."""

from __future__ import annotations

from .base import FaultInjector
from .sqlite import SQLiteStateStore


class MemoryStateStore(SQLiteStateStore):
    """SQLite schema-v1 semantics over one process-local in-memory database."""

    def __init__(
        self,
        *,
        store_id: str,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._initialize_memory_store(
            store_id=store_id,
            fault_injector=fault_injector,
        )
