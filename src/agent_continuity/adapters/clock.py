"""Logical clock seam for orchestration without kernel time access."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from agent_continuity.kernel.canonical import validate_logical_time
from agent_continuity.kernel.model import LogicalTime


class Clock(Protocol):
    def now(self) -> LogicalTime: ...


class SystemClock:
    """Return canonical UTC whole-second logical time."""

    def now(self) -> LogicalTime:
        value = datetime.now(UTC).replace(microsecond=0).isoformat()
        return validate_logical_time(value.replace("+00:00", "Z"))
