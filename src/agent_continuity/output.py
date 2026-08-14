"""Canonical, sanitized command-line output records."""

from __future__ import annotations

import re
from dataclasses import dataclass

from agent_continuity.kernel.canonical import CanonicalJSONError, canonical_bytes
from agent_continuity.kernel.model import JsonObject

_CATEGORIES = frozenset({"integrity", "internal", "request", "transition"})
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]*$")


@dataclass(frozen=True, slots=True)
class ErrorRecord:
    """Stable public error envelope with no caller-controlled values."""

    category: str
    code: str
    message_id: str

    def __post_init__(self) -> None:
        if self.category not in _CATEGORIES:
            raise CanonicalJSONError("error category is invalid")
        for field, value, limit in (
            ("error code", self.code, 128),
            ("error message ID", self.message_id, 192),
        ):
            if (
                type(value) is not str
                or len(value) > limit
                or _IDENTIFIER.fullmatch(value) is None
            ):
                raise CanonicalJSONError(f"{field} is invalid")
        canonical_bytes(error_payload(self))


def error_payload(error: ErrorRecord) -> JsonObject:
    """Return the exact Error/v1 payload used by command boundaries."""

    if type(error) is not ErrorRecord:
        raise CanonicalJSONError("error record is invalid")
    return {
        "schema": "Error/v1",
        "category": error.category,
        "code": error.code,
        "message_id": error.message_id,
        "parameters": {},
    }


def canonical_output(payload: JsonObject) -> bytes:
    """Encode one canonical JSON value without a line terminator."""

    return canonical_bytes(payload)
