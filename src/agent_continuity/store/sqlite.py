"""Atomic SQLite StateStore with immutable records and linked audit events."""

from __future__ import annotations

from ._sqlite_audit import _SQLiteAuditMixin
from ._sqlite_lifecycle import _SQLiteLifecycleMixin
from ._sqlite_transactions import _SQLiteTransactionsMixin


class SQLiteStateStore(
    _SQLiteAuditMixin,
    _SQLiteTransactionsMixin,
    _SQLiteLifecycleMixin,
):
    """Schema-v1 SQLite implementation of the public StateStore protocol."""
