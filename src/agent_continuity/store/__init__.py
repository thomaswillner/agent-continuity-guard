"""External Agent Continuity Guard state contracts and adapters."""

from agent_continuity.kernel.audit import AuditAnchorV1, AuditVerification

from .base import (
    AuditEventDraft,
    AuditHeadState,
    CommitReceipt,
    HeadState,
    HeadUpdate,
    MultiHeadCommitReceipt,
    SensitiveLocalValueDraft,
    StateStore,
    StateStoreError,
    StoreConflictError,
    StoreIntegrityError,
    StoreValidationError,
)
from .memory import MemoryStateStore
from .paths import ExternalStateRoot, open_external_state_root, resolve_state_home
from .sqlite import SQLiteStateStore

__all__ = [
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
