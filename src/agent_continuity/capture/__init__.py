"""Read-only target observation adapters."""

from .base import (
    CaptureRequestError,
    CaptureSnapshot,
    CaptureUnknownError,
    TargetAdapter,
    TargetIdentityV1,
    target_identity_payload,
)
from .git import GitTargetAdapter

__all__ = [
    "CaptureRequestError",
    "CaptureSnapshot",
    "CaptureUnknownError",
    "GitTargetAdapter",
    "TargetAdapter",
    "TargetIdentityV1",
    "target_identity_payload",
]
