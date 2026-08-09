"""Read-only target observation adapters."""

from .base import CaptureSnapshot, TargetAdapter, TargetIdentityV1
from .git import GitTargetAdapter

__all__ = ["CaptureSnapshot", "GitTargetAdapter", "TargetAdapter", "TargetIdentityV1"]

