"""Agent Continuity Guard public package with lazy facade exports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_continuity.kernel.evaluation import Profile
from agent_continuity.kernel.model import PromotionMode

if TYPE_CHECKING:
    from agent_continuity.api import (
        AlreadyInitialized,
        CheckpointReceipt,
        Continuity,
        ContinuityError,
        ContinuityRequestError,
        TransitionRefused,
    )

__version__ = "0.1.0.dev0"

__all__ = [
    "AlreadyInitialized",
    "CheckpointReceipt",
    "Continuity",
    "ContinuityError",
    "ContinuityRequestError",
    "Profile",
    "PromotionMode",
    "TransitionRefused",
]

_FACADE_EXPORTS = frozenset(
    {
        "AlreadyInitialized",
        "CheckpointReceipt",
        "Continuity",
        "ContinuityError",
        "ContinuityRequestError",
        "TransitionRefused",
    }
)


def __getattr__(name: str) -> object:
    if name not in _FACADE_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module("agent_continuity.api"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()).union(__all__))
