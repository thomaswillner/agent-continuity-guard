"""Agent Continuity Guard public package."""

from agent_continuity.api import (
    AlreadyInitialized,
    CheckpointReceipt,
    Continuity,
    ContinuityError,
    ContinuityRequestError,
    TransitionRefused,
)
from agent_continuity.kernel.evaluation import Profile
from agent_continuity.kernel.model import PromotionMode

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
