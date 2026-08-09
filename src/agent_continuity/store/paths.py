"""External state-root resolution and target-overlap refusal."""

from __future__ import annotations

import os
import sys
from pathlib import Path


class StatePathError(ValueError):
    """State path is invalid or overlaps guarded target state."""


def resolve_state_home(override: str | Path | None) -> Path:
    selected: str | Path | None = override
    if selected is None:
        selected = os.environ.get("ACG_STATE_HOME")
    if selected is not None:
        path = Path(selected)
        if not path.is_absolute():
            raise StatePathError("state-home override must be absolute")
        return path

    if sys.platform == "darwin":
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "agent-continuity-guard"
        )
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "agent-continuity-guard"
        return Path.home() / "AppData" / "Local" / "agent-continuity-guard"
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        xdg_path = Path(xdg_state)
        if not xdg_path.is_absolute():
            raise StatePathError("XDG_STATE_HOME must be absolute")
        return xdg_path / "agent-continuity-guard"
    return Path.home() / ".local" / "state" / "agent-continuity-guard"


def _projected_real_path(path: Path) -> Path:
    if not path.is_absolute():
        raise StatePathError("security-sensitive paths must be absolute")
    cursor = path
    missing: list[str] = []
    while not os.path.lexists(cursor):
        if cursor.parent == cursor:
            raise StatePathError("path has no resolvable ancestor")
        missing.append(cursor.name)
        cursor = cursor.parent
    try:
        resolved = cursor.resolve(strict=True)
    except OSError as error:
        raise StatePathError("path ancestor could not be resolved") from error
    for component in reversed(missing):
        resolved /= component
    return resolved


def _within(candidate: Path, root: Path) -> bool:
    return candidate == root or candidate.is_relative_to(root)


def assert_external_state(
    target: Path,
    git_directory: Path | None,
    state_home: Path,
) -> None:
    target_real = _projected_real_path(target)
    state_real = _projected_real_path(state_home)
    if _within(state_real, target_real):
        raise StatePathError("state root overlaps target")
    if git_directory is not None:
        git_real = _projected_real_path(git_directory)
        if _within(state_real, git_real):
            raise StatePathError("state root overlaps Git directory")
