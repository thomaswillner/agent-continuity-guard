"""External state-root resolution, refusal, and pinned safe creation."""

from __future__ import annotations

import contextlib
import os
import stat
import sys
from pathlib import Path


class StatePathError(ValueError):
    """State path is invalid or overlaps guarded target state."""


class ExternalStateRoot:
    """Pinned owner-only state directory returned by atomic safe creation."""

    __slots__ = ("dir_fd", "path")

    def __init__(self, path: Path, dir_fd: int) -> None:
        self.path = path
        self.dir_fd = dir_fd

    def close(self) -> None:
        if self.dir_fd >= 0:
            try:
                os.close(self.dir_fd)
            finally:
                self.dir_fd = -1

    def __enter__(self) -> ExternalStateRoot:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


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


def _reject_dot_components(path: Path) -> None:
    if not path.is_absolute():
        raise StatePathError("security-sensitive paths must be absolute")
    if any(component in {".", ".."} for component in path.parts):
        raise StatePathError("dot path components are forbidden")


def _projected_real_path(path: Path) -> Path:
    _reject_dot_components(path)
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
    """Read-only preflight; callers must use open_external_state_root to create."""

    target_real = _projected_real_path(target)
    state_real = _projected_real_path(state_home)
    if _within(state_real, target_real):
        raise StatePathError("state root overlaps target")
    if git_directory is not None:
        git_real = _projected_real_path(git_directory)
        if _within(state_real, git_real):
            raise StatePathError("state root overlaps Git directory")


def _directory_flags() -> int:
    if os.name == "nt" or not hasattr(os, "O_NOFOLLOW"):
        raise StatePathError("safe state-root creation is unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return flags


def _open_absolute_directory(path: Path, *, create: bool) -> int:
    _reject_dot_components(path)
    flags = _directory_flags()
    current = -1
    try:
        current = os.open(os.path.sep, flags)
        for component in path.parts[1:]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o700, dir_fd=current)
                next_descriptor = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_descriptor
        return current
    except OSError as error:
        if current >= 0:
            with contextlib.suppress(OSError):
                os.close(current)
        raise StatePathError("directory traversal could not be pinned") from error


def _identity(descriptor: int) -> tuple[int, int, int]:
    metadata = os.fstat(descriptor)
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _locator_identity(path: Path) -> tuple[int, int, int]:
    metadata = os.stat(path, follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def open_external_state_root(
    target: Path,
    git_directory: Path | None,
    state_home: Path,
) -> ExternalStateRoot:
    """Validate and create state root through one pinned no-follow operation."""

    assert_external_state(target, git_directory, state_home)
    try:
        target_real = target.resolve(strict=True)
        git_real = None if git_directory is None else git_directory.resolve(strict=True)
    except OSError as error:
        raise StatePathError("target identity could not be pinned") from error
    target_fd = _open_absolute_directory(target_real, create=False)
    git_fd = -1
    state_fd = -1
    try:
        target_identity = _identity(target_fd)
        if git_real is not None:
            git_fd = _open_absolute_directory(git_real, create=False)
            git_identity = _identity(git_fd)
        else:
            git_identity = None
        state_fd = _open_absolute_directory(state_home, create=True)
        state_identity = _identity(state_fd)
        if state_identity in {target_identity, git_identity}:
            raise StatePathError("state root resolves to guarded directory")
        metadata = os.fstat(state_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise StatePathError("state root is not a directory")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise StatePathError("state root mode must be 0700")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise StatePathError("state root owner is invalid")
        if _locator_identity(target_real) != target_identity:
            raise StatePathError("target identity changed during state creation")
        if git_real is not None and _locator_identity(git_real) != git_identity:
            raise StatePathError("Git identity changed during state creation")
        if _locator_identity(state_home) != state_identity:
            raise StatePathError("state locator changed during state creation")
        handle = ExternalStateRoot(state_home, state_fd)
        state_fd = -1
        return handle
    except OSError as error:
        raise StatePathError("state-root identity could not be verified") from error
    finally:
        for descriptor in (state_fd, git_fd, target_fd):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
