from __future__ import annotations

import os
from pathlib import Path

import pytest

import agent_continuity.store.paths as state_paths
from agent_continuity.store.paths import (
    StatePathError,
    assert_external_state,
    resolve_state_home,
)
from tests.helpers.git_repo import make_git_repo


def test_state_inside_target_or_git_is_rejected_before_creation(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    candidates = [repo.root / "state", repo.git_dir / "state"]

    for candidate in candidates:
        with pytest.raises(StatePathError):
            assert_external_state(repo.root, repo.git_dir, candidate)
        assert not candidate.exists()


def test_state_symlink_alias_into_target_is_rejected_before_creation(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    alias = tmp_path / "target-alias"
    os.symlink(repo.root, alias)
    candidate = alias / "nested-state"

    with pytest.raises(StatePathError):
        assert_external_state(repo.root, repo.git_dir, candidate)
    assert not candidate.exists()


def test_external_state_is_allowed_without_eager_directory_creation(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    candidate = tmp_path / "external-state"

    assert_external_state(repo.root, repo.git_dir, candidate)

    assert not candidate.exists()


def test_absolute_override_precedes_environment_without_creating_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit = tmp_path / "explicit"
    environment = tmp_path / "environment"
    monkeypatch.setenv("ACG_STATE_HOME", os.fspath(environment))

    assert resolve_state_home(explicit) == explicit
    assert resolve_state_home(None) == environment
    assert not explicit.exists()
    assert not environment.exists()


def test_relative_state_override_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ACG_STATE_HOME", raising=False)
    with pytest.raises(StatePathError):
        resolve_state_home("relative/state")
    monkeypatch.setenv("ACG_STATE_HOME", "relative/environment")
    with pytest.raises(StatePathError):
        resolve_state_home(None)


def test_unresolved_parent_components_are_rejected_before_creation(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    candidate = outside / "new" / ".." / ".." / repo.root.name / "state"

    with pytest.raises(StatePathError):
        assert_external_state(repo.root, repo.git_dir, candidate)


def test_pinned_state_creator_returns_secure_handle_and_mode(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    candidate = tmp_path / "secure-state"
    creator = getattr(state_paths, "open_external_state_root", None)
    assert callable(creator)

    with creator(repo.root, repo.git_dir, candidate) as handle:
        assert handle.path == candidate
        assert candidate.is_dir()
        assert os.fstat(handle.dir_fd).st_ino == candidate.stat().st_ino
        assert candidate.stat().st_mode & 0o777 == 0o700


def test_state_ancestor_swap_during_creation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    candidate = outside / "state"
    creator = getattr(state_paths, "open_external_state_root", None)
    assert callable(creator)
    real_mkdir = os.mkdir
    swapped = False

    def swapping_mkdir(
        path: str | bytes,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if os.fsdecode(path) == "state" and not swapped:
            swapped = True
            outside.rename(tmp_path / "outside-original")
            os.symlink(repo.root, outside)
        real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", swapping_mkdir)
    with pytest.raises(StatePathError):
        creator(repo.root, repo.git_dir, candidate)
    assert not (repo.root / "state").exists()
