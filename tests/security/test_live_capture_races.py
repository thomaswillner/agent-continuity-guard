from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from agent_continuity.capture import (
    CaptureSnapshot,
    CaptureUnknownError,
    GitTargetAdapter,
)
from agent_continuity.capture.coordinator import CaptureCoordinator
from agent_continuity.capture.filesystem import FilesystemTargetAdapter
from agent_continuity.kernel.paths import PathIdentityV1
from tests.helpers.git_repo import make_git_repo


def _path(raw: bytes) -> PathIdentityV1:
    return PathIdentityV1.from_bytes("posix-bytes", raw)


def _capture_unknown(target: Path, required: tuple[PathIdentityV1, ...] = ()) -> None:
    with pytest.raises(CaptureUnknownError):
        CaptureCoordinator(FilesystemTargetAdapter(target)).capture_stable(required)


def test_live_capture_rejects_leaf_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "leaf-swap-target"
    target.mkdir()
    leaf = target / "leaf.txt"
    replacement = target / "replacement.txt"
    leaf.write_bytes(b"original\n")
    replacement.write_bytes(b"replacement\n")
    leaf_inode = leaf.stat().st_ino
    real_pread = os.pread
    replaced = False

    def replace_leaf(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal replaced
        content = real_pread(descriptor, size, offset)
        if not replaced and os.fstat(descriptor).st_ino == leaf_inode:
            replaced = True
            os.replace(replacement, leaf)
        return content

    monkeypatch.setattr(os, "pread", replace_leaf)
    _capture_unknown(target, (_path(b"leaf.txt"),))
    assert replaced


def test_live_capture_rejects_ancestor_swap_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "ancestor-swap-target"
    nested = target / "nested"
    nested.mkdir(parents=True)
    leaf = nested / "leaf.txt"
    leaf.write_bytes(b"original\n")
    leaf_inode = leaf.stat().st_ino
    moved = target / "moved"
    real_pread = os.pread
    swapped = False

    def replace_ancestor(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal swapped
        content = real_pread(descriptor, size, offset)
        if not swapped and os.fstat(descriptor).st_ino == leaf_inode:
            swapped = True
            os.rename(nested, moved)
            nested.mkdir()
            (nested / "leaf.txt").write_bytes(b"replacement\n")
        return content

    monkeypatch.setattr(os, "pread", replace_ancestor)
    _capture_unknown(target, (_path(b"nested/leaf.txt"),))
    assert swapped


def test_live_capture_rejects_hardlinks(tmp_path: Path) -> None:
    target = tmp_path / "hardlink-target"
    target.mkdir()
    original = target / "original.txt"
    original.write_bytes(b"shared\n")
    os.link(original, target / "alias.txt")

    _capture_unknown(target)


def test_live_capture_rejects_truncation_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "truncate-target"
    target.mkdir()
    leaf = target / "leaf.txt"
    leaf.write_bytes(b"long original bytes\n")
    leaf_inode = leaf.stat().st_ino
    real_pread = os.pread
    truncations = 0

    def truncate_leaf(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal truncations
        content = real_pread(descriptor, size, offset)
        if os.fstat(descriptor).st_ino == leaf_inode:
            truncations += 1
            leaf.write_bytes(b"" if truncations % 2 else b"restored bytes\n")
        return content

    monkeypatch.setattr(os, "pread", truncate_leaf)
    _capture_unknown(target, (_path(b"leaf.txt"),))
    assert truncations >= 2


def test_live_capture_rejects_path_census_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "census-target"
    target.mkdir()
    leaf = target / "leaf.txt"
    leaf.write_bytes(b"stable\n")
    leaf_inode = leaf.stat().st_ino
    real_pread = os.pread
    added = False

    def add_path(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal added
        content = real_pread(descriptor, size, offset)
        if not added and os.fstat(descriptor).st_ino == leaf_inode:
            added = True
            (target / "added.txt").write_bytes(b"new census member\n")
        return content

    monkeypatch.setattr(os, "pread", add_path)
    _capture_unknown(target)
    assert added


def test_live_capture_rejects_case_colliding_required_identities(
    tmp_path: Path,
) -> None:
    target = tmp_path / "case-target"
    target.mkdir()
    (target / "Case.txt").write_bytes(b"case-bound bytes\n")

    _capture_unknown(target, (_path(b"Case.txt"), _path(b"case.txt")))


def test_second_live_instability_is_explicit_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "second-instability-target"
    target.mkdir()
    leaf = target / "leaf.txt"
    leaf.write_bytes(b"zero\n")
    leaf_inode = leaf.stat().st_ino
    real_pread = os.pread
    changes = 0

    def always_change(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal changes
        content = real_pread(descriptor, size, offset)
        if os.fstat(descriptor).st_ino == leaf_inode:
            changes += 1
            leaf.write_bytes(f"change-{changes}\n".encode("ascii"))
        return content

    monkeypatch.setattr(os, "pread", always_change)
    _capture_unknown(target, (_path(b"leaf.txt"),))
    assert changes >= 2


@dataclass
class _NonCapableAdapter:
    snapshot: CaptureSnapshot
    adapter_id: str = "windows-non-capable"
    calls: int = 0

    def capture(self, instruction_paths: tuple[bytes, ...]) -> CaptureSnapshot:
        assert instruction_paths == ()
        self.calls += 1
        return self.snapshot


def test_non_capable_live_promotion_is_unknown_while_git_snapshot_still_works(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    with GitTargetAdapter(repo.root) as git_adapter:
        immutable = git_adapter.capture(())
    adapter = _NonCapableAdapter(immutable)

    assert adapter.capture(()) == immutable
    with pytest.raises(CaptureUnknownError):
        CaptureCoordinator(adapter).capture_stable()
    assert adapter.calls >= 2
