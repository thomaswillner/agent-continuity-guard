from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

import pytest

from agent_continuity.capture import CaptureUnknownError, GitTargetAdapter
from agent_continuity.capture.coordinator import CaptureCoordinator
from agent_continuity.capture.filesystem import FilesystemTargetAdapter
from agent_continuity.kernel.canonical import digest_bytes
from agent_continuity.kernel.paths import PathIdentityV1
from tests.helpers.git_repo import make_git_repo, repository_write_manifest


def _path(raw: bytes, *, git: bool = False) -> PathIdentityV1:
    encoding = "git-path-bytes" if git else "posix-bytes"
    return PathIdentityV1.from_bytes(encoding, raw)


def _captured_bytes(root: Path, identity: PathIdentityV1) -> bytes:
    root_fd = os.open(root, os.O_RDONLY)
    try:
        descriptor = os.open(identity.raw_bytes(), os.O_RDONLY, dir_fd=root_fd)
        try:
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 64 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)


def test_git_stable_capture_promotes_dirty_tracked_and_nonignored_untracked(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    dirty = b"dirty tracked bytes\n"
    untracked_name = b"notes-\xc3\xa9.bin"
    (repo.root / "README.md").write_bytes(dirty)
    root_fd = os.open(repo.root, os.O_RDONLY)
    try:
        descriptor = os.open(
            untracked_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=root_fd,
        )
        try:
            os.write(descriptor, b"raw untracked bytes\n")
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    (repo.root / "ignored.tmp").write_text("excluded by Git ignore\n", encoding="utf-8")
    before = repository_write_manifest(repo.root)
    required = (_path(b"README.md", git=True), _path(untracked_name, git=True))

    with GitTargetAdapter(repo.root) as adapter:
        view = CaptureCoordinator(adapter).capture_stable(required)

    assert not view.snapshot.target.is_clean
    assert required[0] in view.files
    assert required[1] in view.files
    assert all(
        item.path.raw_bytes() != b"ignored.tmp" for item in view.files.values()
    )
    assert all(
        not item.path.raw_bytes().startswith(b".git/")
        for item in view.files.values()
    )
    assert view.files[required[0]].content_digest == digest_bytes(dirty)
    assert view.ephemeral_root is not None
    assert not view.ephemeral_root.is_relative_to(repo.root)
    assert _captured_bytes(view.ephemeral_root, required[0]) == dirty
    assert _captured_bytes(view.ephemeral_root, required[1]) == b"raw untracked bytes\n"
    assert repository_write_manifest(repo.root) == before
    shutil.rmtree(view.ephemeral_root)


def test_filesystem_capture_is_deterministic_identity_bound_and_read_only(
    tmp_path: Path,
) -> None:
    target = tmp_path / "plain-target"
    target.mkdir()
    (target / "keep.txt").write_bytes(b"keep\n")
    (target / "excluded.txt").write_bytes(b"excluded\n")
    excluded = _path(b"excluded.txt")
    before = repository_write_manifest(target)
    adapter = FilesystemTargetAdapter(target, exclusions=(excluded,))

    first = adapter.capture((b"keep.txt",))
    second = adapter.capture((b"keep.txt",))
    view = CaptureCoordinator(adapter).capture_stable((_path(b"keep.txt"),))

    assert first == second == view.snapshot
    assert tuple(item.path.raw_bytes() for item in first.instructions) == (b"keep.txt",)
    assert tuple(path.raw_bytes() for path in view.files) == (b"keep.txt",)
    assert excluded not in view.files
    assert repository_write_manifest(target) == before
    assert view.ephemeral_root is not None
    shutil.rmtree(view.ephemeral_root)


def test_filesystem_capture_binds_symlink_leaf_without_dereference(
    tmp_path: Path,
) -> None:
    target = tmp_path / "symlink-target"
    target.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside bytes must not be captured\n")
    os.symlink(os.fsencode(outside), target / "link")
    identity = _path(b"link")
    before = repository_write_manifest(target)

    view = CaptureCoordinator(FilesystemTargetAdapter(target)).capture_stable(
        (identity,)
    )

    observation = view.files[identity]
    assert observation.object_type == "symlink"
    assert stat.S_ISLNK(observation.mode)
    assert observation.content_digest == digest_bytes(os.fsencode(outside))
    assert view.ephemeral_root is not None
    assert _captured_bytes(view.ephemeral_root, identity) == os.fsencode(outside)
    assert repository_write_manifest(target) == before
    shutil.rmtree(view.ephemeral_root)


def test_filesystem_capture_refuses_special_files(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation unavailable")
    target = tmp_path / "special-target"
    target.mkdir()
    os.mkfifo(target / "pipe")

    with pytest.raises(CaptureUnknownError):
        FilesystemTargetAdapter(target).capture(())


def test_stable_capture_retries_one_unstable_read_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "retry-target"
    target.mkdir()
    cited = target / "cited.txt"
    cited.write_bytes(b"before\n")
    cited_inode = cited.stat().st_ino
    real_pread = os.pread
    changed = False

    def change_once(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal changed
        content = real_pread(descriptor, size, offset)
        if not changed and os.fstat(descriptor).st_ino == cited_inode:
            changed = True
            cited.write_bytes(b"after\n")
        return content

    monkeypatch.setattr(os, "pread", change_once)
    identity = _path(b"cited.txt")

    view = CaptureCoordinator(FilesystemTargetAdapter(target)).capture_stable(
        (identity,)
    )

    assert changed
    assert view.files[identity].content_digest == digest_bytes(b"after\n")
    assert view.ephemeral_root is not None
    assert _captured_bytes(view.ephemeral_root, identity) == b"after\n"
    shutil.rmtree(view.ephemeral_root)


def test_required_bytes_remain_immutable_after_target_changes(tmp_path: Path) -> None:
    target = tmp_path / "immutable-view-target"
    target.mkdir()
    cited = target / "cited.txt"
    cited.write_bytes(b"captured\n")
    identity = _path(b"cited.txt")
    view = CaptureCoordinator(FilesystemTargetAdapter(target)).capture_stable(
        (identity,)
    )

    cited.write_bytes(b"changed later\n")

    assert view.ephemeral_root is not None
    assert _captured_bytes(view.ephemeral_root, identity) == b"captured\n"
    assert view.files[identity].content_digest == digest_bytes(b"captured\n")
    shutil.rmtree(view.ephemeral_root)
