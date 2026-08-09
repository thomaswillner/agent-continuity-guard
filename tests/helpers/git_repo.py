from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

ManifestValue: TypeAlias = tuple[str, int, int, int, str]


@dataclass(frozen=True, slots=True)
class GitRepo:
    root: Path

    @property
    def git_dir(self) -> Path:
        return self.root / ".git"

    def git(self, *args: str, check: bool = True) -> bytes:
        result = subprocess.run(
            ["git", "-C", os.fspath(self.root), *args],
            check=check,
            capture_output=True,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            timeout=30,
        )
        return result.stdout


def make_git_repo(base: Path, *, remote: str | None = None) -> GitRepo:
    root = base / "synthetic-target"
    root.mkdir()
    repo = GitRepo(root)
    repo.git("init", "-q")
    repo.git("config", "user.name", "Synthetic Test")
    repo.git("config", "user.email", "synthetic@example.invalid")
    (root / "README.md").write_text("synthetic target\n", encoding="utf-8")
    (root / "AGENTS.md").write_text("# Synthetic instructions\n", encoding="utf-8")
    (root / ".gitignore").write_text("ignored.tmp\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "guide.txt").write_text("guide\n", encoding="utf-8")
    os.symlink("README.md", root / "latest")
    repo.git("add", ".")
    repo.git("commit", "-q", "-m", "synthetic fixture")
    if remote is not None:
        repo.git("remote", "add", "origin", remote)
    return repo


def repository_write_manifest(root: Path) -> dict[str, ManifestValue]:
    manifest: dict[str, ManifestValue] = {}
    for path in sorted(root.rglob("*"), key=lambda item: os.fsencode(item)):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            kind = "symlink"
            digest = hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
        elif path.is_dir():
            kind = "directory"
            digest = ""
        elif path.is_file():
            kind = "file"
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            kind = "special"
            digest = ""
        manifest[relative] = (
            kind,
            mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            digest,
        )
    return manifest


def repository_git_observation(repo: GitRepo) -> dict[str, bytes]:
    return {
        "config": repo.git("config", "--local", "--list", "--null"),
        "head": repo.git("rev-parse", "HEAD"),
        "hooks": b"\x00".join(
            sorted(
                os.fsencode(path.relative_to(repo.root))
                + b":"
                + str(stat.S_IMODE(path.lstat().st_mode)).encode("ascii")
                + b":"
                + hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii")
                for path in repo.git_dir.joinpath("hooks").glob("*")
                if path.is_file()
            )
        ),
        "index": repo.git("ls-files", "--stage", "-z"),
        "refs": repo.git("show-ref", "--head", "-d"),
        "status": repo.git("status", "--porcelain=v2", "-z", "--untracked-files=all"),
        "tree": repo.git("rev-parse", "HEAD^{tree}"),
    }
