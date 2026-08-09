from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, cast

ManifestValue: TypeAlias = tuple[str, int, int, int, str]


@dataclass(frozen=True, slots=True)
class GitRepo:
    root: Path

    @property
    def git_dir(self) -> Path:
        return self.root / ".git"

    def git(self, *args: str, check: bool = True) -> bytes:
        result = subprocess.run(
            [
                "git",
                "-c",
                "maintenance.auto=false",
                "-c",
                "gc.auto=0",
                "-C",
                os.fspath(self.root),
                *args,
            ],
            check=check,
            capture_output=True,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            timeout=30,
        )
        return result.stdout


@dataclass(frozen=True, slots=True)
class GitExecutableWrapper:
    """Controllable executable that delegates to the real Git binary."""

    bin_dir: Path
    config_path: Path
    log_path: Path
    state_path: Path

    def configure(self, **values: object) -> None:
        self.config_path.write_text(
            json.dumps(values, sort_keys=True), encoding="utf-8"
        )

    def invocations(self) -> list[list[str]]:
        if not self.log_path.exists():
            return []
        return [
            cast(list[str], json.loads(line))
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
            if line
        ]


def make_git_executable_wrapper(base: Path) -> GitExecutableWrapper:
    """Create a PATH-selectable Git wrapper for public adapter probes."""

    candidate = shutil.which("git")
    if candidate is None:
        raise RuntimeError("Git executable is unavailable")
    real_git = Path(candidate).resolve(strict=True)
    bin_dir = base / "git-wrapper-bin"
    bin_dir.mkdir()
    config_path = base / "git-wrapper-config.json"
    log_path = base / "git-wrapper-invocations.jsonl"
    state_path = base / "git-wrapper-triggered"
    wrapper = bin_dir / "git"
    wrapper.write_text(
        f"#!{sys.executable}\n"
        "import json\n"
        "import os\n"
        "import signal\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "from pathlib import Path\n"
        f"REAL_GIT = {os.fspath(real_git)!r}\n"
        f"CONFIG = Path({os.fspath(config_path)!r})\n"
        f"LOG = Path({os.fspath(log_path)!r})\n"
        f"STATE = Path({os.fspath(state_path)!r})\n"
        "config = json.loads(CONFIG.read_text(encoding='utf-8'))\n"
        "argv = sys.argv[1:]\n"
        "with LOG.open('a', encoding='utf-8') as stream:\n"
        "    stream.write(json.dumps([sys.argv[0], *argv]) + '\\n')\n"
        "commands = {'cat-file', 'config', 'ls-files', 'ls-tree', 'rev-parse'}\n"
        "command = next((item for item in argv if item in commands), '')\n"
        "selected = not config.get('trigger_command') or "
        "command == config['trigger_command']\n"
        "first = False\n"
        "if selected:\n"
        "    try:\n"
        "        descriptor = os.open(\n"
        "            STATE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600\n"
        "        )\n"
        "    except FileExistsError:\n"
        "        pass\n"
        "    else:\n"
        "        os.close(descriptor)\n"
        "        first = True\n"
        "active = selected and (first or not config.get('once', False))\n"
        "if active and config.get('fd_probe'):\n"
        "    open_fds = []\n"
        "    for descriptor in range(3, 256):\n"
        "        try:\n"
        "            os.fstat(descriptor)\n"
        "        except OSError:\n"
        "            continue\n"
        "        open_fds.append(descriptor)\n"
        "    Path(config['fd_probe']).write_text(\n"
        "        json.dumps(open_fds), encoding='utf-8'\n"
        "    )\n"
        "if active and config.get('mutate_path'):\n"
        "    Path(config['mutate_path']).write_text(\n"
        "        config['mutate_content'], encoding='ascii'\n"
        "    )\n"
        "if active and config.get('root_swap'):\n"
        "    swap = config['root_swap']\n"
        "    os.rename(swap['target'], swap['displaced'])\n"
        "    os.rename(swap['replacement'], swap['target'])\n"
        "if active and config.get('sleep_seconds'):\n"
        "    time.sleep(float(config['sleep_seconds']))\n"
        "if active and config.get('stderr_text') is not None:\n"
        "    sys.stderr.write(config['stderr_text'])\n"
        "    sys.stderr.flush()\n"
        "if active and config.get('signal'):\n"
        "    os.kill(os.getpid(), getattr(signal, config['signal']))\n"
        "if active and config.get('exit_code') is not None:\n"
        "    raise SystemExit(int(config['exit_code']))\n"
        "if active and config.get('overflow_stream'):\n"
        "    descriptor = 1 if config['overflow_stream'] == 'stdout' else 2\n"
        "    chunk = b'x' * (64 * 1024)\n"
        "    for _ in range(160):\n"
        "        os.write(descriptor, chunk)\n"
        "    raise SystemExit(0)\n"
        "result = subprocess.run([REAL_GIT, *argv], capture_output=True, check=False)\n"
        "stdout = result.stdout\n"
        "if active and config.get('strip_final_nul') and stdout.endswith(b'\\x00'):\n"
        "    stdout = stdout[:-1]\n"
        "if active and config.get('stdout_text') is not None:\n"
        "    stdout = config['stdout_text'].encode('ascii')\n"
        "sys.stdout.buffer.write(stdout)\n"
        "sys.stderr.buffer.write(result.stderr)\n"
        "raise SystemExit(result.returncode)\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    result = GitExecutableWrapper(
        bin_dir=bin_dir,
        config_path=config_path,
        log_path=log_path,
        state_path=state_path,
    )
    result.configure()
    return result


def make_git_repo(
    base: Path,
    *,
    remote: str | None = None,
    object_format: str | None = None,
) -> GitRepo:
    root = base / "synthetic-target"
    root.mkdir()
    repo = GitRepo(root)
    init_args = ["init", "-q"]
    if object_format is not None:
        init_args.append(f"--object-format={object_format}")
    repo.git(*init_args)
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
