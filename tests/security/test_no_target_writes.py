from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import TypeAlias

import pytest

from agent_continuity import Continuity, TransitionRefused
from agent_continuity.capture import CaptureSnapshot, GitTargetAdapter
from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from agent_continuity.kernel.model import LogicalTime
from tests.helpers.git_repo import (
    make_git_repo,
    repository_git_observation,
    repository_write_manifest,
)

ROOT = Path(__file__).parents[2]
Metadata: TypeAlias = tuple[int, int, int, int, int, int, int, int, int, bytes]


def _command(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.fspath(ROOT / "src")
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        [sys.executable, "-m", "agent_continuity.cli", *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
    )


def _payload(result: subprocess.CompletedProcess[bytes]) -> dict[str, object]:
    assert result.returncode == 0
    assert result.stderr == b""
    parsed = json.loads(result.stdout)
    assert type(parsed) is dict
    assert canonical_bytes(parsed) == result.stdout
    return parsed


def _metadata(path: Path) -> Metadata:
    entry = path.lstat()
    attributes: list[bytes] = []
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except (AttributeError, NotImplementedError, OSError):
        names = []
    for name in sorted(names):
        try:
            attributes.append(
                os.fsencode(name)
                + b"="
                + os.getxattr(path, name, follow_symlinks=False)
            )
        except (AttributeError, NotImplementedError, OSError):
            attributes.append(os.fsencode(name) + b"=<unreadable>")
    return (
        entry.st_dev,
        entry.st_ino,
        entry.st_mode,
        entry.st_uid,
        entry.st_gid,
        entry.st_nlink,
        entry.st_size,
        entry.st_mtime_ns,
        entry.st_ctime_ns,
        hashlib.sha256(b"\0".join(attributes)).digest(),
    )


def _application_metadata(root: Path) -> dict[str, Metadata]:
    paths = [root, *sorted(root.rglob("*"), key=os.fspath)]
    return {
        os.fspath(path.relative_to(root)) if path != root else ".": _metadata(path)
        for path in paths
    }


def _state_bytes(root: Path) -> bytes:
    return b"".join(
        path.read_bytes()
        for path in sorted(root.rglob("*"), key=os.fspath)
        if path.is_file()
    )


def _state_manifest(root: Path) -> dict[str, Metadata]:
    return _application_metadata(root)


def _arguments(target: Path, state_home: Path) -> tuple[str, ...]:
    return (
        "--target",
        os.fspath(target),
        "--state-home",
        os.fspath(state_home),
        "--session-key",
        "no-target-writes",
    )


def test_public_cli_commands_preserve_target_and_keep_raw_inputs_external(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    target_marker = b"TARGET_BYTES_MUST_NOT_REACH_STATE_V1"
    instruction_marker = b"INSTRUCTION_BYTES_MUST_NOT_REACH_STATE_V1"
    reason = "REASON_BYTES_MUST_NOT_REACH_STATE_V1"
    (repo.root / "target-marker.bin").write_bytes(target_marker)
    (repo.root / "AGENTS.md").write_bytes(instruction_marker)
    repo.git("add", "target-marker.bin", "AGENTS.md")
    repo.git("commit", "-q", "-m", "private-input-fixture")
    state_home = tmp_path / "external-state"
    anchor = tmp_path / "audit-anchor.json"
    arguments = _arguments(repo.root, state_home)
    before = (
        repository_write_manifest(repo.root),
        repository_git_observation(repo),
        _application_metadata(repo.root),
    )

    _payload(_command("policy-template"))
    initialized = _payload(
        _command(
            "init",
            *arguments,
            "--goal",
            "public synthetic goal",
            "--criterion",
            "public synthetic criterion",
            "--instruction",
            "AGENTS.md",
        )
    )
    repeated = _payload(
        _command(
            "init",
            *arguments,
            "--goal",
            "public synthetic goal",
            "--criterion",
            "public synthetic criterion",
            "--instruction",
            "AGENTS.md",
        )
    )
    assert repeated == initialized
    _payload(_command("checkpoint", *arguments, "--reason", reason))
    before_verify = _state_manifest(state_home)
    _payload(_command("verify", *arguments))
    assert _state_manifest(state_home) == before_verify
    _payload(
        _command(
            "audit-anchor",
            "export",
            *arguments,
            "--output",
            os.fspath(anchor),
        )
    )
    _payload(_command("verify-audit", *arguments, "--anchor", os.fspath(anchor)))

    assert (
        repository_write_manifest(repo.root),
        repository_git_observation(repo),
        _application_metadata(repo.root),
    ) == before
    persisted = _state_bytes(state_home) + anchor.read_bytes()
    for forbidden in (target_marker, instruction_marker, reason.encode("utf-8")):
        assert forbidden not in persisted


def test_concurrent_public_checkpoints_append_through_sqlite_cas(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    state_home = tmp_path / "external-state"
    arguments = _arguments(repo.root, state_home)
    initialized = _command(
        "init", *arguments, "--goal", "goal", "--instruction", "AGENTS.md"
    )
    assert initialized.returncode == 0
    before_target = repository_write_manifest(repo.root)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(
                lambda _index: _command("checkpoint", *arguments),
                range(2),
            )
        )

    receipts = tuple(_payload(result) for result in results)
    assert {receipt["audit_sequence"] for receipt in receipts} == {2, 3}
    database = next(state_home.glob("*.sqlite3"))
    with sqlite3.connect(database) as connection:
        audit_sequences = tuple(
            row[0]
            for row in connection.execute(
                "SELECT sequence FROM audit_events ORDER BY sequence"
            )
        )
    assert audit_sequences == (1, 2, 3)
    assert repository_write_manifest(repo.root) == before_target


class _FixedClock:
    def now(self) -> LogicalTime:
        return LogicalTime("2026-08-14T12:00:00Z")


class _CaptureSequence:
    def __init__(self, snapshots: tuple[CaptureSnapshot, ...]) -> None:
        self._snapshots = snapshots
        self._index = 0

    def capture(self, instruction_paths: tuple[bytes, ...]) -> CaptureSnapshot:
        assert instruction_paths == (b"AGENTS.md",)
        result = self._snapshots[self._index]
        self._index += 1
        return result


@pytest.mark.parametrize(
    ("phase", "checkpoint_snapshots"),
    [
        ("A", ("changed", "changed")),
        ("B", ("stable", "changed")),
        ("C", ("stable", "stable", "changed")),
    ],
)
def test_checkpoint_refuses_a_b_or_c_drift_before_state_write(
    tmp_path: Path,
    phase: str,
    checkpoint_snapshots: tuple[str, ...],
) -> None:
    repo = make_git_repo(tmp_path)
    with GitTargetAdapter(repo.root) as adapter:
        stable = adapter.capture((b"AGENTS.md",))
    changed = replace(
        stable,
        target=replace(
            stable.target,
            inventory_digest=digest_bytes(f"{phase}-drift".encode("ascii")),
        ),
    )
    observations = tuple(
        stable if item == "stable" else changed for item in checkpoint_snapshots
    )
    state_home = tmp_path / "external-state"
    continuity = Continuity.open(
        repo.root,
        state_home=state_home,
        session_key=f"drift-{phase}",
        clock=_FixedClock(),
        target_adapter=_CaptureSequence((stable,) * 3 + observations),
    )
    continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))
    before_state = _state_bytes(state_home)
    before_target = repository_write_manifest(repo.root)

    with pytest.raises(TransitionRefused):
        continuity.checkpoint()

    assert _state_bytes(state_home) == before_state
    assert repository_write_manifest(repo.root) == before_target
