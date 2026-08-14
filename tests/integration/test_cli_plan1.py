from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

from agent_continuity.kernel.canonical import canonical_bytes
from tests.helpers.git_repo import make_git_repo, repository_write_manifest

ROOT = Path(__file__).parents[2]


def _command(
    *arguments: str,
    injection: Path | None = None,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    paths = [os.fspath(ROOT / "src")]
    if injection is not None:
        paths.insert(0, os.fspath(injection))
    environment["PYTHONPATH"] = os.pathsep.join(paths)
    if extra_environment is not None:
        environment.update(extra_environment)
    return subprocess.run(
        [sys.executable, "-m", "agent_continuity.cli", *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
    )


def _payload(result: subprocess.CompletedProcess[bytes]) -> dict[str, object]:
    assert result.stdout
    parsed = json.loads(result.stdout)
    assert type(parsed) is dict
    assert canonical_bytes(parsed) == result.stdout
    return parsed


def _arguments(target: Path, state_home: Path) -> tuple[str, ...]:
    return (
        "--target",
        os.fspath(target),
        "--state-home",
        os.fspath(state_home),
        "--session-key",
        "cli-plan1",
    )


def _lexical_var_alias(path: Path) -> Path:
    raw = os.fspath(path)
    if raw.startswith("/private/var/"):
        return Path(raw.removeprefix("/private"))
    return path


def _initialize_cli_state(tmp_path: Path) -> tuple[Path, Path, tuple[str, ...]]:
    target = make_git_repo(tmp_path).root
    state_home = tmp_path / "external-state"
    common = _arguments(target, state_home)
    initialized = _command(
        "init", *common, "--goal", "goal", "--instruction", "AGENTS.md"
    )
    assert initialized.returncode == 0
    return target, state_home, common


def _injection_directory(tmp_path: Path, source: str) -> Path:
    injection = tmp_path / "injection"
    injection.mkdir()
    (injection / "sitecustomize.py").write_text(source, encoding="utf-8")
    return injection


def test_plan1_cli_commands_preserve_target_and_pure_verify(tmp_path: Path) -> None:
    target = make_git_repo(tmp_path).root
    state_home = _lexical_var_alias(tmp_path / "external-state")
    before_target = repository_write_manifest(target)
    common = _arguments(target, state_home)

    initialized = _command(
        "init",
        *common,
        "--goal",
        "CLI continuity goal",
        "--criterion",
        "CLI public contract",
        "--instruction",
        "AGENTS.md",
    )
    assert initialized.returncode == 0
    assert initialized.stderr == b""
    assert _payload(initialized)["transition_allowed"] is True

    checkpoint = _command("checkpoint", *common)
    assert checkpoint.returncode == 0
    assert checkpoint.stderr == b""
    assert _payload(checkpoint)["transition_allowed"] is True

    database = next(state_home.glob("*.sqlite3"))
    before_verify = database.read_bytes()
    verified = _command("verify", *common)
    assert verified.returncode == 0
    assert verified.stderr == b""
    assert _payload(verified) == {
        "findings": [],
        "schema": "VerificationResult/v1",
        "transition_allowed": True,
        "verdict": "pass",
    }
    assert database.read_bytes() == before_verify

    anchor_output = tmp_path / "audit-anchor.json"
    exported = _command(
        "audit-anchor", "export", *common, "--output", os.fspath(anchor_output)
    )
    assert exported.returncode == 0
    assert exported.stderr == b""
    exported_payload = _payload(exported)
    assert json.loads(anchor_output.read_bytes()) == exported_payload
    assert stat.S_IMODE(anchor_output.stat().st_mode) == 0o600
    assert not anchor_output.is_relative_to(target)
    assert not anchor_output.is_relative_to(state_home)

    for forbidden_output in (target / "blocked.json", state_home / "blocked.json"):
        refused_export = _command(
            "audit-anchor",
            "export",
            *common,
            "--output",
            os.fspath(forbidden_output),
        )
        assert refused_export.returncode == 2
        assert refused_export.stderr == b""
        assert _payload(refused_export)["schema"] == "Error/v1"

    audit = _command("verify-audit", *common, "--anchor", os.fspath(anchor_output))
    assert audit.returncode == 0
    assert audit.stderr == b""
    audit_payload = _payload(audit)
    assert audit_payload["valid"] is True
    assert audit_payload["supplied_anchor_matched"] is True
    assert repository_write_manifest(target) == before_target


def test_dirty_transition_and_tampered_store_map_to_stable_exit_codes(
    tmp_path: Path,
) -> None:
    target = make_git_repo(tmp_path).root
    state_home = tmp_path / "external-state"
    common = _arguments(target, state_home)
    initialized = _command(
        "init", *common, "--goal", "goal", "--instruction", "AGENTS.md"
    )
    assert initialized.returncode == 0

    (target / "README.md").write_text("dirty\n", encoding="utf-8")
    refused = _command("checkpoint", *common)
    assert refused.returncode == 1
    assert refused.stderr == b""
    refused_payload = _payload(refused)
    assert refused_payload["category"] == "transition"
    assert refused_payload["schema"] == "Error/v1"

    (target / "README.md").write_text("synthetic target\n", encoding="utf-8")
    database = next(state_home.glob("*.sqlite3"))
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'trigger' "
            "AND tbl_name = 'records'"
        ).fetchall()
        for (name,) in rows:
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(
            "UPDATE records SET canonical_bytes = ? WHERE record_type = 'Checkpoint'",
            (b'{"tampered":true}',),
        )
    integrity = _command("verify", *common)
    assert integrity.returncode == 3
    assert integrity.stderr == b""
    integrity_payload = _payload(integrity)
    assert integrity_payload["category"] == "integrity"
    assert integrity_payload["schema"] == "Error/v1"


def test_anchor_export_detects_parent_swap_before_descriptor_create(
    tmp_path: Path,
) -> None:
    _target, state_home, common = _initialize_cli_state(tmp_path)
    parent = tmp_path / "race-parent"
    displaced = tmp_path / "race-displaced"
    parent.mkdir()
    output = parent / "anchor.json"
    injection = _injection_directory(
        tmp_path,
        """
import os
from pathlib import Path

parent = Path(os.environ["ACG_TEST_RACE_PARENT"])
state = Path(os.environ["ACG_TEST_RACE_STATE"])
displaced = Path(os.environ["ACG_TEST_RACE_DISPLACED"])
real_open = os.open
fired = False

def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
    global fired
    value = os.fspath(path)
    if not fired and value in {os.fspath(parent), parent.name}:
        fired = True
        os.rename(parent, displaced)
        os.rename(state, parent)
    return real_open(path, flags, mode, dir_fd=dir_fd)

os.open = guarded_open
""",
    )
    result = _command(
        "audit-anchor",
        "export",
        *common,
        "--output",
        os.fspath(output),
        injection=injection,
        extra_environment={
            "ACG_TEST_RACE_PARENT": os.fspath(parent),
            "ACG_TEST_RACE_STATE": os.fspath(state_home),
            "ACG_TEST_RACE_DISPLACED": os.fspath(displaced),
        },
    )
    assert result.returncode == 2
    assert result.stderr == b""
    assert _payload(result)["schema"] == "Error/v1"

    os.rename(parent, state_home)
    os.rename(displaced, parent)
    assert not (state_home / "anchor.json").exists()


def test_anchor_export_cleans_partial_file_after_directory_fsync_failure(
    tmp_path: Path,
) -> None:
    _target, _state_home, common = _initialize_cli_state(tmp_path)
    output = tmp_path / "anchor.json"
    injection = _injection_directory(
        tmp_path,
        """
import errno
import os
import stat

real_fsync = os.fsync

def failing_directory_fsync(descriptor):
    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
        raise OSError(errno.EIO, "injected directory durability failure")
    return real_fsync(descriptor)

os.fsync = failing_directory_fsync
""",
    )
    failed = _command(
        "audit-anchor",
        "export",
        *common,
        "--output",
        os.fspath(output),
        injection=injection,
    )
    assert failed.returncode == 2
    assert failed.stderr == b""
    assert _payload(failed)["schema"] == "Error/v1"
    assert not output.exists()

    retried = _command(
        "audit-anchor", "export", *common, "--output", os.fspath(output)
    )
    assert retried.returncode == 0
    assert retried.stderr == b""
    assert _payload(retried)["audit_sequence"] >= 1


def test_verify_audit_mismatch_and_tamper_are_integrity_errors(
    tmp_path: Path,
) -> None:
    _target, state_home, common = _initialize_cli_state(tmp_path)
    anchor = tmp_path / "anchor.json"
    exported = _command(
        "audit-anchor", "export", *common, "--output", os.fspath(anchor)
    )
    assert exported.returncode == 0
    anchor_payload = _payload(exported)
    mismatched = {**anchor_payload, "audit_sequence": 999}
    mismatch_path = tmp_path / "mismatch.json"
    mismatch_path.write_bytes(canonical_bytes(mismatched))
    mismatch = _command(
        "verify-audit", *common, "--anchor", os.fspath(mismatch_path)
    )
    assert mismatch.returncode == 3
    assert mismatch.stderr == b""
    assert _payload(mismatch)["category"] == "integrity"

    database = next(state_home.glob("*.sqlite3"))
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'trigger' "
            "AND tbl_name = 'audit_events'"
        ).fetchall()
        for (name,) in rows:
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(
            "UPDATE audit_events SET canonical_bytes = ? WHERE sequence = 1",
            (b'{"tampered":true}',),
        )
    tampered = _command("verify-audit", *common, "--anchor", os.fspath(anchor))
    assert tampered.returncode == 3
    assert tampered.stderr == b""
    assert _payload(tampered)["category"] == "integrity"


def test_invalid_label_and_different_reinitialize_are_request_errors(
    tmp_path: Path,
) -> None:
    _target, _state_home, common = _initialize_cli_state(tmp_path)
    invalid_label = _command(
        "audit-anchor",
        "export",
        *common,
        "--output",
        os.fspath(tmp_path / "anchor.json"),
        "--label",
        "invalid label",
    )
    assert invalid_label.returncode == 2
    assert invalid_label.stderr == b""
    assert _payload(invalid_label)["category"] == "request"

    conflicting = _command(
        "init", *common, "--goal", "different goal", "--instruction", "AGENTS.md"
    )
    assert conflicting.returncode == 2
    assert conflicting.stderr == b""
    assert _payload(conflicting)["category"] == "request"


def test_anchor_export_revalidates_pinned_parent_after_reparent_into_target(
    tmp_path: Path,
) -> None:
    target, _state_home, common = _initialize_cli_state(tmp_path)
    parent = tmp_path / "reparent-parent"
    moved = target / "moved-parent"
    parent.mkdir()
    injection = _injection_directory(
        tmp_path,
        """
import os
from pathlib import Path

parent = Path(os.environ["ACG_TEST_REPARENT_PARENT"])
target = Path(os.environ["ACG_TEST_REPARENT_TARGET"])
real_open = os.open
fired = False

def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
    global fired
    if not fired and os.fspath(path) == "anchor.json" and dir_fd is not None:
        fired = True
        os.rename(parent, target / "moved-parent")
    return real_open(path, flags, mode, dir_fd=dir_fd)

os.open = guarded_open
""",
    )
    result = _command(
        "audit-anchor",
        "export",
        *common,
        "--output",
        os.fspath(parent / "anchor.json"),
        injection=injection,
        extra_environment={
            "ACG_TEST_REPARENT_PARENT": os.fspath(parent),
            "ACG_TEST_REPARENT_TARGET": os.fspath(target),
        },
    )
    assert result.returncode == 2
    assert result.stderr == b""
    assert _payload(result)["schema"] == "Error/v1"
    assert moved.is_dir()
    assert not (moved / "anchor.json").exists()


def test_anchor_export_fails_and_cleans_when_success_close_reports_eio(
    tmp_path: Path,
) -> None:
    _target, _state_home, common = _initialize_cli_state(tmp_path)
    output = tmp_path / "anchor.json"
    injection = _injection_directory(
        tmp_path,
        """
import errno
import os

real_open = os.open
real_close = os.close
output_fd = -1
fired = False

def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
    global output_fd
    descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
    if os.fspath(path) == "anchor.json" and flags & os.O_CREAT:
        output_fd = descriptor
    return descriptor

def guarded_close(descriptor):
    global fired
    if descriptor == output_fd and not fired:
        fired = True
        raise OSError(errno.EIO, "injected output close failure")
    return real_close(descriptor)

os.open = guarded_open
os.close = guarded_close
""",
    )
    failed = _command(
        "audit-anchor",
        "export",
        *common,
        "--output",
        os.fspath(output),
        injection=injection,
    )
    assert failed.returncode == 2
    assert failed.stderr == b""
    assert _payload(failed)["schema"] == "Error/v1"
    assert not output.exists()

    retried = _command(
        "audit-anchor", "export", *common, "--output", os.fspath(output)
    )
    assert retried.returncode == 0
    assert retried.stderr == b""
    assert _payload(retried)["audit_sequence"] >= 1
