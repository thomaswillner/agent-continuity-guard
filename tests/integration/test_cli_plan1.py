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


def _command(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.fspath(ROOT / "src")
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
