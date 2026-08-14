from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from agent_continuity.kernel.canonical import canonical_bytes
from tests.helpers.git_repo import make_git_repo

ROOT = Path(__file__).parents[2]


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
        "anchor-truncation",
    )


def _drop_immutable_triggers(connection: sqlite3.Connection, table: str) -> None:
    rows = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = ?",
        (table,),
    ).fetchall()
    assert rows
    for (name,) in rows:
        connection.execute(f'DROP TRIGGER "{name}"')


@pytest.mark.parametrize("mutation", ("rewritten", "truncated"))
def test_cli_anchor_rejects_rewritten_or_truncated_audit_history(
    tmp_path: Path,
    mutation: str,
) -> None:
    repo = make_git_repo(tmp_path)
    state_home = tmp_path / "external-state"
    anchor = tmp_path / "anchor.json"
    arguments = _arguments(repo.root, state_home)
    initialized = _command(
        "init", *arguments, "--goal", "goal", "--instruction", "AGENTS.md"
    )
    assert initialized.returncode == 0
    assert _command("checkpoint", *arguments).returncode == 0
    assert (
        _command(
            "audit-anchor", "export", *arguments, "--output", os.fspath(anchor)
        ).returncode
        == 0
    )
    database = next(state_home.glob("*.sqlite3"))

    with sqlite3.connect(database) as connection:
        _drop_immutable_triggers(connection, "audit_events")
        if mutation == "truncated":
            first = connection.execute(
                "SELECT event_id FROM audit_events WHERE sequence = 1"
            ).fetchone()
            assert first is not None
            connection.execute(
                "UPDATE heads SET audit_event_id = ?, audit_sequence = 1 "
                "WHERE name = ?",
                (first[0], "session:anchor-truncation:checkpoint"),
            )
            connection.execute("DELETE FROM audit_events WHERE sequence = 2")
        else:
            connection.execute(
                "UPDATE audit_events SET canonical_bytes = ? WHERE sequence = 1",
                (b'{"rewritten":true}',),
            )

    result = _command("verify-audit", *arguments, "--anchor", os.fspath(anchor))
    assert result.returncode == 3
    assert _payload(result)["category"] == "integrity"
