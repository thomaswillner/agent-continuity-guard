from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_continuity import Continuity, ContinuityRequestError
from tests.helpers.git_repo import make_git_repo


def _two_repositories(tmp_path: Path) -> tuple[Path, Path]:
    first_base = tmp_path / "first"
    second_base = tmp_path / "second"
    first_base.mkdir()
    second_base.mkdir()
    return make_git_repo(first_base).root, make_git_repo(second_base).root


def test_facade_refuses_symlink_target_before_policy_or_state_admission(
    tmp_path: Path,
) -> None:
    target, _replacement = _two_repositories(tmp_path)
    alias = tmp_path / "target-alias"
    alias.symlink_to(target, target_is_directory=True)
    state_home = tmp_path / "external-state"

    with pytest.raises(ContinuityRequestError):
        Continuity.open(alias, state_home=state_home)

    assert not state_home.exists()


def test_cli_subprocess_refuses_symlink_alias_before_timed_alias_swap(
    tmp_path: Path,
) -> None:
    target, replacement = _two_repositories(tmp_path)
    alias = tmp_path / "target-alias"
    alias.symlink_to(target, target_is_directory=True)
    state_home = tmp_path / "external-state"
    script = """
import os
import sys
from pathlib import Path
from agent_continuity import api
from agent_continuity.cli import main

alias = Path(sys.argv[1])
replacement = Path(sys.argv[2])
state_home = sys.argv[3]
load_target_policy = api.load_target_policy

def swapping_load_target_policy(authoring):
    alias.unlink()
    alias.symlink_to(replacement, target_is_directory=True)
    return load_target_policy(authoring)

api.load_target_policy = swapping_load_target_policy
raise SystemExit(main((
    "init",
    "--target", os.fspath(alias),
    "--state-home", state_home,
    "--goal", "goal",
    "--instruction", "AGENTS.md",
)))
"""

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            os.fspath(alias),
            os.fspath(replacement),
            os.fspath(state_home),
        ],
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": os.fspath(Path.cwd() / "src")},
        timeout=30,
    )

    assert result.returncode == 2
    assert result.stderr == b""
    payload = json.loads(result.stdout)
    assert payload["category"] == "request"
    assert not state_home.exists()
