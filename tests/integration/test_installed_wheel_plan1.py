from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from agent_continuity.kernel.canonical import canonical_bytes
from tests.helpers.git_repo import make_git_repo

ROOT = Path(__file__).parents[2]


def _run(
    executable: Path, *arguments: str, cwd: Path
) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        [os.fspath(executable), *arguments],
        cwd=cwd,
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


def test_installed_wheel_runs_complete_plan1_public_workflow(tmp_path: Path) -> None:
    distribution = tmp_path / "dist"
    built = _run(
        Path(sys.executable),
        "-m",
        "build",
        "--wheel",
        "--outdir",
        os.fspath(distribution),
        cwd=ROOT,
    )
    assert built.returncode == 0, built.stderr.decode("utf-8", "replace")
    wheel = next(distribution.glob("agent_continuity_guard-*.whl"))
    environment = tmp_path / "installed-environment"
    created = _run(
        Path(sys.executable), "-m", "venv", os.fspath(environment), cwd=tmp_path
    )
    assert created.returncode == 0, created.stderr.decode("utf-8", "replace")
    python = environment / "bin" / "python"
    installed = _run(
        python,
        "-m",
        "pip",
        "install",
        "--no-deps",
        os.fspath(wheel),
        cwd=tmp_path,
    )
    assert installed.returncode == 0, installed.stderr.decode("utf-8", "replace")
    imported = _run(
        python,
        "-c",
        "import agent_continuity; print(agent_continuity.__file__)",
        cwd=tmp_path,
    )
    assert imported.returncode == 0
    imported_path = Path(imported.stdout.decode("utf-8").strip()).resolve()
    assert imported_path.is_relative_to(environment.resolve())
    assert not imported_path.is_relative_to(ROOT)

    acg = environment / "bin" / "acg"
    help_result = _run(acg, "--help", cwd=tmp_path)
    assert help_result.returncode == 0
    for command in (
        b"policy-template",
        b"init",
        b"checkpoint",
        b"verify",
        b"verify-audit",
        b"audit-anchor",
    ):
        assert command in help_result.stdout
    _payload(_run(acg, "policy-template", cwd=tmp_path))

    target = make_git_repo(tmp_path).root
    state_home = tmp_path / "external-state"
    anchor = tmp_path / "anchor.json"
    common = (
        "--target",
        os.fspath(target),
        "--state-home",
        os.fspath(state_home),
        "--session-key",
        "installed-wheel",
    )
    initial = _payload(
        _run(
            acg,
            "init",
            *common,
            "--goal",
            "installed wheel goal",
            "--criterion",
            "installed wheel criterion",
            "--instruction",
            "AGENTS.md",
            cwd=tmp_path,
        )
    )
    repeated = _payload(
        _run(
            acg,
            "init",
            *common,
            "--goal",
            "installed wheel goal",
            "--criterion",
            "installed wheel criterion",
            "--instruction",
            "AGENTS.md",
            cwd=tmp_path,
        )
    )
    assert repeated == initial
    _payload(_run(acg, "checkpoint", *common, cwd=tmp_path))
    database = next(state_home.glob("*.sqlite3"))
    before_verify = database.read_bytes()
    _payload(_run(acg, "verify", *common, cwd=tmp_path))
    assert database.read_bytes() == before_verify
    _payload(
        _run(
            acg,
            "audit-anchor",
            "export",
            *common,
            "--output",
            os.fspath(anchor),
            cwd=tmp_path,
        )
    )
    audit = _payload(
        _run(acg, "verify-audit", *common, "--anchor", os.fspath(anchor), cwd=tmp_path)
    )
    assert audit["valid"] is True
    assert audit["supplied_anchor_matched"] is True
