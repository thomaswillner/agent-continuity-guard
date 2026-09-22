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


def _resume_checked(
    result: subprocess.CompletedProcess[bytes],
) -> dict[str, object]:
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stderr == b""
    value = json.loads(result.stdout)
    assert type(value) is dict
    return value


def test_exact_installed_wheel_resumes_after_restart_through_public_facade(
    tmp_path: Path,
) -> None:
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
    wheels = tuple(distribution.glob("agent_continuity_guard-*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]
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

    target = make_git_repo(tmp_path).root
    state_home = tmp_path / "external-state"
    initialize_script = """
import json
import pathlib
import sys
from agent_continuity import Continuity

continuity = Continuity.open(
    pathlib.Path(sys.argv[1]),
    state_home=pathlib.Path(sys.argv[2]),
    session_key="installed-resume",
)
receipt = continuity.initialize(
    "installed goal display text",
    ("installed criterion display text",),
    instruction_paths=("AGENTS.md",),
)
print(json.dumps({
    "checkpoint_id": receipt.checkpoint_id,
    "module": Continuity.__module__,
}, sort_keys=True))
"""
    initialized = _resume_checked(
        _run(
            python,
            "-c",
            initialize_script,
            os.fspath(target),
            os.fspath(state_home),
            cwd=tmp_path,
        )
    )
    resume_script = """
import dataclasses
import json
import pathlib
import sys
from agent_continuity import Continuity

continuity = Continuity.open(
    pathlib.Path(sys.argv[1]),
    state_home=pathlib.Path(sys.argv[2]),
    session_key="installed-resume",
)
context = continuity.resume()
print(json.dumps({
    "facade_path": str(
        pathlib.Path(sys.modules[Continuity.__module__].__file__).resolve()
    ),
    "field_names": [item.name for item in dataclasses.fields(context)],
    "frozen": context.__dataclass_params__.frozen,
    "has_dict": hasattr(context, "__dict__"),
    "schema": context.__class__.__module__ + "." + context.__class__.__name__,
    "checkpoint_id": context.checkpoint_id,
    "verdict": context.verdict.value,
    "usable": context.usable,
    "goal_digest": context.goal_digest,
    "acceptance_count": len(context.acceptance_criteria),
    "blocker_codes": list(context.blocker_codes),
}, sort_keys=True))
"""
    resumed = _resume_checked(
        _run(
            python,
            "-c",
            resume_script,
            os.fspath(target),
            os.fspath(state_home),
            cwd=tmp_path,
        )
    )

    assert resumed == {
        "acceptance_count": 1,
        "blocker_codes": [],
        "checkpoint_id": initialized["checkpoint_id"],
        "facade_path": resumed["facade_path"],
        "field_names": [
            "checkpoint_id",
            "verdict",
            "usable",
            "target_id",
            "goal_digest",
            "acceptance_criteria",
            "constraint_digests",
            "accepted_decision_ids",
            "pending_work",
            "unresolved",
            "open_assignment_ids",
            "current_evidence_ids",
            "invalidations",
            "blocker_codes",
        ],
        "frozen": True,
        "goal_digest": resumed["goal_digest"],
        "has_dict": False,
        "schema": "agent_continuity.kernel.resume.ResumeContext",
        "usable": True,
        "verdict": "pass",
    }
    facade_path = Path(str(resumed["facade_path"])).resolve()
    assert facade_path.is_relative_to(environment.resolve())
    assert not facade_path.is_relative_to(ROOT)
    assert resumed["goal_digest"] != "installed goal display text"
