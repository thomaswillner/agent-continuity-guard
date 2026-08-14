from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from agent_continuity.kernel.canonical import canonical_bytes

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


def test_console_module_emits_one_canonical_value() -> None:
    result = _command("policy-template")

    assert result.returncode == 0
    assert result.stderr == b""
    assert _payload(result)["schema"] == "PolicyTemplate/v1"


def test_top_level_help_is_deterministic_human_facing_command_inventory() -> None:
    first = _command("--help")
    repeated = _command("--help")

    expected = (
        b"usage: acg --help\n"
        b"\n"
        b"commands:\n"
        b"  policy-template\n"
        b"  init\n"
        b"  checkpoint\n"
        b"  verify\n"
        b"  verify-audit\n"
        b"  audit-anchor\n"
    )
    assert first.returncode == 0
    assert first.stderr == b""
    assert first.stdout == expected
    assert (repeated.returncode, repeated.stdout, repeated.stderr) == (
        first.returncode,
        first.stdout,
        first.stderr,
    )
    assert os.fsencode(ROOT) not in first.stdout


def test_policy_template_is_canonical_complete_and_quiet() -> None:
    result = _command("policy-template")

    assert result.returncode == 0
    assert result.stderr == b""
    payload = _payload(result)
    assert payload["schema"] == "PolicyTemplate/v1"
    assert payload["toml_lines"] == [
        "version = 1",
        'profile = "guard"',
        'promotion_mode = "automatic"',
        'max_assignment_authority = "read_only"',
        "approval_operator_ids = []",
        "rollback_operator_ids = []",
        "required_adapter_capabilities = []",
        "evidence_expiry_seconds = 3600",
        'enabled_detectors = ["capture.unstable", "target.dirty"]',
        'severity_by_code = {"capture.unstable" = "block", "target.dirty" = "block"}',
        "",
        "[limits]",
        "max_paths = 250000",
        "max_file_bytes = 1073741824",
        "max_aggregate_bytes = 21474836480",
        "max_analyzer_text_bytes = 4194304",
        "max_external_json_bytes = 8388608",
    ]


def test_invalid_request_is_sanitized_error_record() -> None:
    marker = "raw-cli-request-marker"
    result = _command(
        "init",
        "--target",
        os.fspath(ROOT / marker),
        "--state-home",
        os.fspath(ROOT / "state"),
        "--goal",
        marker,
    )

    assert result.returncode == 2
    assert result.stderr == b""
    payload = _payload(result)
    assert payload == {
        "schema": "Error/v1",
        "category": "request",
        "code": "request_invalid",
        "message_id": "acg.request.invalid",
        "parameters": {},
    }
    assert marker.encode() not in result.stdout
