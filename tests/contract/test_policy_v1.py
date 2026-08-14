from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from agent_continuity.kernel.evaluation import Profile, Verdict
from agent_continuity.kernel.model import AssignmentAuthority, PromotionMode
from agent_continuity.policy import (
    PolicyRequestError,
    load_policy,
    render_policy_template,
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_builtin_guard_policy_has_frozen_defaults(tmp_path: Path) -> None:
    loaded = load_policy(target=tmp_path.resolve(), explicit=None)

    assert loaded.source == "builtin"
    assert loaded.source_digest == loaded.compiled.authoring_digest
    assert loaded.compiled.profile is Profile.GUARD
    assert loaded.compiled.promotion_mode is PromotionMode.AUTOMATIC
    assert loaded.compiled.max_assignment_authority is AssignmentAuthority.READ_ONLY
    assert loaded.compiled.approval_operator_ids == ()
    assert loaded.compiled.rollback_operator_ids == ()
    assert loaded.compiled.required_adapter_capabilities == ()
    assert loaded.compiled.evidence_expiry_seconds == 3600
    assert loaded.compiled.enabled_detectors == ("capture.unstable", "target.dirty")
    assert loaded.compiled.severity_by_code == (
        ("capture.unstable", Verdict.BLOCK),
        ("target.dirty", Verdict.BLOCK),
    )
    assert loaded.compiled.limits.max_paths == 250_000
    assert loaded.compiled.limits.max_file_bytes == 1_073_741_824
    assert loaded.compiled.limits.max_aggregate_bytes == 21_474_836_480
    assert loaded.compiled.limits.max_analyzer_text_bytes == 4_194_304
    assert loaded.compiled.limits.max_external_json_bytes == 8_388_608


@pytest.mark.parametrize(
    "body",
    [
        "version = 1\nunknown = true\n",
        'version = 1\nprofile = "guard"\nprofile = "strict"\n',
        'version = "1"\n',
        "version = 2\n",
        "version = 1\nprofile = 1\n",
        'version = 1\nprofile = "future"\n',
        'version = 1\npromotion_mode = "future"\n',
        'version = 1\nmax_assignment_authority = "future"\n',
        'version = 1\nrequired_adapter_capabilities = ["future"]\n',
        'version = 1\nenabled_detectors = ["future"]\n',
        'version = 1\nseverity_by_code = {"target.dirty" = "pass"}\n',
        'version = 1\nseverity_by_code = {"target.dirty" = "unknown"}\n',
        "version = 1\n[limits]\nmax_paths = 0\n",
        "version = 1\n[limits]\nmax_paths = 250001\n",
        "version = 1\n[limits]\nmax_file_bytes = 1073741825\n",
        "version = 1\n[limits]\nmax_aggregate_bytes = 21474836481\n",
        "version = 1\n[limits]\nmax_analyzer_text_bytes = 4194305\n",
        "version = 1\n[limits]\nmax_external_json_bytes = 8388609\n",
    ],
)
def test_strict_authoring_rejects_invalid_input_without_echo(
    tmp_path: Path, body: str
) -> None:
    policy = _write(tmp_path / "policy.toml", body)

    with pytest.raises(PolicyRequestError) as captured:
        load_policy(target=tmp_path.resolve(), explicit=policy.resolve())

    assert body.strip() not in str(captured.value)
    assert "future" not in str(captured.value)


def test_authoring_normalizes_set_like_fields_into_canonical_tuples(
    tmp_path: Path,
) -> None:
    policy = _write(
        tmp_path / "policy.toml",
        """version = 1
profile = "strict"
promotion_mode = "review"
required_adapter_capabilities = ["git_network_disabled", "atomic_snapshot"]
approval_operator_ids = [
  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
]
rollback_operator_ids = []
evidence_expiry_seconds = 42
enabled_detectors = ["target.dirty", "capture.unstable"]
severity_by_code = {"target.dirty" = "warn", "capture.unstable" = "block"}

[limits]
max_paths = 10
max_file_bytes = 20
max_aggregate_bytes = 30
max_analyzer_text_bytes = 20
max_external_json_bytes = 40
""",
    )

    compiled = load_policy(
        target=tmp_path.resolve(), explicit=policy.resolve()
    ).compiled
    assert compiled.required_adapter_capabilities == (
        "atomic_snapshot",
        "git_network_disabled",
    )
    assert tuple(compiled.approval_operator_ids) == tuple(
        sorted(compiled.approval_operator_ids)
    )
    assert compiled.enabled_detectors == ("capture.unstable", "target.dirty")
    assert compiled.severity_by_code == (
        ("capture.unstable", Verdict.BLOCK),
        ("target.dirty", Verdict.WARN),
    )


def test_policy_and_template_schemas_are_strict(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    policy_schema = json.loads(
        (root / "schemas/v1/policy.schema.json").read_text(encoding="utf-8")
    )
    template_schema = json.loads(
        (root / "schemas/v1/policy-template.schema.json").read_text(encoding="utf-8")
    )
    loaded = load_policy(target=tmp_path.resolve(), explicit=None)
    policy_value = json.loads(loaded.compiled.record().canonical_bytes)
    template = render_policy_template()

    Draft202012Validator(policy_schema).validate(policy_value)
    Draft202012Validator(template_schema).validate(template)
    with pytest.raises(ValidationError):
        Draft202012Validator(policy_schema).validate({**policy_value, "raw": "secret"})
    with pytest.raises(ValidationError):
        Draft202012Validator(template_schema).validate({**template, "extra": True})
    assert canonical_bytes(template)
    lines = template["toml_lines"]
    assert isinstance(lines, list)
    authored = "\n".join(str(line) for line in lines).encode()
    assert template["authoring_digest"] == digest_bytes(authored)
    assert all(not any(ord(char) < 0x20 for char in str(line)) for line in lines)
    explicit = _write(tmp_path / "template.toml", authored.decode("utf-8"))
    assert (
        load_policy(target=tmp_path.resolve(), explicit=explicit.resolve()).compiled
        == loaded.compiled
    )


def test_raw_authoring_bytes_are_absent_from_policy_record(tmp_path: Path) -> None:
    marker = "raw-authoring-marker-must-not-persist"
    explicit = _write(
        tmp_path / "policy.toml",
        f'# {marker}\nversion = 1\nprofile = "guard"\n',
    )
    record = load_policy(
        target=tmp_path.resolve(), explicit=explicit.resolve()
    ).compiled.record()

    assert marker.encode("utf-8") not in record.canonical_bytes
