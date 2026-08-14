from __future__ import annotations

import json
from dataclasses import replace
from itertools import combinations
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from agent_continuity.kernel import model as policy_model
from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from agent_continuity.kernel.evaluation import Profile, Verdict
from agent_continuity.kernel.model import (
    AssignmentAuthority,
    PromotionMode,
    ResourceLimitsV1,
)
from agent_continuity.kernel.records import policy_payload
from agent_continuity.policy import (
    PolicyRequestError,
    load_policy,
    render_policy_template,
)

RESOURCE_LIMIT_MAXIMA = (
    ("max_paths", 250_000),
    ("max_file_bytes", 1_073_741_824),
    ("max_aggregate_bytes", 21_474_836_480),
    ("max_analyzer_text_bytes", 4_194_304),
    ("max_external_json_bytes", 8_388_608),
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


def test_policy_request_error_exposes_stable_request_exit_code(tmp_path: Path) -> None:
    with pytest.raises(PolicyRequestError) as captured:
        load_policy(target=tmp_path.resolve(), explicit=Path("relative.toml"))

    assert captured.value.exit_code == 2
    assert type(captured.value.exit_code) is int


@pytest.mark.parametrize(
    ("field", "maximum"),
    RESOURCE_LIMIT_MAXIMA,
)
def test_public_resource_limits_enforce_schema_maxima(field: str, maximum: int) -> None:
    assert policy_model.RESOURCE_LIMIT_MAXIMA_V1 == RESOURCE_LIMIT_MAXIMA
    values = dict(RESOURCE_LIMIT_MAXIMA)
    values[field] = maximum + 1

    with pytest.raises(ValueError):
        ResourceLimitsV1(**values)


def test_public_policy_models_enforce_current_vocabularies(tmp_path: Path) -> None:
    compiled = load_policy(target=tmp_path.resolve(), explicit=None).compiled
    assert (
        frozenset(
            {
                "atomic_snapshot",
                "descriptor_pinned_reads",
                "git_immutable_objects",
                "git_network_disabled",
                "windows_reparse_protection",
            }
        )
        == policy_model.ADAPTER_CAPABILITY_VOCABULARY_V1
    )
    assert (
        frozenset({"capture.unstable", "target.dirty"})
        == policy_model.DETECTOR_CODE_VOCABULARY_V1
    )

    with pytest.raises(ValueError):
        replace(compiled, required_adapter_capabilities=("future",))
    with pytest.raises(ValueError):
        replace(
            compiled,
            enabled_detectors=("future",),
            severity_by_code=(("future", Verdict.BLOCK),),
        )


def test_runtime_and_schema_reject_same_order_unique_and_coverage_cases(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[2]
    schema = json.loads(
        (root / "schemas/v1/policy.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    compiled = load_policy(target=tmp_path.resolve(), explicit=None).compiled
    default_value = json.loads(compiled.record().canonical_bytes)
    validator.validate(default_value)

    cases = [
        (
            {
                "required_adapter_capabilities": (
                    "git_network_disabled",
                    "atomic_snapshot",
                )
            },
            {
                "required_adapter_capabilities": [
                    "git_network_disabled",
                    "atomic_snapshot",
                ]
            },
        ),
        (
            {"required_adapter_capabilities": ("atomic_snapshot", "atomic_snapshot")},
            {"required_adapter_capabilities": ["atomic_snapshot", "atomic_snapshot"]},
        ),
        (
            {
                "enabled_detectors": ("target.dirty",),
                "severity_by_code": (
                    ("capture.unstable", Verdict.BLOCK),
                    ("target.dirty", Verdict.BLOCK),
                ),
            },
            {
                "enabled_detectors": ["target.dirty"],
                "severity_by_code": {
                    "capture.unstable": "block",
                    "target.dirty": "block",
                },
            },
        ),
    ]
    for runtime_changes, schema_changes in cases:
        with pytest.raises(ValueError):
            replace(compiled, **runtime_changes)
        with pytest.raises(ValidationError):
            validator.validate({**default_value, **schema_changes})


def test_all_canonical_capability_and_detector_subsets_have_schema_parity(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[2]
    schema = json.loads(
        (root / "schemas/v1/policy.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    compiled = load_policy(target=tmp_path.resolve(), explicit=None).compiled
    capabilities = sorted(policy_model.ADAPTER_CAPABILITY_VOCABULARY_V1)
    for size in range(len(capabilities) + 1):
        for subset in combinations(capabilities, size):
            candidate = replace(compiled, required_adapter_capabilities=subset)
            validator.validate(json.loads(canonical_bytes(policy_payload(candidate))))

    detectors = sorted(policy_model.DETECTOR_CODE_VOCABULARY_V1)
    for size in range(len(detectors) + 1):
        for subset in combinations(detectors, size):
            candidate = replace(
                compiled,
                enabled_detectors=subset,
                severity_by_code=tuple((code, Verdict.BLOCK) for code in subset),
            )
            validator.validate(json.loads(canonical_bytes(policy_payload(candidate))))
