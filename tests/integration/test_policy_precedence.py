from __future__ import annotations

from pathlib import Path

import pytest

from agent_continuity.kernel.evaluation import Profile
from agent_continuity.policy import load_policy


def test_precedence_is_explicit_then_target_then_builtin(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    target_policy = target / "acg.toml"
    target_policy.write_text('version = 1\nprofile = "observe"\n', encoding="utf-8")
    explicit = tmp_path / "explicit.toml"
    explicit.write_text('version = 1\nprofile = "strict"\n', encoding="utf-8")

    assert (
        load_policy(target=target.resolve(), explicit=explicit.resolve()).source
        == "explicit"
    )
    assert (
        load_policy(
            target=target.resolve(), explicit=explicit.resolve()
        ).compiled.profile
        is Profile.STRICT
    )
    assert load_policy(target=target.resolve(), explicit=None).source == "target"
    assert (
        load_policy(target=target.resolve(), explicit=None).compiled.profile
        is Profile.OBSERVE
    )
    target_policy.unlink()
    assert load_policy(target=target.resolve(), explicit=None).source == "builtin"


def test_authoring_and_compiled_changes_bind_policy_identity(tmp_path: Path) -> None:
    target = tmp_path.resolve()
    policy = tmp_path / "policy.toml"
    policy.write_text('version = 1\nprofile = "guard"\n', encoding="utf-8")
    first = load_policy(target=target, explicit=policy.resolve())
    policy.write_text('# comment\nversion = 1\nprofile = "guard"\n', encoding="utf-8")
    comment = load_policy(target=target, explicit=policy.resolve())
    policy.write_text('version = 1\nprofile = "strict"\n', encoding="utf-8")
    compiled = load_policy(target=target, explicit=policy.resolve())

    assert first.compiled.authoring_digest != comment.compiled.authoring_digest
    assert first.compiled.policy_id != comment.compiled.policy_id
    assert comment.compiled.policy_id != compiled.compiled.policy_id
    assert (
        first.compiled.record().canonical_bytes
        != comment.compiled.record().canonical_bytes
    )


@pytest.mark.parametrize(
    "change",
    [
        'promotion_mode = "review"',
        "[limits]\nmax_paths = 249999",
        "[limits]\nmax_file_bytes = 1073741823",
        "[limits]\nmax_aggregate_bytes = 21474836479",
        "[limits]\nmax_analyzer_text_bytes = 4194303",
        "[limits]\nmax_external_json_bytes = 8388607",
        'enabled_detectors = ["target.dirty"]\n'
        'severity_by_code = {"target.dirty" = "block"}',
        'severity_by_code = {"capture.unstable" = "warn", "target.dirty" = "block"}',
        'required_adapter_capabilities = ["atomic_snapshot"]',
        'max_assignment_authority = "scoped_write"',
        'approval_operator_ids = ["sha256:' + "a" * 64 + '"]',
        'rollback_operator_ids = ["sha256:' + "b" * 64 + '"]',
        "evidence_expiry_seconds = 3599",
    ],
)
def test_every_compiled_field_change_changes_policy_identity(
    tmp_path: Path, change: str
) -> None:
    baseline = tmp_path / "baseline.toml"
    baseline.write_text("version = 1\n", encoding="utf-8")
    changed = tmp_path / "changed.toml"
    changed.write_text(f"version = 1\n{change}\n", encoding="utf-8")

    baseline_id = load_policy(
        target=tmp_path.resolve(), explicit=baseline.resolve()
    ).compiled.policy_id
    changed_id = load_policy(
        target=tmp_path.resolve(), explicit=changed.resolve()
    ).compiled.policy_id
    assert changed_id != baseline_id
