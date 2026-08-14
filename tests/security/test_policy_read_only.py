from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

from agent_continuity.policy import (
    PolicyRequestError,
    load_policy,
    render_policy_template,
)
from tests.helpers.git_repo import repository_write_manifest


def test_target_policy_capture_and_template_are_read_only(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    policy = target / "acg.toml"
    policy.write_text('version = 1\nprofile = "guard"\n', encoding="utf-8")
    policy.chmod(0o440)
    before = repository_write_manifest(target)
    before_stat = policy.stat()

    loaded = load_policy(target=target.resolve(), explicit=None)
    render_policy_template()

    after_stat = policy.stat()
    assert loaded.source == "target"
    assert repository_write_manifest(target) == before
    assert after_stat.st_mode == before_stat.st_mode
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns


def test_missing_explicit_and_invalid_raw_paths_are_request_errors(
    tmp_path: Path,
) -> None:
    with pytest.raises(PolicyRequestError):
        load_policy(
            target=tmp_path.resolve(), explicit=(tmp_path / "missing").resolve()
        )
    with pytest.raises(PolicyRequestError):
        load_policy(target=tmp_path.resolve(), explicit=Path("relative.toml"))
    with pytest.raises(PolicyRequestError):
        load_policy(target=Path("relative-target"), explicit=None)
    if os.name == "posix":
        with pytest.raises(PolicyRequestError):
            load_policy(target=Path("/tmp/\udcff"), explicit=None)


def test_external_data_cannot_select_or_mutate_policy(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    before = load_policy(target=target.resolve(), explicit=None)
    candidate = {"policy": "/tmp/attacker.toml", "profile": "observe"}
    assert tuple(inspect.signature(load_policy).parameters) == ("target", "explicit")
    with pytest.raises(TypeError):
        load_policy(  # type: ignore[call-arg]
            target=target.resolve(), explicit=None, candidate=candidate
        )
    after = load_policy(target=target.resolve(), explicit=None)
    assert after == before
