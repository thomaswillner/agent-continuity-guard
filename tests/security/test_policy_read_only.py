from __future__ import annotations

import inspect
import os
import traceback
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


def _exception_surfaces(error: BaseException) -> str:
    surfaces = [str(error), repr(error), "".join(traceback.format_exception(error))]
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        surfaces.extend((str(current), repr(current)))
        current = current.__cause__ or current.__context__
    return "\n".join(surfaces)


@pytest.mark.parametrize("kind", ["toml", "enum", "severity", "path"])
def test_authored_values_and_paths_are_absent_from_all_exception_surfaces(
    tmp_path: Path, kind: str
) -> None:
    marker = f"secret-policy-marker-{kind}"
    if kind == "toml":
        explicit = tmp_path / "policy.toml"
        explicit.write_text(f'version = 1\nprofile = "{marker}\n', encoding="utf-8")
    elif kind == "enum":
        explicit = tmp_path / "policy.toml"
        explicit.write_text(f'version = 1\nprofile = "{marker}"\n', encoding="utf-8")
    elif kind == "severity":
        explicit = tmp_path / "policy.toml"
        explicit.write_text(
            'version = 1\nenabled_detectors = ["target.dirty"]\n'
            f'severity_by_code = {{"target.dirty" = "{marker}"}}\n',
            encoding="utf-8",
        )
    else:
        explicit = tmp_path / f"{marker}.toml"

    with pytest.raises(PolicyRequestError) as captured:
        load_policy(target=tmp_path.resolve(), explicit=explicit.resolve())

    assert marker not in _exception_surfaces(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_dotdot_and_symlinked_path_components_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    policy = real / "policy.toml"
    policy.write_text("version = 1\n", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    final_alias = tmp_path / "final-policy.toml"
    final_alias.symlink_to(policy)
    dotdot = real / ".." / "real" / "policy.toml"

    with pytest.raises(PolicyRequestError):
        load_policy(target=tmp_path.resolve(), explicit=dotdot)
    with pytest.raises(PolicyRequestError):
        load_policy(target=tmp_path.resolve(), explicit=alias / "policy.toml")
    with pytest.raises(PolicyRequestError):
        load_policy(target=tmp_path.resolve(), explicit=final_alias)
    with pytest.raises(PolicyRequestError):
        load_policy(target=alias, explicit=None)


def test_policy_path_and_authoring_reads_are_bounded(tmp_path: Path) -> None:
    overlong_component = "x" * 256
    with pytest.raises(PolicyRequestError):
        load_policy(
            target=tmp_path.resolve(),
            explicit=tmp_path / overlong_component / "policy.toml",
        )

    oversized = tmp_path / "oversized.toml"
    oversized.write_bytes(b"#" * (8 * 1024 * 1024 + 1))
    with pytest.raises(PolicyRequestError):
        load_policy(target=tmp_path.resolve(), explicit=oversized.resolve())


def test_explicit_policy_replacement_after_final_pin_uses_pinned_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text('version = 1\nprofile = "guard"\n', encoding="utf-8")
    moved = tmp_path / "pinned-original.toml"
    real_open = os.open
    replaced = False

    def replacing_open(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if dir_fd is None:
            descriptor = real_open(path, flags, mode)
        else:
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if not replaced and os.fspath(path).endswith("policy.toml"):
            replaced = True
            policy.rename(moved)
            policy.write_text('version = 1\nprofile = "strict"\n', encoding="utf-8")
        return descriptor

    monkeypatch.setattr(os, "open", replacing_open)
    loaded = load_policy(target=tmp_path.resolve(), explicit=policy.resolve())

    assert replaced
    assert loaded.compiled.profile.value == "guard"


def test_missing_no_follow_primitive_fails_before_any_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path.resolve()
    opened = False

    def unexpected_open(*_args: object, **_kwargs: object) -> int:
        nonlocal opened
        opened = True
        raise AssertionError("os.open must not run without O_NOFOLLOW")

    monkeypatch.delattr(os, "O_NOFOLLOW")
    monkeypatch.setattr(os, "open", unexpected_open)

    with pytest.raises(PolicyRequestError) as captured:
        load_policy(target=target, explicit=None)

    assert not opened
    assert captured.value.exit_code == 2
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
