from __future__ import annotations

from pathlib import Path

import pytest

from agent_continuity.capture import CaptureUnknownError, _git_process


@pytest.mark.parametrize(
    "command",
    [
        ("status", "--porcelain"),
        ("-c", "core.hooksPath=/tmp", "rev-parse", "HEAD"),
        ("rev-parse", "--verify", "HEAD^{commit}"),
        ("cat-file", "blob", "--filters"),
        ("ls-files", "--cached", "-z"),
    ],
)
def test_descriptor_git_argv_refuses_commands_outside_fixed_vocabulary(
    command: tuple[str, ...],
) -> None:
    with pytest.raises(CaptureUnknownError):
        _git_process.descriptor_git_argv(3, command, Path("/usr/bin/git"))


def test_git_process_module_has_no_generic_runner() -> None:
    assert not hasattr(_git_process, "run_bounded")


def test_descriptor_git_argv_accepts_validated_dynamic_object_ids() -> None:
    oid = "a" * 40

    argv = _git_process.descriptor_git_argv(
        3,
        ("rev-parse", "--verify", f"{oid}^{{commit}}"),
        Path("/usr/bin/git"),
    )

    assert argv[-3:] == ["rev-parse", "--verify", f"{oid}^{{commit}}"]
