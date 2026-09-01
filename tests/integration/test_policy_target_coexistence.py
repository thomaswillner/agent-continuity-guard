from __future__ import annotations

from pathlib import Path

import pytest

from agent_continuity import Continuity, TransitionRefused
from tests.helpers.git_repo import GitRepo, make_git_repo


def _commit_policy(repo: GitRepo, contents: str, message: str) -> None:
    (repo.root / "acg.toml").write_text(contents, encoding="utf-8")
    repo.git("add", "acg.toml")
    repo.git("commit", "-q", "-m", message)


@pytest.mark.parametrize("mutation", ["change", "add", "remove"])
def test_initialize_refuses_target_policy_state_that_never_coexisted_with_capture(
    tmp_path: Path,
    mutation: str,
) -> None:
    repo = make_git_repo(tmp_path)
    if mutation in {"change", "remove"}:
        _commit_policy(
            repo,
            'version = 1\nprofile = "guard"\n',
            "add initial target policy",
        )
    continuity = Continuity.open(
        repo.root,
        state_home=tmp_path / "external-state",
        session_key=f"policy-{mutation}",
    )

    if mutation == "change":
        _commit_policy(
            repo,
            'version = 1\nprofile = "strict"\n',
            "change target policy",
        )
    elif mutation == "add":
        _commit_policy(
            repo,
            'version = 1\nprofile = "strict"\n',
            "add target policy",
        )
    else:
        repo.git("rm", "-q", "acg.toml")
        repo.git("commit", "-q", "-m", "remove target policy")

    with pytest.raises(TransitionRefused):
        continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))

    assert not (tmp_path / "external-state").exists()
