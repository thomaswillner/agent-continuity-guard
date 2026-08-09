from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_continuity.capture.base import CaptureRequestError
from agent_continuity.capture.coordinator import snapshot_findings
from agent_continuity.capture.git import GitTargetAdapter
from agent_continuity.kernel.evaluation import Profile, Verdict, evaluate
from tests.helpers.git_repo import (
    make_git_repo,
    repository_git_observation,
    repository_write_manifest,
)


def test_clean_git_capture_is_deterministic_and_read_only(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path, remote="https://example.invalid/acg/synthetic.git")
    before_files = repository_write_manifest(repo.root)
    before_git = repository_git_observation(repo)
    adapter = GitTargetAdapter(repo.root)

    first = adapter.capture((b"AGENTS.md", b"README.md"))
    second = adapter.capture((b"AGENTS.md", b"README.md"))

    assert first == second
    assert first.target.is_clean
    assert first.target.head_oid == repo.git("rev-parse", "HEAD").strip().decode()
    expected_tree = repo.git("rev-parse", "HEAD^{tree}").strip().decode()
    assert first.target.tree_oid == expected_tree
    assert [item.path.raw_bytes() for item in first.instructions] == [
        b"AGENTS.md",
        b"README.md",
    ]
    assert [claim.name for claim in first.target.capabilities] == sorted(
        claim.name for claim in first.target.capabilities
    )
    assert {claim.status for claim in first.target.capabilities} >= {
        "proven",
        "unsupported",
    }
    assert repository_git_observation(repo) == before_git
    assert repository_write_manifest(repo.root) == before_files


def test_dirty_target_produces_unknown_finding_without_false_clean_result(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    (repo.root / "README.md").write_text("changed\n", encoding="utf-8")
    snapshot = GitTargetAdapter(repo.root).capture((b"AGENTS.md",))

    result = evaluate(
        snapshot_findings(snapshot, snapshot, Profile.GUARD)
    )

    assert snapshot.target.is_clean is False
    assert result.verdict is Verdict.UNKNOWN
    assert result.transition_allowed is False
    assert [item.code for item in result.findings] == ["target.dirty"]


def test_missing_or_unsafe_instruction_path_is_a_request_error(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)

    with pytest.raises(CaptureRequestError):
        adapter.capture((b"missing.md",))
    with pytest.raises(CaptureRequestError):
        adapter.capture((b"../AGENTS.md",))


def test_symlink_target_mode_and_ignore_provenance_are_identity_bound(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)
    original = adapter.capture((b"AGENTS.md",))

    os.unlink(repo.root / "latest")
    os.symlink("AGENTS.md", repo.root / "latest")
    repo.git("add", "latest")
    repo.git("commit", "-q", "-m", "change symlink")
    changed_link = adapter.capture((b"AGENTS.md",))

    assert (
        changed_link.target.git_object_manifest_digest
        != original.target.git_object_manifest_digest
    )

    exclude = repo.git_dir / "info" / "exclude"
    exclude.write_text("local-only.tmp\n", encoding="utf-8")
    changed_ignore = adapter.capture((b"AGENTS.md",))
    assert (
        changed_ignore.target.ignore_provenance_digest
        != changed_link.target.ignore_provenance_digest
    )


@pytest.mark.parametrize(
    "remote",
    [
        "https://user:secret@example.invalid/acg.git",
        "https://example.invalid/acg.git?token=secret",
        "https://example.invalid/acg.git#fragment",
    ],
)
def test_remote_credentials_query_and_fragment_are_rejected(
    tmp_path: Path, remote: str
) -> None:
    repo = make_git_repo(tmp_path, remote=remote)

    with pytest.raises(CaptureRequestError):
        GitTargetAdapter(repo.root).capture(())


def test_capability_unknown_is_not_treated_as_proven(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    snapshot = GitTargetAdapter(repo.root).capture(())
    by_name = {item.name: item for item in snapshot.target.capabilities}

    assert by_name["windows_reparse_protection"].status in {
        "unsupported",
        "unknown",
    }
    assert by_name["windows_reparse_protection"].status != "proven"
