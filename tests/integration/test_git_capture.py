from __future__ import annotations

import builtins
import hashlib
import json
import os
import stat
import struct
import subprocess
import time
from itertools import pairwise
from pathlib import Path
from typing import cast

import pytest

from agent_continuity.capture import (
    CaptureRequestError,
    CaptureUnknownError,
    GitTargetAdapter,
    target_identity_payload,
)
from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from tests.helpers.git_repo import (
    GitExecutableWrapper,
    GitRepo,
    make_git_executable_wrapper,
    make_git_repo,
    repository_git_observation,
    repository_write_manifest,
)


def use_git_wrapper(
    monkeypatch: pytest.MonkeyPatch, wrapper: GitExecutableWrapper
) -> None:
    current_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", os.fspath(wrapper.bin_dir) + os.pathsep + current_path)


def install_symbolic_head_chain(
    repo: GitRepo, names: tuple[str, ...], terminal_oid: str
) -> None:
    if not names:
        raise ValueError("symbolic chain requires at least one name")
    refs = repo.git_dir / "refs" / "heads"
    refs.mkdir(parents=True, exist_ok=True)
    (repo.git_dir / "HEAD").write_text(
        f"ref: refs/heads/{names[0]}\n", encoding="ascii"
    )
    for current, following in pairwise(names):
        (refs / current).write_text(f"ref: refs/heads/{following}\n", encoding="ascii")
    (refs / names[-1]).write_text(f"{terminal_oid}\n", encoding="ascii")


def install_symbolic_ref_paths(
    repo: GitRepo, ref_paths: tuple[str, ...], terminal_oid: str
) -> None:
    if not ref_paths:
        raise ValueError("symbolic chain requires at least one ref path")
    (repo.git_dir / "HEAD").write_text(
        f"ref: {ref_paths[0]}\n", encoding="ascii"
    )
    for current, following in pairwise(ref_paths):
        path = repo.git_dir / current
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"ref: {following}\n", encoding="ascii")
    terminal = repo.git_dir / ref_paths[-1]
    terminal.parent.mkdir(parents=True, exist_ok=True)
    terminal.write_text(f"{terminal_oid}\n", encoding="ascii")


def make_single_file_repo(base: Path) -> GitRepo:
    root = base / "single-file-target"
    root.mkdir()
    repo = GitRepo(root)
    repo.git("init", "-q")
    repo.git("config", "user.name", "Synthetic Test")
    repo.git("config", "user.email", "synthetic@example.invalid")
    (root / "only.txt").write_text("only record\n", encoding="utf-8")
    repo.git("add", "only.txt")
    repo.git("commit", "-q", "-m", "single record")
    return repo


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
        "unknown",
        "unsupported",
    }
    assert repository_git_observation(repo) == before_git
    assert repository_write_manifest(repo.root) == before_files


def test_dirty_target_is_unknown_without_returning_a_false_clean_snapshot(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    (repo.root / "README.md").write_text("changed\n", encoding="utf-8")

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture((b"AGENTS.md",))


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
        "https://user:secret@example.invalid/acg.git",  # pragma: allowlist secret
        "https://example.invalid/acg.git?token=secret",
        "https://example.invalid/acg.git#fragment",
    ],
)
def test_remote_credentials_query_and_fragment_are_rejected(
    tmp_path: Path, remote: str
) -> None:
    repo = make_git_repo(tmp_path, remote=remote)

    with pytest.raises(CaptureUnknownError) as captured:
        GitTargetAdapter(repo.root).capture(())
    assert remote not in str(captured.value)


def test_capability_unknown_is_not_treated_as_proven(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    snapshot = GitTargetAdapter(repo.root).capture(())
    by_name = {item.name: item for item in snapshot.target.capabilities}

    assert by_name["windows_reparse_protection"].status in {
        "unsupported",
        "unknown",
    }
    assert by_name["windows_reparse_protection"].status != "proven"


@pytest.mark.parametrize("mutation", ["worktree", "index", "head"])
def test_capture_rejects_mutation_after_initial_tree_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repo = make_git_repo(tmp_path)
    original_head = repo.git("rev-parse", "HEAD")
    wrapper = make_git_executable_wrapper(tmp_path)
    if mutation == "worktree":
        actions = [
            {
                "kind": "write_text",
                "path": os.fspath(repo.root / "README.md"),
                "content": "mutated\n",
            }
        ]
    elif mutation == "index":
        actions = [
            {
                "kind": "write_text",
                "path": os.fspath(repo.root / "new.txt"),
                "content": "new\n",
            },
            {
                "kind": "git",
                "args": ["-C", os.fspath(repo.root), "add", "new.txt"],
            },
        ]
    else:
        actions = [
            {
                "kind": "write_text",
                "path": os.fspath(repo.root / "README.md"),
                "content": "new commit\n",
            },
            {
                "kind": "git",
                "args": ["-C", os.fspath(repo.root), "add", "README.md"],
            },
            {
                "kind": "git",
                "args": [
                    "-C",
                    os.fspath(repo.root),
                    "commit",
                    "-q",
                    "-m",
                    "move head",
                ],
            },
        ]
    wrapper.configure(
        trigger_command="ls-tree",
        once=True,
        after_actions=actions,
    )
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture((b"AGENTS.md",))

    assert wrapper.state_path.read_text(encoding="ascii") == "1"
    if mutation == "worktree":
        assert (repo.root / "README.md").read_text(encoding="utf-8") == "mutated\n"
    elif mutation == "index":
        assert b"new.txt" in repo.git("ls-files")
    else:
        assert repo.git("rev-parse", "HEAD") != original_head


def test_tree_listing_is_pinned_to_sampled_tree_oid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    use_git_wrapper(monkeypatch, wrapper)
    snapshot = GitTargetAdapter(repo.root).capture(())
    tree_invocations = [
        invocation for invocation in wrapper.invocations() if "ls-tree" in invocation
    ]

    assert tree_invocations
    assert all(
        invocation[-1] == snapshot.target.tree_oid for invocation in tree_invocations
    )


def test_capture_rechecks_index_after_first_direct_index_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(
        trigger_command="ls-files",
        once=True,
        after_actions=[
            {
                "kind": "write_text",
                "path": os.fspath(repo.root / "late.txt"),
                "content": "late\n",
            },
            {
                "kind": "git",
                "args": ["-C", os.fspath(repo.root), "add", "late.txt"],
            },
        ],
    )
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())

    assert wrapper.state_path.read_text(encoding="ascii") == "1"
    assert b"late.txt" in repo.git("ls-files")


def test_capture_rejects_ordinary_leaf_rename_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    tracked = repo.root / "README.md"
    replacement = tmp_path / "replacement-readme"
    replacement.write_bytes(tracked.read_bytes())
    replacement.chmod(stat.S_IMODE(tracked.stat().st_mode))
    displaced = tmp_path / "displaced-readme"
    adapter = GitTargetAdapter(repo.root)
    real_listdir = os.listdir
    swapped = False

    def swap_after_root_listing(path: int | str | bytes) -> list[str]:
        nonlocal swapped
        result = real_listdir(path)
        if not swapped and "README.md" in result:
            tracked.rename(displaced)
            replacement.rename(tracked)
            swapped = True
        return result

    monkeypatch.setattr(os, "listdir", swap_after_root_listing)

    with pytest.raises(CaptureUnknownError):
        adapter.capture(())
    assert swapped


def test_hostile_local_fsmonitor_is_not_executed_and_network_is_unproven(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    sentinel = tmp_path / "fsmonitor-executed"
    monitor = tmp_path / "hostile-fsmonitor.sh"
    monitor.write_text(
        f"#!/bin/sh\nprintf executed > '{sentinel}'\nprintf '{{}}\\n'\n",
        encoding="utf-8",
    )
    monitor.chmod(0o700)
    repo.git("config", "core.fsmonitor", os.fspath(monitor))

    snapshot = GitTargetAdapter(repo.root).capture(())
    capabilities = {item.name: item.status for item in snapshot.target.capabilities}

    assert not sentinel.exists()
    assert capabilities["git_network_disabled"] != "proven"


@pytest.mark.parametrize("driver", ["clean", "process"])
def test_target_controlled_git_filter_is_rejected_without_execution(
    tmp_path: Path, driver: str
) -> None:
    repo = make_git_repo(tmp_path)
    attributes = repo.root / ".gitattributes"
    attributes.write_text("README.md filter=probe\n", encoding="utf-8")
    repo.git("add", ".gitattributes")
    repo.git("commit", "-q", "-m", "add hostile attributes")

    sentinel = tmp_path / f"{driver}-filter-executed"
    program = tmp_path / f"hostile-{driver}-filter.sh"
    if driver == "clean":
        body = f"#!/bin/sh\nprintf executed > '{sentinel}'\ncat\n"
    else:
        body = f"#!/bin/sh\nprintf executed > '{sentinel}'\nexit 1\n"
    program.write_text(body, encoding="utf-8")
    program.chmod(0o700)
    repo.git("config", f"filter.probe.{driver}", os.fspath(program))
    metadata = (repo.root / "README.md").stat()
    os.utime(
        repo.root / "README.md",
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
    )

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())

    assert not sentinel.exists()


def test_intermediate_symlink_replacement_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "guide.txt").write_text("external\n", encoding="utf-8")
    original_docs = tmp_path / "original-docs"
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(
        trigger_command="ls-tree",
        once=True,
        after_actions=[
            {
                "kind": "rename",
                "source": os.fspath(repo.root / "docs"),
                "target": os.fspath(original_docs),
            },
            {
                "kind": "symlink",
                "target": os.fspath(outside),
                "path": os.fspath(repo.root / "docs"),
            },
        ],
    )
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())

    assert original_docs.is_dir()
    assert (repo.root / "docs").is_symlink()


def test_root_replacement_is_unknown_not_a_request_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    original_root = tmp_path / "original-root"
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(
        trigger_command="ls-tree",
        once=True,
        after_actions=[
            {
                "kind": "rename",
                "source": os.fspath(repo.root),
                "target": os.fspath(original_root),
            },
            {"kind": "mkdir", "path": os.fspath(repo.root)},
        ],
    )
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())

    assert original_root.is_dir()
    assert not (repo.root / ".git").exists()


def test_git_observation_uses_pinned_root_descriptor_during_path_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    expected_head = repo.git("rev-parse", "HEAD^{commit}")

    replacement_base = tmp_path / "replacement-base"
    replacement_base.mkdir()
    replacement = make_git_repo(replacement_base)
    (replacement.root / "README.md").write_text(
        "replacement target\n", encoding="utf-8"
    )
    replacement.git("add", "README.md")
    replacement.git("commit", "-q", "-m", "different replacement")
    assert replacement.git("rev-parse", "HEAD^{commit}") != expected_head

    original_location = tmp_path / "original-target"
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(
        trigger_command="rev-parse",
        once=True,
        before_actions=[
            {
                "kind": "rename",
                "source": os.fspath(repo.root),
                "target": os.fspath(original_location),
            },
            {
                "kind": "rename",
                "source": os.fspath(replacement.root),
                "target": os.fspath(repo.root),
            },
        ],
        after_actions=[
            {
                "kind": "rename",
                "source": os.fspath(repo.root),
                "target": os.fspath(replacement.root),
            },
            {
                "kind": "rename",
                "source": os.fspath(original_location),
                "target": os.fspath(repo.root),
            },
        ],
    )
    use_git_wrapper(monkeypatch, wrapper)

    snapshot = GitTargetAdapter(repo.root).capture(())

    assert snapshot.target.head_oid.encode("ascii") + b"\n" == expected_head
    assert repo.git("rev-parse", "HEAD^{commit}") == expected_head


def test_symlink_swap_between_observations_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)
    real_readlink = os.readlink
    swapped = False

    def swapping_readlink(
        path: bytes | str, *args: object, **kwargs: object
    ) -> bytes | str:
        nonlocal swapped
        if not swapped and os.fsdecode(path).endswith("latest"):
            swapped = True
            os.unlink(repo.root / "latest")
            os.symlink("AGENTS.md", repo.root / "latest")
        return real_readlink(path, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(os, "readlink", swapping_readlink)
    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


def test_unverified_capture_capabilities_are_not_overclaimed(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    snapshot = GitTargetAdapter(repo.root).capture(())
    capabilities = {item.name: item.status for item in snapshot.target.capabilities}

    assert capabilities["descriptor_pinned_reads"] != "proven"
    assert capabilities["git_network_disabled"] != "proven"
    assert capabilities["git_immutable_objects"] == "unknown"


@pytest.mark.parametrize(
    "stream",
    ["stdout", "stderr"],
)
def test_capture_rejects_inflight_git_output_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stream: str,
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(overflow_stream=stream)
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root)


def test_capture_classifies_git_timeout_as_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(sleep_seconds=31, once=True)
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root)


def test_descriptor_bootstrap_closes_root_fd_before_git_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    probe = tmp_path / "open-fds.json"
    wrapper.configure(
        trigger_command="rev-parse",
        once=True,
        fd_probe=os.fspath(probe),
    )
    use_git_wrapper(monkeypatch, wrapper)

    GitTargetAdapter(repo.root)

    assert json.loads(probe.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "failure",
    ["missing-interpreter", "invalid-format", "not-executable"],
)
def test_constructor_preserves_initial_launch_failures_as_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    executable = wrapper.bin_dir / "git"
    if failure == "missing-interpreter":
        executable.write_text(
            "#!/definitely/missing/interpreter\n", encoding="utf-8"
        )
    elif failure == "invalid-format":
        executable.write_text("not an executable format\n", encoding="utf-8")
    else:
        executable.chmod(0o600)
    monkeypatch.setenv("PATH", os.fspath(wrapper.bin_dir))

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root)


def test_constructor_classifies_true_non_repository_as_request_error(
    tmp_path: Path,
) -> None:
    non_repository = tmp_path / "not-a-repository"
    non_repository.mkdir()

    with pytest.raises(CaptureRequestError):
        GitTargetAdapter(non_repository)


@pytest.mark.parametrize(
    "remote",
    [
        "git@token@host:repo",
        "ssh://git@host.invalid:99999/repo",
        "ext::run-helper",
        "helper with secret",
    ],
)
def test_public_capture_rejects_ambiguous_or_helper_remotes(
    tmp_path: Path, remote: str
) -> None:
    repo = make_git_repo(tmp_path)
    repo.git("config", "--add", "remote.origin.url", remote)

    with pytest.raises(CaptureUnknownError) as captured:
        GitTargetAdapter(repo.root).capture(())
    assert remote not in str(captured.value)


def test_missing_git_object_is_unknown_not_request_error(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    oid = repo.git("rev-parse", "HEAD:AGENTS.md").strip().decode("ascii")
    loose_object = repo.git_dir / "objects" / oid[:2] / oid[2:]
    assert loose_object.is_file()
    loose_object.unlink()

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture((b"AGENTS.md",))


def test_malformed_git_tree_bytes_are_sanitized_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    malformed = b"\xff blob " + b"a" * 40 + b"\tpath\x00"
    wrapper.configure(trigger_command="ls-tree", stdout_hex=malformed.hex())
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_linked_worktree_binds_common_exclude_provenance(tmp_path: Path) -> None:
    primary_base = tmp_path / "primary"
    primary_base.mkdir()
    primary = make_git_repo(primary_base)
    linked_root = tmp_path / "linked"
    primary.git("worktree", "add", "-q", "-b", "linked", os.fspath(linked_root))
    linked = GitRepo(linked_root)
    adapter = GitTargetAdapter(linked.root)
    before = adapter.capture(())

    common_exclude = primary.git_dir / "info" / "exclude"
    common_exclude.write_text("linked-only.tmp\n", encoding="utf-8")
    after = adapter.capture(())

    assert adapter.git_common_directory == primary.git_dir.resolve()
    assert (
        after.target.ignore_provenance_digest != before.target.ignore_provenance_digest
    )


def test_requested_root_is_pinned_before_first_git_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = make_git_repo(tmp_path)
    original_head = original.git("rev-parse", "HEAD^{commit}").strip().decode()
    replacement_base = tmp_path / "replacement"
    replacement_base.mkdir()
    replacement = make_git_repo(replacement_base)
    (replacement.root / "README.md").write_text(
        "replacement target\n", encoding="utf-8"
    )
    replacement.git("add", "README.md")
    replacement.git("commit", "-q", "-m", "replacement identity")
    replacement_head = replacement.git("rev-parse", "HEAD^{commit}").strip().decode()
    assert replacement_head != original_head

    displaced = tmp_path / "displaced-original"
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(
        once=True,
        root_swap={
            "target": os.fspath(original.root),
            "displaced": os.fspath(displaced),
            "replacement": os.fspath(replacement.root),
        },
    )
    use_git_wrapper(monkeypatch, wrapper)
    adapter: GitTargetAdapter | None = None
    try:
        try:
            adapter = GitTargetAdapter(original.root)
            observed = adapter.capture(())
        except CaptureUnknownError:
            return
        assert observed.target.head_oid == original_head
        assert observed.target.head_oid != replacement_head
    finally:
        if adapter is not None:
            adapter.close()
        if displaced.exists():
            original.root.rename(replacement.root)
            displaced.rename(original.root)


def test_capture_git_processes_use_absolute_git_and_no_forbidden_porcelain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    use_git_wrapper(monkeypatch, wrapper)
    GitTargetAdapter(repo.root).capture(())
    observed_argv = wrapper.invocations()

    forbidden = {
        "status",
        "diff",
        "check-attr",
        "hash-object",
        "checkout",
        "submodule",
    }
    assert observed_argv
    assert all(not forbidden.intersection(argv) for argv in observed_argv)
    assert all(
        Path(argv[0]).is_absolute() and Path(argv[0]).name == "git"
        for argv in observed_argv
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "staged-add",
        "staged-delete",
        "staged-content",
        "staged-mode",
        "unstaged-content",
        "unstaged-mode",
        "symlink-target",
        "untracked",
        "ignored-only",
        "empty-directory",
    ],
)
def test_every_non_head_index_worktree_path_state_is_unknown(
    tmp_path: Path, mutation: str
) -> None:
    repo = make_git_repo(tmp_path)
    if mutation == "staged-add":
        (repo.root / "new.txt").write_text("new\n", encoding="utf-8")
        repo.git("add", "new.txt")
    elif mutation == "staged-delete":
        repo.git("rm", "-q", "README.md")
    elif mutation == "staged-content":
        (repo.root / "README.md").write_text("staged\n", encoding="utf-8")
        repo.git("add", "README.md")
    elif mutation == "staged-mode":
        (repo.root / "README.md").chmod(0o755)
        repo.git("add", "README.md")
    elif mutation == "unstaged-content":
        (repo.root / "README.md").write_text("unstaged\n", encoding="utf-8")
    elif mutation == "unstaged-mode":
        (repo.root / "README.md").chmod(0o755)
    elif mutation == "symlink-target":
        (repo.root / "latest").unlink()
        os.symlink("AGENTS.md", repo.root / "latest")
    elif mutation == "untracked":
        (repo.root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    elif mutation == "ignored-only":
        (repo.root / "ignored.tmp").write_text("ignored\n", encoding="utf-8")
    else:
        (repo.root / "empty").mkdir()

    before = repository_write_manifest(repo.root)
    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())
    assert repository_write_manifest(repo.root) == before


@pytest.mark.parametrize("driver", ["clean", "process"])
@pytest.mark.parametrize("trigger_command", ["rev-parse", "ls-files", "ls-tree"])
def test_filter_injected_after_eligibility_check_never_executes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    driver: str,
    trigger_command: str,
) -> None:
    repo = make_git_repo(tmp_path)
    sentinel = tmp_path / f"late-{driver}-executed"
    program = tmp_path / f"late-{driver}.sh"
    if driver == "clean":
        body = f"#!/bin/sh\nprintf executed > '{sentinel}'\ncat\n"
    else:
        body = f"#!/bin/sh\nprintf executed > '{sentinel}'\nexit 1\n"
    program.write_text(body, encoding="utf-8")
    program.chmod(0o700)
    trigger_occurrence = 4 if trigger_command == "rev-parse" else 1
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(
        trigger_command=trigger_command,
        trigger_occurrence=trigger_occurrence,
        once=True,
        after_actions=[
            {
                "kind": "write_text",
                "path": os.fspath(repo.root / ".gitattributes"),
                "content": "README.md filter=probe\n",
            },
            {
                "kind": "git",
                "args": [
                    "-C",
                    os.fspath(repo.root),
                    "config",
                    f"filter.probe.{driver}",
                    os.fspath(program),
                ],
            },
        ],
    )
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())

    assert int(wrapper.state_path.read_text(encoding="ascii")) >= trigger_occurrence
    assert (repo.root / ".gitattributes").is_file()
    assert not sentinel.exists()


def test_present_but_malformed_git_locator_is_unknown(tmp_path: Path) -> None:
    target = tmp_path / "malformed-repository"
    target.mkdir()
    (target / ".git").write_text("not a gitfile\n", encoding="utf-8")

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(target)


def test_clean_status_digest_is_direct_proof_not_empty_porcelain(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    snapshot = GitTargetAdapter(repo.root).capture(())

    assert snapshot.target.is_clean
    assert snapshot.target.status_digest != digest_bytes(b"")


@pytest.mark.parametrize(
    "source",
    [
        "tracked-attributes",
        "info-attributes",
        "include",
        "autocrlf",
        "eol",
        "filter",
        "sparse",
    ],
)
def test_every_conversion_or_sparse_source_is_unknown(
    tmp_path: Path, source: str
) -> None:
    repo = make_git_repo(tmp_path)
    if source == "tracked-attributes":
        (repo.root / ".gitattributes").write_text("README.md -text\n", encoding="utf-8")
        repo.git("add", ".gitattributes")
        repo.git("commit", "-q", "-m", "attributes")
    elif source == "info-attributes":
        (repo.git_dir / "info" / "attributes").write_text(
            "README.md -text\n", encoding="utf-8"
        )
    elif source == "include":
        included = tmp_path / "included-config"
        included.write_text("[core]\n\tautocrlf = false\n", encoding="utf-8")
        repo.git("config", "include.path", os.fspath(included))
    elif source == "autocrlf":
        repo.git("config", "core.autocrlf", "true")
    elif source == "eol":
        repo.git("config", "core.eol", "crlf")
    elif source == "filter":
        repo.git("config", "filter.probe.clean", "cat")
    else:
        repo.git("config", "core.sparseCheckout", "true")

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize(
    "index_state", ["split", "skip-worktree", "intent-to-add", "unmerged"]
)
def test_unsupported_index_semantics_are_unknown(
    tmp_path: Path, index_state: str
) -> None:
    repo = make_git_repo(tmp_path)
    if index_state == "split":
        repo.git("update-index", "--split-index")
    elif index_state == "skip-worktree":
        repo.git("update-index", "--skip-worktree", "README.md")
    elif index_state == "intent-to-add":
        (repo.root / "intent.txt").write_text("intent\n", encoding="utf-8")
        repo.git("add", "-N", "intent.txt")
    else:
        oid = repo.git("rev-parse", "HEAD:README.md").strip()
        repo.git("rm", "-q", "--cached", "README.md")
        rows = b"".join(
            b"100644 " + oid + f" {stage}\tREADME.md\n".encode("ascii")
            for stage in (1, 2, 3)
        )
        subprocess.run(
            ["git", "-C", os.fspath(repo.root), "update-index", "--index-info"],
            input=rows,
            check=True,
            capture_output=True,
            timeout=30,
        )

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_gitlink_tree_entry_is_unknown(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    head = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    repo.git(
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{head},nested-repository",
    )
    repo.git("commit", "-q", "-m", "gitlink")

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_unknown_optional_index_extension_is_unknown(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    index_path = repo.git_dir / "index"
    raw_index = index_path.read_bytes()
    body = raw_index[:-20] + b"ZZZZ" + struct.pack("!I", 0)
    index_path.write_bytes(body + hashlib.sha1(body).digest())

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_unsupported_raw_index_mode_is_unknown(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    index_path = repo.git_dir / "index"
    raw_index = bytearray(index_path.read_bytes())
    struct.pack_into("!I", raw_index, 12 + 24, 0o100600)
    body = bytes(raw_index[:-20])
    index_path.write_bytes(body + hashlib.sha1(body).digest())

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_sha256_repository_uses_exact_local_blob_framing(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path, object_format="sha256")
    snapshot = GitTargetAdapter(repo.root).capture((b"README.md",))

    assert len(snapshot.target.head_oid) == 64
    assert len(snapshot.instructions[0].blob_oid) == 64
    assert snapshot.target.is_clean


def test_dual_object_format_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(
        match_args=["rev-parse", "--show-object-format=input"],
        stdout_text="sha1 sha256\n",
    )
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_capture_rejects_excessive_repository_depth(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    deep_file = repo.root.joinpath(*(f"d{index}" for index in range(129)), "leaf")
    deep_file.parent.mkdir(parents=True)
    deep_file.write_text("deep\n", encoding="utf-8")
    repo.git("add", ".")
    repo.git("commit", "-q", "-m", "deep path")

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_capture_rejects_excessive_declared_index_entries(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    index_path = repo.git_dir / "index"
    raw_index = index_path.read_bytes()
    body = bytearray(raw_index[:-20])
    struct.pack_into("!I", body, 8, 1_000_001)
    index_path.write_bytes(bytes(body) + hashlib.sha1(body).digest())

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_capture_rejects_oversized_reported_tracked_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    tracked_identity = (repo.root / "README.md").stat().st_ino
    real_read = os.read

    class OversizedChunk(bytes):
        def __len__(self) -> int:
            return 1024 * 1024 * 1024 + 1

    def oversized_read(descriptor: int, size: int) -> bytes:
        if os.fstat(descriptor).st_ino == tracked_identity:
            return OversizedChunk(b"x")
        return real_read(descriptor, size)

    monkeypatch.setattr(os, "read", oversized_read)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_capture_rejects_cumulative_reported_file_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cumulative-file-limit"
    root.mkdir()
    repo = GitRepo(root)
    repo.git("init", "-q")
    repo.git("config", "user.name", "Synthetic Test")
    repo.git("config", "user.email", "synthetic@example.invalid")
    reported_size = 900 * 1024 * 1024
    for index in range(5):
        content = f"limit-probe-{index}\n".encode("ascii")
        path = f"file-{index}.txt"
        (root / path).write_bytes(content)
        oid = hashlib.sha1(
            b"blob "
            + str(reported_size).encode("ascii")
            + b"\x00"
            + content
        ).hexdigest()
        repo.git(
            "update-index",
            "--add",
            "--info-only",
            "--cacheinfo",
            f"100644,{oid},{path}",
        )
    tree = repo.git("write-tree", "--missing-ok").strip()
    commit = repo.git("commit-tree", tree, "-m", "logical large files").strip()
    repo.git("update-ref", "HEAD", commit)
    adapter = GitTargetAdapter(repo.root)
    real_len = builtins.len

    def reported_len(value: object) -> int:
        if type(value) is bytes and value.startswith(b"limit-probe-"):
            return reported_size
        return real_len(value)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "len", reported_len)

    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


def test_capture_rejects_oversized_reported_path_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    root_identity = (repo.root.stat().st_dev, repo.root.stat().st_ino)
    real_listdir = os.listdir

    class OversizedPath(bytes):
        def __len__(self) -> int:
            return 256 * 1024 * 1024 + 1

    def oversized_listdir(path: int | str | bytes) -> list[str | bytes]:
        names = real_listdir(path)
        if isinstance(path, int):
            metadata = os.fstat(path)
            if (metadata.st_dev, metadata.st_ino) == root_identity:
                return [
                    OversizedPath(os.fsencode(name))
                    if os.fsencode(name) == b"README.md"
                    else name
                    for name in names
                ]
        return cast(list[str | bytes], names)

    monkeypatch.setattr(os, "listdir", oversized_listdir)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_elapsed_limit_is_rechecked_after_final_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    use_git_wrapper(monkeypatch, wrapper)
    adapter = GitTargetAdapter(repo.root)
    real_monotonic = time.monotonic

    def monotonic() -> float:
        completed_tree_reads = sum(
            "ls-tree" in invocation for invocation in wrapper.invocations()
        )
        return real_monotonic() + (31.0 if completed_tree_reads >= 2 else 0.0)

    monkeypatch.setattr(time, "monotonic", monotonic)

    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


def test_elapsed_budget_covers_post_git_observation_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    use_git_wrapper(monkeypatch, wrapper)
    adapter = GitTargetAdapter(repo.root)
    real_monotonic = time.monotonic

    def monotonic() -> float:
        tree_read_started = any(
            "ls-tree" in invocation for invocation in wrapper.invocations()
        )
        return real_monotonic() + (31.0 if tree_read_started else 0.0)

    monkeypatch.setattr(time, "monotonic", monotonic)

    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


def test_tracked_parent_directory_rename_swap_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    replacement = tmp_path / "replacement-docs"
    replacement.mkdir()
    (replacement / "guide.txt").write_text("guide\n", encoding="utf-8")
    displaced = tmp_path / "displaced-docs"
    real_listdir = os.listdir
    swapped = False

    def swap_after_parent_listing(path: int | str | bytes) -> list[str]:
        nonlocal swapped
        result = real_listdir(path)
        if not swapped and result == ["guide.txt"]:
            (repo.root / "docs").rename(displaced)
            replacement.rename(repo.root / "docs")
            swapped = True
        return result

    monkeypatch.setattr(os, "listdir", swap_after_parent_listing)
    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())
    assert swapped


@pytest.mark.parametrize(
    "action",
    [
        {"exit_code": 1},
        {"signal": "SIGKILL"},
    ],
)
def test_present_git_with_abnormal_initial_result_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: dict[str, object],
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(stderr_text="private-process-detail", **action)
    use_git_wrapper(monkeypatch, wrapper)
    with pytest.raises(CaptureUnknownError) as captured:
        GitTargetAdapter(repo.root)
    assert "private-process-detail" not in str(captured.value)


def test_git_locator_symlink_is_unknown(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    real_git = tmp_path / "real-git"
    repo.git_dir.rename(real_git)
    os.symlink(real_git, repo.git_dir)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root)


def test_untracked_symlink_directory_is_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    outside = tmp_path / "outside-directory"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside\n", encoding="utf-8")
    os.symlink(outside, repo.root / "outside-link")
    outside_identity = (outside.stat().st_dev, outside.stat().st_ino)
    real_listdir = os.listdir

    def refuse_outside_listing(path: int | str | bytes) -> list[str]:
        if isinstance(path, int):
            metadata = os.fstat(path)
            assert (metadata.st_dev, metadata.st_ino) != outside_identity
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", refuse_outside_listing)
    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_remote_identity_export_contains_only_digest(tmp_path: Path) -> None:
    remote = "ssh://git@example.invalid/private/repository.git"
    repo = make_git_repo(tmp_path, remote=remote)
    snapshot = GitTargetAdapter(repo.root).capture(())
    exported = canonical_bytes(target_identity_payload(snapshot.target))

    assert snapshot.target.sanitized_remote_identity_digest is not None
    assert remote.encode("utf-8") not in exported
    assert b"private/repository" not in exported


def test_recursive_symbolic_ref_chain_captures_stable_terminal(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    head = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    install_symbolic_head_chain(repo, ("link-a", "link-b", "base-a"), head)

    snapshot = GitTargetAdapter(repo.root).capture(())

    assert snapshot.target.head_oid == head
    assert snapshot.target.is_clean


def test_terminal_symbolic_ref_mutation_during_capture_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    original = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    tree = repo.git("rev-parse", "HEAD^{tree}").strip().decode("ascii")
    replacement = (
        repo.git("commit-tree", tree, "-p", original, "-m", "same tree")
        .strip()
        .decode("ascii")
    )
    assert replacement != original
    install_symbolic_head_chain(repo, ("link", "base-a"), original)
    terminal_ref = repo.git_dir / "refs" / "heads" / "base-a"
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(
        trigger_command="config",
        once=True,
        mutate_path=os.fspath(terminal_ref),
        mutate_content=f"{replacement}\n",
    )
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize("chain_state", ["cycle", "too-deep", "malformed"])
def test_symbolic_ref_cycle_depth_and_malformed_chain_are_unknown(
    tmp_path: Path, chain_state: str
) -> None:
    repo = make_git_repo(tmp_path)
    head = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    refs = repo.git_dir / "refs" / "heads"
    if chain_state == "cycle":
        (repo.git_dir / "HEAD").write_text("ref: refs/heads/link-a\n", encoding="ascii")
        (refs / "link-a").write_text("ref: refs/heads/link-b\n", encoding="ascii")
        (refs / "link-b").write_text("ref: refs/heads/link-a\n", encoding="ascii")
    elif chain_state == "too-deep":
        names = tuple(f"link-{index:02d}" for index in range(65))
        install_symbolic_head_chain(repo, names, head)
    else:
        (repo.git_dir / "HEAD").write_text("ref: refs/heads/link-a\n", encoding="ascii")
        (refs / "link-a").write_text("ref: refs/heads/bad ref\n", encoding="ascii")

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize("command", ["ls-tree", "ls-files"])
def test_nonempty_z_output_without_terminal_nul_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(trigger_command=command, strip_final_nul=True)
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_empty_z_output_has_defined_empty_repository_semantics(
    tmp_path: Path,
) -> None:
    root = tmp_path / "empty-target"
    root.mkdir()
    repo = GitRepo(root)
    repo.git("init", "-q")
    repo.git("config", "user.name", "Synthetic Test")
    repo.git("config", "user.email", "synthetic@example.invalid")
    repo.git("read-tree", "--empty")
    repo.git("commit", "-q", "--allow-empty", "-m", "empty tree")

    snapshot = GitTargetAdapter(repo.root).capture(())

    assert snapshot.target.is_clean


@pytest.mark.parametrize(
    "invalid_target",
    ["bad\x00path", "", b"byte-target"],
)
def test_plainly_invalid_caller_target_is_request_error(
    invalid_target: object,
) -> None:
    with pytest.raises(CaptureRequestError) as captured:
        GitTargetAdapter(invalid_target)  # type: ignore[arg-type]
    assert "embedded null byte" not in str(captured.value)


@pytest.mark.parametrize("field", ["url", "pushurl"])
@pytest.mark.parametrize(
    "unsafe_remote",
    [
        (
            "https://user:secret@example.invalid/"  # pragma: allowlist secret
            "repository.git"
        ),
        "https://example.invalid/repository.git?token=secret",
        "https://example.invalid/repository.git#private",
        "ext::credential-helper",
        "file:///private/repository.git",
    ],
)
def test_every_unsafe_fetch_or_push_remote_is_redacted_unknown(
    tmp_path: Path, field: str, unsafe_remote: str
) -> None:
    repo = make_git_repo(tmp_path, remote="https://example.invalid/safe/repository.git")
    repo.git("config", "--add", f"remote.origin.{field}", unsafe_remote)

    with pytest.raises(CaptureUnknownError) as captured:
        GitTargetAdapter(repo.root).capture(())
    assert unsafe_remote not in str(captured.value)
    assert "secret" not in str(captured.value)


def test_valid_push_remote_contributes_to_remote_identity_digest(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(
        tmp_path, remote="https://example.invalid/fetch/repository.git"
    )
    before = GitTargetAdapter(repo.root).capture(())
    repo.git(
        "config",
        "--add",
        "remote.origin.pushurl",
        "ssh://git@example.invalid/push/repository.git",
    )
    after = GitTargetAdapter(repo.root).capture(())

    assert (
        before.target.sanitized_remote_identity_digest
        != after.target.sanitized_remote_identity_digest
    )


@pytest.mark.parametrize("command", ["ls-tree", "ls-files"])
@pytest.mark.parametrize(
    "frame",
    ["missing-terminal", "extra-terminal", "interior-empty", "lone-nul"],
)
def test_every_malformed_git_nul_frame_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    frame: str,
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    wrapper.configure(trigger_command=command, nul_frame=frame)
    use_git_wrapper(monkeypatch, wrapper)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_valid_single_record_git_nul_frames_are_clean(tmp_path: Path) -> None:
    repo = make_single_file_repo(tmp_path)

    snapshot = GitTargetAdapter(repo.root).capture(())

    assert snapshot.target.is_clean


def test_valid_multi_record_git_nul_frames_are_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    wrapper = make_git_executable_wrapper(tmp_path)
    use_git_wrapper(monkeypatch, wrapper)

    snapshot = GitTargetAdapter(repo.root).capture(())
    commands = {
        command
        for invocation in wrapper.invocations()
        for command in ("ls-tree", "ls-files")
        if command in invocation
    }

    assert snapshot.target.is_clean
    assert commands == {"ls-tree", "ls-files"}


@pytest.mark.parametrize(
    "invalid_target",
    [
        "nul",
        "lone-surrogate",
        "surrogate-path-like",
        "overlong-component",
        "over-depth",
        "over-byte-budget",
    ],
)
def test_caller_invalid_target_matrix_is_request_error(
    tmp_path: Path, invalid_target: str
) -> None:
    class SurrogatePath:
        def __fspath__(self) -> str:
            return "surrogate-\ud800-path"

    if invalid_target == "nul":
        target: object = "bad\x00path"
    elif invalid_target == "lone-surrogate":
        target = "surrogate-\ud800-path"
    elif invalid_target == "surrogate-path-like":
        target = SurrogatePath()
    elif invalid_target == "overlong-component":
        target = tmp_path / ("x" * 256)
    elif invalid_target == "over-depth":
        target = tmp_path.joinpath(*("d" for _ in range(129)))
    else:
        target = tmp_path / ("x" * (32 * 1024 + 1))

    with pytest.raises(CaptureRequestError) as captured:
        GitTargetAdapter(target)  # type: ignore[arg-type]
    assert "surrogate-" not in str(captured.value)


@pytest.mark.parametrize(
    ("target_state", "expected_error"),
    [
        ("missing", "request"),
        ("nondirectory", "request"),
        ("symlink", "request"),
        ("inaccessible", "unknown"),
    ],
)
def test_target_filesystem_classification_matrix(
    tmp_path: Path, target_state: str, expected_error: str
) -> None:
    repo = make_git_repo(tmp_path)
    restore_mode: int | None = None
    if target_state == "missing":
        target = tmp_path / "missing-target"
    elif target_state == "nondirectory":
        target = tmp_path / "target-file"
        target.write_text("not a directory\n", encoding="utf-8")
    elif target_state == "symlink":
        target = tmp_path / "target-link"
        os.symlink(repo.root, target)
    else:
        target = repo.root
        restore_mode = stat.S_IMODE(target.stat().st_mode)
        target.chmod(0)
    error_type = (
        CaptureRequestError
        if expected_error == "request"
        else CaptureUnknownError
    )
    try:
        with pytest.raises(error_type):
            GitTargetAdapter(target)
    finally:
        if restore_mode is not None:
            target.chmod(restore_mode)


@pytest.mark.parametrize(
    ("component_count", "expected"),
    [(128, "clean"), (129, "request")],
)
def test_target_component_budget_boundary(
    tmp_path: Path, component_count: int, expected: str
) -> None:
    physical_base = tmp_path.resolve()
    nested_count = component_count - len(physical_base.parts) - 1
    assert nested_count > 0
    nested = physical_base.joinpath(
        *(f"d{index:03d}" for index in range(nested_count))
    )
    nested.mkdir(parents=True)
    repo = make_git_repo(nested)
    assert len(repo.root.parts) == component_count

    if expected == "clean":
        assert GitTargetAdapter(repo.root).capture(()).target.is_clean
    else:
        with pytest.raises(CaptureRequestError):
            GitTargetAdapter(repo.root)


@pytest.mark.parametrize(
    ("component_count", "expected"),
    [(128, "clean"), (129, "unknown")],
)
def test_symbolic_ref_component_budget_boundary(
    tmp_path: Path, component_count: int, expected: str
) -> None:
    repo = make_git_repo(tmp_path)
    head = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    ref_path = "/".join(
        ("refs", "heads", *(f"c{index:03d}" for index in range(component_count - 2)))
    )
    install_symbolic_ref_paths(repo, (ref_path,), head)

    if expected == "clean":
        assert GitTargetAdapter(repo.root).capture(()).target.is_clean
    else:
        with pytest.raises(CaptureUnknownError):
            GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize(
    ("chain_count", "expected"),
    [(32, "clean"), (33, "unknown")],
)
def test_symbolic_ref_chain_count_boundary(
    tmp_path: Path, chain_count: int, expected: str
) -> None:
    repo = make_git_repo(tmp_path)
    head = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    paths = tuple(f"refs/heads/chain-{index:02d}" for index in range(chain_count))
    install_symbolic_ref_paths(repo, paths, head)

    if expected == "clean":
        assert GitTargetAdapter(repo.root).capture(()).target.is_clean
    else:
        with pytest.raises(CaptureUnknownError):
            GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize(
    ("total_bytes", "expected"),
    [(8192, "clean"), (8193, "unknown")],
)
def test_symbolic_ref_total_byte_budget_boundary(
    tmp_path: Path, total_bytes: int, expected: str
) -> None:
    repo = make_git_repo(tmp_path)
    head = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    paths = []
    for index in range(32):
        name_length = 245 + (1 if index == 0 and total_bytes == 8193 else 0)
        prefix = f"r{index:02d}-"
        paths.append("refs/heads/" + prefix + "x" * (name_length - len(prefix)))
    assert sum(len(path.encode("ascii")) for path in paths) == total_bytes
    install_symbolic_ref_paths(repo, tuple(paths), head)

    if expected == "clean":
        assert GitTargetAdapter(repo.root).capture(()).target.is_clean
    else:
        with pytest.raises(CaptureUnknownError):
            GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize(
    ("component_bytes", "expected"),
    [(255, "clean"), (256, "unknown")],
)
def test_symbolic_ref_component_byte_boundary(
    tmp_path: Path, component_bytes: int, expected: str
) -> None:
    repo = make_git_repo(tmp_path)
    head = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    ref_path = "refs/heads/" + "r" * component_bytes
    if expected == "clean":
        install_symbolic_ref_paths(repo, (ref_path,), head)
        assert GitTargetAdapter(repo.root).capture(()).target.is_clean
    else:
        (repo.git_dir / "HEAD").write_text(f"ref: {ref_path}\n", encoding="ascii")
        with pytest.raises(CaptureUnknownError):
            GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize("packed_identity", ["same", "different"])
def test_loose_and_packed_terminal_ref_is_ambiguous_unknown(
    tmp_path: Path, packed_identity: str
) -> None:
    repo = make_git_repo(tmp_path)
    original = repo.git("rev-parse", "HEAD^{commit}").strip().decode("ascii")
    tree = repo.git("rev-parse", "HEAD^{tree}").strip().decode("ascii")
    replacement = (
        repo.git("commit-tree", tree, "-p", original, "-m", "same tree")
        .strip()
        .decode("ascii")
    )
    ref_path = "refs/heads/ambiguous"
    install_symbolic_ref_paths(repo, (ref_path,), original)
    packed_oid = original if packed_identity == "same" else replacement
    (repo.git_dir / "packed-refs").write_text(
        f"# pack-refs with: peeled fully-peeled sorted\n{packed_oid} {ref_path}\n",
        encoding="ascii",
    )

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize(
    "ref_path",
    [
        "refs/heads/has space",
        "refs/heads/double..dot",
        "refs/heads/at@{brace",
        "refs/heads/back\\slash",
        "refs/heads/tilde~name",
        "refs/heads/caret^name",
        "refs/heads/colon:name",
        "refs/heads/question?name",
        "refs/heads/star*name",
        "refs/heads/bracket[name",
        "refs/heads/.leading-dot",
        "refs/heads/trailing.lock",
        "refs/heads/trailing.",
        "refs//heads/empty",
        "heads/not-under-refs",
    ],
)
def test_symbolic_ref_strict_grammar_matrix_is_unknown(
    tmp_path: Path, ref_path: str
) -> None:
    repo = make_git_repo(tmp_path)
    (repo.git_dir / "HEAD").write_text(f"ref: {ref_path}\n", encoding="ascii")

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


@pytest.mark.parametrize("role", ["url", "pushurl"])
@pytest.mark.parametrize(
    "remote",
    [
        "https://example.invalid/repo path.git",
        "https://example.invalid/repo%20path.git",
        "https://example.invalid/repo%09path.git",
        "https://example.invalid/repo%0Apath.git",
        "https://example.invalid/repo%00path.git",
        "http://example.invalid/repository.git",
        "https://example.invalid:0/repository.git",
        "https://example.invalid:65536/repository.git",
        "https://user@example.invalid/repository.git",
        (
            "https://user:password@example.invalid/"  # pragma: allowlist secret
            "repository.git"
        ),
        "https://example.invalid/repository.git?private=1",
        "https://example.invalid/repository.git#private",
        "file:///private/repository.git",
        "ext::credential-helper",
        "helper with secret",
        "https://example.invalid/repo\\path.git",
    ],
)
def test_remote_value_rejection_matrix_is_redacted_unknown(
    tmp_path: Path, role: str, remote: str
) -> None:
    repo = make_git_repo(tmp_path)
    repo.git("config", "--add", f"remote.origin.{role}", remote)

    with pytest.raises(CaptureUnknownError) as captured:
        GitTargetAdapter(repo.root).capture(())
    assert remote not in str(captured.value)


@pytest.mark.parametrize(
    "remote_name",
    ["", "bad name", "bad/name", ".leading", "trailing.", "bad@name", "x" * 129],
)
def test_invalid_remote_name_is_unknown(tmp_path: Path, remote_name: str) -> None:
    repo = make_git_repo(tmp_path)
    with (repo.git_dir / "config").open("a", encoding="utf-8") as stream:
        stream.write(
            f'\n[remote "{remote_name}"]\n\turl = https://example.invalid/repo.git\n'
        )

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_remote_role_swap_changes_identity_digest(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    fetch = "https://example.invalid/fetch.git"
    push = "ssh://git@example.invalid/push.git"
    repo.git("config", "--add", "remote.origin.url", fetch)
    repo.git("config", "--add", "remote.origin.pushurl", push)
    before = GitTargetAdapter(repo.root).capture(())
    repo.git("config", "--unset-all", "remote.origin.url")
    repo.git("config", "--unset-all", "remote.origin.pushurl")
    repo.git("config", "--add", "remote.origin.url", push)
    repo.git("config", "--add", "remote.origin.pushurl", fetch)
    after = GitTargetAdapter(repo.root).capture(())

    assert (
        before.target.sanitized_remote_identity_digest
        != after.target.sanitized_remote_identity_digest
    )


def test_remote_name_swap_changes_identity_digest(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    first = "https://example.invalid/first.git"
    second = "https://example.invalid/second.git"
    repo.git("config", "--add", "remote.alpha.url", first)
    repo.git("config", "--add", "remote.beta.url", second)
    before = GitTargetAdapter(repo.root).capture(())
    repo.git("config", "--unset-all", "remote.alpha.url")
    repo.git("config", "--unset-all", "remote.beta.url")
    repo.git("config", "--add", "remote.alpha.url", second)
    repo.git("config", "--add", "remote.beta.url", first)
    after = GitTargetAdapter(repo.root).capture(())

    assert (
        before.target.sanitized_remote_identity_digest
        != after.target.sanitized_remote_identity_digest
    )


def test_case_distinct_remote_name_swap_changes_identity_digest(
    tmp_path: Path,
) -> None:
    repo = make_git_repo(tmp_path)
    first = "https://example.invalid/first.git"
    second = "https://example.invalid/second.git"
    repo.git("config", "--add", "remote.Alpha.url", first)
    repo.git("config", "--add", "remote.alpha.url", second)
    assert (
        repo.git("config", "--get-all", "remote.Alpha.url").strip()
        == first.encode()
    )
    assert (
        repo.git("config", "--get-all", "remote.alpha.url").strip()
        == second.encode()
    )
    before = GitTargetAdapter(repo.root).capture(())
    repo.git("config", "--unset-all", "remote.Alpha.url")
    repo.git("config", "--unset-all", "remote.alpha.url")
    repo.git("config", "--add", "remote.Alpha.url", second)
    repo.git("config", "--add", "remote.alpha.url", first)
    after = GitTargetAdapter(repo.root).capture(())

    assert (
        before.target.sanitized_remote_identity_digest
        != after.target.sanitized_remote_identity_digest
    )


def test_remote_duplicate_values_are_retained_deterministically(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    first = "https://example.invalid/first.git"
    second = "https://example.invalid/second.git"
    for value in (first, first, second):
        repo.git("config", "--add", "remote.origin.url", value)
    before = GitTargetAdapter(repo.root).capture(())
    repo.git("config", "--unset-all", "remote.origin.url")
    for value in (second, first, first):
        repo.git("config", "--add", "remote.origin.url", value)
    after = GitTargetAdapter(repo.root).capture(())

    assert (
        before.target.sanitized_remote_identity_digest
        == after.target.sanitized_remote_identity_digest
    )


def test_remote_duplicate_addition_changes_identity_digest(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    remote = "https://example.invalid/repository.git"
    repo.git("config", "--add", "remote.origin.url", remote)
    before = GitTargetAdapter(repo.root).capture(())
    repo.git("config", "--add", "remote.origin.url", remote)
    after = GitTargetAdapter(repo.root).capture(())

    assert (
        before.target.sanitized_remote_identity_digest
        != after.target.sanitized_remote_identity_digest
    )


@pytest.mark.parametrize(
    "remote",
    [
        "https://EXAMPLE.invalid/repository.git",
        "git://example.invalid/repository.git",
        "ssh://git@example.invalid:1/repository.git",
        "ssh://git@example.invalid:65535/repository.git",
        "git@example.invalid:repository.git",
    ],
)
def test_safe_remote_normalization_controls_are_clean(
    tmp_path: Path, remote: str
) -> None:
    repo = make_git_repo(tmp_path)
    repo.git("config", "--add", "remote.origin.url", remote)

    assert GitTargetAdapter(repo.root).capture(()).target.is_clean
