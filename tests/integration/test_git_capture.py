from __future__ import annotations

import hashlib
import os
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import agent_continuity.capture.git as git_capture
from agent_continuity.capture.base import (
    CaptureRequestError,
    CaptureUnknownError,
    target_identity_payload,
)
from agent_continuity.capture.git import GitTargetAdapter
from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from tests.helpers.git_repo import (
    GitRepo,
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
    adapter = GitTargetAdapter(repo.root)
    original_run = adapter._run
    mutated = False

    def run_with_mutation(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        nonlocal mutated
        output = original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )
        if args and args[0] == "ls-tree" and not mutated:
            mutated = True
            if mutation == "worktree":
                (repo.root / "README.md").write_text("mutated\n", encoding="utf-8")
            elif mutation == "index":
                (repo.root / "new.txt").write_text("new\n", encoding="utf-8")
                repo.git("add", "new.txt")
            else:
                (repo.root / "README.md").write_text("new commit\n", encoding="utf-8")
                repo.git("add", "README.md")
                repo.git("commit", "-q", "-m", "move head")
        return output

    monkeypatch.setattr(adapter, "_run", run_with_mutation)

    with pytest.raises(CaptureUnknownError):
        adapter.capture((b"AGENTS.md",))


def test_tree_listing_is_pinned_to_sampled_tree_oid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)
    original_run = adapter._run
    tree_arguments: list[tuple[str, ...]] = []

    def recording_run(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        if args and args[0] == "ls-tree":
            tree_arguments.append(args)
        return original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )

    monkeypatch.setattr(adapter, "_run", recording_run)
    snapshot = adapter.capture(())

    assert tree_arguments
    assert all(
        arguments[-1] == snapshot.target.tree_oid for arguments in tree_arguments
    )


def test_capture_rechecks_index_after_first_direct_index_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)
    original_run = adapter._run
    index_count = 0

    def mutate_after_first_index_observation(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        nonlocal index_count
        output = original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )
        if args and args[0] == "ls-files":
            index_count += 1
            if index_count == 1:
                (repo.root / "late.txt").write_text("late\n", encoding="utf-8")
                repo.git("add", "late.txt")
        return output

    monkeypatch.setattr(adapter, "_run", mutate_after_first_index_observation)

    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


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
    adapter = GitTargetAdapter(repo.root)
    original_run = adapter._run
    mutated = False

    def replace_directory(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        nonlocal mutated
        output = original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )
        if args and args[0] == "ls-tree" and not mutated:
            mutated = True
            shutil.move(repo.root / "docs", tmp_path / "original-docs")
            os.symlink(outside, repo.root / "docs")
        return output

    monkeypatch.setattr(adapter, "_run", replace_directory)
    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


def test_root_replacement_is_unknown_not_a_request_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)
    original_run = adapter._run
    replaced = False

    def replace_root(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        nonlocal replaced
        output = original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )
        if args and args[0] == "ls-tree" and not replaced:
            replaced = True
            repo.root.rename(tmp_path / "original-root")
            repo.root.mkdir()
        return output

    monkeypatch.setattr(adapter, "_run", replace_root)
    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


def test_git_observation_uses_pinned_root_descriptor_during_path_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)
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
    original_run_at = adapter._run_at

    def run_during_path_swap(
        target: Path | int,
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        repo.root.rename(original_location)
        replacement.root.rename(repo.root)
        try:
            return original_run_at(
                target,
                args,
                allowed_codes=allowed_codes,
                input_data=input_data,
            )
        finally:
            repo.root.rename(replacement.root)
            original_location.rename(repo.root)

    monkeypatch.setattr(adapter, "_run_at", run_during_path_swap)

    observed_head = adapter._run(("rev-parse", "HEAD^{commit}"))

    assert observed_head == expected_head


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
def test_bounded_runner_rejects_inflight_output_overflow(
    stream: str,
) -> None:
    runner = getattr(git_capture, "_run_bounded", None)
    assert callable(runner)
    descriptor = "1" if stream == "stdout" else "2"
    program = f"import os; os.write({descriptor}, b'x' * 65536)"

    with pytest.raises(CaptureUnknownError):
        runner(
            [sys.executable, "-c", program],
            env={"LC_ALL": "C"},
            timeout=5,
            max_output=1024,
        )


def test_bounded_runner_classifies_timeout_as_unknown() -> None:
    runner = getattr(git_capture, "_run_bounded", None)
    assert callable(runner)

    with pytest.raises(CaptureUnknownError):
        runner(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            env={"LC_ALL": "C"},
            timeout=0.05,
            max_output=1024,
        )


def test_descriptor_bootstrap_closes_root_fd_before_git_exec(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    descriptor = os.open(repo.root, os.O_RDONLY)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    fake_git.write_text(
        f"#!{sys.executable}\n"
        "import errno\n"
        "import os\n"
        "import sys\n"
        "descriptor = int(os.environ['EXPECTED_FD'])\n"
        "try:\n"
        "    os.fstat(descriptor)\n"
        "except OSError as error:\n"
        "    if error.errno == errno.EBADF:\n"
        "        sys.stdout.buffer.write(b'closed')\n"
        "        raise SystemExit(0)\n"
        "sys.stdout.buffer.write(b'open')\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o700)
    try:
        result = git_capture._run_bounded(
            GitTargetAdapter._descriptor_git_argv(
                descriptor, ("rev-parse", "HEAD"), fake_git
            ),
            env={
                "EXPECTED_FD": str(descriptor),
                "LC_ALL": "C",
                "PATH": os.fspath(fake_bin),
            },
            timeout=5,
            max_output=1024,
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)

    assert result.returncode == 0
    assert result.stdout == b"closed"


@pytest.mark.parametrize("failure", ["spawn", "timeout", "overflow"])
def test_constructor_preserves_initial_proof_failures_as_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    repo = make_git_repo(tmp_path)

    def fail_initial_observation(*_args: object, **_kwargs: object) -> object:
        raise CaptureUnknownError(f"initial {failure} proof failure")

    monkeypatch.setattr(git_capture, "_run_bounded", fail_initial_observation)

    with pytest.raises(CaptureUnknownError, match=failure):
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
def test_remote_sanitizer_rejects_ambiguous_or_helper_forms(remote: str) -> None:
    with pytest.raises(CaptureRequestError):
        git_capture._sanitize_remote(remote)


def test_missing_git_object_is_unknown_not_request_error(tmp_path: Path) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)

    with pytest.raises(CaptureUnknownError):
        adapter._run(("cat-file", "blob", "0" * 40))


def test_malformed_git_tree_bytes_are_sanitized_unknown() -> None:
    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter._parse_tree(b"\xff blob " + b"a" * 40 + b"\tpath\x00")


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
    real_run_bounded = git_capture._run_bounded
    swapped = False

    def swap_before_first_git(*args: object, **kwargs: object) -> object:
        nonlocal swapped
        if not swapped:
            original.root.rename(displaced)
            replacement.root.rename(original.root)
            swapped = True
        return real_run_bounded(*args, **kwargs)

    monkeypatch.setattr(git_capture, "_run_bounded", swap_before_first_git)
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
        if swapped:
            original.root.rename(replacement.root)
            displaced.rename(original.root)


def test_capture_git_processes_use_absolute_git_and_no_forbidden_porcelain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    real_run_bounded = git_capture._run_bounded
    observed_argv: list[tuple[str, ...]] = []

    def record_argv(argv: object, *args: object, **kwargs: object) -> object:
        assert isinstance(argv, (list, tuple))
        observed_argv.append(tuple(str(item) for item in argv))
        return real_run_bounded(argv, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(git_capture, "_run_bounded", record_argv)
    GitTargetAdapter(repo.root).capture(())

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
        any(Path(item).is_absolute() and Path(item).name == "git" for item in argv)
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
    adapter = GitTargetAdapter(repo.root)
    sentinel = tmp_path / f"late-{driver}-executed"
    program = tmp_path / f"late-{driver}.sh"
    if driver == "clean":
        body = f"#!/bin/sh\nprintf executed > '{sentinel}'\ncat\n"
    else:
        body = f"#!/bin/sh\nprintf executed > '{sentinel}'\nexit 1\n"
    program.write_text(body, encoding="utf-8")
    program.chmod(0o700)
    original_run = adapter._run
    injected = False

    def inject_after_selected_git_phase(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        nonlocal injected
        output = original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )
        if args and args[0] == trigger_command and not injected:
            injected = True
            (repo.root / ".gitattributes").write_text(
                "README.md filter=probe\n", encoding="utf-8"
            )
            repo.git("config", f"filter.probe.{driver}", os.fspath(program))
            metadata = (repo.root / "README.md").stat()
            os.utime(
                repo.root / "README.md",
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
            )
        return output

    monkeypatch.setattr(adapter, "_run", inject_after_selected_git_phase)
    with pytest.raises(CaptureUnknownError):
        adapter.capture(())
    assert injected
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
    adapter = GitTargetAdapter(repo.root)
    original_run = adapter._run

    def report_dual_format(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        if args == ("rev-parse", "--show-object-format=input"):
            return b"sha1 sha256\n"
        return original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )

    monkeypatch.setattr(adapter, "_run", report_dual_format)
    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


@pytest.mark.parametrize(
    ("limit_name", "limit_value"),
    [
        ("_MAX_TRAVERSAL_DEPTH", 1),
        ("_MAX_TRAVERSAL_ENTRIES", 2),
        ("_MAX_TOTAL_PATH_BYTES", 8),
        ("_MAX_FILE_BYTES", 4),
        ("_MAX_TOTAL_FILE_BYTES", 4),
        ("_MAX_CAPTURE_SECONDS", 1e-9),
    ],
)
def test_capture_resource_limits_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit_value: int | float,
) -> None:
    repo = make_git_repo(tmp_path)
    monkeypatch.setattr(git_capture, limit_name, limit_value)

    with pytest.raises(CaptureUnknownError):
        GitTargetAdapter(repo.root).capture(())


def test_elapsed_limit_is_rechecked_after_final_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)
    original_observe = adapter._observe
    clock = 0.0
    observation_count = 0

    def monotonic() -> float:
        return clock

    def advance_after_final_observation(
        requested: tuple[object, ...],
    ) -> object:
        nonlocal clock, observation_count
        result = original_observe(requested)  # type: ignore[arg-type]
        observation_count += 1
        if observation_count == 2:
            clock = 2.0
        return result

    monkeypatch.setattr(git_capture, "_MAX_CAPTURE_SECONDS", 1.0)
    monkeypatch.setattr(git_capture.time, "monotonic", monotonic)
    monkeypatch.setattr(adapter, "_observe", advance_after_final_observation)

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


@pytest.mark.parametrize("returncode", [1, -9])
def test_present_git_with_abnormal_initial_result_is_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
) -> None:
    repo = make_git_repo(tmp_path)

    def abnormal_result(*_args: object, **_kwargs: object) -> object:
        return git_capture._BoundedResult(returncode, b"", b"redacted")

    monkeypatch.setattr(git_capture, "_run_bounded", abnormal_result)
    with pytest.raises(CaptureUnknownError) as captured:
        GitTargetAdapter(repo.root)
    assert "redacted" not in str(captured.value)


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
