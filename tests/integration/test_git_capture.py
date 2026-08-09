from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

import agent_continuity.capture.git as git_capture
from agent_continuity.capture.base import CaptureRequestError, CaptureUnknownError
from agent_continuity.capture.coordinator import snapshot_findings
from agent_continuity.capture.git import GitTargetAdapter
from agent_continuity.kernel.evaluation import Profile, Verdict, evaluate
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


@pytest.mark.parametrize("mutation", ["worktree", "index", "head"])
def test_capture_rejects_mutation_after_initial_clean_status(
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
        if args and args[0] == "status" and not mutated:
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


def test_commit_boundary_rechecks_index_after_second_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    adapter = GitTargetAdapter(repo.root)
    original_run = adapter._run
    status_count = 0

    def mutate_after_second_status(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        nonlocal status_count
        output = original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )
        if args and args[0] == "status":
            status_count += 1
            if status_count == 2:
                (repo.root / "late.txt").write_text("late\n", encoding="utf-8")
                repo.git("add", "late.txt")
        return output

    monkeypatch.setattr(adapter, "_run", mutate_after_second_status)

    with pytest.raises(CaptureUnknownError):
        adapter.capture(())


def test_capture_rejects_aba_content_schedule_using_permission_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_git_repo(tmp_path)
    tracked = repo.root / "README.md"
    content_a = tracked.read_bytes()
    content_b = b"B" * len(content_a)
    mode_a = stat.S_IMODE(tracked.stat().st_mode)
    adapter = GitTargetAdapter(repo.root)
    original_run = adapter._run
    status_count = 0

    def run_with_aba_schedule(
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        nonlocal status_count
        is_status = bool(args and args[0] == "status")
        if is_status:
            status_count += 1
            if status_count in {2, 3}:
                tracked.chmod(mode_a)
                tracked.write_bytes(content_a)
        output = original_run(
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )
        if is_status and status_count == 1:
            tracked.write_bytes(content_b)
            tracked.chmod(0o600)
        elif is_status and status_count == 2:
            tracked.write_bytes(content_b)
            tracked.chmod(0o400)
        return output

    monkeypatch.setattr(adapter, "_run", run_with_aba_schedule)

    with pytest.raises(CaptureUnknownError):
        adapter.capture(())

    assert status_count == 3
    assert tracked.read_bytes() == content_a
    assert stat.S_IMODE(tracked.stat().st_mode) == mode_a
    assert repo.git("status", "--porcelain=v2", "-z") == b""


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
        if args and args[0] == "status" and not mutated:
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
        if args and args[0] == "status" and not replaced:
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
            GitTargetAdapter._descriptor_git_argv(descriptor, ("rev-parse", "HEAD")),
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
        after.target.ignore_provenance_digest
        != before.target.ignore_provenance_digest
    )
