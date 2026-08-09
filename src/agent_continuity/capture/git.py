"""Read-only, bounded, stability-checked Git target capture."""

from __future__ import annotations

import contextlib
import os
import platform
import re
import stat
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final
from urllib.parse import urlsplit, urlunsplit

from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    digest_bytes,
)
from agent_continuity.kernel.capabilities import CapabilityClaimV1, CapabilityStatus
from agent_continuity.kernel.model import Digest, JsonValue
from agent_continuity.kernel.paths import PathIdentityV1, path_identity_payload

from .base import (
    CaptureRequestError,
    CaptureSnapshot,
    CaptureUnknownError,
    InstructionFileV1,
    TargetIdentityV1,
)

_ADAPTER_ID: Final = "acg-git"
_ADAPTER_VERSION: Final = "1"
_MAX_GIT_OUTPUT: Final = 8 * 1024 * 1024
_MAX_FILE_BYTES: Final = 1024 * 1024 * 1024
_OID_RE = re.compile(rb"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SCP_REMOTE_RE = re.compile(
    r"^git@(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):(?P<path>[^\s?#]+)$"
)
_DESCRIPTOR_GIT_BOOTSTRAP: Final = (
    "import os,sys;"
    "descriptor=int(sys.argv[1]);"
    "os.fchdir(descriptor);"
    "os.close(descriptor);"
    "os.execvp('git',['git',*sys.argv[2:]])"
)


@dataclass(frozen=True, slots=True)
class _BoundedResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=0.5)
    except (OSError, subprocess.TimeoutExpired):
        with contextlib.suppress(OSError):
            process.kill()
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=1)


def _run_bounded(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout: float,
    max_output: int,
    input_data: bytes | None = None,
    pass_fds: Sequence[int] = (),
) -> _BoundedResult:
    """Run argv while retaining at most max_output bytes per output channel."""

    if max_output < 1 or timeout <= 0:
        raise CaptureUnknownError("subprocess resource limits are invalid")
    if input_data is not None and len(input_data) > max_output:
        raise CaptureUnknownError("subprocess input exceeded limit")
    try:
        process = subprocess.Popen(
            list(argv),
            shell=False,
            env=dict(env),
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(pass_fds),
        )
    except OSError as error:
        raise CaptureUnknownError("bounded subprocess could not start") from error

    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    stop_lock = threading.Lock()

    def stop_once() -> None:
        with stop_lock:
            _stop_process(process)

    def drain(stream: BinaryIO, destination: bytearray) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                remaining = max_output - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()
                    stop_once()
                    return
        finally:
            stream.close()

    if process.stdout is None or process.stderr is None:
        stop_once()
        raise CaptureUnknownError("bounded subprocess pipes are unavailable")
    threads = (
        threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
    )
    for thread in threads:
        thread.start()

    if process.stdin is not None:
        try:
            process.stdin.write(input_data or b"")
            process.stdin.close()
        except (BrokenPipeError, OSError) as error:
            stop_once()
            for thread in threads:
                thread.join(timeout=1)
            raise CaptureUnknownError("bounded subprocess input failed") from error

    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stop_once()
        for thread in threads:
            thread.join(timeout=1)
        raise CaptureUnknownError("bounded subprocess timed out") from error
    for thread in threads:
        thread.join(timeout=1)
    if any(thread.is_alive() for thread in threads):
        stop_once()
        raise CaptureUnknownError("bounded subprocess drain did not terminate")
    if overflow.is_set():
        raise CaptureUnknownError("bounded subprocess output exceeded limit")
    return _BoundedResult(returncode, bytes(stdout), bytes(stderr))


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise CaptureUnknownError("directory locator is not canonical absolute path")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        current = os.open(os.path.sep, flags)
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_descriptor
        return current
    except OSError as error:
        with contextlib.suppress(OSError, UnboundLocalError):
            os.close(current)
        raise CaptureUnknownError("directory could not be pinned safely") from error


class GitTargetAdapter:
    """Observe one local Git worktree without issuing a Git write operation."""

    adapter_id = _ADAPTER_ID
    adapter_version = _ADAPTER_VERSION

    def __init__(self, target: str | os.PathLike[str]) -> None:
        self._root_fd = -1
        self._git_fd = -1
        self._common_git_fd = -1
        requested = Path(target)
        if not requested.is_absolute():
            requested = requested.absolute()
        if not requested.is_dir():
            raise CaptureRequestError("target is not an existing directory")
        self._requested = requested
        top_level = self._initial_top_level(requested)
        try:
            root = Path(os.fsdecode(top_level.rstrip(b"\n"))).resolve(strict=True)
            requested_real = requested.resolve(strict=True)
        except (OSError, UnicodeError) as error:
            raise CaptureUnknownError(
                "Git target root proof could not be resolved"
            ) from error
        if root != requested_real:
            raise CaptureRequestError("target must be the Git worktree root")
        self.root = root
        self._root_fd = _open_absolute_directory(root)
        self._root_identity = _directory_identity(os.fstat(self._root_fd))
        self._verify_root_identity()

        raw_git_dir = self._run(("rev-parse", "--git-dir")).rstrip(b"\n")
        raw_common_dir = self._run(("rev-parse", "--git-common-dir")).rstrip(b"\n")
        self.git_directory = self._resolve_git_directory(raw_git_dir)
        self.git_common_directory = self._resolve_git_directory(raw_common_dir)
        self._git_fd = _open_absolute_directory(self.git_directory)
        self._common_git_fd = _open_absolute_directory(self.git_common_directory)
        self._git_identity = _directory_identity(os.fstat(self._git_fd))
        self._common_git_identity = _directory_identity(os.fstat(self._common_git_fd))
        self._verify_pinned_directories()

    def close(self) -> None:
        for name in ("_common_git_fd", "_git_fd", "_root_fd"):
            descriptor = getattr(self, name, -1)
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                setattr(self, name, -1)

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> GitTargetAdapter:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @staticmethod
    def _environment() -> dict[str, str]:
        return {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }

    @staticmethod
    def _git_arguments(
        target: Path | None,
        args: tuple[str, ...],
    ) -> list[str]:
        arguments = [
            "--no-pager",
            "-c",
            f"core.excludesFile={os.devnull}",
            "-c",
            f"core.attributesFile={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "submodule.recurse=false",
            "-c",
            "fetch.recurseSubmodules=false",
        ]
        if target is not None:
            arguments.extend(("-C", os.fspath(target)))
        arguments.extend(args)
        return arguments

    @classmethod
    def _git_argv(cls, target: Path, args: tuple[str, ...]) -> list[str]:
        return ["git", *cls._git_arguments(target, args)]

    @classmethod
    def _descriptor_git_argv(
        cls,
        descriptor: int,
        args: tuple[str, ...],
    ) -> list[str]:
        return [
            sys.executable,
            "-I",
            "-c",
            _DESCRIPTOR_GIT_BOOTSTRAP,
            str(descriptor),
            *cls._git_arguments(None, args),
        ]

    @classmethod
    def _initial_top_level(cls, target: Path) -> bytes:
        result = _run_bounded(
            cls._git_argv(target, ("rev-parse", "--show-toplevel")),
            env=cls._environment(),
            timeout=30,
            max_output=_MAX_GIT_OUTPUT,
        )
        if result.returncode != 0:
            raise CaptureRequestError("target is not a Git worktree")
        return result.stdout

    @classmethod
    def _run_at(
        cls,
        target: Path | int,
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        inherited_fds: tuple[int, ...]
        if isinstance(target, int):
            if os.name != "posix":
                raise CaptureUnknownError("descriptor-addressed Git is unsupported")
            argv = cls._descriptor_git_argv(target, args)
            inherited_fds = (target,)
        else:
            argv = cls._git_argv(target, args)
            inherited_fds = ()
        result = _run_bounded(
            argv,
            env=cls._environment(),
            timeout=30,
            max_output=_MAX_GIT_OUTPUT,
            input_data=input_data,
            pass_fds=inherited_fds,
        )
        if result.returncode not in allowed_codes:
            raise CaptureUnknownError("Git observation did not establish proof")
        return result.stdout

    def _run(
        self,
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        self._verify_pinned_directories()
        descriptor = self._descriptor_git_fd()
        output = self._run_at(
            descriptor,
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )
        self._verify_pinned_directories()
        return output

    def _descriptor_git_fd(self) -> int:
        if os.name != "posix" or self._root_fd < 0:
            raise CaptureUnknownError("descriptor-addressed Git is unsupported")
        try:
            identity = _directory_identity(os.fstat(self._root_fd))
        except OSError as error:
            raise CaptureUnknownError(
                "descriptor-addressed Git is unavailable"
            ) from error
        if identity != self._root_identity or not stat.S_ISDIR(identity[2]):
            raise CaptureUnknownError("descriptor-addressed Git identity changed")
        return self._root_fd

    def _resolve_git_directory(self, raw: bytes) -> Path:
        try:
            value = Path(os.fsdecode(raw))
        except UnicodeError as error:
            raise CaptureUnknownError("Git directory output was malformed") from error
        if not value.is_absolute():
            value = self.root / value
        try:
            return value.resolve(strict=True)
        except OSError as error:
            raise CaptureUnknownError("Git directory could not be resolved") from error

    @staticmethod
    def _verify_directory_locator(
        path: Path,
        descriptor: int,
        expected: tuple[int, int, int],
    ) -> None:
        try:
            descriptor_identity = _directory_identity(os.fstat(descriptor))
            locator_identity = _directory_identity(
                os.stat(path, follow_symlinks=False)
            )
        except OSError as error:
            raise CaptureUnknownError("pinned directory became unavailable") from error
        if descriptor_identity != expected or locator_identity != expected:
            raise CaptureUnknownError("pinned directory identity changed")
        if not stat.S_ISDIR(expected[2]):
            raise CaptureUnknownError("pinned path is not a directory")

    def _verify_root_identity(self) -> None:
        self._verify_directory_locator(self.root, self._root_fd, self._root_identity)

    def _verify_pinned_directories(self) -> None:
        self._verify_root_identity()
        if self._git_fd >= 0:
            self._verify_directory_locator(
                self.git_directory, self._git_fd, self._git_identity
            )
        if self._common_git_fd >= 0:
            self._verify_directory_locator(
                self.git_common_directory,
                self._common_git_fd,
                self._common_git_identity,
            )

    def capture(self, instruction_paths: Sequence[bytes]) -> CaptureSnapshot:
        self._verify_pinned_directories()
        self._reject_target_program_configuration()
        head_oid = self._single_oid(("rev-parse", "HEAD^{commit}"))
        tree_oid = self._single_oid(("rev-parse", f"{head_oid}^{{tree}}"))
        index = self._run(("ls-files", "--stage", "-z"))
        tree = self._run(("ls-tree", "-rz", "--full-tree", tree_oid))
        tree_entries = self._parse_tree(tree)
        index_entries = self._parse_index(index)
        status = self._status()
        instructions = self._capture_instructions(instruction_paths, tree_entries)
        worktree_manifest = self._worktree_manifest(index_entries)
        object_manifest = self._object_manifest(tree_entries)
        ignore_manifest = self._ignore_manifest(tree_entries)
        remote_digest = self._remote_identity_digest()

        final_head = self._single_oid(("rev-parse", "HEAD^{commit}"))
        final_index = self._run(("ls-files", "--stage", "-z"))
        final_status = self._status()
        final_worktree = self._worktree_manifest(index_entries)
        final_ignore = self._ignore_manifest(tree_entries)
        final_remote = self._remote_identity_digest()
        commit_head = self._single_oid(("rev-parse", "HEAD^{commit}"))
        commit_index = self._run(("ls-files", "--stage", "-z"))
        commit_status = self._status()
        self._verify_pinned_directories()
        if (
            final_head != head_oid
            or commit_head != head_oid
            or final_index != index
            or commit_index != index
            or final_status != status
            or commit_status != status
            or final_worktree != worktree_manifest
            or final_ignore != ignore_manifest
            or final_remote != remote_digest
        ):
            raise CaptureUnknownError("target changed during bounded capture")

        root_stat = os.fstat(self._root_fd)
        physical_root_fingerprint = digest_bytes(
            b"physical-root-v1\x00"
            + os.fsencode(self.root)
            + b"\x00"
            + str(root_stat.st_dev).encode("ascii")
            + b":"
            + str(root_stat.st_ino).encode("ascii")
        )
        inventory = canonical_bytes(
            {
                "index": [path_identity_payload(item[3]) for item in index_entries],
                "status_digest": digest_bytes(status),
                "tree": [path_identity_payload(item[3]) for item in tree_entries],
            }
        )
        target = TargetIdentityV1(
            adapter_id=_ADAPTER_ID,
            adapter_version=_ADAPTER_VERSION,
            sanitized_remote_identity_digest=remote_digest,
            head_oid=head_oid,
            tree_oid=tree_oid,
            index_manifest_digest=digest_bytes(index),
            worktree_manifest_digest=digest_bytes(worktree_manifest),
            inventory_digest=digest_bytes(inventory),
            status_digest=digest_bytes(status),
            git_object_manifest_digest=digest_bytes(object_manifest),
            ignore_provenance_digest=digest_bytes(ignore_manifest),
            platform_id=sys.platform,
            filesystem_id=f"{os.name}:{platform.system().lower()}",
            physical_root_fingerprint=physical_root_fingerprint,
            capabilities=self._capabilities(),
        )
        return CaptureSnapshot(target=target, instructions=instructions)

    def _reject_target_program_configuration(self) -> None:
        filters = self._run(
            (
                "config",
                "--includes",
                "--get-regexp",
                r"^filter\..*\.(clean|process)$",
            ),
            allowed_codes=(0, 1),
        )
        if filters:
            raise CaptureUnknownError("target Git programs are unsupported")

    def _status(self) -> bytes:
        return self._run(
            ("status", "--porcelain=v2", "-z", "--untracked-files=all")
        )

    def _single_oid(self, args: tuple[str, ...]) -> str:
        value = self._run(args).strip()
        if _OID_RE.fullmatch(value) is None:
            raise CaptureUnknownError("Git returned an invalid object identity")
        return value.decode("ascii")

    @staticmethod
    def _parse_tree(data: bytes) -> tuple[tuple[str, str, str, PathIdentityV1], ...]:
        entries: list[tuple[str, str, str, PathIdentityV1]] = []
        for row in data.split(b"\x00"):
            if not row:
                continue
            try:
                header, raw_path = row.split(b"\t", 1)
                mode, object_type, oid = header.split(b" ", 2)
                if _OID_RE.fullmatch(oid) is None:
                    raise ValueError("invalid object identity")
                entry = (
                    mode.decode("ascii"),
                    object_type.decode("ascii"),
                    oid.decode("ascii"),
                    PathIdentityV1.from_bytes("git-path-bytes", raw_path),
                )
            except (CanonicalJSONError, UnicodeError, ValueError) as error:
                raise CaptureUnknownError("Git tree output was malformed") from error
            entries.append(entry)
        return tuple(entries)

    @staticmethod
    def _parse_index(data: bytes) -> tuple[tuple[str, str, int, PathIdentityV1], ...]:
        entries: list[tuple[str, str, int, PathIdentityV1]] = []
        for row in data.split(b"\x00"):
            if not row:
                continue
            try:
                header, raw_path = row.split(b"\t", 1)
                mode, oid, stage_bytes = header.split(b" ", 2)
                stage = int(stage_bytes)
                if stage != 0 or _OID_RE.fullmatch(oid) is None:
                    raise ValueError("unsupported index entry")
                entry = (
                    mode.decode("ascii"),
                    oid.decode("ascii"),
                    stage,
                    PathIdentityV1.from_bytes("git-path-bytes", raw_path),
                )
            except (CanonicalJSONError, UnicodeError, ValueError) as error:
                raise CaptureUnknownError("Git index output was malformed") from error
            entries.append(entry)
        return tuple(entries)

    def _capture_instructions(
        self,
        requested: Sequence[bytes],
        tree_entries: tuple[tuple[str, str, str, PathIdentityV1], ...],
    ) -> tuple[InstructionFileV1, ...]:
        by_path = {item[3].raw_bytes(): item for item in tree_entries}
        captured: list[InstructionFileV1] = []
        for raw_path in requested:
            try:
                path = PathIdentityV1.from_bytes("git-path-bytes", raw_path)
            except (CanonicalJSONError, TypeError) as error:
                raise CaptureRequestError("instruction path is invalid") from error
            entry = by_path.get(raw_path)
            if entry is None or entry[1] != "blob":
                raise CaptureRequestError(
                    "instruction path is missing from target HEAD"
                )
            blob = self._run(("cat-file", "blob", entry[2]))
            captured.append(
                InstructionFileV1(
                    path=path,
                    blob_oid=entry[2],
                    byte_digest=digest_bytes(blob),
                )
            )
        return tuple(captured)

    @staticmethod
    def _open_relative_parent(root_fd: int, raw_path: bytes) -> tuple[int, bytes]:
        components = raw_path.split(b"/")
        if not components or any(item in {b"", b".", b".."} for item in components):
            raise CaptureUnknownError("relative capture path is invalid")
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            current = os.dup(root_fd)
            for component in components[:-1]:
                next_descriptor = os.open(component, flags, dir_fd=current)
                os.close(current)
                current = next_descriptor
            return current, components[-1]
        except OSError as error:
            with contextlib.suppress(OSError, UnboundLocalError):
                os.close(current)
            raise CaptureUnknownError("path containment could not be pinned") from error

    @classmethod
    def _read_relative_object(
        cls,
        root_fd: int,
        raw_path: bytes,
    ) -> tuple[bytes, str, os.stat_result]:
        parent_fd, final = cls._open_relative_parent(root_fd, raw_path)
        try:
            before = os.stat(final, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                content = os.readlink(final, dir_fd=parent_fd)
                if isinstance(content, str):
                    content = os.fsencode(content)
                after = os.stat(final, dir_fd=parent_fd, follow_symlinks=False)
                if _stat_identity(before) != _stat_identity(after):
                    raise CaptureUnknownError("symlink changed during capture")
                return content, "symlink", after
            if not stat.S_ISREG(before.st_mode):
                raise CaptureUnknownError("target path is not a regular object")
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(final, flags, dir_fd=parent_fd)
            try:
                opened = os.fstat(descriptor)
                if _stat_identity(before) != _stat_identity(opened):
                    raise CaptureUnknownError("target changed before descriptor pin")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_FILE_BYTES:
                        raise CaptureUnknownError("target file exceeds capture limit")
                    chunks.append(chunk)
                after = os.fstat(descriptor)
                if _stat_identity(opened) != _stat_identity(after):
                    raise CaptureUnknownError("target file changed during capture")
                return b"".join(chunks), "file", after
            finally:
                os.close(descriptor)
        except OSError as error:
            raise CaptureUnknownError(
                "target object could not be read safely"
            ) from error
        finally:
            os.close(parent_fd)

    def _worktree_manifest(
        self,
        entries: tuple[tuple[str, str, int, PathIdentityV1], ...],
    ) -> bytes:
        manifest: list[JsonValue] = []
        for mode, oid, stage, path in entries:
            content, kind, metadata = self._read_relative_object(
                self._root_fd, path.raw_bytes()
            )
            manifest.append(
                {
                    "byte_digest": digest_bytes(content),
                    "git_mode": mode,
                    "kind": kind,
                    "oid": oid,
                    "path": path_identity_payload(path),
                    "size": len(content),
                    "stage": stage,
                    "stat": {
                        "change_time_ns": metadata.st_ctime_ns,
                        "device": metadata.st_dev,
                        "inode": metadata.st_ino,
                        "mode": metadata.st_mode,
                        "modify_time_ns": metadata.st_mtime_ns,
                        "permissions": stat.S_IMODE(metadata.st_mode),
                        "size": metadata.st_size,
                    },
                }
            )
        return canonical_bytes(manifest)

    def _object_manifest(
        self,
        entries: tuple[tuple[str, str, str, PathIdentityV1], ...],
    ) -> bytes:
        manifest: list[JsonValue] = []
        for mode, object_type, oid, path in entries:
            symlink_target_digest: Digest | None = None
            if mode == "120000":
                symlink_target_digest = digest_bytes(
                    self._run(("cat-file", "blob", oid))
                )
            manifest.append(
                {
                    "mode": mode,
                    "object_type": object_type,
                    "oid": oid,
                    "path": path_identity_payload(path),
                    "symlink_target_digest": symlink_target_digest,
                }
            )
        return canonical_bytes(manifest)

    def _ignore_manifest(
        self,
        entries: tuple[tuple[str, str, str, PathIdentityV1], ...],
    ) -> bytes:
        manifest: list[JsonValue] = []
        for _mode, object_type, oid, path in entries:
            basename = path.raw_bytes().split(b"/")[-1]
            if object_type == "blob" and basename == b".gitignore":
                manifest.append(
                    {
                        "blob_oid": oid,
                        "path": path_identity_payload(path),
                        "source": "repository",
                    }
                )
        try:
            content, kind, _metadata = self._read_relative_object(
                self._common_git_fd, b"info/exclude"
            )
        except CaptureUnknownError:
            if self._relative_exists(self._common_git_fd, b"info/exclude"):
                raise
        else:
            if kind != "file":
                raise CaptureUnknownError("local exclude is not a regular file")
            manifest.append(
                {
                    "byte_digest": digest_bytes(content),
                    "source": "local-exclude",
                }
            )
        return canonical_bytes(manifest)

    @classmethod
    def _relative_exists(cls, root_fd: int, raw_path: bytes) -> bool:
        try:
            parent_fd, final = cls._open_relative_parent(root_fd, raw_path)
        except CaptureUnknownError:
            return False
        try:
            os.stat(final, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as error:
            raise CaptureUnknownError("relative path status is unavailable") from error
        finally:
            os.close(parent_fd)
        return True

    def _remote_identity_digest(self) -> Digest | None:
        output = self._run(
            ("config", "--local", "--get-regexp", r"^remote\..*\.url$"),
            allowed_codes=(0, 1),
        )
        identities: list[str] = []
        for row in output.splitlines():
            if not row:
                continue
            try:
                _key, value = row.decode("utf-8", errors="strict").split(None, 1)
            except (UnicodeDecodeError, ValueError) as error:
                raise CaptureRequestError("remote identity is malformed") from error
            identities.append(_sanitize_remote(value))
        if not identities:
            return None
        canonical_identities: list[JsonValue] = [item for item in sorted(identities)]
        return digest_bytes(canonical_bytes(canonical_identities))

    @staticmethod
    def _capabilities() -> tuple[CapabilityClaimV1, ...]:
        def claim(name: str, status: CapabilityStatus) -> CapabilityClaimV1:
            return CapabilityClaimV1(
                name=name,
                status=status,
                adapter_id=_ADAPTER_ID,
                adapter_version=_ADAPTER_VERSION,
                evidence_digest=None,
            )

        values = (
            claim("descriptor_pinned_reads", "unknown"),
            claim("git_immutable_objects", "unknown"),
            claim("git_network_disabled", "unknown"),
            claim(
                "windows_reparse_protection",
                "unknown" if os.name == "nt" else "unsupported",
            ),
        )
        return tuple(sorted(values, key=lambda item: item.name))


def _sanitize_remote(value: str) -> str:
    if type(value) is not str or any(ord(character) < 0x20 for character in value):
        raise CaptureRequestError("remote identity contains invalid characters")
    if "://" in value:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as error:
            raise CaptureRequestError("remote URL port is invalid") from error
        if parsed.scheme not in {"git", "https", "ssh"}:
            raise CaptureRequestError("remote URL scheme is unsupported")
        if parsed.query or parsed.fragment or parsed.password is not None:
            raise CaptureRequestError("remote credentials or URL suffix are forbidden")
        if parsed.username is not None and not (
            parsed.scheme == "ssh" and parsed.username == "git"
        ):
            raise CaptureRequestError("remote credentials are forbidden")
        if not parsed.hostname or not parsed.path or "@" in parsed.hostname:
            raise CaptureRequestError("remote URL is malformed")
        host = parsed.hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if port is not None:
            host = f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), host, parsed.path, "", ""))
    if value.count("@") != 1:
        raise CaptureRequestError("remote SCP identity is malformed")
    match = _SCP_REMOTE_RE.fullmatch(value)
    if match is None:
        raise CaptureRequestError("remote identity grammar is unsupported")
    host = match.group("host").lower()
    return f"ssh://{host}/{match.group('path')}"
