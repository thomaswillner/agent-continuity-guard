"""Read-only, bounded, descriptor-rooted Git target capture."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
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
    DIRECT_CLEAN_STATUS_DIGEST,
    CaptureRequestError,
    CaptureSnapshot,
    CaptureUnknownError,
    InstructionFileV1,
    TargetIdentityV1,
)

_ADAPTER_ID: Final = "acg-git"
_ADAPTER_VERSION: Final = "2"
_MAX_GIT_OUTPUT: Final = 8 * 1024 * 1024
_MAX_FILE_BYTES: Final = 1024 * 1024 * 1024
_MAX_TOTAL_FILE_BYTES: Final = 4 * 1024 * 1024 * 1024
_MAX_TRAVERSAL_DEPTH: Final = 128
_MAX_TRAVERSAL_ENTRIES: Final = 1_000_000
_MAX_TOTAL_PATH_BYTES: Final = 256 * 1024 * 1024
_MAX_CAPTURE_SECONDS: Final = 30.0
_MAX_METADATA_BYTES: Final = 8 * 1024 * 1024
_ALLOWED_INDEX_EXTENSIONS: Final = frozenset({b"TREE"})
_OID_RE = re.compile(rb"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SCP_REMOTE_RE = re.compile(
    r"^git@(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):(?P<path>[^\s?#]+)$"
)
_FILTER_KEY_RE = re.compile(r"^filter\..+\.")
_DESCRIPTOR_GIT_BOOTSTRAP: Final = (
    "import os,sys;"
    "descriptor=int(sys.argv[1]);"
    "executable=sys.argv[2];"
    "os.fchdir(descriptor);"
    "os.close(descriptor);"
    "os.execv(executable,[executable,*sys.argv[3:]])"
)

_StatIdentity = tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _BoundedResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class _ObservedFile:
    exists: bool
    identity: _StatIdentity | None
    digest: Digest | None
    content: bytes | None


@dataclass(frozen=True, slots=True)
class _IndexEntry:
    mode: str
    oid: str
    stage: int
    path: PathIdentityV1


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    mode: str
    object_type: str
    oid: str
    path: PathIdentityV1


@dataclass(frozen=True, slots=True)
class _WorktreeProof:
    manifest: bytes
    traversal_manifest: bytes
    contents: dict[bytes, bytes]


@dataclass(frozen=True, slots=True)
class _Observation:
    head_oid: str
    tree_oid: str
    object_format: str
    index_digest: Digest
    index_entries: tuple[_IndexEntry, ...]
    tree_entries: tuple[_TreeEntry, ...]
    worktree_manifest: bytes
    traversal_manifest: bytes
    object_manifest: bytes
    ignore_manifest: bytes
    remote_digest: Digest | None
    config_digest: Digest
    dependency_digest: Digest
    instructions: tuple[InstructionFileV1, ...]


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


def _stat_identity(metadata: os.stat_result) -> _StatIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _locator_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _directory_flags() -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise CaptureUnknownError("descriptor-rooted capture is unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _file_flags() -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise CaptureUnknownError("descriptor-rooted capture is unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise CaptureUnknownError("directory locator is not canonical absolute path")
    flags = _directory_flags()
    current = -1
    try:
        current = os.open(os.path.sep, flags)
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_descriptor
        return current
    except OSError as error:
        if current >= 0:
            with contextlib.suppress(OSError):
                os.close(current)
        raise CaptureUnknownError("directory could not be pinned safely") from error


def _open_absolute_file(path: Path) -> int:
    parent_fd = _open_absolute_directory(path.parent)
    try:
        descriptor = os.open(path.name, _file_flags(), dir_fd=parent_fd)
    except OSError as error:
        raise CaptureUnknownError("file locator could not be pinned safely") from error
    finally:
        os.close(parent_fd)
    return descriptor


def _read_descriptor(descriptor: int, *, max_bytes: int) -> _ObservedFile:
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CaptureUnknownError("metadata source is not a regular file")
        chunks: list[bytes] = []
        offset = 0
        while True:
            chunk = os.pread(
                descriptor, min(1024 * 1024, max_bytes + 1 - offset), offset
            )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
            if offset > max_bytes:
                raise CaptureUnknownError("metadata source exceeded limit")
        after = os.fstat(descriptor)
    except OSError as error:
        raise CaptureUnknownError("metadata source could not be read safely") from error
    if _stat_identity(before) != _stat_identity(after):
        raise CaptureUnknownError("metadata source changed during read")
    content = b"".join(chunks)
    return _ObservedFile(
        exists=True,
        identity=_stat_identity(after),
        digest=digest_bytes(content),
        content=content,
    )


def _resolve_locator(base: Path, raw_value: bytes) -> Path:
    if (
        not raw_value
        or b"\x00" in raw_value
        or b"\n" in raw_value
        or b"\r" in raw_value
    ):
        raise CaptureUnknownError("Git metadata locator was malformed")
    base_bytes = os.fsencode(base)
    combined = (
        raw_value if os.path.isabs(raw_value) else os.path.join(base_bytes, raw_value)
    )
    normalized = os.path.normpath(combined)
    if not os.path.isabs(normalized):
        raise CaptureUnknownError("Git metadata locator was not absolute")
    return Path(os.fsdecode(normalized))


def _git_digest(data: bytes, object_format: str) -> str:
    if object_format == "sha1":
        return hashlib.sha1(data).hexdigest()
    if object_format == "sha256":
        return hashlib.sha256(data).hexdigest()
    raise CaptureUnknownError("Git object format is unsupported")


def _blob_oid(content: bytes, object_format: str) -> str:
    framed = b"blob " + str(len(content)).encode("ascii") + b"\x00" + content
    return _git_digest(framed, object_format)


def _expected_oid_length(object_format: str) -> int:
    if object_format == "sha1":
        return 40
    if object_format == "sha256":
        return 64
    raise CaptureUnknownError("Git object format is unsupported")


def _validate_repo_path(raw_path: bytes) -> None:
    components = raw_path.split(b"/")
    if (
        not raw_path
        or raw_path.startswith(b"/")
        or raw_path.endswith(b"/")
        or any(item in {b"", b".", b"..", b".git"} for item in components)
    ):
        raise CaptureUnknownError("Git path was malformed")
    if len(components) > _MAX_TRAVERSAL_DEPTH:
        raise CaptureUnknownError("Git path depth exceeded limit")


def _file_payload(observation: _ObservedFile) -> JsonValue:
    return {
        "digest": observation.digest,
        "exists": observation.exists,
        "identity": (
            None if observation.identity is None else list(observation.identity)
        ),
    }


class GitTargetAdapter:
    """Conservatively prove one local Git worktree is exactly HEAD-clean."""

    adapter_id = _ADAPTER_ID
    adapter_version = _ADAPTER_VERSION

    def __init__(self, target: str | os.PathLike[str]) -> None:
        self._root_fd = -1
        self._git_fd = -1
        self._common_git_fd = -1
        self._git_locator_fd = -1
        self._commondir_fd = -1
        self._git_executable_fd = -1
        self._active_deadline: float | None = None
        self._git_locator_kind = ""
        self._git_locator_identity: _StatIdentity | None = None
        self._commondir_identity: _StatIdentity | None = None
        try:
            self._git_executable = self._resolve_git_executable()
            self._pin_requested_root(target)
            self._pin_git_directories()
            self._verify_pinned_directories()
            prefix = self._run(("rev-parse", "--show-prefix"))
            inside = self._run(("rev-parse", "--is-inside-work-tree"))
            bare = self._run(("rev-parse", "--is-bare-repository"))
            if prefix.rstrip(b"\n") != b"" or inside.strip() != b"true":
                raise CaptureUnknownError("target worktree root could not be proved")
            if bare.strip() != b"false":
                raise CaptureUnknownError("bare repositories are unsupported")
        except BaseException:
            self.close()
            raise

    def _resolve_git_executable(self) -> Path:
        candidate = shutil.which("git")
        if candidate is None:
            raise CaptureUnknownError("trusted Git executable is unavailable")
        candidate_path = Path(candidate)
        if not candidate_path.is_absolute():
            raise CaptureUnknownError("trusted Git executable is not absolute")
        try:
            executable = candidate_path.resolve(strict=True)
        except OSError as error:
            raise CaptureUnknownError(
                "trusted Git executable could not be resolved"
            ) from error
        descriptor = _open_absolute_file(executable)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            os.close(descriptor)
            raise CaptureUnknownError("trusted Git executable is invalid")
        self._git_executable_fd = descriptor
        self._git_executable_identity = _stat_identity(metadata)
        return executable

    def _pin_requested_root(self, target: str | os.PathLike[str]) -> None:
        try:
            raw_target = os.fspath(target)
        except TypeError as error:
            raise CaptureRequestError("target path is invalid") from error
        if not isinstance(raw_target, str) or not raw_target:
            raise CaptureRequestError("target path is invalid")
        requested = Path(os.path.abspath(raw_target))
        try:
            self._root_fd = _open_absolute_directory(requested)
        except CaptureUnknownError as error:
            cause = error.__cause__
            if isinstance(cause, (FileNotFoundError, NotADirectoryError)):
                raise CaptureRequestError(
                    "target is not an existing directory"
                ) from error
            raise
        self.root = requested
        metadata = os.fstat(self._root_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise CaptureRequestError("target is not an existing directory")
        self._root_identity = _locator_identity(metadata)

    def _pin_git_directories(self) -> None:
        try:
            locator_metadata = os.stat(
                b".git", dir_fd=self._root_fd, follow_symlinks=False
            )
        except FileNotFoundError as error:
            raise CaptureRequestError("target has no Git locator") from error
        except OSError as error:
            raise CaptureUnknownError("Git locator could not be inspected") from error
        self._git_locator_identity = _stat_identity(locator_metadata)
        if stat.S_ISDIR(locator_metadata.st_mode):
            try:
                self._git_fd = os.open(
                    b".git", _directory_flags(), dir_fd=self._root_fd
                )
            except OSError as error:
                raise CaptureUnknownError(
                    "Git directory could not be pinned"
                ) from error
            self._git_locator_kind = "directory"
            self.git_directory = self.root / ".git"
        elif stat.S_ISREG(locator_metadata.st_mode):
            try:
                self._git_locator_fd = os.open(
                    b".git", _file_flags(), dir_fd=self._root_fd
                )
            except OSError as error:
                raise CaptureUnknownError(
                    "Git locator file could not be pinned"
                ) from error
            locator = _read_descriptor(
                self._git_locator_fd, max_bytes=_MAX_METADATA_BYTES
            )
            if locator.identity != self._git_locator_identity:
                raise CaptureUnknownError("Git locator changed before pinning")
            content = locator.content or b""
            if not content.startswith(b"gitdir: "):
                raise CaptureUnknownError("Git locator file was malformed")
            value = content[len(b"gitdir: ") :].rstrip(b"\n")
            if b"\n" in value or b"\r" in value:
                raise CaptureUnknownError("Git locator file was malformed")
            self.git_directory = _resolve_locator(self.root, value)
            self._git_fd = _open_absolute_directory(self.git_directory)
            self._git_locator_kind = "file"
        else:
            raise CaptureUnknownError("Git locator has unsupported type")

        self._git_identity = _locator_identity(os.fstat(self._git_fd))
        commondir = self._observe_file(
            self._git_fd, b"commondir", required=False, max_bytes=_MAX_METADATA_BYTES
        )
        if commondir.exists:
            content = (commondir.content or b"").rstrip(b"\n")
            if b"\n" in content or b"\r" in content:
                raise CaptureUnknownError("common Git locator was malformed")
            self.git_common_directory = _resolve_locator(self.git_directory, content)
            self._common_git_fd = _open_absolute_directory(self.git_common_directory)
            try:
                self._commondir_fd = os.open(
                    b"commondir", _file_flags(), dir_fd=self._git_fd
                )
            except OSError as error:
                raise CaptureUnknownError(
                    "common Git locator could not be pinned"
                ) from error
            pinned_commondir = _read_descriptor(
                self._commondir_fd, max_bytes=_MAX_METADATA_BYTES
            )
            if pinned_commondir != commondir:
                raise CaptureUnknownError("common Git locator changed before pinning")
            self._commondir_identity = commondir.identity
        else:
            self.git_common_directory = self.git_directory
            self._common_git_fd = os.dup(self._git_fd)
        self._common_git_identity = _locator_identity(os.fstat(self._common_git_fd))

    def close(self) -> None:
        for name in (
            "_commondir_fd",
            "_git_locator_fd",
            "_common_git_fd",
            "_git_fd",
            "_root_fd",
            "_git_executable_fd",
        ):
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
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }

    @staticmethod
    def _git_arguments(args: tuple[str, ...]) -> list[str]:
        return [
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
            *args,
        ]

    @classmethod
    def _descriptor_git_argv(
        cls,
        descriptor: int,
        args: tuple[str, ...],
        git_executable: Path | None = None,
    ) -> list[str]:
        if git_executable is None:
            candidate = shutil.which("git")
            if candidate is None or not Path(candidate).is_absolute():
                raise CaptureUnknownError("trusted Git executable is unavailable")
            try:
                git_executable = Path(candidate).resolve(strict=True)
            except OSError as error:
                raise CaptureUnknownError(
                    "trusted Git executable could not be resolved"
                ) from error
        return [
            sys.executable,
            "-I",
            "-c",
            _DESCRIPTOR_GIT_BOOTSTRAP,
            str(descriptor),
            os.fspath(git_executable),
            *cls._git_arguments(args),
        ]

    def _remaining_timeout(self) -> float:
        if self._active_deadline is None:
            return 30.0
        remaining = self._active_deadline - time.monotonic()
        if remaining <= 0:
            raise CaptureUnknownError("capture elapsed-time limit was exceeded")
        return min(30.0, remaining)

    def _check_deadline(self) -> None:
        self._remaining_timeout()

    def _run_at(
        self,
        target: Path | int,
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        if not isinstance(target, int) or os.name != "posix":
            raise CaptureUnknownError("descriptor-addressed Git is unsupported")
        argv = self._descriptor_git_argv(target, args, self._git_executable)
        result = _run_bounded(
            argv,
            env=self._environment(),
            timeout=self._remaining_timeout(),
            max_output=_MAX_GIT_OUTPUT,
            input_data=input_data,
            pass_fds=(target,),
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
        output = self._run_at(
            self._descriptor_git_fd(),
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
            identity = _locator_identity(os.fstat(self._root_fd))
        except OSError as error:
            raise CaptureUnknownError(
                "descriptor-addressed Git is unavailable"
            ) from error
        if identity != self._root_identity or not stat.S_ISDIR(identity[2]):
            raise CaptureUnknownError("descriptor-addressed Git identity changed")
        return self._root_fd

    @staticmethod
    def _verify_directory_locator(
        path: Path,
        descriptor: int,
        expected: tuple[int, int, int],
    ) -> None:
        try:
            descriptor_identity = _locator_identity(os.fstat(descriptor))
            locator_identity = _locator_identity(os.stat(path, follow_symlinks=False))
        except OSError as error:
            raise CaptureUnknownError("pinned directory became unavailable") from error
        if descriptor_identity != expected or locator_identity != expected:
            raise CaptureUnknownError("pinned directory identity changed")
        if not stat.S_ISDIR(expected[2]):
            raise CaptureUnknownError("pinned path is not a directory")

    def _verify_git_locator(self) -> None:
        if self._git_locator_identity is None:
            raise CaptureUnknownError("Git locator identity is unavailable")
        try:
            locator = os.stat(b".git", dir_fd=self._root_fd, follow_symlinks=False)
        except OSError as error:
            raise CaptureUnknownError("Git locator became unavailable") from error
        if self._git_locator_kind == "directory":
            expected_locator = self._git_locator_identity
            if _locator_identity(locator) != (
                expected_locator[0],
                expected_locator[1],
                expected_locator[2],
            ):
                raise CaptureUnknownError("Git locator identity changed")
        elif self._git_locator_kind == "file":
            if _stat_identity(locator) != self._git_locator_identity:
                raise CaptureUnknownError("Git locator identity changed")
            current = _read_descriptor(
                self._git_locator_fd, max_bytes=_MAX_METADATA_BYTES
            )
            if current.identity != self._git_locator_identity:
                raise CaptureUnknownError("Git locator file identity changed")
        else:
            raise CaptureUnknownError("Git locator type is unavailable")

    def _verify_executable(self) -> None:
        try:
            descriptor = os.fstat(self._git_executable_fd)
            locator = os.stat(self._git_executable, follow_symlinks=False)
        except OSError as error:
            raise CaptureUnknownError(
                "trusted Git executable became unavailable"
            ) from error
        if (
            _stat_identity(descriptor) != self._git_executable_identity
            or _stat_identity(locator) != self._git_executable_identity
        ):
            raise CaptureUnknownError("trusted Git executable identity changed")

    def _verify_pinned_directories(self) -> None:
        self._verify_directory_locator(self.root, self._root_fd, self._root_identity)
        self._verify_git_locator()
        self._verify_directory_locator(
            self.git_directory, self._git_fd, self._git_identity
        )
        self._verify_directory_locator(
            self.git_common_directory,
            self._common_git_fd,
            self._common_git_identity,
        )
        if self._commondir_fd >= 0:
            current = _read_descriptor(
                self._commondir_fd, max_bytes=_MAX_METADATA_BYTES
            )
            if current.identity != self._commondir_identity:
                raise CaptureUnknownError("common Git locator identity changed")
        self._verify_executable()

    @classmethod
    def _open_relative_parent(
        cls, root_fd: int, raw_path: bytes, *, required: bool
    ) -> tuple[int | None, bytes]:
        components = raw_path.split(b"/")
        if not components or any(item in {b"", b".", b".."} for item in components):
            raise CaptureUnknownError("relative metadata path is invalid")
        current = os.dup(root_fd)
        try:
            for component in components[:-1]:
                try:
                    next_descriptor = os.open(
                        component, _directory_flags(), dir_fd=current
                    )
                except FileNotFoundError:
                    if not required:
                        os.close(current)
                        return None, components[-1]
                    raise
                os.close(current)
                current = next_descriptor
            return current, components[-1]
        except OSError as error:
            with contextlib.suppress(OSError):
                os.close(current)
            raise CaptureUnknownError("metadata path could not be pinned") from error

    @classmethod
    def _observe_file(
        cls,
        root_fd: int,
        raw_path: bytes,
        *,
        required: bool,
        max_bytes: int,
    ) -> _ObservedFile:
        parent_fd, final = cls._open_relative_parent(
            root_fd, raw_path, required=required
        )
        if parent_fd is None:
            return _ObservedFile(False, None, None, None)
        try:
            try:
                descriptor = os.open(final, _file_flags(), dir_fd=parent_fd)
            except FileNotFoundError as error:
                if required:
                    raise CaptureUnknownError(
                        "required metadata source is absent"
                    ) from error
                return _ObservedFile(False, None, None, None)
            except OSError as error:
                raise CaptureUnknownError(
                    "metadata source could not be pinned"
                ) from error
            try:
                observed = _read_descriptor(descriptor, max_bytes=max_bytes)
                locator = os.stat(final, dir_fd=parent_fd, follow_symlinks=False)
            finally:
                os.close(descriptor)
            if observed.identity != _stat_identity(locator):
                raise CaptureUnknownError("metadata source locator changed")
            return observed
        finally:
            os.close(parent_fd)

    def _locator_manifest(self) -> bytes:
        self._verify_pinned_directories()
        values: list[JsonValue] = [
            {"name": "root", "identity": list(_stat_identity(os.fstat(self._root_fd)))},
            {"name": "git", "identity": list(_stat_identity(os.fstat(self._git_fd)))},
            {
                "name": "common-git",
                "identity": list(_stat_identity(os.fstat(self._common_git_fd))),
            },
            {
                "name": "git-executable",
                "identity": list(_stat_identity(os.fstat(self._git_executable_fd))),
            },
        ]
        if self._git_locator_fd >= 0:
            values.append(
                {
                    "name": "gitfile",
                    "value": _file_payload(
                        _read_descriptor(
                            self._git_locator_fd, max_bytes=_MAX_METADATA_BYTES
                        )
                    ),
                }
            )
        if self._commondir_fd >= 0:
            values.append(
                {
                    "name": "commondir",
                    "value": _file_payload(
                        _read_descriptor(
                            self._commondir_fd, max_bytes=_MAX_METADATA_BYTES
                        )
                    ),
                }
            )
        return canonical_bytes(values)

    def _config_sources(self) -> tuple[_ObservedFile, ...]:
        values = [
            self._observe_file(
                self._common_git_fd,
                b"config",
                required=True,
                max_bytes=_MAX_METADATA_BYTES,
            )
        ]
        if self.git_directory != self.git_common_directory:
            values.append(
                self._observe_file(
                    self._git_fd,
                    b"config",
                    required=False,
                    max_bytes=_MAX_METADATA_BYTES,
                )
            )
        values.append(
            self._observe_file(
                self._git_fd,
                b"config.worktree",
                required=False,
                max_bytes=_MAX_METADATA_BYTES,
            )
        )
        return tuple(values)

    def _attribute_sources(self) -> tuple[_ObservedFile, ...]:
        values = [
            self._observe_file(
                self._common_git_fd,
                b"info/attributes",
                required=False,
                max_bytes=_MAX_METADATA_BYTES,
            )
        ]
        if self.git_directory != self.git_common_directory:
            values.append(
                self._observe_file(
                    self._git_fd,
                    b"info/attributes",
                    required=False,
                    max_bytes=_MAX_METADATA_BYTES,
                )
            )
        return tuple(values)

    def _ignore_sources(self) -> tuple[_ObservedFile, ...]:
        values = [
            self._observe_file(
                self._common_git_fd,
                b"info/exclude",
                required=False,
                max_bytes=_MAX_METADATA_BYTES,
            )
        ]
        if self.git_directory != self.git_common_directory:
            values.append(
                self._observe_file(
                    self._git_fd,
                    b"info/exclude",
                    required=False,
                    max_bytes=_MAX_METADATA_BYTES,
                )
            )
        return tuple(values)

    def _head_sources(self) -> tuple[_ObservedFile, ...]:
        head = self._observe_file(
            self._git_fd,
            b"HEAD",
            required=True,
            max_bytes=_MAX_METADATA_BYTES,
        )
        content = (head.content or b"").rstrip(b"\n")
        values = [head]
        if content.startswith(b"ref: "):
            ref_path = content[len(b"ref: ") :]
            _validate_repo_path(ref_path)
            if not ref_path.startswith(b"refs/"):
                raise CaptureUnknownError("HEAD symbolic reference is unsupported")
            loose = self._observe_file(
                self._common_git_fd,
                ref_path,
                required=False,
                max_bytes=_MAX_METADATA_BYTES,
            )
            packed = self._observe_file(
                self._common_git_fd,
                b"packed-refs",
                required=False,
                max_bytes=_MAX_METADATA_BYTES,
            )
            if not loose.exists and not packed.exists:
                raise CaptureUnknownError("HEAD reference source is unavailable")
            values.extend((loose, packed))
        elif b"\n" in content or b"\r" in content or _OID_RE.fullmatch(content) is None:
            raise CaptureUnknownError("HEAD metadata is malformed")
        return tuple(values)

    def _alternates_source(self) -> _ObservedFile:
        return self._observe_file(
            self._common_git_fd,
            b"objects/info/alternates",
            required=False,
            max_bytes=_MAX_METADATA_BYTES,
        )

    @staticmethod
    def _parse_config(data: bytes) -> tuple[tuple[str, str], ...]:
        if data and not data.endswith(b"\x00"):
            raise CaptureUnknownError("Git config output was malformed")
        entries: list[tuple[str, str]] = []
        for row in data.split(b"\x00"):
            if not row:
                continue
            try:
                raw_key, raw_value = row.split(b"\n", 1)
                key = raw_key.decode("ascii", errors="strict").lower()
                value = raw_value.decode("utf-8", errors="strict")
            except (UnicodeError, ValueError) as error:
                raise CaptureUnknownError("Git config output was malformed") from error
            if not key or any(ord(character) < 0x20 for character in key):
                raise CaptureUnknownError("Git config key was malformed")
            entries.append((key, value))
        return tuple(entries)

    @staticmethod
    def _config_values(
        entries: tuple[tuple[str, str], ...], key: str
    ) -> tuple[str, ...]:
        return tuple(value for candidate, value in entries if candidate == key)

    @staticmethod
    def _is_false(value: str) -> bool:
        return value.strip().lower() in {"false", "no", "off", "0", ""}

    @staticmethod
    def _is_true(value: str) -> bool:
        return value.strip().lower() in {"true", "yes", "on", "1"}

    @classmethod
    def _assert_config_eligible(cls, entries: tuple[tuple[str, str], ...]) -> None:
        for key, _value in entries:
            if (
                key.startswith("include.")
                or key.startswith("includeif.")
                or _FILTER_KEY_RE.match(key) is not None
                or key == "core.attributesfile"
                or key == "core.worktree"
            ):
                raise CaptureUnknownError("Git conversion source is unsupported")
        autocrlf = cls._config_values(entries, "core.autocrlf")
        if any(not cls._is_false(value) for value in autocrlf):
            raise CaptureUnknownError("Git line-ending conversion is unsupported")
        eol = cls._config_values(entries, "core.eol")
        if any(value.strip().lower() != "native" for value in eol):
            raise CaptureUnknownError("Git line-ending configuration is unsupported")
        filemode = cls._config_values(entries, "core.filemode")
        if len(filemode) != 1 or not cls._is_true(filemode[0]):
            raise CaptureUnknownError("executable-mode semantics are unproved")
        for key in (
            "core.sparsecheckout",
            "core.sparsecheckoutcone",
            "core.splitindex",
            "extensions.sparseindex",
            "extensions.worktreeconfig",
            "index.sparse",
        ):
            if any(cls._is_true(value) for value in cls._config_values(entries, key)):
                raise CaptureUnknownError("sparse or split index is unsupported")
        ref_storage = cls._config_values(entries, "extensions.refstorage")
        if any(value.strip().lower() != "files" for value in ref_storage):
            raise CaptureUnknownError("Git reference storage is unsupported")

    def _object_format(self) -> str:
        storage = self._run(("rev-parse", "--show-object-format=storage")).strip()
        input_formats = (
            self._run(("rev-parse", "--show-object-format=input")).strip().split()
        )
        if storage not in {b"sha1", b"sha256"}:
            raise CaptureUnknownError("Git object format is unsupported")
        if len(input_formats) != 1 or input_formats[0] != storage:
            raise CaptureUnknownError("dual Git object formats are unsupported")
        return storage.decode("ascii")

    def _single_oid(self, args: tuple[str, ...], object_format: str) -> str:
        value = self._run(args).strip()
        if (
            len(value) != _expected_oid_length(object_format)
            or _OID_RE.fullmatch(value) is None
        ):
            raise CaptureUnknownError("Git returned an invalid object identity")
        return value.decode("ascii")

    @staticmethod
    def _parse_tree(
        data: bytes, object_format: str | None = None
    ) -> tuple[_TreeEntry, ...]:
        entries: list[_TreeEntry] = []
        previous: bytes | None = None
        total_path_bytes = 0
        for row in data.split(b"\x00"):
            if not row:
                continue
            try:
                header, raw_path = row.split(b"\t", 1)
                mode, object_type, oid = header.split(b" ", 2)
                _validate_repo_path(raw_path)
                expected_length = (
                    len(oid)
                    if object_format is None
                    else _expected_oid_length(object_format)
                )
                if len(oid) != expected_length or _OID_RE.fullmatch(oid) is None:
                    raise ValueError("invalid object identity")
                decoded_mode = mode.decode("ascii")
                decoded_type = object_type.decode("ascii")
                if decoded_mode not in {"100644", "100755", "120000"}:
                    raise ValueError("unsupported tree mode")
                if decoded_type != "blob":
                    raise ValueError("unsupported tree object type")
                if previous is not None and raw_path <= previous:
                    raise ValueError("tree paths are not strictly ordered")
                previous = raw_path
                total_path_bytes += len(raw_path)
                if total_path_bytes > _MAX_TOTAL_PATH_BYTES:
                    raise ValueError("tree paths exceeded limit")
                entries.append(
                    _TreeEntry(
                        mode=decoded_mode,
                        object_type=decoded_type,
                        oid=oid.decode("ascii"),
                        path=PathIdentityV1.from_bytes("git-path-bytes", raw_path),
                    )
                )
            except (CanonicalJSONError, UnicodeError, ValueError) as error:
                raise CaptureUnknownError("Git tree output was malformed") from error
            if len(entries) > _MAX_TRAVERSAL_ENTRIES:
                raise CaptureUnknownError("Git tree entry limit was exceeded")
        return tuple(entries)

    @staticmethod
    def _parse_index(
        data: bytes, object_format: str | None = None
    ) -> tuple[_IndexEntry, ...]:
        entries: list[_IndexEntry] = []
        previous: bytes | None = None
        total_path_bytes = 0
        for row in data.split(b"\x00"):
            if not row:
                continue
            try:
                header, raw_path = row.split(b"\t", 1)
                mode, oid, stage_bytes = header.split(b" ", 2)
                stage = int(stage_bytes)
                expected_length = (
                    len(oid)
                    if object_format is None
                    else _expected_oid_length(object_format)
                )
                if stage != 0 or len(oid) != expected_length:
                    raise ValueError("unsupported index entry")
                if _OID_RE.fullmatch(oid) is None:
                    raise ValueError("invalid index object identity")
                decoded_mode = mode.decode("ascii")
                if decoded_mode not in {"100644", "100755", "120000"}:
                    raise ValueError("unsupported index mode")
                _validate_repo_path(raw_path)
                if previous is not None and raw_path <= previous:
                    raise ValueError("index paths are not strictly ordered")
                previous = raw_path
                total_path_bytes += len(raw_path)
                if total_path_bytes > _MAX_TOTAL_PATH_BYTES:
                    raise ValueError("index paths exceeded limit")
                entries.append(
                    _IndexEntry(
                        mode=decoded_mode,
                        oid=oid.decode("ascii"),
                        stage=stage,
                        path=PathIdentityV1.from_bytes("git-path-bytes", raw_path),
                    )
                )
            except (CanonicalJSONError, UnicodeError, ValueError) as error:
                raise CaptureUnknownError("Git index output was malformed") from error
            if len(entries) > _MAX_TRAVERSAL_ENTRIES:
                raise CaptureUnknownError("Git index entry limit was exceeded")
        return tuple(entries)

    @staticmethod
    def _parse_raw_index(data: bytes, object_format: str) -> tuple[_IndexEntry, ...]:
        hash_bytes = _expected_oid_length(object_format) // 2
        if len(data) < 12 + hash_bytes:
            raise CaptureUnknownError("raw Git index was truncated")
        body = data[:-hash_bytes]
        checksum = data[-hash_bytes:]
        expected_checksum = bytes.fromhex(_git_digest(body, object_format))
        if checksum != expected_checksum:
            raise CaptureUnknownError("raw Git index checksum was invalid")
        if body[:4] != b"DIRC":
            raise CaptureUnknownError("raw Git index signature was invalid")
        version, entry_count = struct.unpack_from("!II", body, 4)
        if version not in {2, 3}:
            raise CaptureUnknownError("raw Git index version is unsupported")
        if entry_count > _MAX_TRAVERSAL_ENTRIES:
            raise CaptureUnknownError("raw Git index entry limit was exceeded")
        entries: list[_IndexEntry] = []
        offset = 12
        previous: bytes | None = None
        total_path_bytes = 0
        for _entry_number in range(entry_count):
            entry_start = offset
            minimum = 40 + hash_bytes + 2
            if offset + minimum > len(body):
                raise CaptureUnknownError("raw Git index entry was truncated")
            fields = struct.unpack_from("!10I", body, offset)
            mode_value = fields[6]
            offset += 40
            oid_bytes = body[offset : offset + hash_bytes]
            offset += hash_bytes
            flags = struct.unpack_from("!H", body, offset)[0]
            offset += 2
            if flags & 0x8000:
                raise CaptureUnknownError("assume-valid index entries are unsupported")
            extended = bool(flags & 0x4000)
            stage = (flags >> 12) & 0x3
            if stage != 0:
                raise CaptureUnknownError("unmerged index entries are unsupported")
            if extended:
                if version < 3 or offset + 2 > len(body):
                    raise CaptureUnknownError("extended index entry was malformed")
                extended_flags = struct.unpack_from("!H", body, offset)[0]
                offset += 2
                if extended_flags != 0:
                    raise CaptureUnknownError(
                        "skip-worktree or intent-to-add is unsupported"
                    )
                raise CaptureUnknownError("extended index entries are unsupported")
            nul = body.find(b"\x00", offset)
            if nul < 0:
                raise CaptureUnknownError("raw Git index path was unterminated")
            raw_path = body[offset:nul]
            encoded_length = flags & 0x0FFF
            if (encoded_length < 0x0FFF and encoded_length != len(raw_path)) or (
                encoded_length == 0x0FFF and len(raw_path) < 0x0FFF
            ):
                raise CaptureUnknownError("raw Git index path length was invalid")
            _validate_repo_path(raw_path)
            consumed = nul + 1 - entry_start
            padding = (-consumed) % 8
            end = nul + 1 + padding
            if end > len(body) or any(body[nul + 1 : end]):
                raise CaptureUnknownError("raw Git index padding was invalid")
            offset = end
            if mode_value not in {0o100644, 0o100755, 0o120000}:
                raise CaptureUnknownError("raw Git index mode is unsupported")
            if previous is not None and raw_path <= previous:
                raise CaptureUnknownError("raw Git index order was invalid")
            previous = raw_path
            total_path_bytes += len(raw_path)
            if total_path_bytes > _MAX_TOTAL_PATH_BYTES:
                raise CaptureUnknownError("raw Git index paths exceeded limit")
            entries.append(
                _IndexEntry(
                    mode=f"{mode_value:06o}",
                    oid=oid_bytes.hex(),
                    stage=stage,
                    path=PathIdentityV1.from_bytes("git-path-bytes", raw_path),
                )
            )
        seen_extensions: set[bytes] = set()
        while offset < len(body):
            if offset + 8 > len(body):
                raise CaptureUnknownError("raw Git index extension was truncated")
            signature = body[offset : offset + 4]
            extension_size = struct.unpack_from("!I", body, offset + 4)[0]
            offset += 8
            end = offset + extension_size
            if end > len(body) or signature in seen_extensions:
                raise CaptureUnknownError("raw Git index extension was malformed")
            seen_extensions.add(signature)
            if signature not in _ALLOWED_INDEX_EXTENSIONS:
                raise CaptureUnknownError("raw Git index extension is unsupported")
            offset = end
        return tuple(entries)

    @staticmethod
    def _entry_key(entry: _IndexEntry | _TreeEntry) -> tuple[str, str, bytes]:
        return entry.mode, entry.oid, entry.path.raw_bytes()

    @classmethod
    def _prove_head_equals_index(
        cls,
        tree_entries: tuple[_TreeEntry, ...],
        index_entries: tuple[_IndexEntry, ...],
    ) -> None:
        tree = tuple(cls._entry_key(entry) for entry in tree_entries)
        index = tuple(cls._entry_key(entry) for entry in index_entries)
        if tree != index:
            raise CaptureUnknownError("HEAD tree does not equal the raw index")

    @staticmethod
    def _directory_entries(
        descriptor: int,
    ) -> tuple[tuple[bytes, _StatIdentity], ...]:
        try:
            names = os.listdir(descriptor)
            raw_names = sorted(os.fsencode(name) for name in names)
            if len(set(raw_names)) != len(raw_names):
                raise CaptureUnknownError("directory entries were ambiguous")
            entries = tuple(
                (
                    name,
                    _stat_identity(
                        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    ),
                )
                for name in raw_names
            )
        except OSError as error:
            raise CaptureUnknownError(
                "directory could not be enumerated safely"
            ) from error
        return entries

    @staticmethod
    def _read_leaf(
        parent_fd: int,
        name: bytes,
        before_identity: _StatIdentity,
        expected_mode: str,
        object_format: str,
        remaining_total: int,
    ) -> tuple[bytes, _StatIdentity]:
        mode = before_identity[2]
        if expected_mode == "120000":
            if not stat.S_ISLNK(mode):
                raise CaptureUnknownError("tracked symlink type changed")
            try:
                content = os.readlink(name, dir_fd=parent_fd)
                if isinstance(content, str):
                    content = os.fsencode(content)
                after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as error:
                raise CaptureUnknownError(
                    "tracked symlink could not be read"
                ) from error
            if _stat_identity(after) != before_identity:
                raise CaptureUnknownError("tracked symlink changed during read")
        else:
            if not stat.S_ISREG(mode):
                raise CaptureUnknownError("tracked file type changed")
            try:
                descriptor = os.open(name, _file_flags(), dir_fd=parent_fd)
            except OSError as error:
                raise CaptureUnknownError("tracked file could not be pinned") from error
            try:
                opened = os.fstat(descriptor)
                if _stat_identity(opened) != before_identity:
                    raise CaptureUnknownError("tracked file changed before pinning")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_FILE_BYTES or total > remaining_total:
                        raise CaptureUnknownError("tracked file bytes exceeded limit")
                    chunks.append(chunk)
                after = os.fstat(descriptor)
            except OSError as error:
                raise CaptureUnknownError("tracked file could not be read") from error
            finally:
                os.close(descriptor)
            if _stat_identity(after) != before_identity:
                raise CaptureUnknownError("tracked file changed during read")
            executable = bool(after.st_mode & 0o111)
            if executable != (expected_mode == "100755"):
                raise CaptureUnknownError("tracked executable mode differs from index")
            content = b"".join(chunks)
        if len(content) > _MAX_FILE_BYTES or len(content) > remaining_total:
            raise CaptureUnknownError("tracked object bytes exceeded limit")
        if _blob_oid(content, object_format) == "":
            raise CaptureUnknownError("tracked object identity was unavailable")
        return content, before_identity

    def _worktree_proof(
        self,
        entries: tuple[_IndexEntry, ...],
        object_format: str,
    ) -> _WorktreeProof:
        by_path = {entry.path.raw_bytes(): entry for entry in entries}
        allowed_directories: set[bytes] = set()
        for raw_path in by_path:
            components = raw_path.split(b"/")
            for index in range(1, len(components)):
                allowed_directories.add(b"/".join(components[:index]))
        seen: set[bytes] = set()
        file_manifest: list[JsonValue] = []
        directory_manifest: list[JsonValue] = []
        contents: dict[bytes, bytes] = {}
        counters = {"entries": 0, "path_bytes": 0, "file_bytes": 0}

        def walk(descriptor: int, prefix: bytes, depth: int) -> None:
            self._check_deadline()
            if depth > _MAX_TRAVERSAL_DEPTH:
                raise CaptureUnknownError("worktree traversal depth exceeded limit")
            before_directory = _stat_identity(os.fstat(descriptor))
            before_entries = self._directory_entries(descriptor)
            entry_payload: list[JsonValue] = []
            for name, identity in before_entries:
                raw_path = name if not prefix else prefix + b"/" + name
                counters["entries"] += 1
                counters["path_bytes"] += len(raw_path)
                if counters["entries"] > _MAX_TRAVERSAL_ENTRIES:
                    raise CaptureUnknownError("worktree entry limit was exceeded")
                if counters["path_bytes"] > _MAX_TOTAL_PATH_BYTES:
                    raise CaptureUnknownError("worktree path-byte limit was exceeded")
                entry_payload.append(
                    {
                        "identity": list(identity),
                        "path": path_identity_payload(
                            PathIdentityV1.from_bytes("git-path-bytes", raw_path)
                        ),
                    }
                )
                if prefix == b"" and name == b".git":
                    continue
                mode = identity[2]
                if stat.S_ISDIR(mode):
                    if raw_path not in allowed_directories:
                        raise CaptureUnknownError("non-index directory exists")
                    try:
                        child_fd = os.open(name, _directory_flags(), dir_fd=descriptor)
                    except OSError as error:
                        raise CaptureUnknownError(
                            "tracked parent directory could not be pinned"
                        ) from error
                    try:
                        if _stat_identity(os.fstat(child_fd)) != identity:
                            raise CaptureUnknownError(
                                "tracked parent directory changed before pinning"
                            )
                        walk(child_fd, raw_path, depth + 1)
                    finally:
                        os.close(child_fd)
                    continue
                expected = by_path.get(raw_path)
                if expected is None:
                    raise CaptureUnknownError("non-index path exists")
                remaining = _MAX_TOTAL_FILE_BYTES - counters["file_bytes"]
                content, after_identity = self._read_leaf(
                    descriptor,
                    name,
                    identity,
                    expected.mode,
                    object_format,
                    remaining,
                )
                local_oid = _blob_oid(content, object_format)
                if local_oid != expected.oid:
                    raise CaptureUnknownError("worktree bytes differ from index")
                counters["file_bytes"] += len(content)
                if counters["file_bytes"] > _MAX_TOTAL_FILE_BYTES:
                    raise CaptureUnknownError("worktree file-byte limit was exceeded")
                seen.add(raw_path)
                contents[raw_path] = content
                file_manifest.append(
                    {
                        "byte_digest": digest_bytes(content),
                        "git_mode": expected.mode,
                        "identity": list(after_identity),
                        "local_blob_oid": local_oid,
                        "path": path_identity_payload(expected.path),
                        "size": len(content),
                    }
                )
            after_entries = self._directory_entries(descriptor)
            after_directory = _stat_identity(os.fstat(descriptor))
            if before_entries != after_entries or before_directory != after_directory:
                raise CaptureUnknownError("worktree directory changed during traversal")
            directory_manifest.append(
                {
                    "directory": (
                        None
                        if not prefix
                        else path_identity_payload(
                            PathIdentityV1.from_bytes("git-path-bytes", prefix)
                        )
                    ),
                    "entries": entry_payload,
                    "identity": list(after_directory),
                }
            )

        walk(self._root_fd, b"", 0)
        if seen != set(by_path):
            raise CaptureUnknownError("tracked worktree paths are missing")
        return _WorktreeProof(
            manifest=canonical_bytes(file_manifest),
            traversal_manifest=canonical_bytes(directory_manifest),
            contents=contents,
        )

    def _capture_instructions(
        self,
        requested: tuple[PathIdentityV1, ...],
        tree_entries: tuple[_TreeEntry, ...],
        object_format: str,
    ) -> tuple[InstructionFileV1, ...]:
        by_path = {item.path.raw_bytes(): item for item in tree_entries}
        captured: list[InstructionFileV1] = []
        for path in requested:
            entry = by_path.get(path.raw_bytes())
            if entry is None or entry.object_type != "blob":
                raise CaptureRequestError(
                    "instruction path is missing from target HEAD"
                )
            blob = self._run(("cat-file", "blob", entry.oid))
            if _blob_oid(blob, object_format) != entry.oid:
                raise CaptureUnknownError("instruction object identity was invalid")
            captured.append(
                InstructionFileV1(
                    path=path,
                    blob_oid=entry.oid,
                    byte_digest=digest_bytes(blob),
                )
            )
        return tuple(captured)

    def _object_manifest(
        self,
        entries: tuple[_TreeEntry, ...],
        worktree_contents: dict[bytes, bytes],
        object_format: str,
    ) -> bytes:
        manifest: list[JsonValue] = []
        for entry in entries:
            symlink_target: JsonValue = None
            if entry.mode == "120000":
                blob = self._run(("cat-file", "blob", entry.oid))
                if (
                    _blob_oid(blob, object_format) != entry.oid
                    or blob != worktree_contents[entry.path.raw_bytes()]
                ):
                    raise CaptureUnknownError("symlink object identity was invalid")
                symlink_target = {
                    "encoding": "base64url-no-padding",
                    "raw_b64": base64.urlsafe_b64encode(blob)
                    .rstrip(b"=")
                    .decode("ascii"),
                }
            manifest.append(
                {
                    "mode": entry.mode,
                    "object_type": entry.object_type,
                    "oid": entry.oid,
                    "path": path_identity_payload(entry.path),
                    "symlink_target": symlink_target,
                }
            )
        return canonical_bytes(manifest)

    @staticmethod
    def _ignore_manifest(
        entries: tuple[_TreeEntry, ...],
        sources: tuple[_ObservedFile, ...],
    ) -> bytes:
        manifest: list[JsonValue] = []
        for entry in entries:
            basename = entry.path.raw_bytes().split(b"/")[-1]
            if basename == b".gitignore":
                manifest.append(
                    {
                        "blob_oid": entry.oid,
                        "path": path_identity_payload(entry.path),
                        "source": "repository",
                    }
                )
        for index, source in enumerate(sources):
            manifest.append(
                {
                    "evidence": _file_payload(source),
                    "source": f"local-exclude-{index}",
                }
            )
        return canonical_bytes(manifest)

    @staticmethod
    def _remote_identity_digest(config: tuple[tuple[str, str], ...]) -> Digest | None:
        identities: list[str] = []
        for key, value in config:
            if key.startswith("remote.") and key.endswith(".url"):
                try:
                    identities.append(_sanitize_remote(value))
                except CaptureRequestError as error:
                    raise CaptureUnknownError(
                        "remote identity metadata is unsupported"
                    ) from error
        if not identities:
            return None
        canonical_identities: list[JsonValue] = [item for item in sorted(identities)]
        return digest_bytes(canonical_bytes(canonical_identities))

    @staticmethod
    def _validate_instruction_paths(
        instruction_paths: Sequence[bytes],
    ) -> tuple[PathIdentityV1, ...]:
        values: list[PathIdentityV1] = []
        for raw_path in instruction_paths:
            if not isinstance(raw_path, bytes):
                raise CaptureRequestError("instruction path is invalid")
            try:
                _validate_repo_path(raw_path)
                values.append(PathIdentityV1.from_bytes("git-path-bytes", raw_path))
            except (CanonicalJSONError, CaptureUnknownError) as error:
                raise CaptureRequestError("instruction path is invalid") from error
        return tuple(values)

    @staticmethod
    def _sources_digest(
        locator: bytes,
        config: tuple[_ObservedFile, ...],
        attributes: tuple[_ObservedFile, ...],
        ignores: tuple[_ObservedFile, ...],
        head: tuple[_ObservedFile, ...],
        index: _ObservedFile,
        alternates: _ObservedFile,
    ) -> Digest:
        payload: list[JsonValue] = [
            {"locator_digest": digest_bytes(locator)},
            {"config": [_file_payload(item) for item in config]},
            {"attributes": [_file_payload(item) for item in attributes]},
            {"ignores": [_file_payload(item) for item in ignores]},
            {"head": [_file_payload(item) for item in head]},
            {"index": _file_payload(index)},
            {"alternates": _file_payload(alternates)},
        ]
        return digest_bytes(canonical_bytes(payload))

    def _observe(self, requested: tuple[PathIdentityV1, ...]) -> _Observation:
        locator_before = self._locator_manifest()
        config_before = self._config_sources()
        attributes_before = self._attribute_sources()
        ignores_before = self._ignore_sources()
        head_before = self._head_sources()
        index_before = self._observe_file(
            self._git_fd,
            b"index",
            required=True,
            max_bytes=_MAX_GIT_OUTPUT,
        )
        alternates_before = self._alternates_source()
        if alternates_before.exists:
            raise CaptureUnknownError("alternate Git object stores are unsupported")
        if any(source.exists for source in attributes_before):
            raise CaptureUnknownError("Git info attributes are unsupported")

        config_output = self._run(
            ("config", "--no-includes", "--local", "--null", "--list")
        )
        config = self._parse_config(config_output)
        self._assert_config_eligible(config)
        config_digest = digest_bytes(
            canonical_bytes([[key, value] for key, value in config])
        )

        object_format = self._object_format()
        head_oid = self._single_oid(
            ("rev-parse", "--verify", "HEAD^{commit}"), object_format
        )
        tree_oid = self._single_oid(
            ("rev-parse", "--verify", f"{head_oid}^{{tree}}"), object_format
        )
        raw_index = index_before.content or b""
        raw_entries = self._parse_raw_index(raw_index, object_format)
        listed_entries = self._parse_index(
            self._run(("ls-files", "--stage", "-z")), object_format
        )
        if raw_entries != listed_entries:
            raise CaptureUnknownError("raw and Git-parsed index differ")
        tree_entries = self._parse_tree(
            self._run(("ls-tree", "-rz", "--full-tree", tree_oid)),
            object_format,
        )
        self._prove_head_equals_index(tree_entries, raw_entries)
        if any(
            entry.path.raw_bytes().split(b"/")[-1] == b".gitattributes"
            for entry in raw_entries
        ):
            raise CaptureUnknownError("worktree attributes are unsupported")
        symlinks = any(entry.mode == "120000" for entry in raw_entries)
        if symlinks and any(
            self._is_false(value)
            for value in self._config_values(config, "core.symlinks")
        ):
            raise CaptureUnknownError("symlink semantics are unproved")

        worktree = self._worktree_proof(raw_entries, object_format)
        instructions = self._capture_instructions(
            requested, tree_entries, object_format
        )
        object_manifest = self._object_manifest(
            tree_entries, worktree.contents, object_format
        )
        ignore_manifest = self._ignore_manifest(tree_entries, ignores_before)
        remote_digest = self._remote_identity_digest(config)

        locator_after = self._locator_manifest()
        config_after = self._config_sources()
        attributes_after = self._attribute_sources()
        ignores_after = self._ignore_sources()
        head_after = self._head_sources()
        index_after = self._observe_file(
            self._git_fd,
            b"index",
            required=True,
            max_bytes=_MAX_GIT_OUTPUT,
        )
        alternates_after = self._alternates_source()
        if (
            locator_after != locator_before
            or config_after != config_before
            or attributes_after != attributes_before
            or ignores_after != ignores_before
            or head_after != head_before
            or index_after != index_before
            or alternates_after != alternates_before
        ):
            raise CaptureUnknownError("Git dependencies changed during capture")
        dependency_digest = self._sources_digest(
            locator_after,
            config_after,
            attributes_after,
            ignores_after,
            head_after,
            index_after,
            alternates_after,
        )
        return _Observation(
            head_oid=head_oid,
            tree_oid=tree_oid,
            object_format=object_format,
            index_digest=digest_bytes(raw_index),
            index_entries=raw_entries,
            tree_entries=tree_entries,
            worktree_manifest=worktree.manifest,
            traversal_manifest=worktree.traversal_manifest,
            object_manifest=object_manifest,
            ignore_manifest=ignore_manifest,
            remote_digest=remote_digest,
            config_digest=config_digest,
            dependency_digest=dependency_digest,
            instructions=instructions,
        )

    def capture(self, instruction_paths: Sequence[bytes]) -> CaptureSnapshot:
        requested = self._validate_instruction_paths(instruction_paths)
        if self._active_deadline is not None:
            raise CaptureUnknownError("concurrent capture is unsupported")
        if _MAX_CAPTURE_SECONDS <= 0:
            raise CaptureUnknownError("capture elapsed-time limit is invalid")
        self._active_deadline = time.monotonic() + _MAX_CAPTURE_SECONDS
        try:
            first = self._observe(requested)
            second = self._observe(requested)
            if first != second:
                raise CaptureUnknownError("target changed during bounded capture")
            self._verify_pinned_directories()
            self._check_deadline()
        finally:
            self._active_deadline = None

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
                "config_evidence_digest": first.config_digest,
                "dependency_evidence_digest": first.dependency_digest,
                "direct_proof_status_digest": DIRECT_CLEAN_STATUS_DIGEST,
                "index": [
                    path_identity_payload(item.path) for item in first.index_entries
                ],
                "traversal_digest": digest_bytes(first.traversal_manifest),
                "tree": [
                    path_identity_payload(item.path) for item in first.tree_entries
                ],
            }
        )
        target = TargetIdentityV1(
            adapter_id=_ADAPTER_ID,
            adapter_version=_ADAPTER_VERSION,
            sanitized_remote_identity_digest=first.remote_digest,
            head_oid=first.head_oid,
            tree_oid=first.tree_oid,
            index_manifest_digest=first.index_digest,
            worktree_manifest_digest=digest_bytes(first.worktree_manifest),
            inventory_digest=digest_bytes(inventory),
            status_digest=DIRECT_CLEAN_STATUS_DIGEST,
            git_object_manifest_digest=digest_bytes(first.object_manifest),
            ignore_provenance_digest=digest_bytes(first.ignore_manifest),
            platform_id=sys.platform,
            filesystem_id=f"{os.name}:{platform.system().lower()}",
            physical_root_fingerprint=physical_root_fingerprint,
            capabilities=self._capabilities(),
        )
        return CaptureSnapshot(target=target, instructions=first.instructions)

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
            claim("atomic_snapshot", "unknown"),
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
