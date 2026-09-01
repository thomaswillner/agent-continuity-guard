"""Fixed-vocabulary, bounded Git process execution."""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ._git_locator import open_absolute_file, stat_identity
from .base import CaptureUnknownError

_DESCRIPTOR_GIT_BOOTSTRAP = (
    "import os,sys;"
    "descriptor=int(sys.argv[1]);"
    "executable=sys.argv[2];"
    "os.fchdir(descriptor);"
    "os.close(descriptor);"
    "os.execv(executable,[executable,*sys.argv[3:]])"
)


@dataclass(frozen=True, slots=True)
class BoundedResult:
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


def run_bounded(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout: float,
    max_output: int,
    input_data: bytes | None = None,
    pass_fds: Sequence[int] = (),
) -> BoundedResult:
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
    return BoundedResult(returncode, bytes(stdout), bytes(stderr))


def sanitized_environment() -> dict[str, str]:
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


def git_arguments(args: tuple[str, ...]) -> list[str]:
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


def descriptor_git_argv(
    descriptor: int, args: tuple[str, ...], executable: Path
) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-c",
        _DESCRIPTOR_GIT_BOOTSTRAP,
        str(descriptor),
        os.fspath(executable),
        *git_arguments(args),
    ]


def resolve_git_executable() -> tuple[
    Path, int, tuple[int, int, int, int, int, int, int]
]:
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
    descriptor = open_absolute_file(executable)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        os.close(descriptor)
        raise CaptureUnknownError("trusted Git executable is invalid")
    return executable, descriptor, stat_identity(metadata)


def verify_git_executable(
    executable: Path,
    descriptor: int,
    expected: tuple[int, int, int, int, int, int, int],
) -> None:
    try:
        pinned = os.fstat(descriptor)
        locator = os.stat(executable, follow_symlinks=False)
    except OSError as error:
        raise CaptureUnknownError(
            "trusted Git executable could not be verified"
        ) from error
    if (
        stat_identity(pinned) != expected
        or stat_identity(locator) != expected
        or not stat.S_ISREG(pinned.st_mode)
        or not pinned.st_mode & 0o111
    ):
        raise CaptureUnknownError("trusted Git executable identity changed")


def remaining_timeout(deadline: float | None) -> float:
    if deadline is None:
        return 30.0
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CaptureUnknownError("capture elapsed-time limit was exceeded")
    return min(30.0, remaining)
