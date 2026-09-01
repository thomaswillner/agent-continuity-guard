"""Descriptor-pinned target locators and stable leaf observations."""

from __future__ import annotations

import contextlib
import os
import stat
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from agent_continuity.kernel.model import Digest, JsonValue
from agent_continuity.kernel.paths import (
    PathEncoding,
    PathIdentityV1,
    path_identity_payload,
)

from .base import CaptureRequestError, CaptureUnknownError, FileObservation

MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_TRAVERSAL_DEPTH = 128
MAX_TRAVERSAL_ENTRIES = 1_000_000
MAX_TOTAL_PATH_BYTES = 256 * 1024 * 1024

StatIdentity = tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class ObservedFile:
    exists: bool
    identity: StatIdentity | None
    digest: Digest | None
    content: bytes | None


@dataclass(frozen=True, slots=True)
class ObservedTree:
    files: Mapping[PathIdentityV1, FileObservation]
    required_contents: Mapping[PathIdentityV1, bytes]
    manifest: bytes
    traversal_manifest: bytes


def stat_identity(metadata: os.stat_result) -> StatIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def locator_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def directory_flags() -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise CaptureUnknownError("descriptor-rooted capture is unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def file_flags() -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise CaptureUnknownError("descriptor-rooted capture is unsupported")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def open_absolute_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise CaptureUnknownError("directory locator is not canonical absolute path")
    current = -1
    try:
        current = os.open(os.path.sep, directory_flags())
        for component in path.parts[1:]:
            next_descriptor = os.open(component, directory_flags(), dir_fd=current)
            os.close(current)
            current = next_descriptor
        return current
    except OSError as error:
        if current >= 0:
            with contextlib.suppress(OSError):
                os.close(current)
        raise CaptureUnknownError("directory could not be pinned safely") from error


def open_absolute_file(path: Path) -> int:
    parent_fd = open_absolute_directory(path.parent)
    try:
        descriptor = os.open(path.name, file_flags(), dir_fd=parent_fd)
    except OSError as error:
        raise CaptureUnknownError("file locator could not be pinned safely") from error
    finally:
        os.close(parent_fd)
    return descriptor


def read_descriptor(descriptor: int, *, max_bytes: int) -> ObservedFile:
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
        raise CaptureUnknownError("metadata source could not be read") from error
    identity = stat_identity(before)
    if stat_identity(after) != identity:
        raise CaptureUnknownError("metadata source changed during read")
    content = b"".join(chunks)
    return ObservedFile(True, identity, digest_bytes(content), content)


def resolve_locator(base: Path, raw_value: bytes) -> Path:
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


def verify_directory_locator(path: Path, expected: StatIdentity) -> None:
    descriptor = open_absolute_directory(path)
    try:
        if stat_identity(os.fstat(descriptor)) != expected:
            raise CaptureUnknownError("directory locator identity changed")
    finally:
        os.close(descriptor)


def verify_pinned_directory(
    path: Path, descriptor: int, expected: tuple[int, int, int]
) -> None:
    try:
        descriptor_identity = locator_identity(os.fstat(descriptor))
        path_identity = locator_identity(os.stat(path, follow_symlinks=False))
    except OSError as error:
        raise CaptureUnknownError("pinned directory became unavailable") from error
    if descriptor_identity != expected or path_identity != expected:
        raise CaptureUnknownError("pinned directory identity changed")
    if not stat.S_ISDIR(expected[2]):
        raise CaptureUnknownError("pinned path is not a directory")


def _open_relative_parent(
    root_fd: int, raw_path: bytes, *, required: bool
) -> tuple[int | None, bytes]:
    components = raw_path.split(b"/")
    if not components or any(item in {b"", b".", b".."} for item in components):
        raise CaptureUnknownError("relative metadata path is invalid")
    current = os.dup(root_fd)
    try:
        for component in components[:-1]:
            try:
                next_descriptor = os.open(
                    component, directory_flags(), dir_fd=current
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


def observe_relative_file(
    root_fd: int,
    raw_path: bytes,
    *,
    required: bool,
    max_bytes: int,
) -> ObservedFile:
    parent_fd, final = _open_relative_parent(root_fd, raw_path, required=required)
    if parent_fd is None:
        return ObservedFile(False, None, None, None)
    try:
        try:
            descriptor = os.open(final, file_flags(), dir_fd=parent_fd)
        except FileNotFoundError as error:
            if required:
                raise CaptureUnknownError(
                    "required metadata source is absent"
                ) from error
            return ObservedFile(False, None, None, None)
        except OSError as error:
            raise CaptureUnknownError("metadata source could not be pinned") from error
        try:
            observed = read_descriptor(descriptor, max_bytes=max_bytes)
            locator = os.stat(final, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(descriptor)
        if observed.identity != stat_identity(locator):
            raise CaptureUnknownError("metadata source locator changed")
        return observed
    finally:
        os.close(parent_fd)


def _directory_entries(descriptor: int) -> tuple[tuple[bytes, StatIdentity], ...]:
    try:
        raw_names = sorted(os.fsencode(name) for name in os.listdir(descriptor))
        if len(raw_names) != len(set(raw_names)):
            raise CaptureUnknownError("directory entries were ambiguous")
        return tuple(
            (
                name,
                stat_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)),
            )
            for name in raw_names
        )
    except OSError as error:
        raise CaptureUnknownError("directory could not be enumerated safely") from error


def directory_entries(descriptor: int) -> tuple[tuple[bytes, StatIdentity], ...]:
    return _directory_entries(descriptor)


def read_tracked_leaf(
    parent_fd: int,
    name: bytes,
    before_identity: StatIdentity,
    expected_mode: str,
    remaining_total: int,
) -> tuple[bytes, StatIdentity]:
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
            raise CaptureUnknownError("tracked symlink could not be read") from error
        if stat_identity(after) != before_identity:
            raise CaptureUnknownError("tracked symlink changed during read")
    else:
        if not stat.S_ISREG(mode):
            raise CaptureUnknownError("tracked file type changed")
        try:
            descriptor = os.open(name, file_flags(), dir_fd=parent_fd)
        except OSError as error:
            raise CaptureUnknownError("tracked file could not be pinned") from error
        try:
            opened = os.fstat(descriptor)
            if stat_identity(opened) != before_identity:
                raise CaptureUnknownError("tracked file changed before pinning")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE_BYTES or total > remaining_total:
                    raise CaptureUnknownError("tracked file bytes exceeded limit")
                chunks.append(chunk)
            after = os.fstat(descriptor)
        except OSError as error:
            raise CaptureUnknownError("tracked file could not be read") from error
        finally:
            os.close(descriptor)
        if stat_identity(after) != before_identity:
            raise CaptureUnknownError("tracked file changed during read")
        executable = bool(after.st_mode & 0o111)
        if executable != (expected_mode == "100755"):
            raise CaptureUnknownError("tracked executable mode differs from index")
        content = b"".join(chunks)
    if len(content) > MAX_FILE_BYTES or len(content) > remaining_total:
        raise CaptureUnknownError("tracked object bytes exceeded limit")
    return content, before_identity


def _path_identity(encoding: PathEncoding, raw_path: bytes) -> PathIdentityV1:
    try:
        return PathIdentityV1.from_bytes(encoding, raw_path)
    except ValueError as error:
        raise CaptureUnknownError("observed target path was malformed") from error


def _observation_identity(identity: StatIdentity) -> tuple[int, int, int, int, int]:
    return identity[0], identity[1], identity[2], identity[3], identity[6]


def _read_regular_leaf(
    parent_fd: int,
    name: bytes,
    identity: StatIdentity,
    *,
    remaining_total: int,
) -> bytes:
    if identity[3] != 1:
        raise CaptureUnknownError("hardlinked target files are unsupported")
    try:
        descriptor = os.open(name, file_flags(), dir_fd=parent_fd)
    except OSError as error:
        raise CaptureUnknownError("target file could not be pinned") from error
    try:
        if stat_identity(os.fstat(descriptor)) != identity:
            raise CaptureUnknownError("target file changed before pinning")
        chunks: list[bytes] = []
        offset = 0
        while True:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, MAX_FILE_BYTES + 1 - offset),
                offset,
            )
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
            if offset > MAX_FILE_BYTES or offset > remaining_total:
                raise CaptureUnknownError("target file bytes exceeded limit")
        if stat_identity(os.fstat(descriptor)) != identity:
            raise CaptureUnknownError("target file changed during read")
    except OSError as error:
        raise CaptureUnknownError("target file could not be read") from error
    finally:
        os.close(descriptor)
    try:
        locator = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise CaptureUnknownError(
            "target file locator could not be revalidated"
        ) from error
    if stat_identity(locator) != identity:
        raise CaptureUnknownError("target file locator changed during read")
    return b"".join(chunks)


def _read_symlink_leaf(
    parent_fd: int, name: bytes, identity: StatIdentity
) -> bytes:
    if identity[3] != 1:
        raise CaptureUnknownError("hardlinked target symlinks are unsupported")
    try:
        content = os.readlink(name, dir_fd=parent_fd)
        if isinstance(content, str):
            content = os.fsencode(content)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise CaptureUnknownError("target symlink could not be observed") from error
    if stat_identity(after) != identity:
        raise CaptureUnknownError("target symlink changed during read")
    if len(content) > MAX_FILE_BYTES:
        raise CaptureUnknownError("target symlink bytes exceeded limit")
    return content


def observe_tree(
    root_fd: int,
    *,
    encoding: PathEncoding,
    inclusions: Collection[bytes] | None,
    exclusions: Collection[bytes],
    retained_paths: Collection[bytes],
    check_deadline: Callable[[], None] | None = None,
) -> ObservedTree:
    """Observe one descriptor-rooted tree without following target symlinks."""

    if os.name != "posix":
        raise CaptureUnknownError("stable live-worktree capture is unsupported")
    include_set = None if inclusions is None else frozenset(inclusions)
    exclude_set = frozenset(exclusions)
    retained_set = frozenset(retained_paths)
    declared_case_keys: dict[bytes, bytes] = {}
    for raw_path in include_set if include_set is not None else retained_set:
        folded = raw_path.translate(
            bytes.maketrans(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
            )
        )
        prior = declared_case_keys.setdefault(folded, raw_path)
        if prior != raw_path:
            raise CaptureUnknownError(
                "case-colliding target paths are unsupported"
            )
    if include_set is not None and not retained_set.issubset(include_set):
        raise CaptureRequestError("required path is outside the captured census")
    allowed_directories: set[bytes] | None = None
    if include_set is not None:
        allowed_directories = set()
        for raw_path in include_set:
            components = raw_path.split(b"/")
            for index in range(1, len(components)):
                allowed_directories.add(b"/".join(components[:index]))
    files: dict[PathIdentityV1, FileObservation] = {}
    required_contents: dict[PathIdentityV1, bytes] = {}
    file_manifest: list[JsonValue] = []
    directory_manifest: list[JsonValue] = []
    case_keys: dict[bytes, bytes] = {}
    counters = {"entries": 0, "path_bytes": 0, "file_bytes": 0}

    def tick() -> None:
        if check_deadline is not None:
            check_deadline()

    def walk(descriptor: int, prefix: bytes, depth: int) -> None:
        tick()
        if depth > MAX_TRAVERSAL_DEPTH:
            raise CaptureUnknownError("target traversal depth exceeded limit")
        before_directory = stat_identity(os.fstat(descriptor))
        before_entries = _directory_entries(descriptor)
        bound_entries: list[JsonValue] = []
        for name, identity in before_entries:
            raw_path = name if not prefix else prefix + b"/" + name
            excluded = raw_path in exclude_set or any(
                raw_path.startswith(item + b"/") for item in exclude_set
            )
            if excluded:
                continue
            mode = identity[2]
            selected_directory = stat.S_ISDIR(mode) and (
                allowed_directories is None or raw_path in allowed_directories
            )
            selected_leaf = not stat.S_ISDIR(mode) and (
                include_set is None or raw_path in include_set
            )
            if not selected_directory and not selected_leaf:
                continue
            counters["entries"] += 1
            counters["path_bytes"] += len(raw_path)
            if counters["entries"] > MAX_TRAVERSAL_ENTRIES:
                raise CaptureUnknownError("target traversal entry limit was exceeded")
            if counters["path_bytes"] > MAX_TOTAL_PATH_BYTES:
                raise CaptureUnknownError("target path-byte limit was exceeded")
            folded = raw_path.translate(
                bytes.maketrans(
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
                )
            )
            prior = case_keys.setdefault(folded, raw_path)
            if prior != raw_path:
                raise CaptureUnknownError("case-colliding target paths are unsupported")
            path = _path_identity(encoding, raw_path)
            bound_entries.append(
                {"identity": list(identity), "path": path_identity_payload(path)}
            )
            if stat.S_ISDIR(mode):
                try:
                    child_fd = os.open(name, directory_flags(), dir_fd=descriptor)
                except OSError as error:
                    raise CaptureUnknownError(
                        "target directory could not be pinned"
                    ) from error
                try:
                    if stat_identity(os.fstat(child_fd)) != identity:
                        raise CaptureUnknownError(
                            "target directory changed before pinning"
                        )
                    walk(child_fd, raw_path, depth + 1)
                finally:
                    os.close(child_fd)
                try:
                    locator = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as error:
                    raise CaptureUnknownError(
                        "target directory locator could not be revalidated"
                    ) from error
                if stat_identity(locator) != identity:
                    raise CaptureUnknownError("target directory locator changed")
                continue
            if stat.S_ISREG(mode):
                remaining = MAX_TOTAL_FILE_BYTES - counters["file_bytes"]
                content = _read_regular_leaf(
                    descriptor, name, identity, remaining_total=remaining
                )
                object_type = "file"
            elif stat.S_ISLNK(mode):
                content = _read_symlink_leaf(descriptor, name, identity)
                object_type = "symlink"
            else:
                raise CaptureUnknownError("special target files are unsupported")
            counters["file_bytes"] += len(content)
            if counters["file_bytes"] > MAX_TOTAL_FILE_BYTES:
                raise CaptureUnknownError("target aggregate byte limit was exceeded")
            observation = FileObservation(
                path=path,
                object_type=object_type,
                mode=identity[2],
                size=len(content),
                content_digest=digest_bytes(content),
                file_identity=_observation_identity(identity),
            )
            files[path] = observation
            if raw_path in retained_set:
                required_contents[path] = content
            file_manifest.append(
                {
                    "content_digest": observation.content_digest,
                    "file_identity": list(observation.file_identity),
                    "mode": observation.mode,
                    "object_type": observation.object_type,
                    "path": path_identity_payload(path),
                    "size": observation.size,
                }
            )
        after_entries = _directory_entries(descriptor)
        after_directory = stat_identity(os.fstat(descriptor))
        if before_entries != after_entries or before_directory != after_directory:
            raise CaptureUnknownError("target directory changed during traversal")
        directory_manifest.append(
            {
                "directory": (
                    None
                    if not prefix
                    else path_identity_payload(_path_identity(encoding, prefix))
                ),
                "entries": bound_entries,
                "identity": list(after_directory),
            }
        )

    walk(root_fd, b"", 0)
    observed_raw = {path.raw_bytes() for path in files}
    if include_set is not None and observed_raw != include_set:
        raise CaptureUnknownError("captured path census differs from declared census")
    missing_required = retained_set - observed_raw
    if missing_required:
        raise CaptureRequestError("required path is absent from target")
    ordered_files = dict(
        sorted(files.items(), key=lambda item: item[0].raw_bytes())
    )
    ordered_contents = dict(
        sorted(required_contents.items(), key=lambda item: item[0].raw_bytes())
    )
    return ObservedTree(
        files=MappingProxyType(ordered_files),
        required_contents=MappingProxyType(ordered_contents),
        manifest=canonical_bytes(file_manifest),
        traversal_manifest=canonical_bytes(directory_manifest),
    )
