"""Read-only, bounded, descriptor-rooted Git target capture."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import platform
import re
import stat
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import unquote_to_bytes, urlsplit, urlunsplit

from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    digest_bytes,
)
from agent_continuity.kernel.capabilities import CapabilityClaimV1, CapabilityStatus
from agent_continuity.kernel.model import Digest, JsonValue
from agent_continuity.kernel.paths import PathIdentityV1, path_identity_payload

from ._git_locator import (
    ObservedFile as _ObservedFile,
)
from ._git_locator import (
    StatIdentity as _StatIdentity,
)
from ._git_locator import (
    directory_flags as _directory_flags,
)
from ._git_locator import (
    file_flags as _file_flags,
)
from ._git_locator import (
    locator_identity as _locator_identity,
)
from ._git_locator import (
    observe_relative_file,
    observe_tree,
    verify_pinned_directory,
)
from ._git_locator import (
    open_absolute_directory as _open_absolute_directory,
)
from ._git_locator import (
    read_descriptor as _read_descriptor,
)
from ._git_locator import (
    resolve_locator as _resolve_locator,
)
from ._git_locator import (
    stat_identity as _stat_identity,
)
from ._git_process import (
    descriptor_git_argv,
    remaining_timeout,
    resolve_git_executable,
    run_bounded,
    sanitized_environment,
    verify_git_executable,
)
from ._git_proof import (
    IndexEntry as _IndexEntry,
)
from ._git_proof import (
    TreeEntry as _TreeEntry,
)
from ._git_proof import (
    build_git_object_manifest,
    build_ignore_manifest,
    build_live_snapshot,
    entry_key,
    parse_index,
    parse_raw_index,
    parse_tree,
    prove_clean_worktree,
    prove_head_equals_index,
)
from ._git_proof import (
    expected_oid_length as _expected_oid_length,
)
from ._git_proof import (
    git_blob_oid as _blob_oid,
)
from ._git_proof import (
    observed_file_payload as _file_payload,
)
from ._git_proof import (
    parse_nul_frame as _parse_nul_frame,
)
from ._git_proof import (
    validate_repo_path as _validate_repo_path,
)
from .base import (
    DIRECT_CLEAN_STATUS_DIGEST,
    CaptureRequestError,
    CaptureSnapshot,
    CaptureUnknownError,
    InstructionFileV1,
    TargetIdentityV1,
    _LiveCapture,
)

_ADAPTER_ID: Final = "acg-git"
_ADAPTER_VERSION: Final = "2"
_MAX_GIT_OUTPUT: Final = 8 * 1024 * 1024
_MAX_TRAVERSAL_DEPTH: Final = 128
_MAX_CAPTURE_SECONDS: Final = 30.0
_MAX_METADATA_BYTES: Final = 8 * 1024 * 1024
_MAX_TARGET_PATH_BYTES: Final = 32 * 1024
_MAX_PATH_COMPONENT_BYTES: Final = 255
_MAX_SYMBOLIC_REF_DEPTH: Final = 32
_MAX_SYMBOLIC_REF_TOTAL_BYTES: Final = 8 * 1024
_OID_RE = re.compile(rb"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SCP_REMOTE_RE = re.compile(
    r"^git@(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):(?P<path>[^\s?#]+)$"
)
_REMOTE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_REMOTE_HOST_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$"
)
_PERCENT_ESCAPE_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_FILTER_KEY_RE = re.compile(r"^filter\..+\.")
@dataclass(frozen=True, slots=True)
class _HeadProof:
    sources: tuple[_ObservedFile, ...]
    terminal_oid: bytes


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
    target_policy_digest: Digest | None


def _validate_target_path(target: str | os.PathLike[str]) -> Path:
    try:
        raw_target = os.fspath(target)
    except TypeError as error:
        raise CaptureRequestError("target path is invalid") from error
    if (
        not isinstance(raw_target, str)
        or not raw_target
        or "\x00" in raw_target
        or any(0xD800 <= ord(character) <= 0xDFFF for character in raw_target)
    ):
        raise CaptureRequestError("target path is invalid")
    try:
        raw_bytes = os.fsencode(raw_target)
    except UnicodeEncodeError as error:
        raise CaptureRequestError("target path is invalid") from error
    if len(raw_bytes) > _MAX_TARGET_PATH_BYTES:
        raise CaptureRequestError("target path exceeded byte limit")
    try:
        absolute = os.path.abspath(raw_target)
    except OSError as error:
        raise CaptureUnknownError("target path could not be resolved") from error
    try:
        absolute_bytes = os.fsencode(absolute)
    except UnicodeEncodeError as error:
        raise CaptureRequestError("target path is invalid") from error
    if len(absolute_bytes) > _MAX_TARGET_PATH_BYTES:
        raise CaptureRequestError("target path exceeded byte limit")
    requested = Path(absolute)
    encoded_parts = tuple(os.fsencode(part) for part in requested.parts)
    if len(encoded_parts) > _MAX_TRAVERSAL_DEPTH:
        raise CaptureRequestError("target path exceeded component limit")
    if any(len(part) > _MAX_PATH_COMPONENT_BYTES for part in encoded_parts):
        raise CaptureRequestError("target path component exceeded byte limit")
    return requested


def _validate_symbolic_ref_path(raw_path: bytes) -> None:
    components = raw_path.split(b"/")
    forbidden = b" ~^:?*[\\"
    if (
        not raw_path.startswith(b"refs/")
        or len(components) < 2
        or any(
            not component
            or component.startswith(b".")
            or component.endswith((b".", b".lock"))
            for component in components
        )
        or b".." in raw_path
        or b"@{" in raw_path
        or len(components) > _MAX_TRAVERSAL_DEPTH
        or any(len(component) > _MAX_PATH_COMPONENT_BYTES for component in components)
        or any(
            byte < 0x20 or byte == 0x7F or byte in forbidden for byte in raw_path
        )
    ):
        raise CaptureUnknownError("symbolic reference path was malformed")


def _metadata_line(observation: _ObservedFile) -> bytes:
    content = observation.content
    if content is None:
        raise CaptureUnknownError("reference metadata was unavailable")
    if content.endswith(b"\n"):
        content = content[:-1]
    if not content or b"\n" in content or b"\r" in content:
        raise CaptureUnknownError("reference metadata was malformed")
    return content


def _packed_ref_oid(data: bytes, target: bytes) -> bytes | None:
    if data and (not data.endswith(b"\n") or b"\r" in data or b"\x00" in data):
        raise CaptureUnknownError("packed reference metadata was malformed")
    found: bytes | None = None
    previous_entry = False
    seen: set[bytes] = set()
    for line in data.split(b"\n"):
        if not line:
            continue
        if line.startswith(b"#"):
            previous_entry = False
            continue
        if line.startswith(b"^"):
            if not previous_entry or _OID_RE.fullmatch(line[1:]) is None:
                raise CaptureUnknownError("packed reference metadata was malformed")
            previous_entry = False
            continue
        try:
            oid, ref_path = line.split(b" ", 1)
            _validate_symbolic_ref_path(ref_path)
        except (ValueError, CaptureUnknownError) as error:
            raise CaptureUnknownError(
                "packed reference metadata was malformed"
            ) from error
        if _OID_RE.fullmatch(oid) is None or ref_path in seen:
            raise CaptureUnknownError("packed reference metadata was malformed")
        seen.add(ref_path)
        previous_entry = True
        if ref_path == target:
            found = oid
    return found


class GitTargetAdapter:
    """Conservatively prove one local Git worktree is exactly HEAD-clean."""

    adapter_id = _ADAPTER_ID
    adapter_version = _ADAPTER_VERSION
    _observe_file = staticmethod(observe_relative_file)

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
            (
                self._git_executable,
                self._git_executable_fd,
                self._git_executable_identity,
            ) = resolve_git_executable()
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

    def _pin_requested_root(self, target: str | os.PathLike[str]) -> None:
        requested = _validate_target_path(target)
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

    def _check_deadline(self) -> None:
        remaining_timeout(self._active_deadline)

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
        argv = descriptor_git_argv(target, args, self._git_executable)
        result = run_bounded(
            argv,
            env=sanitized_environment(),
            timeout=remaining_timeout(self._active_deadline),
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

    def _verify_pinned_directories(self) -> None:
        verify_pinned_directory(self.root, self._root_fd, self._root_identity)
        self._verify_git_locator()
        verify_pinned_directory(
            self.git_directory, self._git_fd, self._git_identity
        )
        verify_pinned_directory(
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
        verify_git_executable(
            self._git_executable,
            self._git_executable_fd,
            self._git_executable_identity,
        )

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

    def _common_local_metadata_sources(
        self,
        raw_path: bytes,
        *,
        common_required: bool,
        additional_git_paths: tuple[bytes, ...] = (),
    ) -> tuple[_ObservedFile, ...]:
        values = [
            self._observe_file(
                self._common_git_fd,
                raw_path,
                required=common_required,
                max_bytes=_MAX_METADATA_BYTES,
            )
        ]
        if self.git_directory != self.git_common_directory:
            values.append(
                self._observe_file(
                    self._git_fd,
                    raw_path,
                    required=False,
                    max_bytes=_MAX_METADATA_BYTES,
                )
            )
        values.extend(
            self._observe_file(
                self._git_fd, path, required=False, max_bytes=_MAX_METADATA_BYTES
            )
            for path in additional_git_paths
        )
        return tuple(values)

    def _config_sources(self) -> tuple[_ObservedFile, ...]:
        return self._common_local_metadata_sources(
            b"config",
            common_required=True,
            additional_git_paths=(b"config.worktree",),
        )

    def _attribute_sources(self) -> tuple[_ObservedFile, ...]:
        return self._common_local_metadata_sources(
            b"info/attributes", common_required=False
        )

    def _ignore_sources(self) -> tuple[_ObservedFile, ...]:
        return self._common_local_metadata_sources(
            b"info/exclude", common_required=False
        )

    def _head_sources(self) -> _HeadProof:
        head = self._observe_file(
            self._git_fd,
            b"HEAD",
            required=True,
            max_bytes=_MAX_METADATA_BYTES,
        )
        content = _metadata_line(head)
        values = [head]
        if not content.startswith(b"ref: "):
            if _OID_RE.fullmatch(content) is None:
                raise CaptureUnknownError("HEAD metadata is malformed")
            return _HeadProof(sources=tuple(values), terminal_oid=content)

        packed = self._observe_file(
            self._common_git_fd,
            b"packed-refs",
            required=False,
            max_bytes=_MAX_METADATA_BYTES,
        )
        visited: set[bytes] = set()
        depth = 0
        total_ref_bytes = 0
        values.append(packed)
        while content.startswith(b"ref: "):
            if depth >= _MAX_SYMBOLIC_REF_DEPTH:
                raise CaptureUnknownError("symbolic reference depth exceeded limit")
            ref_path = content[len(b"ref: ") :]
            _validate_symbolic_ref_path(ref_path)
            total_ref_bytes += len(ref_path)
            if total_ref_bytes > _MAX_SYMBOLIC_REF_TOTAL_BYTES:
                raise CaptureUnknownError(
                    "symbolic reference byte budget exceeded limit"
                )
            if ref_path in visited:
                raise CaptureUnknownError("symbolic reference cycle is unsupported")
            visited.add(ref_path)
            depth += 1
            loose = self._observe_file(
                self._common_git_fd,
                ref_path,
                required=False,
                max_bytes=_MAX_METADATA_BYTES,
            )
            values.append(loose)
            packed_oid = _packed_ref_oid(packed.content or b"", ref_path)
            if loose.exists and packed_oid is not None:
                raise CaptureUnknownError(
                    "loose and packed reference sources are ambiguous"
                )
            if loose.exists:
                content = _metadata_line(loose)
                continue
            if packed_oid is None:
                raise CaptureUnknownError("HEAD reference source is unavailable")
            content = packed_oid

        if _OID_RE.fullmatch(content) is None:
            raise CaptureUnknownError("HEAD reference metadata is malformed")
        return _HeadProof(sources=tuple(values), terminal_oid=content)

    def _alternates_source(self) -> _ObservedFile:
        return self._observe_file(
            self._common_git_fd,
            b"objects/info/alternates",
            required=False,
            max_bytes=_MAX_METADATA_BYTES,
        )

    @staticmethod
    def _parse_config(data: bytes) -> tuple[tuple[str, str], ...]:
        entries: list[tuple[str, str]] = []
        for row in _parse_nul_frame(data):
            try:
                raw_key, raw_value = row.split(b"\n", 1)
                key = raw_key.decode("ascii", errors="strict")
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
        return tuple(
            value for candidate, value in entries if candidate.lower() == key
        )

    @staticmethod
    def _is_false(value: str) -> bool:
        return value.strip().lower() in {"false", "no", "off", "0", ""}

    @staticmethod
    def _is_true(value: str) -> bool:
        return value.strip().lower() in {"true", "yes", "on", "1"}

    @classmethod
    def _assert_config_eligible(cls, entries: tuple[tuple[str, str], ...]) -> None:
        for key, _value in entries:
            normalized_key = key.lower()
            if (
                normalized_key.startswith("include.")
                or normalized_key.startswith("includeif.")
                or _FILTER_KEY_RE.match(normalized_key) is not None
                or normalized_key == "core.attributesfile"
                or normalized_key == "core.worktree"
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
    @staticmethod
    def _remote_identity_digest(config: tuple[tuple[str, str], ...]) -> Digest | None:
        identities: list[tuple[str, str, str]] = []
        for key, value in config:
            remote_key = _remote_key(key)
            if remote_key is None:
                continue
            name, role = remote_key
            try:
                normalized = _sanitize_remote(value)
            except CaptureRequestError as error:
                raise CaptureUnknownError(
                    "remote identity metadata is unsupported"
                ) from error
            identities.append((name, role, normalized))
        if not identities:
            return None
        canonical_identities: list[JsonValue] = [
            [name, role, value] for name, role, value in sorted(identities)
        ]
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
        target_policy_before = self._observe_file(
            self._root_fd,
            b"acg.toml",
            required=False,
            max_bytes=_MAX_METADATA_BYTES,
        )
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
        resolved_head = head_before.terminal_oid.decode("ascii")
        head_oid = self._single_oid(
            ("rev-parse", "--verify", f"{resolved_head}^{{commit}}"),
            object_format,
        )
        tree_oid = self._single_oid(
            ("rev-parse", "--verify", f"{head_oid}^{{tree}}"), object_format
        )
        raw_index = index_before.content or b""
        raw_entries = parse_raw_index(raw_index, object_format)
        listed_entries = parse_index(
            self._run(("ls-files", "--stage", "-z")), object_format
        )
        if raw_entries != listed_entries:
            raise CaptureUnknownError("raw and Git-parsed index differ")
        tree_entries = parse_tree(
            self._run(("ls-tree", "-rz", "--full-tree", tree_oid)),
            object_format,
        )
        prove_head_equals_index(tree_entries, raw_entries)
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

        worktree = prove_clean_worktree(
            self._root_fd, raw_entries, object_format, self._check_deadline
        )
        instructions = self._capture_instructions(
            requested, tree_entries, object_format
        )
        object_manifest = build_git_object_manifest(
            tree_entries, worktree.contents, object_format, self._run
        )
        ignore_manifest = build_ignore_manifest(tree_entries, ignores_before)
        remote_digest = self._remote_identity_digest(config)

        locator_after = self._locator_manifest()
        target_policy_after = self._observe_file(
            self._root_fd,
            b"acg.toml",
            required=False,
            max_bytes=_MAX_METADATA_BYTES,
        )
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
            or target_policy_after != target_policy_before
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
            head_after.sources,
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
            target_policy_digest=target_policy_after.digest,
        )

    def _live_census(self) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
        tracked = _parse_nul_frame(self._run(("ls-files", "--cached", "-z")))
        untracked = _parse_nul_frame(
            self._run(("ls-files", "--others", "--exclude-standard", "-z"))
        )
        for values in (tracked, untracked):
            previous: bytes | None = None
            for raw_path in values:
                _validate_repo_path(raw_path)
                if previous is not None and raw_path <= previous:
                    raise CaptureUnknownError("Git live census is not ordered")
                previous = raw_path
        if set(tracked) & set(untracked):
            raise CaptureUnknownError("Git live census is ambiguous")
        return tracked, untracked

    def _capture_live(
        self, required_paths: Sequence[PathIdentityV1]
    ) -> _LiveCapture:
        requested = tuple(required_paths)
        if any(
            type(path) is not PathIdentityV1 or path.encoding != "git-path-bytes"
            for path in requested
        ):
            raise CaptureRequestError("Git required path identity is invalid")
        if len(requested) != len(set(requested)):
            raise CaptureRequestError("Git required paths must be unique")
        if self._active_deadline is not None:
            raise CaptureUnknownError("concurrent capture is unsupported")
        self._active_deadline = time.monotonic() + _MAX_CAPTURE_SECONDS
        try:
            result = self._observe_live(requested)
            self._check_deadline()
            return result
        finally:
            self._active_deadline = None

    def _observe_live(
        self, requested: tuple[PathIdentityV1, ...]
    ) -> _LiveCapture:
        locator_before = self._locator_manifest()
        target_policy_before = self._observe_file(
            self._root_fd,
            b"acg.toml",
            required=False,
            max_bytes=_MAX_METADATA_BYTES,
        )
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
        object_format = self._object_format()
        resolved_head = head_before.terminal_oid.decode("ascii")
        head_oid = self._single_oid(
            ("rev-parse", "--verify", f"{resolved_head}^{{commit}}"), object_format
        )
        tree_oid = self._single_oid(
            ("rev-parse", "--verify", f"{head_oid}^{{tree}}"), object_format
        )
        raw_index = index_before.content or b""
        index_entries = parse_raw_index(raw_index, object_format)
        listed_entries = parse_index(
            self._run(("ls-files", "--stage", "-z")), object_format
        )
        if index_entries != listed_entries:
            raise CaptureUnknownError("raw and Git-parsed index differ")
        tree_entries = parse_tree(
            self._run(("ls-tree", "-rz", "--full-tree", tree_oid)), object_format
        )
        tracked, untracked = self._live_census()
        if tracked != tuple(entry.path.raw_bytes() for entry in index_entries):
            raise CaptureUnknownError("Git tracked census differs from index")
        census = frozenset((*tracked, *untracked))
        retained = tuple(path.raw_bytes() for path in requested)
        observed = observe_tree(
            self._root_fd,
            encoding="git-path-bytes",
            inclusions=census,
            exclusions=(),
            retained_paths=retained,
            check_deadline=self._check_deadline,
        )
        tracked_after, untracked_after = self._live_census()

        locator_after = self._locator_manifest()
        target_policy_after = self._observe_file(
            self._root_fd,
            b"acg.toml",
            required=False,
            max_bytes=_MAX_METADATA_BYTES,
        )
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
            or target_policy_after != target_policy_before
            or config_after != config_before
            or attributes_after != attributes_before
            or ignores_after != ignores_before
            or head_after != head_before
            or index_after != index_before
            or alternates_after != alternates_before
            or tracked_after != tracked
            or untracked_after != untracked
        ):
            raise CaptureUnknownError("Git dependencies changed during live capture")

        object_manifest = canonical_bytes(
            [
                {
                    "mode": entry.mode,
                    "object_type": entry.object_type,
                    "oid": entry.oid,
                    "path": path_identity_payload(entry.path),
                }
                for entry in tree_entries
            ]
        )
        ignore_manifest = build_ignore_manifest(tree_entries, ignores_after)
        inventory_extra: dict[str, JsonValue] = {
            "head_index_equivalent": tuple(
                entry_key(entry) for entry in tree_entries
            )
            == tuple(entry_key(entry) for entry in index_entries),
            "index": [
                path_identity_payload(entry.path) for entry in index_entries
            ],
            "tracked_worktree": [
                path_identity_payload(
                    PathIdentityV1.from_bytes("git-path-bytes", raw_path)
                )
                for raw_path in tracked
            ],
            "untracked_worktree": [
                path_identity_payload(
                    PathIdentityV1.from_bytes("git-path-bytes", raw_path)
                )
                for raw_path in untracked
            ],
        }
        descriptor_evidence = digest_bytes(
            observed.manifest + b"\x00" + observed.traversal_manifest
        )

        def live_claim(
            name: str, status: CapabilityStatus
        ) -> CapabilityClaimV1:
            return CapabilityClaimV1(
                name=name,
                status=status,
                adapter_id=_ADAPTER_ID,
                adapter_version=_ADAPTER_VERSION,
                evidence_digest=(
                    descriptor_evidence if status == "proven" else None
                ),
            )

        capabilities = tuple(
            sorted(
                (
                    live_claim("atomic_snapshot", "unknown"),
                    live_claim("descriptor_pinned_reads", "proven"),
                    live_claim("git_immutable_objects", "proven"),
                    live_claim("git_network_disabled", "unknown"),
                    live_claim("windows_reparse_protection", "unsupported"),
                ),
                key=lambda item: item.name,
            )
        )
        root_stat = os.fstat(self._root_fd)
        snapshot = build_live_snapshot(
            adapter_id=_ADAPTER_ID,
            adapter_version=_ADAPTER_VERSION,
            root_path=os.fsencode(self.root),
            root_stat=root_stat,
            files=observed.files,
            required_paths=requested,
            required_contents=observed.required_contents,
            traversal_manifest=observed.traversal_manifest,
            capabilities=capabilities,
            head_oid=head_oid,
            tree_oid=tree_oid,
            index_manifest_digest=digest_bytes(raw_index),
            git_object_manifest=object_manifest,
            ignore_manifest=ignore_manifest,
            remote_digest=self._remote_identity_digest(config),
            target_policy_digest=target_policy_after.digest,
            object_format=object_format,
            inventory_extra=inventory_extra,
        )
        return _LiveCapture(
            snapshot=snapshot,
            files=observed.files,
            required_contents=observed.required_contents,
        )

    def read_target_policy(self) -> bytes | None:
        """Read target-root policy through the admitted descriptor root."""

        if self._active_deadline is not None:
            raise CaptureUnknownError("concurrent capture is unsupported")
        self._active_deadline = time.monotonic() + _MAX_CAPTURE_SECONDS
        try:
            self._verify_pinned_directories()
            first = self._observe_file(
                self._root_fd,
                b"acg.toml",
                required=False,
                max_bytes=_MAX_METADATA_BYTES,
            )
            self._verify_pinned_directories()
            second = self._observe_file(
                self._root_fd,
                b"acg.toml",
                required=False,
                max_bytes=_MAX_METADATA_BYTES,
            )
            self._verify_pinned_directories()
            self._check_deadline()
        finally:
            self._active_deadline = None
        if first != second:
            raise CaptureUnknownError("target policy changed during bounded read")
        return first.content

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
        return CaptureSnapshot(
            target=target,
            instructions=first.instructions,
            target_policy_digest=first.target_policy_digest,
        )

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


def _remote_key(key: str) -> tuple[str, str] | None:
    normalized_key = key.lower()
    if not normalized_key.startswith("remote."):
        return None
    if normalized_key.endswith(".pushurl"):
        name = key[len("remote.") : -len(".pushurl")]
        role = "push"
    elif normalized_key.endswith(".url"):
        name = key[len("remote.") : -len(".url")]
        role = "fetch"
    else:
        return None
    if (
        len(name.encode("ascii")) > 128
        or _REMOTE_NAME_RE.fullmatch(name) is None
        or name.endswith(".")
        or ".." in name
    ):
        raise CaptureUnknownError("remote name metadata is unsupported")
    return name, role


def _normalized_remote_host(host: str) -> str:
    if ":" in host:
        try:
            return f"[{ipaddress.IPv6Address(host).compressed}]"
        except ipaddress.AddressValueError as error:
            raise CaptureRequestError("remote host is invalid") from error
    if _REMOTE_HOST_RE.fullmatch(host) is None:
        raise CaptureRequestError("remote host is invalid")
    return host.lower()


def _normalized_percent_escapes(value: str) -> str:
    if "%" in _PERCENT_ESCAPE_RE.sub("", value):
        raise CaptureRequestError("remote percent escape is invalid")
    decoded = unquote_to_bytes(value)
    if any(byte <= 0x20 or byte in {0x5C, 0x7F} for byte in decoded):
        raise CaptureRequestError("remote identity contains invalid characters")
    return _PERCENT_ESCAPE_RE.sub(
        lambda match: f"%{match.group(1).upper()}", value
    )


def _sanitize_remote(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or any(
            ord(character) <= 0x20
            or ord(character) >= 0x7F
            or character == "\\"
            for character in value
        )
    ):
        raise CaptureRequestError("remote identity contains invalid characters")
    normalized = _normalized_percent_escapes(value)
    if "://" in normalized:
        try:
            parsed = urlsplit(normalized)
            port = parsed.port
        except ValueError as error:
            raise CaptureRequestError("remote URL port is invalid") from error
        scheme = parsed.scheme.lower()
        if scheme not in {"git", "https", "ssh"}:
            raise CaptureRequestError("remote URL scheme is unsupported")
        if parsed.query or parsed.fragment or parsed.password is not None:
            raise CaptureRequestError("remote credentials or URL suffix are forbidden")
        if parsed.username is not None and not (
            scheme == "ssh" and parsed.username == "git"
        ):
            raise CaptureRequestError("remote credentials are forbidden")
        if (
            not parsed.hostname
            or not parsed.path
            or not parsed.path.startswith("/")
            or "@" in parsed.hostname
        ):
            raise CaptureRequestError("remote URL is malformed")
        host = _normalized_remote_host(parsed.hostname)
        if port is not None:
            if not 1 <= port <= 65535:
                raise CaptureRequestError("remote URL port is invalid")
            host = f"{host}:{port}"
        return urlunsplit((scheme, host, parsed.path, "", ""))
    if normalized.count("@") != 1:
        raise CaptureRequestError("remote SCP identity is malformed")
    match = _SCP_REMOTE_RE.fullmatch(normalized)
    if match is None:
        raise CaptureRequestError("remote identity grammar is unsupported")
    raw_host = match.group("host")
    if raw_host.startswith("[") and raw_host.endswith("]"):
        raw_host = raw_host[1:-1]
    host = _normalized_remote_host(raw_host)
    return f"ssh://{host}/{match.group('path')}"
