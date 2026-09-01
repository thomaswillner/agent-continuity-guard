"""Canonical Git and live-worktree proof construction."""

from __future__ import annotations

import base64
import hashlib
import os
import platform
import re
import stat
import struct
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    digest_bytes,
)
from agent_continuity.kernel.capabilities import CapabilityClaimV1
from agent_continuity.kernel.model import Digest, JsonValue
from agent_continuity.kernel.paths import PathIdentityV1, path_identity_payload

from ._git_locator import (
    MAX_TOTAL_FILE_BYTES,
    MAX_TOTAL_PATH_BYTES,
    MAX_TRAVERSAL_DEPTH,
    MAX_TRAVERSAL_ENTRIES,
    ObservedFile,
    directory_entries,
    directory_flags,
    read_tracked_leaf,
    stat_identity,
)
from .base import (
    CaptureRequestError,
    CaptureSnapshot,
    CaptureUnknownError,
    FileObservation,
    InstructionFileV1,
    TargetIdentityV1,
)

_ALLOWED_INDEX_EXTENSIONS = frozenset({b"TREE"})
_OID_RE = re.compile(rb"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


@dataclass(frozen=True, slots=True)
class IndexEntry:
    mode: str
    oid: str
    stage: int
    path: PathIdentityV1


@dataclass(frozen=True, slots=True)
class TreeEntry:
    mode: str
    object_type: str
    oid: str
    path: PathIdentityV1


@dataclass(frozen=True, slots=True)
class WorktreeProof:
    manifest: bytes
    traversal_manifest: bytes
    contents: dict[bytes, bytes]


def git_digest(data: bytes, object_format: str) -> str:
    if object_format == "sha1":
        return hashlib.sha1(data, usedforsecurity=False).hexdigest()
    if object_format == "sha256":
        return hashlib.sha256(data).hexdigest()
    raise CaptureUnknownError("Git object format is unsupported")


def expected_oid_length(object_format: str) -> int:
    if object_format == "sha1":
        return 40
    if object_format == "sha256":
        return 64
    raise CaptureUnknownError("Git object format is unsupported")


def parse_nul_frame(data: bytes) -> tuple[bytes, ...]:
    if not data:
        return ()
    if not data.endswith(b"\x00"):
        raise CaptureUnknownError("Git NUL-delimited output was truncated")
    records = tuple(data[:-1].split(b"\x00"))
    if any(not record for record in records):
        raise CaptureUnknownError("Git NUL-delimited output was malformed")
    return records


def validate_repo_path(raw_path: bytes) -> None:
    components = raw_path.split(b"/")
    if (
        not raw_path
        or raw_path.startswith(b"/")
        or raw_path.endswith(b"/")
        or any(item in {b"", b".", b"..", b".git"} for item in components)
    ):
        raise CaptureUnknownError("Git path was malformed")
    if len(components) > MAX_TRAVERSAL_DEPTH:
        raise CaptureUnknownError("Git path depth exceeded limit")


def parse_tree(data: bytes, object_format: str | None = None) -> tuple[TreeEntry, ...]:
    entries: list[TreeEntry] = []
    previous: bytes | None = None
    total_path_bytes = 0
    for row in parse_nul_frame(data):
        try:
            header, raw_path = row.split(b"\t", 1)
            mode, object_type, oid = header.split(b" ", 2)
            validate_repo_path(raw_path)
            expected_length = (
                len(oid)
                if object_format is None
                else expected_oid_length(object_format)
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
            if total_path_bytes > MAX_TOTAL_PATH_BYTES:
                raise ValueError("tree paths exceeded limit")
            entries.append(
                TreeEntry(
                    mode=decoded_mode,
                    object_type=decoded_type,
                    oid=oid.decode("ascii"),
                    path=PathIdentityV1.from_bytes("git-path-bytes", raw_path),
                )
            )
        except (CanonicalJSONError, UnicodeError, ValueError) as error:
            raise CaptureUnknownError("Git tree output was malformed") from error
        if len(entries) > MAX_TRAVERSAL_ENTRIES:
            raise CaptureUnknownError("Git tree entry limit was exceeded")
    return tuple(entries)


def parse_index(
    data: bytes, object_format: str | None = None
) -> tuple[IndexEntry, ...]:
    entries: list[IndexEntry] = []
    previous: bytes | None = None
    total_path_bytes = 0
    for row in parse_nul_frame(data):
        try:
            header, raw_path = row.split(b"\t", 1)
            mode, oid, stage_bytes = header.split(b" ", 2)
            stage = int(stage_bytes)
            expected_length = (
                len(oid)
                if object_format is None
                else expected_oid_length(object_format)
            )
            if stage != 0 or len(oid) != expected_length:
                raise ValueError("unsupported index entry")
            if _OID_RE.fullmatch(oid) is None:
                raise ValueError("invalid index object identity")
            decoded_mode = mode.decode("ascii")
            if decoded_mode not in {"100644", "100755", "120000"}:
                raise ValueError("unsupported index mode")
            validate_repo_path(raw_path)
            if previous is not None and raw_path <= previous:
                raise ValueError("index paths are not strictly ordered")
            previous = raw_path
            total_path_bytes += len(raw_path)
            if total_path_bytes > MAX_TOTAL_PATH_BYTES:
                raise ValueError("index paths exceeded limit")
            entries.append(
                IndexEntry(
                    mode=decoded_mode,
                    oid=oid.decode("ascii"),
                    stage=stage,
                    path=PathIdentityV1.from_bytes("git-path-bytes", raw_path),
                )
            )
        except (CanonicalJSONError, UnicodeError, ValueError) as error:
            raise CaptureUnknownError("Git index output was malformed") from error
        if len(entries) > MAX_TRAVERSAL_ENTRIES:
            raise CaptureUnknownError("Git index entry limit was exceeded")
    return tuple(entries)


def parse_raw_index(data: bytes, object_format: str) -> tuple[IndexEntry, ...]:
    hash_bytes = expected_oid_length(object_format) // 2
    if len(data) < 12 + hash_bytes:
        raise CaptureUnknownError("raw Git index was truncated")
    body = data[:-hash_bytes]
    checksum = data[-hash_bytes:]
    expected_checksum = bytes.fromhex(git_digest(body, object_format))
    if checksum != expected_checksum:
        raise CaptureUnknownError("raw Git index checksum was invalid")
    if body[:4] != b"DIRC":
        raise CaptureUnknownError("raw Git index signature was invalid")
    version, entry_count = struct.unpack_from("!II", body, 4)
    if version not in {2, 3}:
        raise CaptureUnknownError("raw Git index version is unsupported")
    if entry_count > MAX_TRAVERSAL_ENTRIES:
        raise CaptureUnknownError("raw Git index entry limit was exceeded")
    entries: list[IndexEntry] = []
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
        validate_repo_path(raw_path)
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
        if total_path_bytes > MAX_TOTAL_PATH_BYTES:
            raise CaptureUnknownError("raw Git index paths exceeded limit")
        entries.append(
            IndexEntry(
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


def entry_key(entry: IndexEntry | TreeEntry) -> tuple[str, str, bytes]:
    return entry.mode, entry.oid, entry.path.raw_bytes()


def prove_head_equals_index(
    tree_entries: tuple[TreeEntry, ...], index_entries: tuple[IndexEntry, ...]
) -> None:
    if tuple(entry_key(entry) for entry in tree_entries) != tuple(
        entry_key(entry) for entry in index_entries
    ):
        raise CaptureUnknownError("HEAD tree does not equal the raw index")


def prove_clean_worktree(
    root_fd: int,
    entries: tuple[IndexEntry, ...],
    object_format: str,
    check_deadline: Callable[[], None],
) -> WorktreeProof:
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
        check_deadline()
        if depth > MAX_TRAVERSAL_DEPTH:
            raise CaptureUnknownError("worktree traversal depth exceeded limit")
        before_directory = stat_identity(os.fstat(descriptor))
        before_entries = directory_entries(descriptor)
        entry_payload: list[JsonValue] = []
        for name, identity in before_entries:
            raw_path = name if not prefix else prefix + b"/" + name
            counters["entries"] += 1
            counters["path_bytes"] += len(raw_path)
            if counters["entries"] > MAX_TRAVERSAL_ENTRIES:
                raise CaptureUnknownError("worktree entry limit was exceeded")
            if counters["path_bytes"] > MAX_TOTAL_PATH_BYTES:
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
                    child_fd = os.open(name, directory_flags(), dir_fd=descriptor)
                except OSError as error:
                    raise CaptureUnknownError(
                        "tracked parent directory could not be pinned"
                    ) from error
                try:
                    if stat_identity(os.fstat(child_fd)) != identity:
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
            remaining = MAX_TOTAL_FILE_BYTES - counters["file_bytes"]
            content, after_identity = read_tracked_leaf(
                descriptor, name, identity, expected.mode, remaining
            )
            local_oid = git_blob_oid(content, object_format)
            if local_oid != expected.oid:
                raise CaptureUnknownError("worktree bytes differ from index")
            counters["file_bytes"] += len(content)
            if counters["file_bytes"] > MAX_TOTAL_FILE_BYTES:
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
        after_entries = directory_entries(descriptor)
        after_directory = stat_identity(os.fstat(descriptor))
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

    walk(root_fd, b"", 0)
    if seen != set(by_path):
        raise CaptureUnknownError("tracked worktree paths are missing")
    return WorktreeProof(
        manifest=canonical_bytes(file_manifest),
        traversal_manifest=canonical_bytes(directory_manifest),
        contents=contents,
    )


def observed_file_payload(observation: ObservedFile) -> JsonValue:
    return {
        "digest": observation.digest,
        "exists": observation.exists,
        "identity": (
            None if observation.identity is None else list(observation.identity)
        ),
    }


def build_git_object_manifest(
    entries: tuple[TreeEntry, ...],
    worktree_contents: Mapping[bytes, bytes],
    object_format: str,
    read_blob: Callable[[tuple[str, ...]], bytes],
) -> bytes:
    manifest: list[JsonValue] = []
    for entry in entries:
        symlink_target: JsonValue = None
        if entry.mode == "120000":
            blob = read_blob(("cat-file", "blob", entry.oid))
            if (
                git_blob_oid(blob, object_format) != entry.oid
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


def build_ignore_manifest(
    entries: tuple[TreeEntry, ...], sources: tuple[ObservedFile, ...]
) -> bytes:
    manifest: list[JsonValue] = []
    for entry in entries:
        if entry.path.raw_bytes().split(b"/")[-1] == b".gitignore":
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
                "evidence": observed_file_payload(source),
                "source": f"local-exclude-{index}",
            }
        )
    return canonical_bytes(manifest)


def git_blob_oid(content: bytes, object_format: str) -> str:
    framed = b"blob " + str(len(content)).encode("ascii") + b"\x00" + content
    if object_format == "sha1":
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    if object_format == "sha256":
        return hashlib.sha256(framed).hexdigest()
    raise ValueError("unsupported Git object format")


def live_status_digest(*, adapter_id: str) -> Digest:
    return digest_bytes(
        canonical_bytes(
            {
                "adapter_id": adapter_id,
                "observer_version": "stable-live-v1",
                "status": "stable-live-observation",
            }
        )
    )


def canonical_file_manifest(
    files: Mapping[PathIdentityV1, FileObservation],
) -> bytes:
    values: list[JsonValue] = []
    for path, observation in sorted(
        files.items(), key=lambda item: item[0].raw_bytes()
    ):
        values.append(
            {
                "content_digest": observation.content_digest,
                "file_identity": list(observation.file_identity),
                "mode": observation.mode,
                "object_type": observation.object_type,
                "path": path_identity_payload(path),
                "size": observation.size,
            }
        )
    return canonical_bytes(values)


def build_live_snapshot(
    *,
    adapter_id: str,
    adapter_version: str,
    root_path: bytes,
    root_stat: os.stat_result,
    files: Mapping[PathIdentityV1, FileObservation],
    required_paths: Sequence[PathIdentityV1],
    required_contents: Mapping[PathIdentityV1, bytes],
    traversal_manifest: bytes,
    capabilities: tuple[CapabilityClaimV1, ...],
    head_oid: str | None = None,
    tree_oid: str | None = None,
    index_manifest_digest: Digest | None = None,
    git_object_manifest: bytes = b"[]",
    ignore_manifest: bytes = b"[]",
    remote_digest: Digest | None = None,
    target_policy_digest: Digest | None = None,
    object_format: str = "sha256",
    inventory_extra: Mapping[str, JsonValue] | None = None,
) -> CaptureSnapshot:
    manifest = canonical_file_manifest(files)
    synthetic_oid = hashlib.sha256(manifest).hexdigest()
    resolved_head = synthetic_oid if head_oid is None else head_oid
    resolved_tree = synthetic_oid if tree_oid is None else tree_oid
    instructions: list[InstructionFileV1] = []
    for path in required_paths:
        observation = files.get(path)
        content = required_contents.get(path)
        if observation is None or content is None:
            raise CaptureRequestError("required path is absent from captured view")
        instructions.append(
            InstructionFileV1(
                path=path,
                blob_oid=git_blob_oid(content, object_format),
                byte_digest=observation.content_digest,
            )
        )
    inventory: dict[str, JsonValue] = {
        "files": [path_identity_payload(path) for path in files],
        "manifest_digest": digest_bytes(manifest),
        "traversal_digest": digest_bytes(traversal_manifest),
    }
    if inventory_extra is not None:
        for key, value in inventory_extra.items():
            if key in inventory:
                raise ValueError("live inventory extension duplicates a core key")
            inventory[key] = value
    physical_root_fingerprint = digest_bytes(
        b"physical-root-v1\x00"
        + root_path
        + b"\x00"
        + str(root_stat.st_dev).encode("ascii")
        + b":"
        + str(root_stat.st_ino).encode("ascii")
    )
    target = TargetIdentityV1(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        sanitized_remote_identity_digest=remote_digest,
        head_oid=resolved_head,
        tree_oid=resolved_tree,
        index_manifest_digest=(
            digest_bytes(manifest)
            if index_manifest_digest is None
            else index_manifest_digest
        ),
        worktree_manifest_digest=digest_bytes(manifest),
        inventory_digest=digest_bytes(canonical_bytes(inventory)),
        status_digest=live_status_digest(adapter_id=adapter_id),
        git_object_manifest_digest=digest_bytes(git_object_manifest),
        ignore_provenance_digest=digest_bytes(ignore_manifest),
        platform_id=sys.platform,
        filesystem_id=f"{os.name}:{platform.system().lower()}",
        physical_root_fingerprint=physical_root_fingerprint,
        capabilities=capabilities,
    )
    return CaptureSnapshot(
        target=target,
        instructions=tuple(instructions),
        target_policy_digest=target_policy_digest,
    )
