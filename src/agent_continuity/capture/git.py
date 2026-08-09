"""Read-only clean-Git target capture."""

from __future__ import annotations

import os
import platform
import re
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit, urlunsplit

from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
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
_OID_RE = re.compile(rb"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class GitTargetAdapter:
    """Observe one local Git worktree without issuing a Git write operation."""

    adapter_id = _ADAPTER_ID
    adapter_version = _ADAPTER_VERSION

    def __init__(self, target: str | os.PathLike[str]) -> None:
        requested = Path(target)
        if not requested.is_absolute():
            requested = requested.absolute()
        if not requested.is_dir():
            raise CaptureRequestError("target is not an existing directory")
        self._requested = requested
        top_level = self._run_at(requested, ("rev-parse", "--show-toplevel"))
        try:
            root = Path(os.fsdecode(top_level.rstrip(b"\n"))).resolve(strict=True)
        except (OSError, UnicodeError) as error:
            raise CaptureRequestError(
                "Git target root could not be resolved"
            ) from error
        if root != requested.resolve(strict=True):
            raise CaptureRequestError("target must be the Git worktree root")
        self.root = root
        raw_git_dir = self._run(("rev-parse", "--git-dir")).rstrip(b"\n")
        git_dir = Path(os.fsdecode(raw_git_dir))
        if not git_dir.is_absolute():
            git_dir = root / git_dir
        self.git_directory = git_dir.resolve(strict=True)

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

    @classmethod
    def _run_at(
        cls,
        target: Path,
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        argv = [
            "git",
            "--no-pager",
            "-c",
            f"core.excludesFile={os.devnull}",
            "-C",
            os.fspath(target),
            *args,
        ]
        try:
            result = subprocess.run(
                argv,
                check=False,
                shell=False,
                env=cls._environment(),
                input=input_data,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CaptureUnknownError("Git observation could not complete") from error
        if result.returncode not in allowed_codes:
            raise CaptureRequestError("Git rejected the observation request")
        if len(result.stdout) > _MAX_GIT_OUTPUT or len(result.stderr) > _MAX_GIT_OUTPUT:
            raise CaptureUnknownError("Git observation exceeded output limit")
        return result.stdout

    def _run(
        self,
        args: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
        input_data: bytes | None = None,
    ) -> bytes:
        return self._run_at(
            self.root,
            args,
            allowed_codes=allowed_codes,
            input_data=input_data,
        )

    def capture(self, instruction_paths: Sequence[bytes]) -> CaptureSnapshot:
        head_oid = self._single_oid(("rev-parse", "HEAD^{commit}"))
        tree_oid = self._single_oid(("rev-parse", "HEAD^{tree}"))
        index = self._run(("ls-files", "--stage", "-z"))
        tree = self._run(("ls-tree", "-rz", "--full-tree", "HEAD"))
        status = self._run(
            ("status", "--porcelain=v2", "-z", "--untracked-files=all")
        )
        tree_entries = self._parse_tree(tree)
        index_entries = self._parse_index(index)
        instructions = self._capture_instructions(instruction_paths, tree_entries)
        worktree_manifest = self._worktree_manifest(index_entries)
        object_manifest = self._object_manifest(tree_entries)
        ignore_manifest = self._ignore_manifest(tree_entries)
        remote_digest = self._remote_identity_digest()
        root_stat = self.root.stat()
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
            except ValueError as error:
                raise CaptureUnknownError("Git tree output was malformed") from error
            if _OID_RE.fullmatch(oid) is None:
                raise CaptureUnknownError("Git tree object identity was malformed")
            path = PathIdentityV1.from_bytes("git-path-bytes", raw_path)
            entries.append(
                (
                    mode.decode("ascii"),
                    object_type.decode("ascii"),
                    oid.decode("ascii"),
                    path,
                )
            )
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
            except (ValueError, UnicodeError) as error:
                raise CaptureUnknownError("Git index output was malformed") from error
            if stage != 0:
                raise CaptureUnknownError("unmerged Git index cannot be proven clean")
            if _OID_RE.fullmatch(oid) is None:
                raise CaptureUnknownError("Git index object identity was malformed")
            entries.append(
                (
                    mode.decode("ascii"),
                    oid.decode("ascii"),
                    stage,
                    PathIdentityV1.from_bytes("git-path-bytes", raw_path),
                )
            )
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
            except Exception as error:
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

    def _read_regular(self, path: bytes) -> tuple[bytes, os.stat_result]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise CaptureUnknownError(
                "target file could not be opened safely"
            ) from error
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise CaptureUnknownError("target path is not a regular file")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 1024 * 1024 * 1024:
                    raise CaptureUnknownError("target file exceeds capture limit")
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise CaptureUnknownError("target file changed during capture")
            return b"".join(chunks), after
        finally:
            os.close(descriptor)

    def _worktree_manifest(
        self,
        entries: tuple[tuple[str, str, int, PathIdentityV1], ...],
    ) -> bytes:
        root = os.fsencode(self.root)
        manifest: list[JsonValue] = []
        for mode, oid, stage, path in entries:
            absolute = os.path.join(root, path.raw_bytes())
            try:
                metadata = os.lstat(absolute)
            except OSError as error:
                raise CaptureUnknownError(
                    "tracked worktree path is unavailable"
                ) from error
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    content = os.readlink(absolute)
                except OSError as error:
                    raise CaptureUnknownError(
                        "symlink target could not be observed"
                    ) from error
                kind = "symlink"
            elif stat.S_ISREG(metadata.st_mode):
                content, metadata = self._read_regular(absolute)
                kind = "file"
            else:
                raise CaptureUnknownError("unsupported tracked worktree object")
            manifest.append(
                {
                    "byte_digest": digest_bytes(content),
                    "git_mode": mode,
                    "kind": kind,
                    "oid": oid,
                    "path": path_identity_payload(path),
                    "size": len(content),
                    "stage": stage,
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
        local_exclude = os.fsencode(self.git_directory / "info" / "exclude")
        if os.path.exists(local_exclude):
            content, _metadata = self._read_regular(local_exclude)
            manifest.append(
                {
                    "byte_digest": digest_bytes(content),
                    "source": "local-exclude",
                }
            )
        return canonical_bytes(manifest)

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
        adapter_evidence = digest_bytes(b"acg-git-adapter-v1")

        def claim(
            name: str,
            status: CapabilityStatus,
        ) -> CapabilityClaimV1:
            return CapabilityClaimV1(
                name=name,
                status=status,
                adapter_id=_ADAPTER_ID,
                adapter_version=_ADAPTER_VERSION,
                evidence_digest=adapter_evidence if status == "proven" else None,
            )

        values = (
            claim(
                "descriptor_pinned_reads",
                "proven" if hasattr(os, "O_NOFOLLOW") else "unsupported",
            ),
            claim("git_immutable_objects", "proven"),
            claim("git_network_disabled", "proven"),
            claim(
                "windows_reparse_protection",
                "unknown" if os.name == "nt" else "unsupported",
            ),
        )
        return tuple(sorted(values, key=lambda item: item.name))


def _sanitize_remote(value: str) -> str:
    if any(ord(character) < 0x20 for character in value):
        raise CaptureRequestError("remote identity contains control characters")
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.query or parsed.fragment or parsed.password is not None:
            raise CaptureRequestError("remote credentials or URL suffix are forbidden")
        if parsed.username is not None and not (
            parsed.scheme == "ssh" and parsed.username == "git"
        ):
            raise CaptureRequestError("remote credentials are forbidden")
        if not parsed.scheme or not parsed.hostname:
            raise CaptureRequestError("remote URL is malformed")
        host = parsed.hostname.lower()
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        return urlunsplit((parsed.scheme.lower(), host, parsed.path, "", ""))
    if "?" in value or "#" in value:
        raise CaptureRequestError("remote query and fragment are forbidden")
    if "@" in value and ":" in value:
        user_host, path = value.split(":", 1)
        user, host = user_host.split("@", 1)
        if user != "git" or not host or not path:
            raise CaptureRequestError("remote credentials are forbidden")
        return f"ssh://{host.lower()}/{path}"
    return value
