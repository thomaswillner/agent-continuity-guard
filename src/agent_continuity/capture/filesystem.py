"""Deterministic descriptor-rooted capture for non-Git directories."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Sequence
from pathlib import Path

from agent_continuity.kernel.canonical import digest_bytes
from agent_continuity.kernel.capabilities import CapabilityClaimV1, CapabilityStatus
from agent_continuity.kernel.paths import PathIdentityV1

from ._git_locator import (
    observe_tree,
    open_absolute_directory,
    stat_identity,
    verify_directory_locator,
)
from ._git_proof import build_live_snapshot
from .base import (
    CaptureRequestError,
    CaptureSnapshot,
    CaptureUnknownError,
    _LiveCapture,
)

_ADAPTER_ID = "acg-filesystem"
_ADAPTER_VERSION = "1"


class FilesystemTargetAdapter:
    """Capture one non-Git directory without dereferencing target symlinks."""

    adapter_id = _ADAPTER_ID
    adapter_version = _ADAPTER_VERSION

    def __init__(
        self,
        target: Path,
        exclusions: Sequence[PathIdentityV1] = (),
    ) -> None:
        self._root_fd = -1
        if not isinstance(target, Path):
            raise CaptureRequestError("filesystem target must be a Path")
        try:
            absolute = Path(os.path.abspath(target))
        except OSError as error:
            raise CaptureUnknownError(
                "filesystem target could not be resolved"
            ) from error
        self.root = absolute
        normalized: list[PathIdentityV1] = []
        for exclusion in exclusions:
            if (
                type(exclusion) is not PathIdentityV1
                or exclusion.encoding != "posix-bytes"
            ):
                raise CaptureRequestError("filesystem exclusion identity is invalid")
            normalized.append(exclusion)
        if len(set(normalized)) != len(normalized):
            raise CaptureRequestError("filesystem exclusions must be unique")
        self._exclusions = tuple(sorted(normalized, key=lambda item: item.raw_bytes()))
        self._root_fd = open_absolute_directory(self.root)
        self._root_identity = stat_identity(os.fstat(self._root_fd))
        self._verify_root()

    def close(self) -> None:
        if getattr(self, "_root_fd", -1) >= 0:
            with contextlib.suppress(OSError):
                os.close(self._root_fd)
            self._root_fd = -1

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> FilesystemTargetAdapter:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _verify_root(self) -> None:
        if self._root_fd < 0:
            raise CaptureUnknownError("filesystem target adapter is closed")
        if stat_identity(os.fstat(self._root_fd)) != self._root_identity:
            raise CaptureUnknownError("filesystem target root identity changed")
        verify_directory_locator(self.root, self._root_identity)

    @staticmethod
    def _path(raw_path: bytes) -> PathIdentityV1:
        if type(raw_path) is not bytes:
            raise CaptureRequestError("filesystem instruction path is invalid")
        try:
            return PathIdentityV1.from_bytes("posix-bytes", raw_path)
        except ValueError as error:
            raise CaptureRequestError(
                "filesystem instruction path is invalid"
            ) from error

    @classmethod
    def _paths(cls, raw_paths: Sequence[bytes]) -> tuple[PathIdentityV1, ...]:
        paths = tuple(cls._path(raw_path) for raw_path in raw_paths)
        if len(paths) != len(set(paths)):
            raise CaptureRequestError("filesystem instruction paths must be unique")
        return paths

    def _capture_live(
        self, required_paths: Sequence[PathIdentityV1]
    ) -> _LiveCapture:
        required = tuple(required_paths)
        if any(
            type(path) is not PathIdentityV1 or path.encoding != "posix-bytes"
            for path in required
        ):
            raise CaptureRequestError("filesystem required path identity is invalid")
        if len(required) != len(set(required)):
            raise CaptureRequestError("filesystem required paths must be unique")
        self._verify_root()
        observed = observe_tree(
            self._root_fd,
            encoding="posix-bytes",
            inclusions=None,
            exclusions=tuple(item.raw_bytes() for item in self._exclusions),
            retained_paths=tuple(item.raw_bytes() for item in required),
        )
        self._verify_root()
        policy = next(
            (
                observation.content_digest
                for path, observation in observed.files.items()
                if path.raw_bytes() == b"acg.toml"
            ),
            None,
        )
        snapshot = build_live_snapshot(
            adapter_id=_ADAPTER_ID,
            adapter_version=_ADAPTER_VERSION,
            root_path=os.fsencode(self.root),
            root_stat=os.fstat(self._root_fd),
            files=observed.files,
            required_paths=required,
            required_contents=observed.required_contents,
            traversal_manifest=observed.traversal_manifest,
            capabilities=self._capabilities(observed.manifest),
            target_policy_digest=policy,
        )
        return _LiveCapture(
            snapshot=snapshot,
            files=observed.files,
            required_contents=observed.required_contents,
        )

    def capture(self, instruction_paths: Sequence[bytes]) -> CaptureSnapshot:
        requested = self._paths(instruction_paths)
        return self._capture_live(requested).snapshot

    @staticmethod
    def _capabilities(manifest: bytes) -> tuple[CapabilityClaimV1, ...]:
        evidence = digest_bytes(manifest)

        def claim(name: str, status: CapabilityStatus) -> CapabilityClaimV1:
            return CapabilityClaimV1(
                name=name,
                status=status,
                adapter_id=_ADAPTER_ID,
                adapter_version=_ADAPTER_VERSION,
                evidence_digest=evidence if status == "proven" else None,
            )

        return tuple(
            sorted(
                (
                    claim("atomic_snapshot", "unknown"),
                    claim("descriptor_pinned_reads", "proven"),
                    claim("git_immutable_objects", "unsupported"),
                    claim("git_network_disabled", "unsupported"),
                    claim("windows_reparse_protection", "unsupported"),
                ),
                key=lambda item: item.name,
            )
        )
