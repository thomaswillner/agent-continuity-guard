"""Read-only capture contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    digest_bytes,
)
from agent_continuity.kernel.capabilities import CapabilityClaimV1
from agent_continuity.kernel.model import Digest, JsonObject, StoredRecord
from agent_continuity.kernel.paths import PathIdentityV1, path_identity_payload
from agent_continuity.kernel.records import (
    make_record,
    require_digest,
    require_public_component,
)

_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
DIRECT_CLEAN_STATUS_DIGEST = digest_bytes(
    canonical_bytes(
        {
            "conversion_eligibility": "proven",
            "head_tree_equals_index": "proven",
            "index_equals_worktree": "proven",
            "no_non_index_paths": "proven",
            "observer_version": "direct-git-v2",
        }
    )
)


class CaptureError(RuntimeError):
    """Base class for sanitized capture failures."""


class CaptureRequestError(CaptureError):
    """Caller supplied an invalid target or capture request."""


class CaptureUnknownError(CaptureError):
    """Required target proof could not be established."""


@dataclass(frozen=True, slots=True)
class TargetIdentityV1:
    adapter_id: str
    adapter_version: str
    sanitized_remote_identity_digest: Digest | None
    head_oid: str
    tree_oid: str
    index_manifest_digest: Digest
    worktree_manifest_digest: Digest
    inventory_digest: Digest
    status_digest: Digest
    git_object_manifest_digest: Digest
    ignore_provenance_digest: Digest
    platform_id: str
    filesystem_id: str
    physical_root_fingerprint: Digest
    capabilities: tuple[CapabilityClaimV1, ...]

    def __post_init__(self) -> None:
        if type(self.adapter_id) is not str or type(self.adapter_version) is not str:
            raise CanonicalJSONError("target adapter identity must use plain strings")
        require_public_component(self.adapter_id, field="target adapter identifier")
        require_public_component(self.adapter_version, field="target adapter version")
        for field_name, value in (
            ("platform_id", self.platform_id),
            ("filesystem_id", self.filesystem_id),
        ):
            if (
                type(value) is not str
                or not value
                or len(value) > 128
                or any(ord(character) < 0x20 for character in value)
            ):
                raise CanonicalJSONError(f"target {field_name} is invalid")
        if type(self.head_oid) is not str or type(self.tree_oid) is not str:
            raise CanonicalJSONError("target Git object IDs must be plain strings")
        if _OID_RE.fullmatch(self.head_oid) is None:
            raise CanonicalJSONError("target HEAD object ID is invalid")
        if _OID_RE.fullmatch(self.tree_oid) is None:
            raise CanonicalJSONError("target tree object ID is invalid")
        for value in (
            self.index_manifest_digest,
            self.worktree_manifest_digest,
            self.inventory_digest,
            self.status_digest,
            self.git_object_manifest_digest,
            self.ignore_provenance_digest,
            self.physical_root_fingerprint,
        ):
            if type(value) is not str:
                raise CanonicalJSONError("target digest fields must be plain strings")
            require_digest(value)
        if self.sanitized_remote_identity_digest is not None:
            if type(self.sanitized_remote_identity_digest) is not str:
                raise CanonicalJSONError(
                    "remote identity digest must be a plain string"
                )
            require_digest(self.sanitized_remote_identity_digest)
        if type(self.capabilities) is not tuple or any(
            type(item) is not CapabilityClaimV1 for item in self.capabilities
        ):
            raise CanonicalJSONError("target capabilities must be an immutable tuple")
        ordered = tuple(sorted(self.capabilities, key=lambda item: item.name))
        if self.capabilities != ordered:
            raise CanonicalJSONError("capability claims must be ordered by name")
        if len({item.name for item in self.capabilities}) != len(self.capabilities):
            raise CanonicalJSONError("capability claim names must be unique")

    @property
    def is_clean(self) -> bool:
        return self.status_digest == DIRECT_CLEAN_STATUS_DIGEST

    def record(self) -> StoredRecord:
        return make_record("TargetIdentity", target_identity_payload(self))


@dataclass(frozen=True, slots=True)
class InstructionFileV1:
    path: PathIdentityV1
    blob_oid: str
    byte_digest: Digest

    def __post_init__(self) -> None:
        if _OID_RE.fullmatch(self.blob_oid) is None:
            raise CanonicalJSONError("instruction blob object ID is invalid")
        require_digest(self.byte_digest)


@dataclass(frozen=True, slots=True)
class CaptureSnapshot:
    target: TargetIdentityV1
    instructions: tuple[InstructionFileV1, ...]
    target_policy_digest: Digest | None = None

    def __post_init__(self) -> None:
        if self.target_policy_digest is not None:
            require_digest(self.target_policy_digest)

    def instruction_record(self) -> StoredRecord:
        return make_record(
            "InstructionManifest", instruction_manifest_payload(self.instructions)
        )


@dataclass(frozen=True, slots=True)
class FileObservation:
    path: PathIdentityV1
    object_type: str
    mode: int
    size: int
    content_digest: Digest
    file_identity: tuple[int, int, int, int, int]

    def __post_init__(self) -> None:
        if type(self.path) is not PathIdentityV1:
            raise CanonicalJSONError("file observation path is invalid")
        if self.object_type not in {"file", "symlink"}:
            raise CanonicalJSONError("file observation object type is invalid")
        if type(self.mode) is not int or self.mode < 0:
            raise CanonicalJSONError("file observation mode is invalid")
        if type(self.size) is not int or self.size < 0:
            raise CanonicalJSONError("file observation size is invalid")
        if type(self.content_digest) is not str:
            raise CanonicalJSONError("file observation digest is invalid")
        require_digest(self.content_digest)
        if (
            type(self.file_identity) is not tuple
            or len(self.file_identity) != 5
            or any(type(item) is not int for item in self.file_identity)
        ):
            raise CanonicalJSONError("file observation identity is invalid")


@dataclass(frozen=True, slots=True)
class CapturedView:
    snapshot: CaptureSnapshot
    files: Mapping[PathIdentityV1, FileObservation]
    ephemeral_root: Path | None


@dataclass(frozen=True, slots=True)
class _LiveCapture:
    snapshot: CaptureSnapshot
    files: Mapping[PathIdentityV1, FileObservation]
    required_contents: Mapping[PathIdentityV1, bytes]


class TargetAdapter(Protocol):
    def capture(self, instruction_paths: Sequence[bytes]) -> CaptureSnapshot: ...


def target_identity_payload(target: TargetIdentityV1) -> JsonObject:
    capabilities: JsonObject = {}
    for item in target.capabilities:
        capabilities[item.name] = {
            "adapter_id": item.adapter_id,
            "adapter_version": item.adapter_version,
            "evidence_digest": item.evidence_digest,
            "status": item.status,
        }
    return {
        "adapter_id": target.adapter_id,
        "adapter_version": target.adapter_version,
        "capabilities": capabilities,
        "filesystem_id": target.filesystem_id,
        "git_object_manifest_digest": target.git_object_manifest_digest,
        "head_oid": target.head_oid,
        "ignore_provenance_digest": target.ignore_provenance_digest,
        "index_manifest_digest": target.index_manifest_digest,
        "inventory_digest": target.inventory_digest,
        "physical_root_fingerprint": target.physical_root_fingerprint,
        "platform_id": target.platform_id,
        "sanitized_remote_identity_digest": target.sanitized_remote_identity_digest,
        "status_digest": target.status_digest,
        "tree_oid": target.tree_oid,
        "worktree_manifest_digest": target.worktree_manifest_digest,
    }


def instruction_file_payload(value: InstructionFileV1) -> JsonObject:
    return {
        "blob_oid": value.blob_oid,
        "byte_digest": value.byte_digest,
        "path": path_identity_payload(value.path),
    }


def instruction_manifest_payload(
    instructions: tuple[InstructionFileV1, ...],
) -> JsonObject:
    return {"files": [instruction_file_payload(item) for item in instructions]}
