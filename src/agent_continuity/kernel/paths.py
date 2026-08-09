"""Exact byte-preserving PathIdentity/v1 records and scopes."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from .canonical import CanonicalJSONError
from .model import JsonObject, StoredRecord

PathEncoding = Literal["posix-bytes", "git-path-bytes", "windows-utf16le"]
_PATH_ENCODINGS = frozenset({"posix-bytes", "git-path-bytes", "windows-utf16le"})


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not value or "=" in value:
        raise CanonicalJSONError("path byte encoding is not canonical base64url")
    try:
        encoded = value.encode("ascii", errors="strict")
        padding = b"=" * ((4 - len(encoded) % 4) % 4)
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise CanonicalJSONError("path byte encoding is invalid") from error
    if _b64encode(decoded) != value:
        raise CanonicalJSONError("path byte encoding is not canonical base64url")
    return decoded


def _posix_segment_offsets(raw: bytes) -> tuple[int, ...]:
    if not raw or raw.startswith(b"/") or b"\x00" in raw:
        raise CanonicalJSONError("path must be nonempty, relative, and NUL-free")
    segments = raw.split(b"/")
    if any(not segment for segment in segments):
        raise CanonicalJSONError("path contains an empty segment")
    if any(segment == b".." for segment in segments):
        raise CanonicalJSONError("path contains a parent traversal segment")
    offsets: list[int] = []
    offset = 0
    for segment in segments:
        offsets.append(offset)
        offset += len(segment) + 1
    return tuple(offsets)


def _windows_segment_offsets(raw: bytes) -> tuple[int, ...]:
    if not raw or len(raw) % 2:
        raise CanonicalJSONError("Windows path bytes must be nonempty UTF-16LE")
    try:
        text = raw.decode("utf-16le", errors="strict")
    except UnicodeDecodeError as error:
        raise CanonicalJSONError("Windows path is not valid UTF-16LE") from error
    if "\x00" in text or text.startswith(("\\", "/")):
        raise CanonicalJSONError("Windows path must be relative and NUL-free")
    if len(text) >= 2 and text[1] == ":":
        raise CanonicalJSONError("drive-qualified Windows paths are forbidden")
    segments: list[tuple[int, bytes]] = []
    start = 0
    for index in range(0, len(raw), 2):
        code_unit = raw[index : index + 2]
        if code_unit in {b"\\\x00", b"/\x00"}:
            segments.append((start, raw[start:index]))
            start = index + 2
    segments.append((start, raw[start:]))
    if any(not segment for _, segment in segments):
        raise CanonicalJSONError("path contains an empty segment")
    if any(segment == b".\x00.\x00" for _, segment in segments):
        raise CanonicalJSONError("path contains a parent traversal segment")
    return tuple(index for index, _ in segments)


def _segment_offsets(encoding: PathEncoding, raw: bytes) -> tuple[int, ...]:
    if encoding == "windows-utf16le":
        return _windows_segment_offsets(raw)
    return _posix_segment_offsets(raw)


def _trusted_case_key(encoding: PathEncoding, raw: bytes) -> bytes:
    """Derive the sole CaseKey/v1 normalization admitted by the kernel."""

    if encoding == "windows-utf16le":
        try:
            return raw.decode("utf-16le", errors="strict").casefold().encode("utf-16le")
        except UnicodeError as error:
            raise CanonicalJSONError("Windows case key source is invalid") from error
    uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowercase = b"abcdefghijklmnopqrstuvwxyz"
    return raw.translate(bytes.maketrans(uppercase, lowercase))


def _path_components(encoding: PathEncoding, raw: bytes) -> tuple[bytes, ...]:
    if encoding != "windows-utf16le":
        return tuple(raw.split(b"/"))
    components: list[bytes] = []
    start = 0
    for index in range(0, len(raw), 2):
        if raw[index : index + 2] in {b"\\\x00", b"/\x00"}:
            components.append(raw[start:index])
            start = index + 2
    components.append(raw[start:])
    return tuple(components)


@dataclass(frozen=True, slots=True)
class PathIdentityV1:
    """Exact path bytes with explicit platform encoding and segment starts."""

    encoding: PathEncoding
    raw_b64: str
    segment_offsets: tuple[int, ...]
    case_key_b64: str | None

    def __post_init__(self) -> None:
        if type(self.encoding) is not str:
            raise CanonicalJSONError("path encoding must be a plain string")
        if self.encoding not in _PATH_ENCODINGS:
            raise CanonicalJSONError("unsupported path encoding")
        if type(self.raw_b64) is not str:
            raise CanonicalJSONError("path byte encoding must be a plain string")
        if type(self.segment_offsets) is not tuple or any(
            type(item) is not int for item in self.segment_offsets
        ):
            raise CanonicalJSONError("path offsets must be an immutable integer tuple")
        raw = _b64decode(self.raw_b64)
        expected_offsets = _segment_offsets(self.encoding, raw)
        if self.segment_offsets != expected_offsets:
            raise CanonicalJSONError("path segment offsets do not match raw bytes")
        if self.case_key_b64 is not None:
            if type(self.case_key_b64) is not str:
                raise CanonicalJSONError("case key must be a plain string")
            case_key = _b64decode(self.case_key_b64)
            if case_key != _trusted_case_key(self.encoding, raw):
                raise CanonicalJSONError(
                    "case key is not a trusted CaseKey/v1 derivation"
                )

    @classmethod
    def from_bytes(
        cls,
        encoding: PathEncoding,
        raw: bytes,
        *,
        case_key: bytes | None = None,
    ) -> PathIdentityV1:
        invalid_case_key = case_key is not None and type(case_key) is not bytes
        if type(raw) is not bytes or invalid_case_key:
            raise CanonicalJSONError("path and case key inputs must be exact bytes")
        offsets = _segment_offsets(encoding, raw)
        return cls(
            encoding=encoding,
            raw_b64=_b64encode(raw),
            segment_offsets=offsets,
            case_key_b64=None if case_key is None else _b64encode(case_key),
        )

    def raw_bytes(self) -> bytes:
        return _b64decode(self.raw_b64)

    def case_key_bytes(self) -> bytes | None:
        if self.case_key_b64 is None:
            return None
        return _b64decode(self.case_key_b64)

    def display(self) -> str:
        """Return an escaped, non-identity display string."""

        if self.encoding == "windows-utf16le":
            try:
                return self.raw_bytes().decode("utf-16le", errors="strict")
            except UnicodeDecodeError:  # constructor already rejects this
                return "<invalid-windows-path>"
        pieces: list[str] = []
        for byte in self.raw_bytes():
            if 0x20 <= byte <= 0x7E and byte != 0x5C:
                pieces.append(chr(byte))
            elif byte == 0x5C:
                pieces.append("\\\\")
            else:
                pieces.append(f"\\x{byte:02x}")
        return "".join(pieces)

    def record(self) -> StoredRecord:
        from .records import make_record

        return make_record("PathIdentity", path_identity_payload(self))


class PathScopeKind(StrEnum):
    FILE = "file"
    TREE = "tree"


@dataclass(frozen=True, slots=True)
class PathScopeV1:
    path: PathIdentityV1 | None
    kind: PathScopeKind

    def __post_init__(self) -> None:
        if type(self.kind) is not PathScopeKind:
            raise CanonicalJSONError("path scope kind must be a PathScopeKind")
        if self.path is not None and type(self.path) is not PathIdentityV1:
            raise CanonicalJSONError("path scope path must be a PathIdentityV1")
        if self.path is None and self.kind is not PathScopeKind.TREE:
            raise CanonicalJSONError("only a TREE scope may denote target root")

    def contains(self, candidate: PathIdentityV1) -> bool:
        if type(candidate) is not PathIdentityV1:
            return False
        if self.path is None:
            return True
        if self.path.encoding != candidate.encoding:
            return False
        scope_case_key = self.path.case_key_bytes()
        candidate_case_key = candidate.case_key_bytes()
        if (scope_case_key is None) != (candidate_case_key is None):
            return False
        scope_raw = self.path.raw_bytes() if scope_case_key is None else scope_case_key
        candidate_raw = (
            candidate.raw_bytes() if candidate_case_key is None else candidate_case_key
        )
        scope_components = _path_components(self.path.encoding, scope_raw)
        candidate_components = _path_components(candidate.encoding, candidate_raw)
        if self.kind is PathScopeKind.FILE:
            return candidate_components == scope_components
        return candidate_components[: len(scope_components)] == scope_components


def detect_case_collisions(paths: tuple[PathIdentityV1, ...]) -> None:
    observed: dict[tuple[str, bytes], bytes] = {}
    for path in paths:
        case_key = path.case_key_bytes()
        if case_key is None:
            continue
        key = (path.encoding, case_key)
        raw = path.raw_bytes()
        prior = observed.setdefault(key, raw)
        if prior != raw:
            raise CanonicalJSONError("case-colliding paths are forbidden")


def path_identity_payload(identity: PathIdentityV1) -> JsonObject:
    return {
        "case_key_b64": identity.case_key_b64,
        "encoding": identity.encoding,
        "raw_b64": identity.raw_b64,
        "segment_offsets": list(identity.segment_offsets),
    }


def path_scope_payload(scope: PathScopeV1) -> JsonObject:
    return {
        "kind": scope.kind.value,
        "path": None if scope.path is None else path_identity_payload(scope.path),
    }


def parse_path_encoding(value: str) -> PathEncoding:
    if value not in _PATH_ENCODINGS:
        raise CanonicalJSONError("unsupported path encoding")
    return cast(PathEncoding, value)


def parse_path_scope_kind(value: str) -> PathScopeKind:
    if type(value) is not str:
        raise CanonicalJSONError("path scope kind must be a plain string")
    try:
        return PathScopeKind(value)
    except ValueError as error:
        raise CanonicalJSONError("unsupported path scope kind") from error
