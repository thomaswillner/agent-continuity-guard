"""Strict Citation/v1 records over exact path and byte identities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .canonical import digest_bytes
from .model import Digest, JsonObject, JsonValue, StoredRecord
from .paths import PathIdentityV1, parse_path_encoding, path_identity_payload
from .records import RecordSchemaError, make_record, require_digest


@dataclass(frozen=True, slots=True)
class CitationV1:
    path: PathIdentityV1
    file_digest: Digest
    byte_start: int | None = None
    byte_end: int | None = None
    span_digest: Digest | None = None

    def __post_init__(self) -> None:
        validate_citation(self)

    def record(self) -> StoredRecord:
        return make_record("Citation", citation_payload(self))


def validate_citation(value: CitationV1) -> None:
    """Reject incomplete, ambiguous, or invalid raw-byte spans."""

    if type(value) is not CitationV1:
        raise RecordSchemaError("citation is invalid")
    if type(value.path) is not PathIdentityV1:
        raise RecordSchemaError("citation path is invalid")
    try:
        require_digest(value.file_digest)
    except ValueError as error:
        raise RecordSchemaError("citation file digest is invalid") from error
    span = (value.byte_start, value.byte_end, value.span_digest)
    if span == (None, None, None):
        return
    if any(part is None for part in span):
        raise RecordSchemaError("citation span fields must be supplied together")
    if type(value.byte_start) is not int or type(value.byte_end) is not int:
        raise RecordSchemaError("citation byte range is invalid")
    assert value.span_digest is not None
    try:
        require_digest(value.span_digest)
    except ValueError as error:
        raise RecordSchemaError("citation span digest is invalid") from error
    if value.byte_start < 0 or value.byte_start >= value.byte_end:
        raise RecordSchemaError("citation byte range is invalid")


def citation_payload(citation: CitationV1) -> JsonObject:
    validate_citation(citation)
    return {
        "byte_end": citation.byte_end,
        "byte_start": citation.byte_start,
        "file_digest": citation.file_digest,
        "path": path_identity_payload(citation.path),
        "span_digest": citation.span_digest,
    }


def citation_v1(
    path_bytes: bytes,
    file_bytes: bytes,
    byte_start: int | None = None,
    byte_end: int | None = None,
) -> CitationV1:
    """Construct Citation/v1 from explicit POSIX path and raw file bytes."""

    if type(path_bytes) is not bytes or type(file_bytes) is not bytes:
        raise RecordSchemaError("citation bytes are invalid")
    span_digest = None
    if byte_start is not None or byte_end is not None:
        if type(byte_start) is not int or type(byte_end) is not int:
            raise RecordSchemaError("citation byte range is invalid")
        if byte_start < 0 or byte_start >= byte_end or byte_end > len(file_bytes):
            raise RecordSchemaError("citation byte range is invalid")
        span_digest = digest_bytes(file_bytes[byte_start:byte_end])
    return CitationV1(
        path=PathIdentityV1.from_bytes("posix-bytes", path_bytes),
        file_digest=digest_bytes(file_bytes),
        byte_start=byte_start,
        byte_end=byte_end,
        span_digest=span_digest,
    )


def citation_from_payload(payload: JsonObject) -> CitationV1:
    """Decode Citation/v1 only from a complete exact canonical payload."""

    expected = {"byte_end", "byte_start", "file_digest", "path", "span_digest"}
    if set(payload) != expected:
        raise RecordSchemaError("citation fields are invalid")
    path_payload = payload["path"]
    if type(path_payload) is not dict:
        raise RecordSchemaError("citation path is invalid")
    if set(path_payload) != {
        "case_key_b64",
        "encoding",
        "raw_b64",
        "segment_offsets",
    }:
        raise RecordSchemaError("citation path fields are invalid")
    encoding = _string_field(path_payload, "encoding")
    raw_b64 = _string_field(path_payload, "raw_b64")
    case_key_b64 = _optional_string_field(path_payload, "case_key_b64")
    segment_offsets = _integer_tuple_field(path_payload, "segment_offsets")
    try:
        path = PathIdentityV1(
            encoding=parse_path_encoding(encoding),
            raw_b64=raw_b64,
            segment_offsets=segment_offsets,
            case_key_b64=case_key_b64,
        )
        return CitationV1(
            path=path,
            file_digest=Digest(_string_field(payload, "file_digest")),
            byte_start=_optional_integer_field(payload, "byte_start"),
            byte_end=_optional_integer_field(payload, "byte_end"),
            span_digest=(
                None
                if payload["span_digest"] is None
                else Digest(_string_field(payload, "span_digest"))
            ),
        )
    except (TypeError, ValueError) as error:
        raise RecordSchemaError("citation payload is invalid") from error


def _string_field(payload: JsonObject, field: str) -> str:
    value = payload[field]
    if type(value) is not str:
        raise RecordSchemaError("citation payload is invalid")
    return value


def _optional_string_field(payload: JsonObject, field: str) -> str | None:
    value = payload[field]
    if value is None:
        return None
    if type(value) is not str:
        raise RecordSchemaError("citation payload is invalid")
    return value


def _optional_integer_field(payload: JsonObject, field: str) -> int | None:
    value = payload[field]
    if value is None:
        return None
    if type(value) is not int:
        raise RecordSchemaError("citation payload is invalid")
    return value


def _integer_tuple_field(payload: JsonObject, field: str) -> tuple[int, ...]:
    value: JsonValue = payload[field]
    if type(value) is not list or any(type(item) is not int for item in value):
        raise RecordSchemaError("citation payload is invalid")
    return tuple(cast(list[int], value))
