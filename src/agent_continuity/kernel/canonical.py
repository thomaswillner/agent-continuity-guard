"""CanonicalJSON/v1 and domain-separated identities."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Callable
from datetime import datetime
from typing import NoReturn, cast

from .model import Digest, JsonObject, JsonValue, LogicalTime, RecordId

_LOGICAL_TIME_RE = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})Z$"
)
_CONTROL_RE = re.compile(r"[\x00-\x1f]")


class CanonicalJSONError(ValueError):
    """Input cannot be represented by CanonicalJSON/v1."""


def _normalize_string(value: str) -> str:
    if _CONTROL_RE.search(value):
        raise CanonicalJSONError("control characters are forbidden")
    return unicodedata.normalize("NFC", value)


def _normalize(value: object) -> JsonValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return _normalize_string(value)
    if isinstance(value, float):
        raise CanonicalJSONError("floating-point values are forbidden")
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError("object keys must be strings")
            normalized_key = _normalize_string(key)
            if normalized_key in normalized:
                raise CanonicalJSONError("normalized object keys collide")
            normalized[normalized_key] = _normalize(item)
        return normalized
    raise CanonicalJSONError("unsupported canonical JSON value")


def canonical_bytes(value: JsonValue) -> bytes:
    """Return the unique CanonicalJSON/v1 UTF-8 representation."""

    normalized = _normalize(value)
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:  # defensive boundary
        raise CanonicalJSONError("value cannot be encoded canonically") from error
    return encoded.encode("utf-8")


def _reject_constant(_value: str) -> NoReturn:
    raise CanonicalJSONError("non-finite numeric values are forbidden")


def _unique_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError("duplicate object key")
        result[key] = value
    return result


def canonical_loads(data: bytes) -> JsonObject:
    """Load a canonical top-level object and reject alternate encodings."""

    if not isinstance(data, bytes):
        raise CanonicalJSONError("canonical input must be bytes")
    try:
        text = data.decode("utf-8", errors="strict")
        loaded = json.loads(
            text,
            object_pairs_hook=cast(
                Callable[[list[tuple[str, object]]], object], _unique_object
            ),
            parse_constant=_reject_constant,
        )
    except CanonicalJSONError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalJSONError("invalid canonical JSON") from error
    if not isinstance(loaded, dict):
        raise CanonicalJSONError("canonical record must be an object")
    normalized = _normalize(loaded)
    if not isinstance(normalized, dict):  # narrowed above; defensive for typing
        raise CanonicalJSONError("canonical record must be an object")
    if canonical_bytes(normalized) != data:
        raise CanonicalJSONError("input is valid JSON but not canonical")
    return normalized


def digest_bytes(data: bytes) -> Digest:
    """Return a lowercase SHA-256 content digest."""

    return Digest("sha256:" + hashlib.sha256(data).hexdigest())


def validate_logical_time(value: str) -> LogicalTime:
    """Validate canonical UTC RFC 3339 whole-second logical time."""

    match = _LOGICAL_TIME_RE.fullmatch(value)
    if match is None:
        raise CanonicalJSONError("logical time must be canonical UTC whole seconds")
    try:
        datetime(
            int(match["year"]),
            int(match["month"]),
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
        )
    except ValueError as error:
        raise CanonicalJSONError("logical time is not a valid timestamp") from error
    return LogicalTime(value)


def record_id(
    record_type: str,
    schema_version: str,
    payload: JsonObject,
) -> RecordId:
    """Return a CanonicalJSON/v1 domain-separated record identity."""

    try:
        record_type_bytes = record_type.encode("ascii", errors="strict")
        schema_version_bytes = schema_version.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise CanonicalJSONError("record domain components must be ASCII") from error
    if not record_type_bytes or not schema_version_bytes:
        raise CanonicalJSONError("record domain components must be nonempty")
    if b"\x00" in record_type_bytes or b"\x00" in schema_version_bytes:
        raise CanonicalJSONError("record domain components contain NUL")
    preimage = (
        b"acg\x00"
        + record_type_bytes
        + b"\x00"
        + schema_version_bytes
        + b"\x00"
        + canonical_bytes(payload)
    )
    return RecordId("sha256:" + hashlib.sha256(preimage).hexdigest())
