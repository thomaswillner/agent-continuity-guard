from __future__ import annotations

import pytest

from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    canonical_loads,
    digest_bytes,
    record_id,
    validate_logical_time,
)


def test_canonical_json_normalizes_semantic_strings_and_sorts_keys() -> None:
    value = {"z": 2, "name": "e\u0301"}
    assert canonical_bytes(value) == b'{"name":"\xc3\xa9","z":2}'


def test_domain_separated_record_id_matches_golden_vector() -> None:
    value = {"z": 2, "name": "e\u0301"}
    assert record_id("Example", "v1", value) == (
        "sha256:82b307ef376f1e81dc3ba17b2ab503c0bceef10dcf29d1136fe7150faa0d3422"
    )


def test_digest_and_logical_time_are_strict() -> None:
    assert digest_bytes(b"value").startswith("sha256:")
    assert validate_logical_time("2026-08-08T12:00:00Z") == (
        "2026-08-08T12:00:00Z"
    )
    with pytest.raises(CanonicalJSONError):
        validate_logical_time("2026-08-08 12:00:00")


@pytest.mark.parametrize("value", [1.5, float("nan"), "line\nbreak"])
def test_canonical_json_rejects_forbidden_values(value: object) -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_bytes({"value": value})  # type: ignore[dict-item]


def test_loader_rejects_noncanonical_or_duplicate_input() -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_loads(b'{"b":2, "a":1}')
    with pytest.raises(CanonicalJSONError):
        canonical_loads(b'{"a":1,"a":2}')


def test_canonical_json_rejects_normalized_key_collision() -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_bytes({"e\u0301": 1, "\u00e9": 2})


@pytest.mark.parametrize(
    "value",
    [
        "2026-08-08T12:00:00.000Z",
        "2026-08-08T12:00:00+00:00",
        "2026-8-08T12:00:00Z",
        "2026-02-30T12:00:00Z",
    ],
)
def test_logical_time_requires_valid_canonical_utc_whole_seconds(value: str) -> None:
    with pytest.raises(CanonicalJSONError):
        validate_logical_time(value)
