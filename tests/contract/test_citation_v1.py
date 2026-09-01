from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

from agent_continuity.kernel.canonical import digest_bytes
from agent_continuity.kernel.citation import (
    CitationV1,
    citation_payload,
    citation_v1,
)
from agent_continuity.kernel.paths import PathIdentityV1
from agent_continuity.kernel.records import (
    RecordSchemaError,
    decode_record,
    encode_record,
)


def _golden() -> dict[str, str]:
    path = Path(__file__).parents[1] / "golden" / "citation-v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_span_citation_requires_complete_bounds_and_digest() -> None:
    path = PathIdentityV1.from_bytes("posix-bytes", b"docs/guide.md")
    file_digest = digest_bytes(b"whole")

    for byte_start, byte_end, span_digest in (
        (4, None, None),
        (None, 8, None),
        (None, None, digest_bytes(b"span")),
    ):
        with pytest.raises(RecordSchemaError, match="supplied together"):
            CitationV1(path, file_digest, byte_start, byte_end, span_digest)


@pytest.mark.parametrize("byte_start, byte_end", [(-1, 1), (4, 4), (9, 4)])
def test_span_citation_rejects_negative_equal_and_reversed_offsets(
    byte_start: int, byte_end: int
) -> None:
    with pytest.raises(RecordSchemaError, match="byte range is invalid"):
        citation_v1(b"docs/guide.md", b"whole", byte_start, byte_end)


def test_span_citation_hashes_exact_raw_byte_slice() -> None:
    raw_file = b"A\xff\x00BC"
    citation = citation_v1(b"docs/guide.md", raw_file, 1, 4)

    assert citation.span_digest == digest_bytes(b"\xff\x00B")
    assert citation.file_digest == digest_bytes(raw_file)


def test_whole_file_citation_round_trips_canonically() -> None:
    citation = citation_v1(b"docs/guide.md", b"whole")

    assert decode_record(encode_record(citation)) == citation


def test_non_utf8_posix_path_bytes_are_preserved_in_canonical_citation() -> None:
    citation = citation_v1(b"docs/\xff.md", b"whole")

    assert citation.path.raw_bytes() == b"docs/\xff.md"
    assert citation_payload(citation)["path"]["raw_b64"] == "ZG9jcy__Lm1k"


def test_decode_rejects_unknown_fields_and_wrong_record_type_or_version() -> None:
    citation = citation_v1(b"docs/guide.md", b"whole")
    encoded = encode_record(citation)
    payload = json.loads(encoded.canonical_bytes)
    payload["unknown"] = True

    with pytest.raises(RecordSchemaError, match="fields"):
        decode_record(
            replace(
                encoded,
                canonical_bytes=json.dumps(
                    payload, sort_keys=True, separators=(",", ":")
                ).encode(),
            )
        )
    with pytest.raises(RecordSchemaError, match="record type"):
        decode_record(replace(encoded, record_type="Unknown"))
    with pytest.raises(RecordSchemaError, match="schema version"):
        decode_record(replace(encoded, schema_version="v2"))


def test_citation_golden_canonical_bytes_and_identity_are_stable() -> None:
    golden = _golden()
    citation = citation_v1(b"docs/\xff.md", b"whole")
    encoded = encode_record(citation)

    assert base64.b64encode(encoded.canonical_bytes).decode("ascii") == golden[
        "canonical_b64"
    ]
    assert encoded.record_id == golden["record_id"]
