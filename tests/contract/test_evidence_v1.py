from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

from agent_continuity.kernel.canonical import digest_bytes
from agent_continuity.kernel.evidence import (
    EvidenceAuthority,
    InvalidatorKind,
    InvalidatorV1,
    evidence_v1,
)
from agent_continuity.kernel.records import (
    FactV1,
    RecordSchemaError,
    decode_record,
    encode_record,
)


def _golden() -> dict[str, str]:
    path = Path(__file__).parents[1] / "golden" / "evidence-v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_deterministic_evidence_requires_its_required_input_fields() -> None:
    value = evidence_v1()

    for field, replacement in (
        ("target_id", None),
        ("checkpoint_id", None),
        ("producer", None),
        ("payload_digest", None),
        ("facts", ()),
    ):
        with pytest.raises(RecordSchemaError):
            replace(value, **{field: replacement})  # type: ignore[arg-type]


def test_advisory_evidence_is_not_deterministic() -> None:
    value = evidence_v1(authority=EvidenceAuthority.ADVISORY)

    assert value.authority is EvidenceAuthority.ADVISORY


def test_expiry_cannot_precede_observation() -> None:
    with pytest.raises(RecordSchemaError, match="expiry"):
        evidence_v1(
            observed_at="2026-09-01T00:00:10Z",
            expires_at="2026-09-01T00:00:09Z",
        )


def test_invalidators_must_be_unique_and_canonically_sorted() -> None:
    first = InvalidatorV1(
        InvalidatorKind.CITATION, digest_bytes(b"first"), required=True
    )
    second = InvalidatorV1(
        InvalidatorKind.TARGET, digest_bytes(b"second"), required=False
    )

    with pytest.raises(RecordSchemaError, match="invalidators"):
        evidence_v1(invalidators=(second, first))
    with pytest.raises(RecordSchemaError, match="invalidators"):
        evidence_v1(invalidators=(first, first))


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("terminal_status", None),
        ("declared_output_digest", digest_bytes(b"declared")),
        ("observed_output_digest", digest_bytes(b"observed")),
        ("collected_check_count", 0),
        ("pagination_complete", False),
    ],
)
def test_complete_command_evidence_requires_complete_command_receipt(
    field: str, replacement: object
) -> None:
    with pytest.raises(RecordSchemaError, match="command"):
        replace(evidence_v1(), **{field: replacement})  # type: ignore[arg-type]


def test_decode_rejects_unknown_fact_fields_and_unknown_evidence_kind() -> None:
    encoded = encode_record(evidence_v1())
    payload = json.loads(encoded.canonical_bytes)
    payload["facts"][0]["unknown"] = True

    with pytest.raises(RecordSchemaError, match="fact fields"):
        decode_record(
            replace(
                encoded,
                canonical_bytes=json.dumps(
                    payload, sort_keys=True, separators=(",", ":")
                ).encode(),
            )
        )
    payload = json.loads(encoded.canonical_bytes)
    payload["kind"] = "unknown"
    with pytest.raises(RecordSchemaError, match="payload"):
        decode_record(
            replace(
                encoded,
                canonical_bytes=json.dumps(
                    payload, sort_keys=True, separators=(",", ":")
                ).encode(),
            )
        )


def test_evidence_golden_canonical_bytes_and_identity_are_stable() -> None:
    golden = _golden()
    encoded = encode_record(evidence_v1())

    assert base64.b64encode(encoded.canonical_bytes).decode("ascii") == golden[
        "canonical_b64"
    ]
    assert encoded.record_id == golden["record_id"]


def test_evidence_facts_are_immutable_and_canonically_sorted() -> None:
    earlier = FactV1(("alpha",), 1)
    later = FactV1(("zeta",), 2)

    with pytest.raises(RecordSchemaError, match="facts"):
        evidence_v1(facts=(later, earlier))
    with pytest.raises(RecordSchemaError, match="facts"):
        evidence_v1(facts=(earlier, earlier))
