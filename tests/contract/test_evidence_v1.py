from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

from agent_continuity.kernel.canonical import digest_bytes
from agent_continuity.kernel.evidence import (
    EvidenceAuthority,
    EvidenceCompleteness,
    EvidenceKind,
    InvalidatorKind,
    InvalidatorV1,
    evidence_v1,
)
from agent_continuity.kernel.model import LogicalTime, RecordId
from agent_continuity.kernel.records import (
    FactV1,
    ProducerIdentity,
    RecordSchemaError,
    decode_record,
    encode_record,
)
from tools import verify_schemas


def _golden() -> dict[str, str]:
    path = Path(__file__).parents[1] / "golden" / "evidence-v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _evidence(**changes: object):
    values: dict[str, object] = {
        "authority": EvidenceAuthority.DETERMINISTIC,
        "checkpoint_id": RecordId(digest_bytes(b"checkpoint")),
        "collected_check_count": 1,
        "completeness": EvidenceCompleteness.COMPLETE,
        "declared_output_digest": digest_bytes(b"stdout"),
        "expires_at": None,
        "facts": (FactV1(("target", "clean"), True),),
        "invalidators": (
            InvalidatorV1(
                InvalidatorKind.CITATION,
                RecordId(digest_bytes(b"citation")),
                required=True,
            ),
        ),
        "kind": EvidenceKind.COMMAND,
        "observed_at": LogicalTime("2026-09-01T00:00:00Z"),
        "observed_output_digest": digest_bytes(b"stdout"),
        "pagination_complete": True,
        "payload_digest": digest_bytes(b"payload"),
        "producer": ProducerIdentity("acg-test", "1", digest_bytes(b"producer")),
        "subject_digest": digest_bytes(b"subject"),
        "target_id": RecordId(digest_bytes(b"target")),
        "terminal_status": 0,
    }
    values.update(changes)
    return evidence_v1(**values)  # type: ignore[arg-type]


def test_deterministic_evidence_requires_its_required_input_fields() -> None:
    value = _evidence()

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
    value = _evidence(authority=EvidenceAuthority.ADVISORY)

    assert value.authority is EvidenceAuthority.ADVISORY


def test_expiry_cannot_precede_observation() -> None:
    with pytest.raises(RecordSchemaError, match="expiry"):
        _evidence(
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
        _evidence(invalidators=(second, first))
    with pytest.raises(RecordSchemaError, match="invalidators"):
        _evidence(invalidators=(first, first))


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
        replace(_evidence(), **{field: replacement})  # type: ignore[arg-type]


def test_decode_rejects_unknown_fact_fields_and_unknown_evidence_kind() -> None:
    encoded = encode_record(_evidence())
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
    encoded = encode_record(_evidence())

    assert base64.b64encode(encoded.canonical_bytes).decode("ascii") == golden[
        "canonical_b64"
    ]
    assert encoded.record_id == golden["record_id"]


def test_evidence_facts_are_immutable_and_canonically_sorted() -> None:
    earlier = FactV1(("alpha",), 1)
    later = FactV1(("zeta",), 2)

    with pytest.raises(RecordSchemaError, match="facts"):
        _evidence(facts=(later, earlier))
    with pytest.raises(RecordSchemaError, match="facts"):
        _evidence(facts=(earlier, earlier))


def test_builder_requires_explicit_proof_bearing_arguments() -> None:
    with pytest.raises(TypeError):
        evidence_v1()


def test_nullable_outputs_round_trip_through_schema_verifier() -> None:
    value = _evidence(
        kind=EvidenceKind.CITATION,
        completeness=EvidenceCompleteness.INCOMPLETE,
        terminal_status=None,
        declared_output_digest=None,
        observed_output_digest=None,
        collected_check_count=None,
        pagination_complete=None,
    )
    encoded = encode_record(value)
    payload = json.loads(encoded.canonical_bytes)
    schemas = verify_schemas._load()

    assert payload["declared_output_digest"] is None
    assert payload["observed_output_digest"] is None
    assert decode_record(encoded) == value
    verify_schemas.validate_schema_instance("evidence.schema.json", payload, schemas)
