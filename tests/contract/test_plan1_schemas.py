from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from agent_continuity.capture.base import TargetIdentityV1
from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    digest_bytes,
)
from agent_continuity.kernel.capabilities import CapabilityClaimV1
from tools import verify_schemas

SCHEMA_ROOT = Path(__file__).parents[2] / "schemas" / "v1"


def _schemas() -> dict[str, dict[str, Any]]:
    loaded: dict[str, dict[str, Any]] = {}
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        loaded[path.name] = schema
    return loaded


def _registry(schemas: dict[str, dict[str, Any]]) -> Registry[Any]:
    resources = [
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    ]
    return Registry().with_resources(resources)


def test_plan1_core_schemas_accept_golden_records_and_reject_unknown_fields() -> None:
    schemas = _schemas()
    expected_names = {
        "evaluation-result.schema.json",
        "fact.schema.json",
        "finding.schema.json",
        "path-identity.schema.json",
        "path-scope.schema.json",
        "producer-identity.schema.json",
    }
    assert expected_names <= schemas.keys()
    registry = _registry(schemas)
    digest = "sha256:" + "1" * 64
    positives: dict[str, dict[str, Any]] = {
        "path-identity.schema.json": {
            "case_key_b64": None,
            "encoding": "posix-bytes",
            "raw_b64": "UkVBRE1FLm1k",
            "segment_offsets": [0],
        },
        "path-scope.schema.json": {
            "kind": "tree",
            "path": None,
        },
        "producer-identity.schema.json": {
            "digest": digest,
            "name": "acg-git",
            "version": "1.0",
        },
        "fact.schema.json": {
            "field_path": ["target", "clean"],
            "value": True,
        },
        "finding.schema.json": {
            "code": "target.dirty",
            "integrity_failure": False,
            "message_id": "acg.target.dirty",
            "parameters": {},
            "subject_id": digest,
            "verdict": "unknown",
        },
        "evaluation-result.schema.json": {
            "findings": [],
            "schema": "EvaluationResult/v1",
            "transition_allowed": True,
            "verdict": "pass",
        },
    }

    for name, positive in positives.items():
        validator = Draft202012Validator(schemas[name], registry=registry)
        validator.validate(positive)
        negative = {**positive, "unexpected": True}
        with pytest.raises(ValidationError):
            validator.validate(negative)


def test_file_path_scope_cannot_use_null_root() -> None:
    schemas = _schemas()
    registry = _registry(schemas)
    validator = Draft202012Validator(
        schemas["path-scope.schema.json"], registry=registry
    )

    with pytest.raises(ValidationError):
        validator.validate({"kind": "file", "path": None})


def _capture_schema_goldens() -> dict[str, dict[str, Any]]:
    digest = "sha256:" + "1" * 64
    capability = {
        "adapter_id": "acg-git",
        "adapter_version": "1",
        "evidence_digest": digest,
        "name": "git_immutable_objects",
        "status": "proven",
    }
    path = {
        "case_key_b64": None,
        "encoding": "git-path-bytes",
        "raw_b64": "QUdFTlRTLm1k",
        "segment_offsets": [0],
    }
    return {
        "capability-claim.schema.json": capability,
        "instruction-manifest.schema.json": {
            "files": [
                {"blob_oid": "a" * 40, "byte_digest": digest, "path": path}
            ]
        },
        "target-identity.schema.json": {
            "adapter_id": "acg-git",
            "adapter_version": "1",
            "capabilities": [capability],
            "filesystem_id": "posix:darwin",
            "git_object_manifest_digest": digest,
            "head_oid": "a" * 40,
            "ignore_provenance_digest": digest,
            "index_manifest_digest": digest,
            "inventory_digest": digest,
            "physical_root_fingerprint": digest,
            "platform_id": "darwin",
            "sanitized_remote_identity_digest": None,
            "status_digest": digest,
            "tree_oid": "b" * 40,
            "worktree_manifest_digest": digest,
        },
    }


def test_capture_schemas_accept_strict_golden_records() -> None:
    schemas = _schemas()
    expected_names = {
        "capability-claim.schema.json",
        "instruction-manifest.schema.json",
        "target-identity.schema.json",
    }
    assert expected_names <= schemas.keys()
    registry = _registry(schemas)
    positives = _capture_schema_goldens()
    for name, positive in positives.items():
        validator = Draft202012Validator(schemas[name], registry=registry)
        validator.validate(positive)
        with pytest.raises(ValidationError):
            validator.validate({**positive, "unexpected": True})


def test_capture_goldens_have_complete_independent_tool_parity() -> None:
    tool_goldens = verify_schemas._goldens()
    capture_goldens = _capture_schema_goldens()

    assert {name: tool_goldens[name] for name in capture_goldens} == capture_goldens


def test_capability_schema_requires_evidence_when_status_is_proven() -> None:
    schemas = _schemas()
    validator = Draft202012Validator(schemas["capability-claim.schema.json"])
    invalid = {
        "adapter_id": "acg-git",
        "adapter_version": "1",
        "evidence_digest": None,
        "name": "git_immutable_objects",
        "status": "proven",
    }

    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_target_schema_rejects_duplicate_capability_records() -> None:
    schemas = _schemas()
    registry = _registry(schemas)
    positive = _capture_schema_goldens()["target-identity.schema.json"]
    capability = positive["capabilities"][0]
    invalid = {**positive, "capabilities": [capability, capability]}

    with pytest.raises(ValidationError):
        Draft202012Validator(
            schemas["target-identity.schema.json"], registry=registry
        ).validate(invalid)


def test_runtime_target_rejects_schema_invalid_public_strings() -> None:
    digest = digest_bytes(b"value")
    capability = CapabilityClaimV1(
        name="git_immutable_objects",
        status="proven",
        adapter_id="acg-git",
        adapter_version="1",
        evidence_digest=digest,
    )

    with pytest.raises(CanonicalJSONError):
        TargetIdentityV1(
            adapter_id="acg-git",
            adapter_version="1",
            sanitized_remote_identity_digest=None,
            head_oid="a" * 40,
            tree_oid="b" * 40,
            index_manifest_digest=digest,
            worktree_manifest_digest=digest,
            inventory_digest=digest,
            status_digest=digest,
            git_object_manifest_digest=digest,
            ignore_provenance_digest=digest,
            platform_id="bad\nplatform",
            filesystem_id="posix:darwin",
            physical_root_fingerprint=digest,
            capabilities=(capability,),
        )


def test_schema_verifier_enforces_capability_name_order_and_uniqueness() -> None:
    semantic_validate = getattr(verify_schemas, "_semantic_validate", None)
    assert callable(semantic_validate)
    target = _capture_schema_goldens()["target-identity.schema.json"]
    first = target["capabilities"][0]
    second = {**first, "name": "descriptor_pinned_reads"}
    unordered = {**target, "capabilities": [first, second]}

    with pytest.raises(verify_schemas.SchemaVerificationError):
        semantic_validate("target-identity.schema.json", unordered)


def _valid_tool_schema(*, schema_id: str, record_type: str) -> dict[str, Any]:
    return {
        "$id": schema_id,
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
        "type": "object",
        "x-record-type": record_type,
    }


@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    [
        ("invalid_schema", "invalid_schema"),
        ("missing_id", "invalid_schema_metadata"),
        ("unresolved_ref", "invalid_golden"),
        ("duplicate_record_type", "registry_mismatch"),
        ("missing_record_type", "invalid_schema_metadata"),
        ("malformed_golden", "invalid_golden"),
        ("unknown_fields", "schema_allows_unknown_fields"),
    ],
)
def test_schema_verifier_normalizes_every_expected_failure_as_canonical_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    scenario: str,
    expected_code: str,
) -> None:
    root = tmp_path / "schemas"
    root.mkdir()
    first_name = "example.schema.json"
    first = _valid_tool_schema(
        schema_id="https://example.invalid/example.schema.json",
        record_type="Example/v1",
    )
    registry = {"Example/v1": first_name}
    goldens: dict[str, dict[str, Any]] = {first_name: {"value": "ok"}}

    if scenario == "invalid_schema":
        first["type"] = "not-a-json-schema-type"
    elif scenario == "missing_id":
        del first["$id"]
    elif scenario == "unresolved_ref":
        first["properties"] = {
            "value": {"$ref": "https://example.invalid/missing.schema.json"}
        }
    elif scenario == "duplicate_record_type":
        second_name = "second.schema.json"
        second = _valid_tool_schema(
            schema_id="https://example.invalid/second.schema.json",
            record_type="Example/v1",
        )
        (root / second_name).write_text(json.dumps(second), encoding="utf-8")
        registry["Second/v1"] = second_name
        goldens[second_name] = {"value": "ok"}
    elif scenario == "missing_record_type":
        del first["x-record-type"]
    elif scenario == "malformed_golden":
        goldens[first_name] = {"value": 1}
    elif scenario == "unknown_fields":
        del first["additionalProperties"]
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError(scenario)

    (root / first_name).write_text(json.dumps(first), encoding="utf-8")
    monkeypatch.setattr(verify_schemas, "SCHEMA_ROOT", root)
    monkeypatch.setattr(verify_schemas, "SCHEMA_REGISTRY", registry)
    monkeypatch.setattr(verify_schemas, "_goldens", lambda: goldens)

    exit_code = verify_schemas.main()
    captured = capfd.readouterr()

    assert exit_code == 1
    assert captured.err == ""
    assert captured.out.encode("utf-8") == canonical_bytes(
        {
            "code": expected_code,
            "schema": "SchemaVerification/v1",
            "status": "fail",
        }
    )
