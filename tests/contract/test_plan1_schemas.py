from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

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


def test_capture_schemas_accept_strict_golden_records() -> None:
    schemas = _schemas()
    expected_names = {
        "capability-claim.schema.json",
        "instruction-manifest.schema.json",
        "target-identity.schema.json",
    }
    assert expected_names <= schemas.keys()
    registry = _registry(schemas)
    digest = "sha256:" + "2" * 64
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
    positives = {
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
    for name, positive in positives.items():
        validator = Draft202012Validator(schemas[name], registry=registry)
        validator.validate(positive)
        with pytest.raises(ValidationError):
            validator.validate({**positive, "unexpected": True})
