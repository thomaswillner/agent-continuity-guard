#!/usr/bin/env python3
"""Verify strict schema registration, golden positives, and unknown fields."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from agent_continuity.kernel.canonical import canonical_bytes
from agent_continuity.kernel.records import SCHEMA_REGISTRY

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas" / "v1"


class SchemaVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _load() -> dict[str, dict[str, Any]]:
    loaded: dict[str, dict[str, Any]] = {}
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SchemaVerificationError("invalid_schema_json") from error
        if not isinstance(value, dict):
            raise SchemaVerificationError("invalid_schema")
        if type(value.get("$id")) is not str or type(
            value.get("x-record-type")
        ) is not str:
            raise SchemaVerificationError("invalid_schema_metadata")
        try:
            Draft202012Validator.check_schema(value)
        except Exception as error:
            raise SchemaVerificationError("invalid_schema") from error
        loaded[path.name] = value
    return loaded


def _registered_schemas(schemas: dict[str, dict[str, Any]]) -> dict[str, str]:
    registered: dict[str, str] = {}
    for name, schema in schemas.items():
        record_type = schema["x-record-type"]
        if not isinstance(record_type, str):
            raise SchemaVerificationError("invalid_schema_metadata")
        if record_type in registered:
            raise SchemaVerificationError("registry_mismatch")
        registered[record_type] = name
    if registered != SCHEMA_REGISTRY:
        raise SchemaVerificationError("registry_mismatch")
    return registered


def _goldens() -> dict[str, dict[str, Any]]:
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
        "evaluation-result.schema.json": {
            "findings": [],
            "schema": "EvaluationResult/v1",
            "transition_allowed": True,
            "verdict": "pass",
        },
        "fact.schema.json": {"field_path": ["target", "clean"], "value": True},
        "finding.schema.json": {
            "code": "target.dirty",
            "integrity_failure": False,
            "message_id": "acg.target.dirty",
            "parameters": {},
            "subject_id": digest,
            "verdict": "unknown",
        },
        "instruction-manifest.schema.json": {
            "files": [
                {"blob_oid": "a" * 40, "byte_digest": digest, "path": path}
            ]
        },
        "path-identity.schema.json": {
            "case_key_b64": None,
            "encoding": "posix-bytes",
            "raw_b64": "UkVBRE1FLm1k",
            "segment_offsets": [0],
        },
        "path-scope.schema.json": {"kind": "tree", "path": None},
        "producer-identity.schema.json": {
            "digest": digest,
            "name": "acg-git",
            "version": "1.0",
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


def main() -> int:
    try:
        schemas = _load()
        _registered_schemas(schemas)
        try:
            registry: Registry[Any] = Registry().with_resources(
                [
                    (schema["$id"], Resource.from_contents(schema))
                    for schema in schemas.values()
                ]
            )
        except Exception as error:
            raise SchemaVerificationError("invalid_schema_metadata") from error
        goldens = _goldens()
        if set(goldens) != set(schemas):
            raise SchemaVerificationError("golden_coverage_mismatch")
        for name, positive in goldens.items():
            validator = Draft202012Validator(schemas[name], registry=registry)
            try:
                validator.validate(positive)
            except Exception as error:
                raise SchemaVerificationError("invalid_golden") from error
            try:
                validator.validate({**positive, "unexpected": True})
            except ValidationError:
                pass
            except Exception as error:
                raise SchemaVerificationError("invalid_golden") from error
            else:
                raise SchemaVerificationError("schema_allows_unknown_fields")
    except SchemaVerificationError as error:
        sys.stdout.buffer.write(
            canonical_bytes(
                {
                    "code": error.code,
                    "schema": "SchemaVerification/v1",
                    "status": "fail",
                }
            )
        )
        return 1
    except Exception:
        sys.stdout.buffer.write(
            canonical_bytes(
                {
                    "code": "internal_verification_error",
                    "schema": "SchemaVerification/v1",
                    "status": "fail",
                }
            )
        )
        return 1

    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "schema": "SchemaVerification/v1",
                "schema_count": len(schemas),
                "status": "pass",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
