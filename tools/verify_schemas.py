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


def _load() -> dict[str, dict[str, Any]]:
    loaded: dict[str, dict[str, Any]] = {}
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"schema is not an object: {path.name}")
        Draft202012Validator.check_schema(value)
        loaded[path.name] = value
    return loaded


def _goldens() -> dict[str, dict[str, Any]]:
    digest = "sha256:" + "1" * 64
    return {
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
    }


def main() -> int:
    try:
        schemas = _load()
        registered = {
            schema.get("x-record-type"): name for name, schema in schemas.items()
        }
        if registered != SCHEMA_REGISTRY:
            raise ValueError("schema registry does not match public schema identifiers")
        registry: Registry[Any] = Registry().with_resources(
            [
                (schema["$id"], Resource.from_contents(schema))
                for schema in schemas.values()
            ]
        )
        goldens = _goldens()
        if set(goldens) != set(schemas):
            raise ValueError("schema golden coverage is incomplete")
        for name, positive in goldens.items():
            validator = Draft202012Validator(schemas[name], registry=registry)
            validator.validate(positive)
            try:
                validator.validate({**positive, "unexpected": True})
            except ValidationError:
                pass
            else:
                raise ValueError(f"schema accepts unknown top-level fields: {name}")
    except (OSError, ValueError, ValidationError, json.JSONDecodeError) as error:
        sys.stdout.buffer.write(
            canonical_bytes(
                {
                    "schema": "SchemaVerification/v1",
                    "status": "fail",
                    "error_type": type(error).__name__,
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
