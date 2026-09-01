#!/usr/bin/env python3
"""Verify strict schema registration, golden positives, and unknown fields."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    validate_logical_time,
)
from agent_continuity.kernel.checkpoint import verification_result_payload
from agent_continuity.kernel.citation import (
    citation_from_payload,
    citation_payload,
    citation_v1,
)
from agent_continuity.kernel.evaluation import EvaluationResult, Verdict
from agent_continuity.kernel.evidence import (
    evidence_from_payload,
    evidence_payload,
    evidence_v1,
)
from agent_continuity.kernel.findings import Finding
from agent_continuity.kernel.model import (
    AssignmentAuthority,
    Digest,
    LogicalTime,
    RecordId,
)
from agent_continuity.kernel.paths import (
    PathIdentityV1,
    PathScopeV1,
    parse_path_encoding,
    parse_path_scope_kind,
)
from agent_continuity.kernel.records import (
    SCHEMA_REGISTRY,
    CriterionV1,
    ProducerIdentity,
    UnresolvedItemV1,
    WorkItemV1,
    build_actor,
    build_checkpoint,
    build_criterion,
    build_ruleset,
    criterion_payload,
)
from agent_continuity.output import ErrorRecord, error_payload

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas" / "v1"


class SchemaVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def schema_format_checker() -> FormatChecker:
    checker = FormatChecker()

    @checker.checks("date-time")
    def canonical_logical_time(value: object) -> bool:
        if type(value) is not str:
            return False
        try:
            validate_logical_time(value)
        except ValueError:
            return False
        return True

    return checker


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


def _record_ids(values: list[str]) -> tuple[RecordId, ...]:
    return tuple(RecordId(value) for value in values)


def _optional_record_id(value: str | None) -> RecordId | None:
    return None if value is None else RecordId(value)


def _path_scope_from_payload(instance: dict[str, Any]) -> PathScopeV1:
    path_payload = instance["path"]
    path = None
    if path_payload is not None:
        path = PathIdentityV1(
            encoding=parse_path_encoding(path_payload["encoding"]),
            raw_b64=path_payload["raw_b64"],
            segment_offsets=tuple(path_payload["segment_offsets"]),
            case_key_b64=path_payload["case_key_b64"],
        )
    return PathScopeV1(
        path=path,
        kind=parse_path_scope_kind(instance["kind"]),
    )


def validate_checkpoint_runtime_payload(instance: dict[str, Any]) -> None:
    """Reconstruct Checkpoint/v1 through public models for semantic admission."""

    criteria = tuple(
        CriterionV1(
            criterion_id=RecordId(item["criterion_id"]),
            ordinal=item["ordinal"],
            digest=Digest(item["digest"]),
        )
        for item in instance["acceptance_criteria"]
    )
    pending_work = tuple(
        WorkItemV1(
            work_item_id=RecordId(item["work_item_id"]),
            kind=item["kind"],
            status_code=item["status_code"],
            digest=Digest(item["digest"]),
        )
        for item in instance["pending_work"]
    )
    unresolved = tuple(
        UnresolvedItemV1(
            unresolved_id=RecordId(item["unresolved_id"]),
            code=item["code"],
            digest=None if item["digest"] is None else Digest(item["digest"]),
        )
        for item in instance["unresolved"]
    )
    checkpoint = build_checkpoint(
        parent_checkpoint_id=_optional_record_id(instance["parent_checkpoint_id"]),
        target_id=RecordId(instance["target_id"]),
        goal_id=RecordId(instance["goal_id"]),
        acceptance_criteria=criteria,
        constraint_digests=tuple(
            Digest(value) for value in instance["constraint_digests"]
        ),
        instruction_id=RecordId(instance["instruction_id"]),
        policy_id=RecordId(instance["policy_id"]),
        ruleset_id=RecordId(instance["ruleset_id"]),
        actor_ids=_record_ids(instance["actor_ids"]),
        evidence_ids=_record_ids(instance["evidence_ids"]),
        invalidation_ids=_record_ids(instance["invalidation_ids"]),
        accepted_decision_ids=_record_ids(instance["accepted_decision_ids"]),
        pending_work=pending_work,
        unresolved=unresolved,
        assignment_authority=AssignmentAuthority(instance["assignment_authority"]),
        authority_scopes=tuple(
            _path_scope_from_payload(item) for item in instance["authority_scopes"]
        ),
        open_assignment_ids=_record_ids(instance["open_assignment_ids"]),
        audit_parent_id=_optional_record_id(instance["audit_parent_id"]),
        initialization_intent_id=RecordId(instance["initialization_intent_id"]),
        created_at=LogicalTime(instance["created_at"]),
    )
    checkpoint.record()


def _semantic_validate(name: str, instance: dict[str, Any]) -> None:
    if (
        name == "capability-claim.schema.json"
        and instance.get("status") == "proven"
        and instance.get(
            "evidence_digest"
        )
        is None
    ):
        raise SchemaVerificationError("invalid_golden")
    try:
        if name == "actor.schema.json":
            producer = instance["producer"]
            build_actor(
                producer=ProducerIdentity(
                    producer["name"],
                    producer["version"],
                    Digest(producer["digest"]),
                ),
                authority=AssignmentAuthority(instance["authority"]),
                scope_ids=_record_ids(instance["scope_ids"]),
            )
        elif name == "ruleset.schema.json":
            build_ruleset(_record_ids(instance["rule_ids"]))
        elif name == "checkpoint.schema.json":
            validate_checkpoint_runtime_payload(instance)
        elif name == "citation.schema.json":
            citation_from_payload(instance)
        elif name == "evidence.schema.json":
            evidence_from_payload(instance)
        elif name == "verification-result.schema.json":
            findings = tuple(
                Finding(
                    code=item["code"],
                    verdict=Verdict(item["verdict"]),
                    subject_id=RecordId(item["subject_id"]),
                    message_id=item["message_id"],
                    parameters=item["parameters"],
                    integrity_failure=item["integrity_failure"],
                )
                for item in instance["findings"]
            )
            result = EvaluationResult(
                verdict=Verdict(instance["verdict"]),
                transition_allowed=instance["transition_allowed"],
                findings=findings,
            )
            if verification_result_payload(result) != instance:
                raise SchemaVerificationError("invalid_instance")
        elif name == "error.schema.json":
            error = ErrorRecord(
                category=instance["category"],
                code=instance["code"],
                message_id=instance["message_id"],
            )
            if error_payload(error) != instance:
                raise SchemaVerificationError("invalid_instance")
    except (CanonicalJSONError, KeyError, TypeError, ValueError) as error:
        raise SchemaVerificationError("invalid_instance") from error


def schema_validator(
    name: str,
    schemas: dict[str, dict[str, Any]],
) -> Draft202012Validator:
    if name not in schemas:
        raise SchemaVerificationError("unknown_schema")
    try:
        registry: Registry[Any] = Registry().with_resources(
            [
                (schema["$id"], Resource.from_contents(schema))
                for schema in schemas.values()
            ]
        )
    except Exception as error:
        raise SchemaVerificationError("invalid_schema_metadata") from error
    return Draft202012Validator(
        schemas[name],
        registry=registry,
        format_checker=schema_format_checker(),
    )


def validate_schema_instance(
    name: str,
    instance: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
) -> None:
    schema_validator(name, schemas).validate(instance)
    _semantic_validate(name, instance)


def schema_goldens() -> dict[str, dict[str, Any]]:
    digest = "sha256:" + "1" * 64
    criterion = build_criterion(ordinal=0, digest=Digest(digest))
    capability = {
        "adapter_id": "acg-git",
        "adapter_version": "1",
        "evidence_digest": digest,
        "name": "git_immutable_objects",
        "status": "proven",
    }
    target_capability = {
        "adapter_id": "acg-git",
        "adapter_version": "1",
        "evidence_digest": digest,
        "status": "proven",
    }
    path = {
        "case_key_b64": None,
        "encoding": "git-path-bytes",
        "raw_b64": "QUdFTlRTLm1k",
        "segment_offsets": [0],
    }
    citation = citation_v1(b"docs/guide.md", b"whole")
    evidence = evidence_v1()
    return {
        "actor.schema.json": {
            "authority": "read_only",
            "producer": {
                "digest": digest,
                "name": "agent-continuity-guard",
                "version": "0.1.0.dev0",
            },
            "scope_ids": [digest],
        },
        "audit-anchor.schema.json": {
            "audit_head_id": digest,
            "audit_sequence": 1,
            "created_at": "2026-08-09T12:00:00Z",
            "label": None,
            "store_id": "store-test",
        },
        "audit-event.schema.json": {
            "details": {},
            "head_updates": {
                "checkpoint": {
                    "expected": None,
                    "new_record_id": digest,
                }
            },
            "inserted_record_ids": [digest],
            "kind": "checkpoint",
            "local_values": [],
            "logical_time": "2026-08-09T12:00:00Z",
            "previous_event_id": None,
            "record_ids": [digest],
            "sequence": 1,
            "store_id": "store-test",
            "subject_id": digest,
        },
        "audit-verification.schema.json": {
            "audit_head_id": digest,
            "audit_sequence": 1,
            "store_id": "store-test",
            "supplied_anchor_matched": False,
            "valid": True,
        },
        "capability-claim.schema.json": capability,
        "checkpoint-receipt.schema.json": {
            "audit_event_id": digest,
            "audit_sequence": 1,
            "checkpoint_id": digest,
            "target_id": digest,
            "transition_allowed": True,
            "verdict": "pass",
        },
        "checkpoint.schema.json": {
            "acceptance_criteria": [criterion_payload(criterion)],
            "accepted_decision_ids": [],
            "actor_ids": [digest],
            "assignment_authority": "read_only",
            "audit_parent_id": None,
            "authority_scopes": [{"kind": "tree", "path": None}],
            "constraint_digests": [],
            "created_at": "2026-08-09T12:00:00Z",
            "evidence_ids": [],
            "goal_id": digest,
            "initialization_intent_id": digest,
            "instruction_id": digest,
            "invalidation_ids": [],
            "open_assignment_ids": [],
            "parent_checkpoint_id": None,
            "pending_work": [],
            "policy_id": digest,
            "ruleset_id": digest,
            "target_id": digest,
            "unresolved": [],
        },
        "citation.schema.json": citation_payload(citation),
        "evidence.schema.json": evidence_payload(evidence),
        "criterion.schema.json": {"digest": digest, "ordinal": 0},
        "error.schema.json": {
            "category": "request",
            "code": "request_invalid",
            "message_id": "acg.request.invalid",
            "parameters": {},
            "schema": "Error/v1",
        },
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
        "initialization-intent.schema.json": {
            "criterion_ids": [digest],
            "goal_id": digest,
            "instruction_id": digest,
            "policy_id": digest,
            "ruleset_id": digest,
            "session_key": "default",
            "target_id": digest,
        },
        "path-identity.schema.json": {
            "case_key_b64": None,
            "encoding": "posix-bytes",
            "raw_b64": "UkVBRE1FLm1k",
            "segment_offsets": [0],
        },
        "path-scope.schema.json": {"kind": "tree", "path": None},
        "policy.schema.json": {
            "approval_operator_ids": [],
            "authoring_digest": digest,
            "enabled_detectors": ["capture.unstable", "target.dirty"],
            "evidence_expiry_seconds": 3600,
            "limits": {
                "max_aggregate_bytes": 21_474_836_480,
                "max_analyzer_text_bytes": 4_194_304,
                "max_external_json_bytes": 8_388_608,
                "max_file_bytes": 1_073_741_824,
                "max_paths": 250_000,
            },
            "max_assignment_authority": "read_only",
            "profile": "guard",
            "promotion_mode": "automatic",
            "required_adapter_capabilities": [],
            "rollback_operator_ids": [],
            "severity_by_code": {
                "capture.unstable": "block",
                "target.dirty": "block",
            },
        },
        "policy-template.schema.json": {
            "authoring_digest": digest,
            "schema": "PolicyTemplate/v1",
            "toml_lines": ["version = 1"],
        },
        "goal.schema.json": {"digest": digest},
        "producer-identity.schema.json": {
            "digest": digest,
            "name": "acg-git",
            "version": "1.0",
        },
        "ruleset.schema.json": {"rule_ids": []},
        "target-identity.schema.json": {
            "adapter_id": "acg-git",
            "adapter_version": "1",
            "capabilities": {"git_immutable_objects": target_capability},
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
        "unresolved-item.schema.json": {"code": "unknown", "digest": None},
        "verification-result.schema.json": {
            "findings": [],
            "schema": "VerificationResult/v1",
            "transition_allowed": True,
            "verdict": "pass",
        },
        "work-item.schema.json": {
            "digest": digest,
            "kind": "task",
            "status_code": "pending",
        },
    }


def main() -> int:
    try:
        schemas = _load()
        _registered_schemas(schemas)
        goldens = schema_goldens()
        if set(goldens) != set(schemas):
            raise SchemaVerificationError("golden_coverage_mismatch")
        for name, positive in goldens.items():
            validator = schema_validator(name, schemas)
            try:
                validator.validate(positive)
                _semantic_validate(name, positive)
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
