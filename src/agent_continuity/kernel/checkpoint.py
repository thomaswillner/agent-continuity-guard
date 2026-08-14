"""Pure checkpoint reconstruction, comparison, and verification serialization."""

from __future__ import annotations

from typing import cast

from agent_continuity.capture.base import (
    CaptureSnapshot,
    InstructionFileV1,
    instruction_manifest_payload,
)
from agent_continuity.capture.coordinator import snapshot_findings

from .canonical import CanonicalJSONError, canonical_bytes, canonical_loads
from .evaluation import (
    EvaluationCase,
    EvaluationResult,
    Profile,
    Verdict,
    evaluate,
    evaluation_result_payload,
)
from .findings import Finding
from .model import (
    AssignmentAuthority,
    Digest,
    JsonObject,
    LogicalTime,
    RecordId,
    StoredRecord,
)
from .paths import (
    PathIdentityV1,
    PathScopeKind,
    PathScopeV1,
    parse_path_encoding,
)
from .records import (
    CheckpointV1,
    CriterionV1,
    UnresolvedItemV1,
    WorkItemV1,
    build_checkpoint,
    make_record,
)

_CHECKPOINT_FIELDS = frozenset(
    {
        "acceptance_criteria",
        "accepted_decision_ids",
        "actor_ids",
        "assignment_authority",
        "audit_parent_id",
        "authority_scopes",
        "constraint_digests",
        "created_at",
        "evidence_ids",
        "goal_id",
        "initialization_intent_id",
        "instruction_id",
        "invalidation_ids",
        "open_assignment_ids",
        "parent_checkpoint_id",
        "pending_work",
        "policy_id",
        "ruleset_id",
        "target_id",
        "unresolved",
    }
)


def _object(value: object, fields: frozenset[str], *, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise CanonicalJSONError(f"{label} fields are invalid")
    return cast(dict[str, object], value)


def _string(value: object, *, label: str) -> str:
    if type(value) is not str:
        raise CanonicalJSONError(f"{label} is invalid")
    return value


def _integer(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise CanonicalJSONError(f"{label} is invalid")
    return value


def _record_id(value: object, *, label: str) -> RecordId:
    return RecordId(_string(value, label=label))


def _optional_record_id(value: object, *, label: str) -> RecordId | None:
    return None if value is None else _record_id(value, label=label)


def _record_ids(value: object, *, label: str) -> tuple[RecordId, ...]:
    if type(value) is not list:
        raise CanonicalJSONError(f"{label} is invalid")
    return tuple(_record_id(item, label=label) for item in value)


def _digests(value: object, *, label: str) -> tuple[Digest, ...]:
    return tuple(Digest(item) for item in _record_ids(value, label=label))


def _path_identity(value: object) -> PathIdentityV1:
    item = _object(
        value,
        frozenset({"case_key_b64", "encoding", "raw_b64", "segment_offsets"}),
        label="path identity",
    )
    offsets = item["segment_offsets"]
    if type(offsets) is not list:
        raise CanonicalJSONError("path offsets are invalid")
    return PathIdentityV1(
        encoding=parse_path_encoding(_string(item["encoding"], label="path encoding")),
        raw_b64=_string(item["raw_b64"], label="path bytes"),
        segment_offsets=tuple(
            _integer(offset, label="path offset") for offset in offsets
        ),
        case_key_b64=(
            None
            if item["case_key_b64"] is None
            else _string(item["case_key_b64"], label="path case key")
        ),
    )


def _scope(value: object) -> PathScopeV1:
    item = _object(
        value,
        frozenset({"kind", "path"}),
        label="checkpoint scope",
    )
    try:
        kind = PathScopeKind(_string(item["kind"], label="scope kind"))
    except ValueError as error:
        raise CanonicalJSONError("checkpoint scope kind is invalid") from error
    return PathScopeV1(
        path=None if item["path"] is None else _path_identity(item["path"]),
        kind=kind,
    )


def checkpoint_from_record(record: StoredRecord) -> CheckpointV1:
    """Reconstruct one exact Checkpoint/v1 or fail without raw payload details."""

    if type(record) is not StoredRecord:
        raise CanonicalJSONError("checkpoint record is invalid")
    if record.record_type != "Checkpoint" or record.schema_version != "v1":
        raise CanonicalJSONError("checkpoint record domain is invalid")
    payload = _object(
        canonical_loads(record.canonical_bytes),
        _CHECKPOINT_FIELDS,
        label="checkpoint",
    )
    criteria_value = payload["acceptance_criteria"]
    work_value = payload["pending_work"]
    unresolved_value = payload["unresolved"]
    scopes_value = payload["authority_scopes"]
    if any(
        type(value) is not list
        for value in (
            criteria_value,
            work_value,
            unresolved_value,
            scopes_value,
        )
    ):
        raise CanonicalJSONError("checkpoint nested values are invalid")
    criteria = tuple(
        CriterionV1(
            criterion_id=_record_id(item["criterion_id"], label="criterion ID"),
            ordinal=_integer(item["ordinal"], label="criterion ordinal"),
            digest=Digest(_string(item["digest"], label="criterion digest")),
        )
        for item in (
            _object(
                value,
                frozenset({"criterion_id", "digest", "ordinal"}),
                label="criterion",
            )
            for value in cast(list[object], criteria_value)
        )
    )
    pending_work = tuple(
        WorkItemV1(
            work_item_id=_record_id(item["work_item_id"], label="work item ID"),
            kind=_string(item["kind"], label="work item kind"),
            status_code=_string(item["status_code"], label="work item status"),
            digest=Digest(_string(item["digest"], label="work item digest")),
        )
        for item in (
            _object(
                value,
                frozenset({"digest", "kind", "status_code", "work_item_id"}),
                label="work item",
            )
            for value in cast(list[object], work_value)
        )
    )
    unresolved = tuple(
        UnresolvedItemV1(
            unresolved_id=_record_id(item["unresolved_id"], label="unresolved item ID"),
            code=_string(item["code"], label="unresolved item code"),
            digest=(
                None
                if item["digest"] is None
                else Digest(_string(item["digest"], label="unresolved item digest"))
            ),
        )
        for item in (
            _object(
                value,
                frozenset({"code", "digest", "unresolved_id"}),
                label="unresolved item",
            )
            for value in cast(list[object], unresolved_value)
        )
    )
    try:
        authority = AssignmentAuthority(
            _string(payload["assignment_authority"], label="assignment authority")
        )
    except ValueError as error:
        raise CanonicalJSONError(
            "checkpoint assignment authority is invalid"
        ) from error
    checkpoint = build_checkpoint(
        parent_checkpoint_id=_optional_record_id(
            payload["parent_checkpoint_id"], label="parent checkpoint ID"
        ),
        target_id=_record_id(payload["target_id"], label="target ID"),
        goal_id=_record_id(payload["goal_id"], label="goal ID"),
        acceptance_criteria=criteria,
        constraint_digests=_digests(
            payload["constraint_digests"], label="constraint digests"
        ),
        instruction_id=_record_id(payload["instruction_id"], label="instruction ID"),
        policy_id=_record_id(payload["policy_id"], label="policy ID"),
        ruleset_id=_record_id(payload["ruleset_id"], label="ruleset ID"),
        actor_ids=_record_ids(payload["actor_ids"], label="actor IDs"),
        evidence_ids=_record_ids(payload["evidence_ids"], label="evidence IDs"),
        invalidation_ids=_record_ids(
            payload["invalidation_ids"], label="invalidation IDs"
        ),
        accepted_decision_ids=_record_ids(
            payload["accepted_decision_ids"], label="decision IDs"
        ),
        pending_work=pending_work,
        unresolved=unresolved,
        assignment_authority=authority,
        authority_scopes=tuple(
            _scope(value) for value in cast(list[object], scopes_value)
        ),
        open_assignment_ids=_record_ids(
            payload["open_assignment_ids"], label="assignment IDs"
        ),
        audit_parent_id=_optional_record_id(
            payload["audit_parent_id"], label="audit parent ID"
        ),
        initialization_intent_id=_record_id(
            payload["initialization_intent_id"], label="initialization intent ID"
        ),
        created_at=LogicalTime(_string(payload["created_at"], label="created at")),
    )
    if checkpoint.record() != record:
        raise CanonicalJSONError("checkpoint record identity is invalid")
    return checkpoint


def instruction_paths_from_record(record: StoredRecord) -> tuple[bytes, ...]:
    """Return exact Git path bytes from a verified InstructionManifest/v1."""

    if type(record) is not StoredRecord:
        raise CanonicalJSONError("instruction record is invalid")
    if record.record_type != "InstructionManifest" or record.schema_version != "v1":
        raise CanonicalJSONError("instruction record domain is invalid")
    payload = _object(
        canonical_loads(record.canonical_bytes),
        frozenset({"files"}),
        label="instruction manifest",
    )
    values = payload["files"]
    if type(values) is not list:
        raise CanonicalJSONError("instruction files are invalid")
    files = tuple(
        InstructionFileV1(
            path=_path_identity(item["path"]),
            blob_oid=_string(item["blob_oid"], label="instruction blob ID"),
            byte_digest=Digest(
                _string(item["byte_digest"], label="instruction byte digest")
            ),
        )
        for item in (
            _object(
                value,
                frozenset({"blob_oid", "byte_digest", "path"}),
                label="instruction file",
            )
            for value in values
        )
    )
    if any(item.path.encoding != "git-path-bytes" for item in files):
        raise CanonicalJSONError("instruction path domain is invalid")
    if (
        make_record("InstructionManifest", instruction_manifest_payload(files))
        != record
    ):
        raise CanonicalJSONError("instruction record identity is invalid")
    paths = tuple(item.path.raw_bytes() for item in files)
    if len(paths) != len(set(paths)):
        raise CanonicalJSONError("instruction paths are not unique")
    return paths


def build_subsequent_checkpoint(
    parent: CheckpointV1,
    *,
    audit_parent_id: RecordId,
    created_at: LogicalTime,
) -> CheckpointV1:
    """Copy protected parent state into one parent-linked child checkpoint."""

    if type(parent) is not CheckpointV1:
        raise CanonicalJSONError("parent checkpoint is invalid")
    return build_checkpoint(
        parent_checkpoint_id=parent.checkpoint_id,
        target_id=parent.target_id,
        goal_id=parent.goal_id,
        acceptance_criteria=parent.acceptance_criteria,
        constraint_digests=parent.constraint_digests,
        instruction_id=parent.instruction_id,
        policy_id=parent.policy_id,
        ruleset_id=parent.ruleset_id,
        actor_ids=parent.actor_ids,
        evidence_ids=parent.evidence_ids,
        invalidation_ids=parent.invalidation_ids,
        accepted_decision_ids=parent.accepted_decision_ids,
        pending_work=parent.pending_work,
        unresolved=parent.unresolved,
        assignment_authority=parent.assignment_authority,
        authority_scopes=parent.authority_scopes,
        open_assignment_ids=parent.open_assignment_ids,
        audit_parent_id=audit_parent_id,
        initialization_intent_id=parent.initialization_intent_id,
        created_at=created_at,
    )


def evaluate_checkpoint_capture(
    checkpoint: CheckpointV1,
    snapshot_a: CaptureSnapshot,
    snapshot_b: CaptureSnapshot,
    profile: Profile,
    *,
    policy_id: RecordId,
    ruleset_id: RecordId,
) -> EvaluationResult:
    """Evaluate capture stability, cleanliness, and checkpoint identity binding."""

    case = snapshot_findings(snapshot_a, snapshot_b, profile)
    findings = list(case.findings)
    identity_matches = (
        snapshot_a.target.record().record_id == checkpoint.target_id
        and snapshot_a.instruction_record().record_id == checkpoint.instruction_id
        and policy_id == checkpoint.policy_id
        and ruleset_id == checkpoint.ruleset_id
    )
    if not identity_matches and not any(
        finding.code == "capture.unstable" for finding in findings
    ):
        findings.append(
            Finding(
                code="capture.unstable",
                verdict=Verdict.UNKNOWN,
                subject_id=checkpoint.checkpoint_id,
                message_id="acg.capture.unstable",
                parameters={},
            )
        )
    return evaluate(EvaluationCase(profile=profile, findings=tuple(findings)))


def verification_result_payload(result: EvaluationResult) -> JsonObject:
    """Serialize public verification output without changing its Python type."""

    if type(result) is not EvaluationResult:
        raise CanonicalJSONError("verification result is invalid")
    payload = evaluation_result_payload(result)
    payload["schema"] = "VerificationResult/v1"
    canonical_bytes(payload)
    return payload
