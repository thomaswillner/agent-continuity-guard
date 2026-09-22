from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, fields, replace

import pytest

from agent_continuity import Continuity
from agent_continuity.kernel.canonical import canonical_bytes, digest_bytes
from agent_continuity.kernel.evaluation import EvaluationResult, Verdict
from agent_continuity.kernel.findings import Finding
from agent_continuity.kernel.invalidation import EvidenceState, Invalidation
from agent_continuity.kernel.model import AssignmentAuthority, RecordId
from agent_continuity.kernel.paths import PathScopeKind, PathScopeV1
from agent_continuity.kernel.records import (
    CheckpointV1,
    build_checkpoint,
    build_criterion,
    build_unresolved_item,
    build_work_item,
)


def _id(label: str) -> RecordId:
    return RecordId(digest_bytes(label.encode()))


def _checkpoint() -> CheckpointV1:
    criterion = build_criterion(ordinal=0, digest=digest_bytes(b"criterion digest"))
    work = build_work_item(
        kind="task",
        status_code="pending",
        digest=digest_bytes(b"work digest"),
    )
    unresolved = build_unresolved_item(code="unknown", digest=None)
    return build_checkpoint(
        parent_checkpoint_id=None,
        target_id=_id("target"),
        goal_id=_id("goal"),
        acceptance_criteria=(criterion,),
        constraint_digests=(digest_bytes(b"constraint"),),
        instruction_id=_id("instruction"),
        policy_id=_id("policy"),
        ruleset_id=_id("ruleset"),
        actor_ids=(),
        evidence_ids=tuple(sorted((_id("evidence-a"), _id("evidence-b")))),
        invalidation_ids=(),
        accepted_decision_ids=(_id("decision"),),
        pending_work=(work,),
        unresolved=(unresolved,),
        assignment_authority=AssignmentAuthority.READ_ONLY,
        authority_scopes=(PathScopeV1(path=None, kind=PathScopeKind.TREE),),
        open_assignment_ids=(_id("assignment"),),
        audit_parent_id=None,
        initialization_intent_id=_id("intent"),
        created_at="2026-09-01T00:00:00Z",
    )


def test_resume_context_public_contract_is_frozen() -> None:
    import agent_continuity
    import agent_continuity.api as api
    from agent_continuity.kernel.resume import ResumeContext

    assert "ResumeContext" not in agent_continuity.__all__
    assert "ResumeContext" not in api.__all__
    assert not hasattr(agent_continuity, "ResumeContext")
    assert api.ResumeContext is ResumeContext
    assert [item.name for item in fields(ResumeContext)] == [
        "checkpoint_id",
        "verdict",
        "usable",
        "target_id",
        "goal_digest",
        "acceptance_criteria",
        "constraint_digests",
        "accepted_decision_ids",
        "pending_work",
        "unresolved",
        "open_assignment_ids",
        "current_evidence_ids",
        "invalidations",
        "blocker_codes",
    ]
    assert inspect.signature(Continuity.resume) == inspect.Signature(
        [
            inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            inspect.Parameter(
                "checkpoint",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default="latest",
                annotation="str",
            ),
        ],
        return_annotation="ResumeContext",
    )


def test_build_resume_context_orders_and_filters_canonically() -> None:
    from agent_continuity.kernel.resume import (
        ResumeContext,
        build_resume_context,
        resume_context_payload,
    )

    checkpoint = _checkpoint()
    evidence_a, evidence_b = checkpoint.evidence_ids
    invalidated = Invalidation(
        evidence_b,
        EvidenceState.INVALIDATED,
        "evidence.expired",
        (),
        (evidence_b,),
    )
    current = Invalidation(evidence_a, EvidenceState.CURRENT, "", (), ())
    result = EvaluationResult(
        Verdict.BLOCK,
        False,
        (
            Finding(
                "evidence.expired",
                Verdict.BLOCK,
                evidence_b,
                "evidence.expired",
                {},
            ),
            Finding(
                "citation.path_missing",
                Verdict.UNKNOWN,
                evidence_a,
                "citation.path_missing",
                {},
            ),
            Finding(
                "evidence.expired",
                Verdict.BLOCK,
                evidence_b,
                "evidence.expired",
                {},
            ),
        ),
    )
    context = build_resume_context(
        checkpoint,
        result,
        goal_digest=digest_bytes(b"goal text"),
        invalidations=(invalidated, current),
    )
    assert isinstance(context, ResumeContext)
    assert context.current_evidence_ids == (evidence_a,)
    assert context.invalidations == (current, invalidated)
    assert context.blocker_codes == ("citation.path_missing", "evidence.expired")
    assert context.usable is False
    with pytest.raises(FrozenInstanceError):
        context.usable = True  # type: ignore[misc]

    payload = resume_context_payload(context)
    assert payload["schema"] == "ResumeContext/v1"
    assert canonical_bytes(payload) == (
        b'{"acceptance_criteria":[{"criterion_id":"sha256:0350421ff2a9b86fa7c9c7bfff31'
        b'a924d83503d321a7f53a9fcf080df3456519","digest":"sha256:4349cc01451e6dbe8812a'
        b'4454eec34f7b036c9d4714d47121ea8583c62adc148","ordinal":0}],"accepted_decisio'
        b'n_ids":["sha256:86ae35d58a6aa3b5742df94ef9d7162219f0106a911ae1954c1f0604aaec'
        b'805d"],"blocker_codes":["citation.path_missing","evidence.expired"],"checkpo'
        b'int_id":"sha256:a8ad8d6d049a5a50b1df4d37528421a70e5a9a79e94b3736083830c1365c'
        b'5aa5","constraint_digests":["sha256:bd00a996380547acaa70a1f1da3d10cd4d5a4586'
        b'e29eccbd6b556709920a0eec"],"current_evidence_ids":["sha256:06359feace303be91'
        b'155e031c2ac5e902b1e0829f11e0b0d8e107d5ce77003ec"],"goal_digest":"sha256:77e0'
        b'40ec2643621118afb9fdbe40c5606b9635b3856edc41448d1946cbaa5881","invalidations'
        b'":[{"code":"","direct_cause_ids":[],"evidence_id":"sha256:06359feace303be911'
        b'55e031c2ac5e902b1e0829f11e0b0d8e107d5ce77003ec","state":"current","transitiv'
        b'e_path":[]},{"code":"evidence.expired","direct_cause_ids":[],"evidence_id":"'
        b'sha256:5b181a581a374d0510150c19437e4c6dc266a82ee735affc9bb33cec7f656224","st'
        b'ate":"invalidated","transitive_path":["sha256:5b181a581a374d0510150c19437e4c'
        b'6dc266a82ee735affc9bb33cec7f656224"]}],"open_assignment_ids":["sha256:ce7a7c'
        b'10b0dfd96808cca64c88cf5c5e13b7775283bdc924767887bfa32c8fa1"],"pending_work":'
        b'[{"digest":"sha256:826530b2d1d7714f4021a90bc3ae9ce420f28a9db2a3e4c119f2b05a2'
        b'5d39d8f","kind":"task","status_code":"pending","work_item_id":"sha256:1fc29c'
        b'515e918839c9ed74a3d969c41d50a6ed898e510814cb5a3eb99f640a69"}],"schema":"Resu'
        b'meContext/v1","target_id":"sha256:34a04005bcaf206eec990bd9637d9fdb6725e0a0c0'
        b'd4aebf003f17f4c956eb5c","unresolved":[{"code":"unknown","digest":null,"unres'
        b'olved_id":"sha256:8623de6e65ca7d3a06982bbd0d74f7296aa9d1075dc2066f0cc1e05efe'
        b'8988a2"}],"usable":false,"verdict":"block"}'
    )
    encoded = canonical_bytes(payload)
    for secret in (b"goal text", b"criterion text", b"prompt", b"transcript"):
        assert secret not in encoded



@pytest.mark.parametrize(
    "field",
    [
        "acceptance_criteria",
        "constraint_digests",
        "accepted_decision_ids",
        "pending_work",
        "unresolved",
        "open_assignment_ids",
        "current_evidence_ids",
        "invalidations",
        "blocker_codes",
    ],
)
def test_resume_context_rejects_mutable_sequence_containers(field: str) -> None:
    from agent_continuity.kernel.canonical import CanonicalJSONError
    from agent_continuity.kernel.resume import build_resume_context

    checkpoint = _checkpoint()
    evidence_a, evidence_b = checkpoint.evidence_ids
    context = build_resume_context(
        checkpoint,
        EvaluationResult(Verdict.PASS, True, ()),
        goal_digest=digest_bytes(b"goal text"),
        invalidations=(
            Invalidation(evidence_a, EvidenceState.CURRENT, "", (), ()),
            Invalidation(evidence_b, EvidenceState.CURRENT, "", (), ()),
        ),
    )

    with pytest.raises(CanonicalJSONError):
        replace(context, **{field: list(getattr(context, field))})


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("acceptance_criteria", object()),
        ("pending_work", object()),
        ("unresolved", object()),
        ("invalidations", object()),
    ],
)
def test_resume_context_rejects_wrong_nested_model_types(
    field: str, wrong_value: object
) -> None:
    from agent_continuity.kernel.canonical import CanonicalJSONError
    from agent_continuity.kernel.resume import build_resume_context

    checkpoint = _checkpoint()
    evidence_a, evidence_b = checkpoint.evidence_ids
    context = build_resume_context(
        checkpoint,
        EvaluationResult(Verdict.PASS, True, ()),
        goal_digest=digest_bytes(b"goal text"),
        invalidations=(
            Invalidation(evidence_a, EvidenceState.CURRENT, "", (), ()),
            Invalidation(evidence_b, EvidenceState.CURRENT, "", (), ()),
        ),
    )

    with pytest.raises(CanonicalJSONError):
        replace(context, **{field: (wrong_value,)})


@pytest.mark.parametrize(
    "blocker_code",
    [
        "BAD CODE",
        "a" * 129,
    ],
)
def test_resume_context_rejects_blocker_codes_outside_schema_contract(
    blocker_code: str,
) -> None:
    from agent_continuity.kernel.canonical import CanonicalJSONError
    from agent_continuity.kernel.resume import build_resume_context

    checkpoint = _checkpoint()
    context = build_resume_context(
        checkpoint,
        EvaluationResult(Verdict.PASS, True, ()),
        goal_digest=digest_bytes(b"goal text"),
        invalidations=(),
    )

    with pytest.raises(CanonicalJSONError):
        replace(context, blocker_codes=(blocker_code,))


def test_resume_context_schema_is_registered_and_strict() -> None:
    import json
    from pathlib import Path

    from tools.verify_schemas import SCHEMA_REGISTRY

    path = Path("schemas/v1/resume-context.schema.json")
    schema = json.loads(path.read_text())
    assert schema["$id"] == (
        "https://agent-continuity-guard.dev/schemas/v1/resume-context.schema.json"
    )
    assert schema["title"] == "ResumeContext/v1"
    assert schema["x-record-type"] == "ResumeContext/v1"
    assert schema["properties"]["schema"] == {"const": "ResumeContext/v1"}
    assert schema["$defs"]["findingCode"] == {
        "maxLength": 128,
        "pattern": "^[a-z][a-z0-9_.-]{0,127}$",
        "type": "string",
    }
    assert schema["additionalProperties"] is False
    assert SCHEMA_REGISTRY["ResumeContext/v1"] == path.name


def test_goal_round_trips_through_strict_record_codec() -> None:
    from agent_continuity.kernel.records import build_goal, decode_record, encode_record

    goal = build_goal(digest_bytes(b"goal text"))
    assert decode_record(encode_record(goal)) == goal


@pytest.mark.parametrize(
    "mutate",
    [
        lambda record: replace(record, record_type="Evidence"),
        lambda record: replace(record, schema_version="v2"),
        lambda record: replace(
            record,
            canonical_bytes=canonical_bytes(
                {"digest": digest_bytes(b"goal text"), "extra": True}
            ),
        ),
        lambda record: replace(record, record_id=digest_bytes(b"wrong identity")),
    ],
)
def test_goal_decode_rejects_wrong_domain_version_fields_or_identity(mutate) -> None:
    from agent_continuity.kernel.records import (
        RecordSchemaError,
        build_goal,
        decode_record,
        encode_record,
    )

    record = encode_record(build_goal(digest_bytes(b"goal text")))
    with pytest.raises(RecordSchemaError):
        decode_record(mutate(record))


def test_goal_codec_rejects_subclass_values() -> None:
    from agent_continuity.kernel.records import (
        GoalV1,
        RecordSchemaError,
        build_goal,
        encode_record,
    )

    class GoalSubclass(GoalV1):
        pass

    goal = build_goal(digest_bytes(b"goal text"))
    with pytest.raises(RecordSchemaError):
        encode_record(GoalSubclass(goal.goal_id, goal.digest))
