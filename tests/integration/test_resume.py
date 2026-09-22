from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread
from types import MappingProxyType

import pytest

from agent_continuity import Continuity, ContinuityRequestError, Profile
from agent_continuity.capture import (
    CaptureSnapshot,
    CaptureUnknownError,
    GitTargetAdapter,
)
from agent_continuity.kernel.canonical import (
    canonical_bytes,
    digest_bytes,
    validate_logical_time,
)
from agent_continuity.kernel.checkpoint import checkpoint_from_record
from agent_continuity.kernel.citation import CitationV1, citation_v1
from agent_continuity.kernel.evaluation import (
    EvaluationCase,
    Verdict,
    evaluate,
)
from agent_continuity.kernel.evidence import (
    EvidenceAuthority,
    EvidenceCompleteness,
    EvidenceKind,
    EvidenceV1,
    InvalidatorKind,
    InvalidatorV1,
    evidence_v1,
    invalidator_payload,
)
from agent_continuity.kernel.findings import Finding
from agent_continuity.kernel.invalidation import EvidenceState
from agent_continuity.kernel.model import (
    AssignmentAuthority,
    LogicalTime,
    RecordId,
    StoredRecord,
)
from agent_continuity.kernel.paths import PathIdentityV1, PathScopeKind, PathScopeV1
from agent_continuity.kernel.records import (
    CheckpointV1,
    FactV1,
    ProducerIdentity,
    build_checkpoint,
    build_initialization_intent,
    build_ruleset,
    make_record,
)
from agent_continuity.kernel.resume import (
    ResumeContext,
    build_resume_context,
    resume_context_payload,
)
from agent_continuity.store import (
    AuditEventDraft,
    HeadUpdate,
    SQLiteStateStore,
    StoreIntegrityError,
    open_external_state_root,
)
from tests.helpers.git_repo import (
    make_git_repo,
    repository_git_observation,
    repository_write_manifest,
)


def _database(state_home: Path) -> Path:
    databases = tuple(state_home.glob("*.sqlite3"))
    assert len(databases) == 1
    return databases[0]


def _tree_projection(root: Path) -> tuple[tuple[str, tuple[int, ...], bytes], ...]:
    paths = (root, *sorted(root.rglob("*"), key=lambda item: item.as_posix()))
    result: list[tuple[str, tuple[int, ...], bytes]] = []
    for path in paths:
        metadata = path.lstat()
        name = "." if path == root else path.relative_to(root).as_posix()
        content = path.read_bytes() if path.is_file() else b""
        result.append(
            (
                name,
                (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_nlink,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                ),
                content,
            )
        )
    return tuple(result)


def _complete_metadata(path: Path) -> tuple[object, ...]:
    entry = path.lstat()
    attributes: list[bytes] = []
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except (AttributeError, NotImplementedError, OSError):
        names = []
    for name in sorted(names):
        try:
            attributes.append(
                os.fsencode(name)
                + b"="
                + os.getxattr(path, name, follow_symlinks=False)
            )
        except (AttributeError, NotImplementedError, OSError):
            attributes.append(os.fsencode(name) + b"=<unreadable>")
    return (
        entry.st_dev,
        entry.st_ino,
        entry.st_mode,
        entry.st_uid,
        entry.st_gid,
        entry.st_nlink,
        entry.st_size,
        entry.st_mtime_ns,
        entry.st_ctime_ns,
        hashlib.sha256(b"\0".join(attributes)).digest(),
    )


def _complete_tree_projection(root: Path) -> tuple[object, ...]:
    paths = [root, *sorted(root.rglob("*"), key=os.fspath)]
    metadata = tuple(
        (
            "." if path == root else os.fspath(path.relative_to(root)),
            _complete_metadata(path),
        )
        for path in paths
    )
    contents = tuple(
        (
            os.fspath(path.relative_to(root)),
            path.read_bytes(),
        )
        for path in paths
        if path.is_file()
    )
    return metadata, contents


def _store_projection(database: Path) -> tuple[bytes, int, tuple[object, ...]]:
    with sqlite3.connect(database) as connection:
        rows = tuple(
            connection.execute(
                "SELECT name, record_id, audit_event_id, audit_sequence "
                "FROM heads ORDER BY name"
            )
        )
        audit = tuple(
            connection.execute(
                "SELECT sequence, event_id, canonical_bytes "
                "FROM audit_events ORDER BY sequence"
            )
        )
    sidecars = tuple(
        sorted(
            path.name
            for path in database.parent.glob(f"{database.name}-*")
            if path.exists()
        )
    )
    return database.read_bytes(), database.stat().st_mtime_ns, (rows, audit, sidecars)


class FixedClock:
    def __init__(self, logical_time: str = "2026-09-01T00:00:10Z") -> None:
        self._logical_time = validate_logical_time(logical_time)

    def now(self) -> LogicalTime:
        return self._logical_time


def _initialized(
    tmp_path: Path,
    *,
    session_key: str = "resume",
    profile: Profile | None = None,
    policy: Path | None = None,
) -> tuple[object, Path, Path, Continuity, str]:
    repo = make_git_repo(tmp_path)
    state_home = tmp_path / "state"
    continuity = Continuity.open(
        repo.root,
        state_home=state_home,
        session_key=session_key,
        profile=profile,
        policy=policy,
        clock=FixedClock(),
    )
    initial = continuity.initialize(
        "resume goal display text",
        ("resume criterion display text",),
        instruction_paths=("AGENTS.md",),
    )
    return repo, repo.root, state_home, continuity, initial.checkpoint_id


def _ordered_invalidators(
    values: Sequence[InvalidatorV1],
) -> tuple[InvalidatorV1, ...]:
    return tuple(
        sorted(values, key=lambda item: canonical_bytes(invalidator_payload(item)))
    )


def _evidence(
    label: str,
    *,
    checkpoint: CheckpointV1,
    producer: ProducerIdentity,
    kind: EvidenceKind = EvidenceKind.STRUCTURED_CLAIM,
    subject_digest: str | None = None,
    invalidators: Sequence[InvalidatorV1] = (),
    expires_at: str | None = None,
    completeness: EvidenceCompleteness = EvidenceCompleteness.COMPLETE,
) -> EvidenceV1:
    return evidence_v1(
        kind=kind,
        subject_digest=(
            digest_bytes(f"subject:{label}".encode())
            if subject_digest is None
            else subject_digest
        ),
        authority=EvidenceAuthority.DETERMINISTIC,
        producer=producer,
        target_id=checkpoint.target_id,
        checkpoint_id=checkpoint.checkpoint_id,
        observed_at=validate_logical_time("2026-09-01T00:00:00Z"),
        expires_at=(None if expires_at is None else validate_logical_time(expires_at)),
        completeness=completeness,
        terminal_status=None,
        declared_output_digest=None,
        observed_output_digest=None,
        collected_check_count=None,
        pagination_complete=None,
        payload_digest=digest_bytes(f"payload:{label}".encode()),
        facts=(FactV1(("fixture", label), True),),
        invalidators=_ordered_invalidators(invalidators),
    )


def _seed_evidence_checkpoint(
    *,
    target: Path,
    state_home: Path,
    session_key: str,
    citations: Sequence[CitationV1],
    evidence_factory: Callable[[CheckpointV1], Sequence[EvidenceV1]],
    admitted_evidence_ids: Sequence[RecordId] | None = None,
) -> tuple[CheckpointV1, tuple[EvidenceV1, ...]]:
    database = _database(state_home)
    root = open_external_state_root(target, target / ".git", state_home)
    with SQLiteStateStore(
        root,
        database_name=database.name,
        store_id=None,
    ) as store:
        head_name = f"session:{session_key}:checkpoint"
        head = store.read_head(head_name)
        assert head is not None
        parent = checkpoint_from_record(store.load_record(head.record_id))
        records = tuple(evidence_factory(parent))
        selected_ids = (
            tuple(record.evidence_id for record in records[-1:])
            if admitted_evidence_ids is None
            else tuple(admitted_evidence_ids)
        )
        child = build_checkpoint(
            parent_checkpoint_id=parent.checkpoint_id,
            target_id=parent.target_id,
            goal_id=parent.goal_id,
            acceptance_criteria=parent.acceptance_criteria,
            constraint_digests=parent.constraint_digests,
            instruction_id=parent.instruction_id,
            policy_id=parent.policy_id,
            ruleset_id=parent.ruleset_id,
            actor_ids=parent.actor_ids,
            evidence_ids=tuple(sorted(selected_ids)),
            invalidation_ids=parent.invalidation_ids,
            accepted_decision_ids=parent.accepted_decision_ids,
            pending_work=parent.pending_work,
            unresolved=parent.unresolved,
            assignment_authority=parent.assignment_authority,
            authority_scopes=parent.authority_scopes,
            open_assignment_ids=parent.open_assignment_ids,
            audit_parent_id=head.audit_event_id,
            initialization_intent_id=parent.initialization_intent_id,
            created_at=validate_logical_time("2026-09-01T00:00:01Z"),
        )
        stored: tuple[StoredRecord, ...] = (
            *(citation.record() for citation in citations),
            *(record.record() for record in records),
            child.record(),
        )
        store.commit_many(
            records=stored,
            event=AuditEventDraft(
                kind="checkpoint",
                subject_id=child.checkpoint_id,
                logical_time=child.created_at,
                details={"record_id": child.checkpoint_id},
            ),
            head_updates=(HeadUpdate(head_name, head, child.checkpoint_id),),
        )
    return child, records


def _seed_identity_drift_checkpoint(
    *,
    target: Path,
    state_home: Path,
    session_key: str,
    field: str,
) -> CheckpointV1:
    database = _database(state_home)
    root = open_external_state_root(target, target / ".git", state_home)
    with SQLiteStateStore(
        root,
        database_name=database.name,
        store_id=None,
    ) as store:
        head_name = f"session:{session_key}:checkpoint"
        head = store.read_head(head_name)
        assert head is not None
        parent = checkpoint_from_record(store.load_record(head.record_id))
        changes = {field: digest_bytes(f"changed:{field}".encode())}
        child = build_checkpoint(
            parent_checkpoint_id=parent.checkpoint_id,
            target_id=changes.get("target_id", parent.target_id),
            goal_id=parent.goal_id,
            acceptance_criteria=parent.acceptance_criteria,
            constraint_digests=parent.constraint_digests,
            instruction_id=changes.get("instruction_id", parent.instruction_id),
            policy_id=changes.get("policy_id", parent.policy_id),
            ruleset_id=changes.get("ruleset_id", parent.ruleset_id),
            actor_ids=parent.actor_ids,
            evidence_ids=parent.evidence_ids,
            invalidation_ids=parent.invalidation_ids,
            accepted_decision_ids=parent.accepted_decision_ids,
            pending_work=parent.pending_work,
            unresolved=parent.unresolved,
            assignment_authority=parent.assignment_authority,
            authority_scopes=parent.authority_scopes,
            open_assignment_ids=parent.open_assignment_ids,
            audit_parent_id=head.audit_event_id,
            initialization_intent_id=parent.initialization_intent_id,
            created_at=validate_logical_time("2026-09-01T00:00:01Z"),
        )
        store.commit_many(
            records=(child.record(),),
            event=AuditEventDraft(
                kind="checkpoint",
                subject_id=child.checkpoint_id,
                logical_time=child.created_at,
                details={"record_id": child.checkpoint_id},
            ),
            head_updates=(HeadUpdate(head_name, head, child.checkpoint_id),),
        )
    return child


def _seed_current_ruleset_mismatch(
    *,
    target: Path,
    state_home: Path,
    session_key: str,
) -> CheckpointV1:
    database = _database(state_home)
    root = open_external_state_root(target, target / ".git", state_home)
    with SQLiteStateStore(
        root,
        database_name=database.name,
        store_id=None,
    ) as store:
        head_name = f"session:{session_key}:checkpoint"
        head = store.read_head(head_name)
        assert head is not None
        parent = checkpoint_from_record(store.load_record(head.record_id))
        changed_ruleset = build_ruleset(
            (RecordId(digest_bytes(b"promoted rule identity")),)
        )
        changed_intent = build_initialization_intent(
            session_key=session_key,
            target_id=parent.target_id,
            goal_id=parent.goal_id,
            criterion_ids=tuple(
                criterion.criterion_id for criterion in parent.acceptance_criteria
            ),
            instruction_id=parent.instruction_id,
            policy_id=parent.policy_id,
            ruleset_id=changed_ruleset.ruleset_id,
        )
        child = build_checkpoint(
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
            audit_parent_id=head.audit_event_id,
            initialization_intent_id=changed_intent.intent_id,
            created_at=validate_logical_time("2026-09-01T00:00:01Z"),
        )
        store.commit_many(
            records=(
                changed_ruleset.record(),
                changed_intent.record(),
                child.record(),
            ),
            event=AuditEventDraft(
                kind="checkpoint",
                subject_id=child.checkpoint_id,
                logical_time=child.created_at,
                details={"record_id": child.checkpoint_id},
            ),
            head_updates=(HeadUpdate(head_name, head, child.checkpoint_id),),
        )
    return child


class ScriptedResumeAdapter:
    def __init__(
        self,
        root: Path,
        *,
        live: Sequence[object | BaseException],
        snapshots: Sequence[CaptureSnapshot | BaseException],
    ) -> None:
        self.root = root
        self.live = deque(live)
        self.snapshots = deque(snapshots)
        self.live_calls: list[tuple[bytes, ...]] = []
        self.capture_calls: list[tuple[bytes, ...]] = []

    def capture(self, instruction_paths: Sequence[bytes]) -> CaptureSnapshot:
        self.capture_calls.append(tuple(instruction_paths))
        if not self.snapshots:
            raise AssertionError("unexpected scripted capture call")
        result = self.snapshots.popleft()
        if isinstance(result, BaseException):
            raise result
        return result

    def _capture_live(self, required_paths: Sequence[PathIdentityV1]):
        self.live_calls.append(tuple(path.raw_bytes() for path in required_paths))
        if not self.live:
            raise AssertionError("unexpected scripted live capture call")
        result = self.live.popleft()
        if isinstance(result, BaseException):
            raise result
        return result


def _resume_capture_baseline(
    target: Path,
) -> tuple[PathIdentityV1, CaptureSnapshot, object, object]:
    instruction = PathIdentityV1.from_bytes("git-path-bytes", b"AGENTS.md")
    with GitTargetAdapter(target) as adapter:
        snapshot = adapter.capture((b"AGENTS.md",))
        census = adapter._capture_live(())
        required = adapter._capture_live((instruction,))
    return instruction, snapshot, census, required


def _resume_with_adapter(
    target: Path,
    state_home: Path,
    adapter: ScriptedResumeAdapter,
    *,
    profile: Profile | None = None,
) -> Continuity:
    return Continuity.open(
        target,
        state_home=state_home,
        session_key="resume",
        profile=profile,
        clock=FixedClock(),
        target_adapter=adapter,
    )


def _capture_roots(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(root.glob("acg-capture-*")))


def test_resume_latest_and_explicit_current_are_read_only_and_public_safe(
    tmp_path: Path,
) -> None:
    repo, target, state_home, continuity, checkpoint_id = _initialized(tmp_path)
    database = _database(state_home)
    before_store = _store_projection(database)
    before_target = repository_write_manifest(target)
    before_git = repository_git_observation(repo)

    latest = continuity.resume()
    explicit = continuity.resume(checkpoint_id)

    assert type(latest) is ResumeContext
    assert explicit == latest
    assert latest.checkpoint_id == checkpoint_id
    assert latest.verdict is Verdict.PASS
    assert latest.usable is True
    assert latest.blocker_codes == ()
    assert _store_projection(database) == before_store
    assert repository_write_manifest(target) == before_target
    assert repository_git_observation(repo) == before_git
    payload_bytes = canonical_bytes(resume_context_payload(latest))
    assert b"resume goal display text" not in payload_bytes
    assert b"resume criterion display text" not in payload_bytes


@pytest.mark.parametrize("profile", list(Profile))
def test_resume_reloads_changed_explicit_policy_and_preserves_state(
    tmp_path: Path, profile: Profile
) -> None:
    explicit = tmp_path / "explicit.toml"
    explicit.write_text(
        'version = 1\nprofile = "observe"\n',
        encoding="utf-8",
    )
    repo, target, state_home, continuity, _checkpoint_id = _initialized(
        tmp_path, profile=profile, policy=explicit
    )
    explicit.write_text(
        'version = 1\nprofile = "strict"\n',
        encoding="utf-8",
    )
    database = _database(state_home)
    before = (
        _store_projection(database),
        repository_write_manifest(target),
        repository_git_observation(repo),
        _complete_tree_projection(state_home),
    )

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == ("resume.policy_changed",)
    assert (
        _store_projection(database),
        repository_write_manifest(target),
        repository_git_observation(repo),
        _complete_tree_projection(state_home),
    ) == before


def test_resume_blocks_explicit_policy_change_between_observation_and_capture(
    tmp_path: Path,
) -> None:
    explicit = tmp_path / "explicit.toml"
    original_policy = 'version = 1\nprofile = "observe"\n'
    changed_policy = 'version = 1\nprofile = "strict"\n'
    explicit.write_text(original_policy, encoding="utf-8")
    _repo, target, state_home, _continuity, _checkpoint_id = _initialized(
        tmp_path, policy=explicit
    )
    instruction, snapshot, census, required = _resume_capture_baseline(target)

    class PolicyRaceResumeAdapter(ScriptedResumeAdapter):
        def _capture_live(self, required_paths: Sequence[PathIdentityV1]):
            explicit.write_text(changed_policy, encoding="utf-8")
            return super()._capture_live(required_paths)

    adapter = PolicyRaceResumeAdapter(
        target,
        live=(census, required, required),
        snapshots=(snapshot,),
    )
    reopened = Continuity.open(
        target,
        state_home=state_home,
        session_key="resume",
        policy=explicit,
        clock=FixedClock(),
        target_adapter=adapter,
    )

    resumed = reopened.resume()

    assert adapter.live_calls[0] == ()
    assert adapter.capture_calls == [(instruction.raw_bytes(),)]
    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == ("resume.policy_changed",)


def test_resume_reobserves_checkpoint_linked_ruleset_authority(
    tmp_path: Path,
) -> None:
    repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    child = _seed_current_ruleset_mismatch(
        target=target,
        state_home=state_home,
        session_key="resume",
    )
    database = _database(state_home)
    before = (
        _store_projection(database),
        repository_write_manifest(target),
        repository_git_observation(repo),
        _complete_tree_projection(state_home),
    )

    resumed = continuity.resume(child.checkpoint_id)

    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == ("resume.ruleset_changed",)
    assert (
        _store_projection(database),
        repository_write_manifest(target),
        repository_git_observation(repo),
        _complete_tree_projection(state_home),
    ) == before


@pytest.mark.parametrize(
    (
        "profile",
        "input_verdict",
        "input_code",
        "input_integrity_failure",
        "expected_usable",
        "expected_verdict",
        "expected_code",
        "expected_integrity_failure",
    ),
    [
        (Profile.OBSERVE, Verdict.PASS, None, False, True, "pass", None, False),
        (Profile.GUARD, Verdict.PASS, None, False, True, "pass", None, False),
        (Profile.STRICT, Verdict.PASS, None, False, True, "pass", None, False),
        (
            Profile.OBSERVE,
            Verdict.WARN,
            "target.dirty",
            False,
            True,
            "warn",
            "target.dirty",
            False,
        ),
        (
            Profile.GUARD,
            Verdict.WARN,
            "target.dirty",
            False,
            True,
            "warn",
            "target.dirty",
            False,
        ),
        (
            Profile.STRICT,
            Verdict.WARN,
            "target.dirty",
            False,
            False,
            "warn",
            "target.dirty",
            False,
        ),
        (
            Profile.OBSERVE,
            Verdict.UNKNOWN,
            "evidence.observation_unavailable",
            False,
            True,
            "unknown",
            "evidence.observation_unavailable",
            False,
        ),
        (
            Profile.GUARD,
            Verdict.UNKNOWN,
            "evidence.observation_unavailable",
            False,
            False,
            "unknown",
            "evidence.observation_unavailable",
            False,
        ),
        (
            Profile.STRICT,
            Verdict.UNKNOWN,
            "evidence.observation_unavailable",
            False,
            False,
            "unknown",
            "evidence.observation_unavailable",
            False,
        ),
        (
            Profile.OBSERVE,
            Verdict.BLOCK,
            "evidence.expired",
            False,
            True,
            "block",
            "evidence.expired",
            False,
        ),
        (
            Profile.GUARD,
            Verdict.BLOCK,
            "evidence.expired",
            False,
            False,
            "block",
            "evidence.expired",
            False,
        ),
        (
            Profile.STRICT,
            Verdict.BLOCK,
            "evidence.expired",
            False,
            False,
            "block",
            "evidence.expired",
            False,
        ),
        (
            Profile.OBSERVE,
            Verdict.BLOCK,
            "resume.checkpoint_stale",
            True,
            False,
            "block",
            "resume.checkpoint_stale",
            True,
        ),
        (
            Profile.GUARD,
            Verdict.BLOCK,
            "resume.checkpoint_stale",
            True,
            False,
            "block",
            "resume.checkpoint_stale",
            True,
        ),
        (
            Profile.STRICT,
            Verdict.BLOCK,
            "resume.checkpoint_stale",
            True,
            False,
            "block",
            "resume.checkpoint_stale",
            True,
        ),
    ],
)
def test_resume_context_profile_matrix_is_literal_and_complete(
    profile: Profile,
    input_verdict: Verdict,
    input_code: str | None,
    input_integrity_failure: bool,
    expected_usable: bool,
    expected_verdict: str,
    expected_code: str | None,
    expected_integrity_failure: bool,
) -> None:
    checkpoint = build_checkpoint(
        parent_checkpoint_id=None,
        target_id=RecordId("sha256:" + "1" * 64),
        goal_id=RecordId("sha256:" + "2" * 64),
        acceptance_criteria=(),
        constraint_digests=(),
        instruction_id=RecordId("sha256:" + "3" * 64),
        policy_id=RecordId("sha256:" + "4" * 64),
        ruleset_id=RecordId("sha256:" + "5" * 64),
        actor_ids=(),
        evidence_ids=(),
        invalidation_ids=(),
        accepted_decision_ids=(),
        pending_work=(),
        unresolved=(),
        assignment_authority=AssignmentAuthority.READ_ONLY,
        authority_scopes=(PathScopeV1(path=None, kind=PathScopeKind.TREE),),
        open_assignment_ids=(),
        audit_parent_id=None,
        initialization_intent_id=RecordId("sha256:" + "6" * 64),
        created_at=validate_logical_time("2026-09-01T00:00:00Z"),
    )
    findings = (
        ()
        if input_code is None
        else (
            Finding(
                input_code,
                input_verdict,
                checkpoint.checkpoint_id,
                input_code,
                {},
                integrity_failure=input_integrity_failure,
            ),
        )
    )

    evaluation = evaluate(EvaluationCase(profile, findings))
    context = build_resume_context(
        checkpoint,
        evaluation,
        goal_digest=digest_bytes(b"matrix goal"),
        invalidations=(),
    )

    assert context.usable is expected_usable
    assert context.verdict.value == expected_verdict
    assert context.blocker_codes == (() if expected_code is None else (expected_code,))
    assert tuple(finding.code for finding in evaluation.findings) == (
        () if expected_code is None else (expected_code,)
    )
    assert (
        any(finding.integrity_failure for finding in evaluation.findings)
        is expected_integrity_failure
    )


@pytest.mark.parametrize(
    ("outcome", "expected_verdict"),
    [
        ("pass", Verdict.PASS),
        ("block", Verdict.BLOCK),
        ("unknown", Verdict.UNKNOWN),
    ],
)
def test_public_resume_preserves_complete_target_git_and_state_metadata(
    tmp_path: Path,
    outcome: str,
    expected_verdict: Verdict,
) -> None:
    repo, target, state_home, continuity, initial_id = _initialized(tmp_path)
    selector = "latest"
    if outcome == "block":
        continuity.checkpoint("advance to make initial checkpoint stale")
        selector = initial_id
    elif outcome == "unknown":
        (target / "drift.txt").write_text("target drift", encoding="utf-8")
    capture_roots_before = tuple(
        sorted(Path(tempfile.gettempdir()).glob("acg-capture-*"), key=os.fspath)
    )
    before = (
        repository_write_manifest(target),
        repository_git_observation(repo),
        _complete_tree_projection(target),
        _complete_tree_projection(state_home),
    )

    resumed = continuity.resume(selector)

    assert resumed.verdict is expected_verdict
    assert (
        repository_write_manifest(target),
        repository_git_observation(repo),
        _complete_tree_projection(target),
        _complete_tree_projection(state_home),
    ) == before
    assert tuple(state_home.glob("*.sqlite3-*")) == ()
    assert (
        tuple(sorted(Path(tempfile.gettempdir()).glob("acg-capture-*"), key=os.fspath))
        == capture_roots_before
    )


def test_resume_stably_missing_instruction_is_protected_block(tmp_path: Path) -> None:
    _repo, target, _state_home, continuity, _checkpoint = _initialized(tmp_path)
    (target / "AGENTS.md").unlink()

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == (
        "resume.instructions_changed",
        "resume.target_changed",
    )


@pytest.mark.parametrize(
    "profile",
    [Profile.OBSERVE, Profile.GUARD, Profile.STRICT],
)
def test_resume_historical_checkpoint_is_exact_stale_refusal(
    tmp_path: Path,
    profile: Profile,
) -> None:
    _repo, _target, state_home, continuity, initial_id = _initialized(
        tmp_path,
        profile=profile,
    )
    current = continuity.checkpoint("reason display text")
    database = _database(state_home)
    before_store = _store_projection(database)

    historical = continuity.resume(initial_id)

    assert historical.checkpoint_id == initial_id
    assert historical.verdict is Verdict.BLOCK
    assert historical.usable is False
    assert historical.blocker_codes == ("resume.checkpoint_stale",)
    assert continuity.resume(current.checkpoint_id).usable is True
    assert _store_projection(database) == before_store


@pytest.mark.parametrize("profile", list(Profile))
@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("target_id", "resume.target_changed"),
        ("instruction_id", "resume.instructions_changed"),
        ("policy_id", "resume.policy_changed"),
        ("ruleset_id", "resume.ruleset_changed"),
    ],
)
def test_resume_protected_identity_drift_is_blocked_in_every_profile(
    tmp_path: Path,
    profile: Profile,
    field: str,
    code: str,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(
        tmp_path,
        profile=profile,
    )
    if field == "instruction_id":
        instruction, snapshot, census, required = _resume_capture_baseline(target)
        changed_bytes = b"# Changed synthetic instructions\n"
        original_file = required.files[instruction]
        changed_file = replace(
            original_file,
            content_digest=digest_bytes(changed_bytes),
        )
        changed_instruction = replace(
            snapshot.instructions[0],
            byte_digest=digest_bytes(changed_bytes),
        )
        changed_snapshot = replace(
            snapshot,
            instructions=(changed_instruction,),
        )
        changed_live = replace(
            required,
            snapshot=replace(
                required.snapshot,
                instructions=(changed_instruction,),
            ),
            files=MappingProxyType({**required.files, instruction: changed_file}),
            required_contents=MappingProxyType({instruction: changed_bytes}),
        )
        changed_census = replace(
            census,
            snapshot=replace(
                census.snapshot,
                instructions=(changed_instruction,),
            ),
            files=MappingProxyType({**census.files, instruction: changed_file}),
        )
        adapter = ScriptedResumeAdapter(
            target,
            live=(changed_census, changed_live, changed_live),
            snapshots=(changed_snapshot,),
        )
        resumed = _resume_with_adapter(
            target, state_home, adapter, profile=profile
        ).resume()
    else:
        child = _seed_identity_drift_checkpoint(
            target=target,
            state_home=state_home,
            session_key="resume",
            field=field,
        )
        resumed = continuity.resume(child.checkpoint_id)

    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == (code,)


@pytest.mark.parametrize(
    ("profile", "expected_usable"),
    [(Profile.OBSERVE, True), (Profile.GUARD, False), (Profile.STRICT, False)],
)
def test_resume_incomplete_evidence_is_unknown_never_pass(
    tmp_path: Path,
    profile: Profile,
    expected_usable: bool,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(
        tmp_path,
        profile=profile,
    )
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (
            _evidence(
                "incomplete",
                checkpoint=parent,
                producer=producer,
                completeness=EvidenceCompleteness.INCOMPLETE,
            ),
        )

    _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(),
        evidence_factory=records,
    )

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.UNKNOWN
    assert resumed.usable is expected_usable
    assert resumed.blocker_codes == ("evidence.observation_unavailable",)
    assert resumed.invalidations[0].state is EvidenceState.UNKNOWN


def test_resume_reopens_and_rediscovers_the_existing_database(tmp_path: Path) -> None:
    repo, _target, state_home, continuity, checkpoint_id = _initialized(tmp_path)
    first = continuity.resume()

    reopened = Continuity.open(
        repo.root,
        state_home=state_home,
        session_key="resume",
    )

    assert reopened.resume() == first
    assert reopened.resume(checkpoint_id) == first


@pytest.mark.parametrize("selector", ["", "not-a-digest", 1, None])
def test_resume_rejects_invalid_checkpoint_selectors(
    tmp_path: Path,
    selector: object,
) -> None:
    _repo, _target, _state_home, continuity, _checkpoint_id = _initialized(tmp_path)

    with pytest.raises(ContinuityRequestError, match="checkpoint selection is invalid"):
        continuity.resume(selector)  # type: ignore[arg-type]


def test_resume_rejects_unavailable_checkpoint(tmp_path: Path) -> None:
    _repo, _target, _state_home, continuity, _checkpoint_id = _initialized(tmp_path)

    with pytest.raises(ContinuityRequestError, match="checkpoint is unavailable"):
        continuity.resume("sha256:" + "f" * 64)


def test_resume_corrupt_store_raises_integrity_error_without_context(
    tmp_path: Path,
) -> None:
    _repo, _target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    database = _database(state_home)
    with sqlite3.connect(database) as connection:
        triggers = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'trigger' "
            "AND tbl_name = 'records'"
        ).fetchall()
        assert triggers
        for (name,) in triggers:
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(
            "UPDATE records SET canonical_bytes = ? WHERE record_type = 'Goal'",
            (sqlite3.Binary(b'{"digest":"sha256:' + b"0" * 64 + b'"}'),),
        )

    with pytest.raises(StoreIntegrityError) as error:
        continuity.resume()

    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_resume_corrupt_checkpoint_and_instruction_records_scrub_exception_links(
    tmp_path: Path,
) -> None:
    for record_type in ("Checkpoint", "InstructionManifest"):
        case_root = tmp_path / record_type
        case_root.mkdir()
        _repo, _target, state_home, continuity, _checkpoint_id = _initialized(case_root)
        database = _database(state_home)
        with sqlite3.connect(database) as connection:
            triggers = connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'trigger' "
                "AND tbl_name = 'records'"
            ).fetchall()
            assert triggers
            for (name,) in triggers:
                connection.execute(f'DROP TRIGGER "{name}"')
            connection.execute(
                "UPDATE records SET canonical_bytes = ? WHERE record_type = ?",
                (sqlite3.Binary(b'{"raw marker":true}'), record_type),
            )

        with pytest.raises(StoreIntegrityError) as error:
            continuity.resume()

        assert "raw marker" not in str(error.value)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None


@pytest.mark.parametrize("corrupt_record", ["checkpoint", "instruction"])
def test_public_verify_scrubs_checkpoint_decoder_exception_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    corrupt_record: str,
) -> None:
    _repo, target, state_home, continuity, checkpoint_id = _initialized(tmp_path)
    database = _database(state_home)
    root = open_external_state_root(target, target / ".git", state_home)
    with SQLiteStateStore(
        root,
        database_name=database.name,
        store_id=None,
        read_only=True,
    ) as store:
        checkpoint = checkpoint_from_record(store.load_record(checkpoint_id))
    corrupt_id = (
        checkpoint.checkpoint_id
        if corrupt_record == "checkpoint"
        else checkpoint.instruction_id
    )
    corrupt_type = (
        "Checkpoint" if corrupt_record == "checkpoint" else "InstructionManifest"
    )
    corrupt_value = make_record(corrupt_type, {"raw marker": True})
    original_load_record = SQLiteStateStore.load_record

    def load_corrupt_record(
        store: SQLiteStateStore, record_id: RecordId
    ) -> StoredRecord:
        if record_id == corrupt_id:
            return corrupt_value
        return original_load_record(store, record_id)

    monkeypatch.setattr(SQLiteStateStore, "load_record", load_corrupt_record)

    with pytest.raises(StoreIntegrityError) as error:
        continuity.verify()

    assert "raw marker" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_resume_real_git_changed_cited_bytes_reports_exact_invalidation(
    tmp_path: Path,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    citation = citation_v1(b"docs/guide.txt", b"guide\n")
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (
            _evidence(
                "real-git-citation",
                checkpoint=parent,
                producer=producer,
                kind=EvidenceKind.CITATION,
                subject_digest=citation.file_digest,
                invalidators=(
                    InvalidatorV1(
                        InvalidatorKind.CITATION,
                        citation.record().record_id,
                        True,
                    ),
                ),
            ),
        )

    _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(citation,),
        evidence_factory=records,
    )
    (target / "docs" / "guide.txt").write_bytes(b"changed by another process")

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == ("citation.file_changed",)


def test_resume_skips_optional_citation_invalidator_when_cited_bytes_changed(
    tmp_path: Path,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    citation = citation_v1(b"docs/guide.txt", b"stale optional citation\n")
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (
            _evidence(
                "optional-citation",
                checkpoint=parent,
                producer=producer,
                kind=EvidenceKind.CITATION,
                subject_digest=digest_bytes(b"guide\n"),
                invalidators=(
                    InvalidatorV1(
                        InvalidatorKind.CITATION,
                        citation.record().record_id,
                        False,
                    ),
                ),
            ),
        )

    _child, evidence = _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(citation,),
        evidence_factory=records,
    )

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.PASS
    assert resumed.usable is True
    assert resumed.blocker_codes == ()
    assert resumed.current_evidence_ids == (evidence[0].evidence_id,)
    assert resumed.invalidations[0].state is EvidenceState.CURRENT
    assert resumed.invalidations[0].code == ""


def test_resume_real_git_unrelated_dirty_path_does_not_false_pass(
    tmp_path: Path,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    citation = citation_v1(b"docs/guide.txt", b"guide\n")
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (
            _evidence(
                "real-git-unrelated-drift",
                checkpoint=parent,
                producer=producer,
                kind=EvidenceKind.CITATION,
                subject_digest=citation.file_digest,
                invalidators=(
                    InvalidatorV1(
                        InvalidatorKind.CITATION,
                        citation.record().record_id,
                        True,
                    ),
                ),
            ),
        )

    _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(citation,),
        evidence_factory=records,
    )
    (target / "drift.txt").write_text("unrelated drift", encoding="utf-8")

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.UNKNOWN
    assert resumed.usable is False
    assert len(resumed.current_evidence_ids) == 1
    assert resumed.invalidations[0].state is EvidenceState.CURRENT
    assert resumed.blocker_codes == ("evidence.observation_unavailable",)


def test_resume_binds_live_citation_to_stored_citation_not_evidence_subject(
    tmp_path: Path,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    live_bytes = (target / "docs" / "guide.txt").read_bytes()
    citation = citation_v1(b"docs/guide.txt", b"stored citation bytes\n")
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        base = _evidence(
            "self-asserted-live-subject",
            checkpoint=parent,
            producer=producer,
            kind=EvidenceKind.CITATION,
            subject_digest=digest_bytes(live_bytes),
            invalidators=(
                InvalidatorV1(
                    InvalidatorKind.CITATION,
                    citation.record().record_id,
                    True,
                ),
            ),
        )
        dependent = _evidence(
            "binding-dependent",
            checkpoint=parent,
            producer=producer,
            invalidators=(
                InvalidatorV1(
                    InvalidatorKind.EVIDENCE_DEPENDENCY,
                    base.evidence_id,
                    True,
                ),
            ),
        )
        return base, dependent

    _child, evidence = _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(citation,),
        evidence_factory=records,
    )
    base, dependent = evidence

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == (
        "citation.file_changed",
        "evidence.dependency_invalid",
    )
    by_id = {item.evidence_id: item for item in resumed.invalidations}
    assert by_id[base.evidence_id].state is EvidenceState.INVALIDATED
    assert by_id[base.evidence_id].code == "citation.file_changed"
    assert by_id[dependent.evidence_id].state is EvidenceState.INVALIDATED
    assert by_id[dependent.evidence_id].code == "evidence.dependency_invalid"
    assert by_id[dependent.evidence_id].transitive_path == (
        dependent.evidence_id,
        base.evidence_id,
    )


def test_resume_citation_mismatch_propagates_through_transitive_ancestry(
    tmp_path: Path,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    assert (target / "docs" / "guide.txt").read_bytes() == b"guide\n"
    citation = citation_v1(b"docs/guide.txt", b"stale guide\n")
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        base = _evidence(
            "base",
            checkpoint=parent,
            producer=producer,
            kind=EvidenceKind.CITATION,
            subject_digest=citation.file_digest,
            invalidators=(
                InvalidatorV1(
                    InvalidatorKind.CITATION,
                    citation.record().record_id,
                    True,
                ),
            ),
        )
        middle = _evidence(
            "middle",
            checkpoint=parent,
            producer=producer,
            invalidators=(
                InvalidatorV1(
                    InvalidatorKind.EVIDENCE_DEPENDENCY,
                    base.evidence_id,
                    True,
                ),
            ),
        )
        top = _evidence(
            "top",
            checkpoint=parent,
            producer=producer,
            invalidators=(
                InvalidatorV1(
                    InvalidatorKind.EVIDENCE_DEPENDENCY,
                    middle.evidence_id,
                    True,
                ),
            ),
        )
        return base, middle, top

    _child, evidence = _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(citation,),
        evidence_factory=records,
    )
    base, middle, top = evidence

    resumed = continuity.resume()

    by_id = {item.evidence_id: item for item in resumed.invalidations}
    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == (
        "citation.file_changed",
        "evidence.dependency_invalid",
    )
    assert by_id[base.evidence_id].state is EvidenceState.INVALIDATED
    assert by_id[base.evidence_id].code == "citation.file_changed"
    assert by_id[middle.evidence_id].state is EvidenceState.INVALIDATED
    assert by_id[middle.evidence_id].code == "evidence.dependency_invalid"
    assert by_id[top.evidence_id].state is EvidenceState.INVALIDATED
    assert by_id[top.evidence_id].code == "evidence.dependency_invalid"
    assert by_id[top.evidence_id].transitive_path == (
        top.evidence_id,
        middle.evidence_id,
        base.evidence_id,
    )


@pytest.mark.parametrize(
    ("profile", "expected_usable"),
    [(Profile.OBSERVE, True), (Profile.GUARD, False), (Profile.STRICT, False)],
)
def test_resume_unavailable_citation_observation_obeys_profile_semantics(
    tmp_path: Path,
    profile: Profile,
    expected_usable: bool,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(
        tmp_path,
        profile=profile,
    )
    assert (target / "docs" / "guide.txt").read_bytes() == b"guide\n"
    citation = citation_v1(b"docs/guide.txt", b"guide\nextra", 0, 11)
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (
            _evidence(
                "span",
                checkpoint=parent,
                producer=producer,
                kind=EvidenceKind.CITATION,
                subject_digest=citation.span_digest,
                invalidators=(
                    InvalidatorV1(
                        InvalidatorKind.CITATION,
                        citation.record().record_id,
                        True,
                    ),
                ),
            ),
        )

    _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(citation,),
        evidence_factory=records,
    )

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.UNKNOWN
    assert resumed.usable is expected_usable
    assert resumed.blocker_codes == ("evidence.observation_unavailable",)
    assert len(resumed.invalidations) == 1
    assert resumed.invalidations[0].state is EvidenceState.UNKNOWN
    assert resumed.invalidations[0].code == "evidence.observation_unavailable"


def test_resume_cross_checkpoint_dependency_remains_current(tmp_path: Path) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )
    database = _database(state_home)
    root = open_external_state_root(target, target / ".git", state_home)
    with SQLiteStateStore(root, database_name=database.name, store_id=None) as store:
        head_name = "session:resume:checkpoint"
        initial_head = store.read_head(head_name)
        assert initial_head is not None
        initial = checkpoint_from_record(store.load_record(initial_head.record_id))
        ancestor = _evidence("ancestor", checkpoint=initial, producer=producer)
        middle = build_checkpoint(
            parent_checkpoint_id=initial.checkpoint_id,
            target_id=initial.target_id,
            goal_id=initial.goal_id,
            acceptance_criteria=initial.acceptance_criteria,
            constraint_digests=initial.constraint_digests,
            instruction_id=initial.instruction_id,
            policy_id=initial.policy_id,
            ruleset_id=initial.ruleset_id,
            actor_ids=initial.actor_ids,
            evidence_ids=(ancestor.evidence_id,),
            invalidation_ids=initial.invalidation_ids,
            accepted_decision_ids=initial.accepted_decision_ids,
            pending_work=initial.pending_work,
            unresolved=initial.unresolved,
            assignment_authority=initial.assignment_authority,
            authority_scopes=initial.authority_scopes,
            open_assignment_ids=initial.open_assignment_ids,
            audit_parent_id=initial_head.audit_event_id,
            initialization_intent_id=initial.initialization_intent_id,
            created_at=validate_logical_time("2026-09-01T00:00:01Z"),
        )
        middle_commit = store.commit_many(
            records=(ancestor.record(), middle.record()),
            event=AuditEventDraft(
                kind="checkpoint",
                subject_id=middle.checkpoint_id,
                logical_time=middle.created_at,
                details={"record_id": middle.checkpoint_id},
            ),
            head_updates=(HeadUpdate(head_name, initial_head, middle.checkpoint_id),),
        )
        dependant = _evidence(
            "dependant",
            checkpoint=middle,
            producer=producer,
            invalidators=(
                InvalidatorV1(
                    InvalidatorKind.EVIDENCE_DEPENDENCY,
                    ancestor.evidence_id,
                    True,
                ),
            ),
        )
        current = build_checkpoint(
            parent_checkpoint_id=middle.checkpoint_id,
            target_id=middle.target_id,
            goal_id=middle.goal_id,
            acceptance_criteria=middle.acceptance_criteria,
            constraint_digests=middle.constraint_digests,
            instruction_id=middle.instruction_id,
            policy_id=middle.policy_id,
            ruleset_id=middle.ruleset_id,
            actor_ids=middle.actor_ids,
            evidence_ids=(dependant.evidence_id,),
            invalidation_ids=middle.invalidation_ids,
            accepted_decision_ids=middle.accepted_decision_ids,
            pending_work=middle.pending_work,
            unresolved=middle.unresolved,
            assignment_authority=middle.assignment_authority,
            authority_scopes=middle.authority_scopes,
            open_assignment_ids=middle.open_assignment_ids,
            audit_parent_id=dict(middle_commit.heads)[head_name].audit_event_id,
            initialization_intent_id=middle.initialization_intent_id,
            created_at=validate_logical_time("2026-09-01T00:00:02Z"),
        )
        store.commit_many(
            records=(dependant.record(), current.record()),
            event=AuditEventDraft(
                kind="checkpoint",
                subject_id=current.checkpoint_id,
                logical_time=current.created_at,
                details={"record_id": current.checkpoint_id},
            ),
            head_updates=(
                HeadUpdate(
                    head_name,
                    dict(middle_commit.heads)[head_name],
                    current.checkpoint_id,
                ),
            ),
        )

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.PASS
    assert resumed.usable is True
    assert resumed.current_evidence_ids == tuple(
        sorted((ancestor.evidence_id, dependant.evidence_id))
    )
    by_id = {item.evidence_id: item for item in resumed.invalidations}
    assert by_id[ancestor.evidence_id].state is EvidenceState.CURRENT
    assert by_id[dependant.evidence_id].state is EvidenceState.CURRENT


def test_resume_evidence_bound_to_grandparent_checkpoint_is_not_checkpoint_mismatch(
    tmp_path: Path,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (_evidence("lineage", checkpoint=parent, producer=producer),)

    _child, evidence = _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(),
        evidence_factory=records,
    )
    current = continuity.checkpoint("advance after evidence admission")

    resumed = continuity.resume(current.checkpoint_id)

    assert resumed.verdict is Verdict.PASS
    assert resumed.usable is True
    assert resumed.blocker_codes == ()
    assert resumed.current_evidence_ids == (evidence[0].evidence_id,)
    assert resumed.invalidations[0].state is EvidenceState.CURRENT


def test_resume_does_not_self_trust_an_unapproved_evidence_producer(
    tmp_path: Path,
) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    unapproved = ProducerIdentity(
        "unapproved-producer",
        "1.0.0",
        digest_bytes(b"unapproved producer binary"),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (_evidence("untrusted", checkpoint=parent, producer=unapproved),)

    _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(),
        evidence_factory=records,
    )

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.blocker_codes == ("evidence.producer_mismatch",)
    assert len(resumed.invalidations) == 1
    assert resumed.invalidations[0].state is EvidenceState.INVALIDATED
    assert resumed.invalidations[0].code == "evidence.producer_mismatch"


def _resume_with_live_citation_state(
    target: Path,
    state_home: Path,
    *,
    citation: CitationV1,
    observed: bytes | None,
    baseline: tuple[PathIdentityV1, CaptureSnapshot, object, object] | None = None,
) -> ResumeContext:
    instruction, snapshot, _census, required = (
        _resume_capture_baseline(target) if baseline is None else baseline
    )
    citation_path = citation.path
    citation_raw = citation_path.raw_bytes()
    files = {
        path: value
        for path, value in required.files.items()
        if path.raw_bytes() != citation_raw
    }
    contents = {
        path: value
        for path, value in required.required_contents.items()
        if path.raw_bytes() != citation_raw
    }
    if observed is not None:
        base = files[instruction]
        files[citation_path] = replace(
            base,
            path=citation_path,
            size=len(observed),
            content_digest=digest_bytes(observed),
        )
        contents[citation_path] = observed
    captured = replace(
        required,
        files=MappingProxyType(files),
        required_contents=MappingProxyType(contents),
    )
    adapter = ScriptedResumeAdapter(
        target,
        live=(captured, captured, captured) * 2,
        snapshots=(snapshot, snapshot),
    )
    return _resume_with_adapter(target, state_home, adapter).resume()


@pytest.mark.parametrize(
    ("mutation", "expected_code", "expected_current"),
    [
        ("span", "citation.span_changed", False),
        ("missing", "citation.path_missing", False),
        ("unrelated", "", True),
    ],
)
def test_resume_citation_span_missing_and_unrelated_path_semantics(
    tmp_path: Path,
    mutation: str,
    expected_code: str,
    expected_current: bool,
) -> None:
    _repo, target, state_home, _continuity, _checkpoint_id = _initialized(tmp_path)
    path = b"docs/guide.txt" if mutation != "unrelated" else b"docs/other.txt"
    baseline = _resume_capture_baseline(target) if mutation == "unrelated" else None
    if mutation == "unrelated":
        (target / "docs" / "other.txt").write_bytes(b"other citation\n")
        citation = citation_v1(path, b"other citation\n")
    else:
        citation = citation_v1(path, b"guide\n", 0, 5)
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (
            _evidence(
                mutation,
                checkpoint=parent,
                producer=producer,
                kind=EvidenceKind.CITATION,
                subject_digest=(
                    citation.span_digest
                    if citation.span_digest is not None
                    else citation.file_digest
                ),
                invalidators=(
                    InvalidatorV1(
                        InvalidatorKind.CITATION,
                        citation.record().record_id,
                        True,
                    ),
                ),
            ),
        )

    _child, evidence = _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(citation,),
        evidence_factory=records,
    )
    if mutation == "span":
        resumed = _resume_with_live_citation_state(
            target,
            state_home,
            citation=citation,
            observed=b"Guide\n",
        )
    elif mutation == "missing":
        resumed = _resume_with_live_citation_state(
            target,
            state_home,
            citation=citation,
            observed=None,
        )
    else:
        resumed = _resume_with_live_citation_state(
            target,
            state_home,
            citation=citation,
            observed=b"other citation\n",
            baseline=baseline,
        )

    if expected_current:
        assert resumed.verdict is Verdict.PASS
        assert resumed.current_evidence_ids == (evidence[0].evidence_id,)
        assert resumed.invalidations[0].state is EvidenceState.CURRENT
        assert resumed.blocker_codes == ()
    else:
        assert resumed.verdict is Verdict.BLOCK
        assert resumed.current_evidence_ids == ()
        assert resumed.invalidations[0].state is EvidenceState.INVALIDATED
        assert resumed.invalidations[0].code == expected_code
        assert resumed.blocker_codes == (expected_code,)


def test_resume_expires_evidence_at_exact_logical_boundary(tmp_path: Path) -> None:
    _repo, target, state_home, continuity, _checkpoint_id = _initialized(tmp_path)
    producer = ProducerIdentity(
        "agent-continuity-guard",
        "0.1.0.dev0",
        digest_bytes(
            canonical_bytes({"name": "agent-continuity-guard", "version": "0.1.0.dev0"})
        ),
    )

    def records(parent: CheckpointV1) -> tuple[EvidenceV1, ...]:
        return (
            _evidence(
                "expired",
                checkpoint=parent,
                producer=producer,
                expires_at="2026-09-01T00:00:10Z",
            ),
        )

    _seed_evidence_checkpoint(
        target=target,
        state_home=state_home,
        session_key="resume",
        citations=(),
        evidence_factory=records,
    )

    resumed = continuity.resume()

    assert resumed.verdict is Verdict.BLOCK
    assert resumed.usable is False
    assert resumed.current_evidence_ids == ()
    assert resumed.invalidations[0].state is EvidenceState.INVALIDATED
    assert resumed.invalidations[0].code == "evidence.expired"
    assert resumed.blocker_codes == ("evidence.expired",)


def test_resume_retries_unstable_capture_once_then_recovers(tmp_path: Path) -> None:
    _repo, target, state_home, _continuity, _checkpoint = _initialized(tmp_path)
    instruction, snapshot, census, required = _resume_capture_baseline(target)
    changed_target = replace(
        required.snapshot.target,
        inventory_digest=digest_bytes(b"changed inventory"),
    )
    changed_required = replace(
        required,
        snapshot=replace(required.snapshot, target=changed_target),
    )
    adapter = ScriptedResumeAdapter(
        target,
        live=(census, required, changed_required, census, required, required),
        snapshots=(snapshot,),
    )

    context = _resume_with_adapter(target, state_home, adapter).resume()

    assert (context.verdict, context.usable, context.blocker_codes) == (
        Verdict.PASS,
        True,
        (),
    )
    assert (
        adapter.live_calls
        == [
            (),
            (instruction.raw_bytes(),),
            (instruction.raw_bytes(),),
        ]
        * 2
    )
    assert adapter.capture_calls == [(instruction.raw_bytes(),)]


def test_resume_rejects_inventory_digest_aba_after_bounded_retry(
    tmp_path: Path,
) -> None:
    _repo, target, state_home, _continuity, _checkpoint = _initialized(tmp_path)
    _instruction, _snapshot, census, required = _resume_capture_baseline(target)
    changed_target = replace(
        required.snapshot.target,
        inventory_digest=digest_bytes(b"aba inventory"),
    )
    changed_required = replace(
        required,
        snapshot=replace(required.snapshot, target=changed_target),
    )
    adapter = ScriptedResumeAdapter(
        target,
        live=(census, required, changed_required) * 2,
        snapshots=(),
    )

    context = _resume_with_adapter(target, state_home, adapter).resume()

    assert context.verdict is Verdict.UNKNOWN
    assert context.usable is False
    assert context.blocker_codes == ("evidence.observation_unavailable",)
    assert len(adapter.live_calls) == 6
    assert adapter.capture_calls == []


def test_resume_candidate_capture_failure_is_unknown_without_temp_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repo, target, state_home, _continuity, _checkpoint = _initialized(tmp_path)
    instruction, _snapshot, census, required = _resume_capture_baseline(target)
    adapter = ScriptedResumeAdapter(
        target,
        live=(census, required, required) * 2,
        snapshots=(
            CaptureUnknownError("raw marker"),
            CaptureUnknownError("raw marker"),
        ),
    )
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))

    context = _resume_with_adapter(target, state_home, adapter).resume()

    assert context.verdict is Verdict.UNKNOWN
    assert context.usable is False
    assert context.blocker_codes == ("evidence.observation_unavailable",)
    assert adapter.capture_calls == [(instruction.raw_bytes(),)] * 2
    assert len(adapter.live_calls) == 6
    assert _capture_roots(temp_root) == ()


def test_resume_materialization_failure_is_sanitized_and_leak_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repo, target, state_home, _continuity, _checkpoint = _initialized(tmp_path)
    _instruction, snapshot, census, required = _resume_capture_baseline(target)
    adapter = ScriptedResumeAdapter(
        target,
        live=(census, required, required) * 2,
        snapshots=(snapshot, snapshot),
    )
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))

    def fail_materialization(*, prefix: str) -> str:
        assert prefix == "acg-capture-"
        raise OSError("raw marker")

    monkeypatch.setattr(tempfile, "mkdtemp", fail_materialization)
    before = (_tree_projection(target), _tree_projection(state_home))

    context = _resume_with_adapter(target, state_home, adapter).resume()

    assert (_tree_projection(target), _tree_projection(state_home)) == before
    assert context.verdict is Verdict.UNKNOWN
    assert context.usable is False
    assert context.blocker_codes == ("evidence.observation_unavailable",)
    assert "raw marker" not in repr(context)
    assert len(adapter.live_calls) == 3
    assert len(adapter.capture_calls) == 1
    assert _capture_roots(temp_root) == ()


def test_resume_post_creation_materialization_failure_removes_capture_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repo, target, state_home, _continuity, _checkpoint = _initialized(tmp_path)
    _instruction, snapshot, census, required = _resume_capture_baseline(target)
    adapter = ScriptedResumeAdapter(
        target,
        live=(census, required, required),
        snapshots=(snapshot,),
    )
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
    real_is_relative_to = Path.is_relative_to
    real_rmtree = shutil.rmtree
    cleanup_attempts = 0

    def fail_after_root_creation(path: Path, other: Path) -> bool:
        if path.parent == temp_root and path.name.startswith("acg-capture-"):
            raise OSError("raw materialization marker")
        return real_is_relative_to(path, other)

    def fail_cleanup_once(path: Path) -> None:
        nonlocal cleanup_attempts
        cleanup_attempts += 1
        if cleanup_attempts == 1:
            raise OSError("raw cleanup marker")
        real_rmtree(path)

    monkeypatch.setattr(Path, "is_relative_to", fail_after_root_creation)
    monkeypatch.setattr(shutil, "rmtree", fail_cleanup_once)

    context = _resume_with_adapter(target, state_home, adapter).resume()

    assert context.verdict is Verdict.UNKNOWN
    assert context.usable is False
    assert context.blocker_codes == ("evidence.observation_unavailable",)
    assert cleanup_attempts == 2
    assert _capture_roots(temp_root) == ()


def test_resume_cleanup_failure_retries_removal_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repo, target, state_home, _continuity, _checkpoint = _initialized(tmp_path)
    _instruction, snapshot, census, required = _resume_capture_baseline(target)
    adapter = ScriptedResumeAdapter(
        target,
        live=(census, required, required),
        snapshots=(snapshot,),
    )
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
    real_rmtree = shutil.rmtree
    attempts = 0

    def fail_persistently(path: Path) -> None:
        nonlocal attempts
        attempts += 1
        raise OSError("raw cleanup marker")

    monkeypatch.setattr(shutil, "rmtree", fail_persistently)

    try:
        with pytest.raises(
            CaptureUnknownError, match="capture cleanup failed"
        ) as error:
            _resume_with_adapter(target, state_home, adapter).resume()

        assert "raw cleanup marker" not in str(error.value)
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
        assert attempts == 2
    finally:
        monkeypatch.setattr(shutil, "rmtree", real_rmtree)
        for root in _capture_roots(temp_root):
            real_rmtree(root)
    assert _capture_roots(temp_root) == ()


@pytest.mark.parametrize("appears", [True, False])
def test_resume_path_appearance_or_disappearance_is_bounded_unknown(
    tmp_path: Path,
    appears: bool,
) -> None:
    _repo, target, state_home, _continuity, _checkpoint = _initialized(tmp_path)
    _instruction, _snapshot, census, required = _resume_capture_baseline(target)
    path = next(iter(required.files))
    files_without = MappingProxyType(
        {
            item: observation
            for item, observation in required.files.items()
            if item != path
        }
    )
    contents_without = MappingProxyType(
        {
            item: content
            for item, content in required.required_contents.items()
            if item != path
        }
    )
    absent = replace(
        required,
        files=files_without,
        required_contents=contents_without,
    )
    first, second = (absent, required) if appears else (required, absent)
    adapter = ScriptedResumeAdapter(
        target,
        live=(census, first, second) * 2,
        snapshots=(),
    )

    context = _resume_with_adapter(target, state_home, adapter).resume()

    assert context.verdict is Verdict.UNKNOWN
    assert context.usable is False
    assert context.blocker_codes == ("evidence.observation_unavailable",)
    assert len(adapter.live_calls) == 6
    assert adapter.capture_calls == []


def test_resume_normalizes_malformed_sqlite_without_raw_error_leak(
    tmp_path: Path,
) -> None:
    _repo, _target, state_home, continuity, _checkpoint = _initialized(tmp_path)
    database = _database(state_home)
    database.write_bytes(b"not a sqlite database: raw marker")
    database.chmod(0o600)

    with pytest.raises(StoreIntegrityError) as error:
        continuity.resume()

    assert type(error.value) is StoreIntegrityError
    assert "raw marker" not in str(error.value)
    assert "sqlite" not in str(error.value).lower() or str(error.value).startswith(
        "SQLite"
    )
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_resume_reads_audit_head_checkpoint_and_links_from_one_sqlite_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repo, _target, state_home, continuity, checkpoint = _initialized(tmp_path)
    database = _database(state_home)
    original_verify = SQLiteStateStore.verify_audit
    updated = Event()
    committed = Event()
    failures: list[BaseException] = []
    replacement_id = "sha256:" + "f" * 64
    writer: Thread | None = None

    def mutate_after_verified() -> None:
        connection = sqlite3.connect(database, isolation_level=None, timeout=15.0)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE heads SET record_id = ? WHERE name = ?",
                (replacement_id, "session:resume:checkpoint"),
            )
            updated.set()
            connection.execute("COMMIT")
            committed.set()
        except BaseException as error:
            failures.append(error)
        finally:
            connection.close()

    def verify_then_start_writer(
        store: SQLiteStateStore,
        anchor: object = None,
    ) -> object:
        nonlocal writer
        verification = original_verify(store, anchor)
        writer = Thread(target=mutate_after_verified)
        writer.start()
        assert updated.wait(5.0)
        assert not committed.is_set()
        return verification

    monkeypatch.setattr(SQLiteStateStore, "verify_audit", verify_then_start_writer)

    context = continuity.resume()
    assert writer is not None
    writer.join(15.0)

    assert failures == []
    assert committed.is_set()
    assert context.checkpoint_id == checkpoint
    assert context.verdict is Verdict.PASS
    with sqlite3.connect(database) as connection:
        stored_head = connection.execute(
            "SELECT record_id FROM heads WHERE name = ?",
            ("session:resume:checkpoint",),
        ).fetchone()
    assert stored_head == (replacement_id,)
