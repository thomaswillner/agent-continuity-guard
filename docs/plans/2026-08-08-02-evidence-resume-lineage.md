# Evidence, Resume, and Assignment Lineage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add exact citation/evidence invalidation, verified long-session resume, and same-machine parent-child assignment lineage.

**Architecture:** Extend the pure kernel with Citation, Evidence, Invalidation, ResumeContext, Assignment, and AssignmentResult records. The Continuity facade performs capture and StateStore transactions; the kernel remains free of filesystem, clock, database, subprocess, environment, and network access.

**Tech Stack:** Python 3.11+ standard-library runtime, dataclasses, StrEnum, hashlib, sqlite3, pytest, Hypothesis, Ruff, mypy.

## Global Constraints

- Plan 1 must be green and committed before this plan starts.
- MIT public-safe implementation; no private reference source, prose, names, paths, hashes, datasets, or fixtures.
- Targets remain read-only. ACG performs no merge, patch, checkout, reset, Git mutation, or target write.
- Version 0.1 assignments are same-machine and share one StateStore.
- Identity-bearing paths use PathIdentityV1 raw-byte encoding; display strings never define identity.
- Pure verify and resume do not change checkpoint, finding, ruleset, or audit heads.
- Missing, stale, unstable, unsupported, truncated, or incomplete proof is UNKNOWN, never PASS.
- No generic JSON, vendor adapter, cross-machine envelope, Markdown parser, or hook integration in this plan.

---

## File Map

- `schemas/v1/citation.schema.json`: strict Citation/v1 interchange contract.
- `schemas/v1/evidence.schema.json`: strict Evidence/v1 interchange contract.
- `schemas/v1/assignment.schema.json`: strict same-machine Assignment/v1 contract.
- `schemas/v1/assignment-result.schema.json`: strict AssignmentResult/v1 contract.
- `src/agent_continuity/kernel/citation.py`: Citation model and validation.
- `src/agent_continuity/kernel/evidence.py`: Evidence model and validation.
- `src/agent_continuity/kernel/invalidation.py`: pure direct/transitive invalidation.
- `src/agent_continuity/kernel/resume.py`: pure ResumeContext construction.
- `src/agent_continuity/kernel/lineage.py`: pure assignment derivation and result acceptance.
- `src/agent_continuity/api.py`: Continuity and Assignment facade methods.
- `src/agent_continuity/capture/coordinator.py`: stable observation coordination.
- `src/agent_continuity/store/base.py`: store interfaces consumed by facade.
- `src/agent_continuity/store/sqlite.py`: atomic assignment/result transactions.

### Task 1: Extend capture to stable live-worktree observations

**Files:**

- Create: `src/agent_continuity/capture/filesystem.py`
- Modify: `src/agent_continuity/capture/git.py`
- Modify: `src/agent_continuity/capture/coordinator.py`
- Modify: `src/agent_continuity/capture/base.py`
- Create: `tests/integration/test_live_worktree_capture.py`
- Create: `tests/security/test_live_capture_races.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class FileObservation:
    path: PathIdentityV1
    object_type: str
    mode: int
    size: int
    content_digest: Digest
    file_identity: tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class CapturedView:
    snapshot: CaptureSnapshot
    files: Mapping[PathIdentityV1, FileObservation]
    ephemeral_root: Path | None


class CaptureCoordinator:
    def capture_stable(
        self,
        required_paths: Sequence[PathIdentityV1] = (),
    ) -> CapturedView: ...


class FilesystemTargetAdapter:
    def __init__(
        self,
        target: Path,
        exclusions: Sequence[PathIdentityV1] = (),
    ) -> None: ...

    def capture(
        self,
        instruction_paths: Sequence[bytes],
    ) -> CaptureSnapshot: ...
```

- [ ] **Step 1: Write failing live-worktree tests**

Test dirty tracked and nonignored-untracked Git capture plus a deterministic non-Git directory target. Cover raw-byte paths, explicit identity-bound filesystem exclusions, symlink leaf identity without dereference, special-file refusal, one unstable retry, second instability UNKNOWN, changed cited bytes available in immutable view, and exact target pre/post write manifest.

- [ ] **Step 2: Write failing race and capability tests**

Cover leaf replacement, ancestor swap, hardlink, file truncation, path-census change, case collision, and Windows/non-capable adapter returning explicit UNKNOWN for live-worktree promotion while immutable Git-object capture still works.

- [ ] **Step 3: Run RED**

```bash
python -m pytest -q tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
```

Expected: filesystem capture module and CapturedView are absent.

- [ ] **Step 4: Implement descriptor-pinned ephemeral capture**

On POSIX, open approved root, walk with directory descriptors, refuse symlink components and special files, hash from one file descriptor, verify device/inode/mode/link-count/size/ctime before and after read, and write required analyzer bytes only to private external ephemeral storage. Bind symlink leaves as raw target bytes without following. FilesystemTargetAdapter inventories non-Git directories deterministically and binds exact exclusion PathIdentity values plus policy identity.

Git adapter inventories index, tracked worktree, and nonignored-untracked paths separately. Snapshot B repeats census and rehashes changed plus required authority/citation paths. Plan 4 adds the full cross-platform adversarial matrix; unsupported capability is explicit UNKNOWN.

- [ ] **Step 5: Run GREEN**

```bash
python -m pytest -q tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
python -m mypy src/agent_continuity/capture
python -m ruff check src/agent_continuity/capture tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
```

Expected: all pass and no ACG-issued target mutation appears.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/capture tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
git commit -m "feat: capture stable live worktree evidence"
```

### Task 2: Add Citation/v1 and Evidence/v1 contracts

**Files:**

- Create: `schemas/v1/citation.schema.json`
- Create: `schemas/v1/evidence.schema.json`
- Create: `src/agent_continuity/kernel/citation.py`
- Create: `src/agent_continuity/kernel/evidence.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Create: `tests/contract/test_citation_v1.py`
- Create: `tests/contract/test_evidence_v1.py`
- Create: `tests/golden/citation-v1.json`
- Create: `tests/golden/evidence-v1.json`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class CitationV1:
    path: PathIdentityV1
    file_digest: Digest
    byte_start: int | None = None
    byte_end: int | None = None
    span_digest: Digest | None = None


class EvidenceAuthority(StrEnum):
    DETERMINISTIC = "deterministic"
    ADVISORY = "advisory"


class EvidenceKind(StrEnum):
    CITATION = "citation"
    COMMAND = "command"
    STRUCTURED_CLAIM = "structured_claim"
    TARGET = "target"
    HARNESS = "harness"


class EvidenceCompleteness(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    TRUNCATED = "truncated"
    UNAVAILABLE = "unavailable"


class InvalidatorKind(StrEnum):
    CITATION = "citation"
    EVIDENCE_DEPENDENCY = "evidence_dependency"
    TARGET = "target"
    CHECKPOINT = "checkpoint"
    PRODUCER = "producer"
    POLICY = "policy"


@dataclass(frozen=True, slots=True)
class InvalidatorV1:
    kind: InvalidatorKind
    subject_id: RecordId
    required: bool


@dataclass(frozen=True, slots=True)
class EvidenceV1:
    evidence_id: RecordId
    kind: EvidenceKind
    subject_digest: Digest
    authority: EvidenceAuthority
    producer: ProducerIdentity
    target_id: RecordId
    checkpoint_id: RecordId
    observed_at: LogicalTime
    expires_at: LogicalTime | None
    completeness: EvidenceCompleteness
    terminal_status: int | None
    declared_output_digest: Digest | None
    observed_output_digest: Digest | None
    collected_check_count: int | None
    pagination_complete: bool | None
    payload_digest: Digest
    facts: tuple[FactV1, ...]
    invalidators: tuple[InvalidatorV1, ...]


def validate_citation(citation: CitationV1) -> None: ...
def validate_evidence(evidence: EvidenceV1) -> None: ...
```

- [ ] **Step 1: Write failing Citation/v1 contract tests**

```python
def test_span_citation_requires_complete_bounds_and_digest() -> None:
    with pytest.raises(RecordSchemaError):
        CitationV1(
            path=path_identity(b"docs/guide.md"),
            file_digest=digest(b"whole"),
            byte_start=4,
            byte_end=None,
            span_digest=None,
        )


def test_whole_file_citation_round_trips_canonically() -> None:
    citation = citation_v1(b"docs/guide.md", b"whole")
    assert decode_record(encode_record(citation)) == citation
```

Also encode exact tests for non-UTF-8 POSIX path bytes, negative/equal/reversed offsets, partial span fields, unknown fields, and exact span digest over raw byte offsets.

- [ ] **Step 2: Run Citation tests to verify RED**

Run:

```bash
python -m pytest -q tests/contract/test_citation_v1.py
```

Expected: collection fails because `agent_continuity.kernel.citation` does not exist.

- [ ] **Step 3: Implement strict Citation/v1**

```python
def validate_citation(value: CitationV1) -> None:
    span = (value.byte_start, value.byte_end, value.span_digest)
    if span == (None, None, None):
        return
    if any(part is None for part in span):
        raise RecordSchemaError("citation span fields must be supplied together")
    assert value.byte_start is not None
    assert value.byte_end is not None
    if value.byte_start < 0 or value.byte_start >= value.byte_end:
        raise RecordSchemaError("citation byte range is invalid")
```

Register Citation/v1 in the strict record registry. Do not add Markdown parsing, heading resolution, or display-path identity.

- [ ] **Step 4: Write failing Evidence/v1 contract tests**

Tests must prove deterministic Evidence requires target, checkpoint, producer, payload, and facts; advisory Evidence cannot satisfy deterministic authority; expiry before observation is rejected; invalidators are unique and sorted; command Evidence cannot be COMPLETE with missing terminal status, mismatched declared/observed digest, zero checks, or incomplete pagination; unknown fact kinds/fields reject; golden bytes and ID remain stable.

```python
def test_expiry_cannot_precede_observation() -> None:
    with pytest.raises(RecordSchemaError):
        evidence_v1(observed_at=logical_time(10), expires_at=logical_time(9))


def test_advisory_evidence_is_not_deterministic() -> None:
    value = evidence_v1(authority=EvidenceAuthority.ADVISORY)
    assert value.authority is EvidenceAuthority.ADVISORY
```

- [ ] **Step 5: Run Evidence tests to verify RED**

Run:

```bash
python -m pytest -q tests/contract/test_evidence_v1.py
```

Expected: collection fails because EvidenceV1 and its registry entry do not exist.

- [ ] **Step 6: Implement Evidence/v1 and run GREEN**

Run:

```bash
python -m pytest -q tests/contract/test_citation_v1.py tests/contract/test_evidence_v1.py
python -m ruff check src/agent_continuity/kernel/citation.py src/agent_continuity/kernel/evidence.py tests/contract/test_citation_v1.py tests/contract/test_evidence_v1.py
python tools/verify_schemas.py
```

Expected: all commands exit 0.

- [ ] **Step 7: Commit**

```bash
git add schemas/v1/citation.schema.json schemas/v1/evidence.schema.json
git add src/agent_continuity/kernel/citation.py src/agent_continuity/kernel/evidence.py src/agent_continuity/kernel/records.py
git add tests/contract/test_citation_v1.py tests/contract/test_evidence_v1.py
git add tests/golden/citation-v1.json tests/golden/evidence-v1.json
git commit -m "feat: add citation and evidence contracts"
```

### Task 3: Implement direct and transitive evidence invalidation

**Files:**

- Create: `src/agent_continuity/kernel/invalidation.py`
- Modify: `src/agent_continuity/kernel/evaluation.py`
- Modify: `src/agent_continuity/kernel/findings.py`
- Create: `tests/contract/test_evidence_invalidation.py`
- Create: `tests/property/test_invalidation_graph.py`
- Create: `tests/fixtures/content_rot/document.bin`
- Create: `tests/fixtures/content_rot/citations.json`

**Interfaces:**

```python
class EvidenceState(StrEnum):
    CURRENT = "current"
    INVALIDATED = "invalidated"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Invalidation:
    evidence_id: RecordId
    state: EvidenceState
    code: str
    direct_cause_ids: tuple[RecordId, ...]
    transitive_path: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class CitationObservation:
    citation_id: RecordId
    available: bool
    stable: bool
    file_digest: Digest | None
    span_digest: Digest | None
    unknown_code: str | None


@dataclass(frozen=True, slots=True)
class InvalidationContext:
    logical_time: LogicalTime
    target: TargetIdentityV1
    checkpoint_id: RecordId
    producer_ids: frozenset[RecordId]
    citations: Mapping[RecordId, CitationObservation]


def evaluate_invalidations(
    evidence: Mapping[RecordId, EvidenceV1],
    context: InvalidationContext,
) -> tuple[Invalidation, ...]: ...


@dataclass(frozen=True, slots=True)
class EvidenceEvaluationInput:
    evidence: Mapping[RecordId, EvidenceV1]
    context: InvalidationContext
```

Required codes: `citation.path_missing`, `citation.file_changed`, `citation.span_changed`, `evidence.expired`, `evidence.target_mismatch`, `evidence.checkpoint_mismatch`, `evidence.producer_mismatch`, `evidence.dependency_invalid`, `evidence.dependency_unknown`, `evidence.dependency_cycle`, `evidence.observation_unavailable`.

- [ ] **Step 1: Write failing positive, negative-control, and mutation tests**

```python
def test_changed_cited_span_invalidates_only_its_dependants() -> None:
    graph, context = cited_span_graph()
    result = by_id(evaluate_invalidations(graph, replace_cited_bytes(context, b"unsafe")))
    assert result[SPAN].state is EvidenceState.INVALIDATED
    assert result[DERIVED].state is EvidenceState.INVALIDATED
    assert result[UNRELATED].state is EvidenceState.CURRENT


def test_unrelated_file_change_does_not_invalidate_citation() -> None:
    graph, context = cited_span_graph()
    result = by_id(evaluate_invalidations(graph, change_unrelated_file(context)))
    assert result[SPAN].state is EvidenceState.CURRENT
```

Add exact expiry-boundary, missing-file, whole-file, producer/checkpoint mismatch, unavailable observation, two-hop, diamond, and cycle tests. Add a planted comparison mutant and prove the positive test kills it.

- [ ] **Step 2: Run tests to verify RED**

```bash
python -m pytest -q tests/contract/test_evidence_invalidation.py tests/property/test_invalidation_graph.py
```

Expected: import failure because `kernel.invalidation` does not exist.

- [ ] **Step 3: Implement deterministic graph evaluation**

```python
def evaluate_invalidations(evidence, context):
    direct = {
        record_id: _evaluate_direct(record, context)
        for record_id, record in sorted(evidence.items())
    }
    components = _strongly_connected_components(evidence)
    _mark_cycles_unknown(direct, components)
    return _propagate_to_fixed_point(evidence, direct)
```

Use bounded iterative traversal. Invalid dependencies invalidate dependants; unknown dependencies make dependants unknown unless a direct invalidation already exists. Cycles are UNKNOWN. Output is unique and sorted by Evidence ID.

- [ ] **Step 4: Integrate invalidation with pure kernel evaluation**

Extend EvaluationCase with `evidence_input: EvidenceEvaluationInput | None`. Pure kernel evaluation emits normalized Findings from current CitationObservation values. Advisory Evidence never satisfies a deterministic requirement. Pure verify returns Findings; state-changing operations persist them through Plan 1 StateStore transactions.

- [ ] **Step 5: Run GREEN and mutation proof**

```bash
python -m pytest -q tests/contract/test_evidence_invalidation.py tests/property/test_invalidation_graph.py
python -m pytest -q tests/contract/test_evidence_invalidation.py -k mutation
python -m ruff check src/agent_continuity/kernel tests/contract tests/property
```

Expected: all commands exit 0 and the planted mutant is killed.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/kernel/invalidation.py src/agent_continuity/kernel/evaluation.py src/agent_continuity/kernel/findings.py
git add tests/contract/test_evidence_invalidation.py tests/property/test_invalidation_graph.py tests/fixtures/content_rot
git commit -m "feat: add deterministic evidence invalidation"
```

### Task 4: Build verified ResumeContext

**Files:**

- Create: `src/agent_continuity/kernel/resume.py`
- Create: `schemas/v1/resume-context.schema.json`
- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/capture/coordinator.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `tests/contract/test_resume_context.py`
- Create: `tests/integration/test_resume.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class ResumeContext:
    checkpoint_id: RecordId
    verdict: Verdict
    usable: bool
    target_id: RecordId
    goal_digest: Digest
    acceptance_criteria: tuple[CriterionV1, ...]
    constraint_digests: tuple[Digest, ...]
    accepted_decision_ids: tuple[RecordId, ...]
    pending_work: tuple[WorkItemV1, ...]
    unresolved: tuple[UnresolvedItemV1, ...]
    open_assignment_ids: tuple[RecordId, ...]
    current_evidence_ids: tuple[RecordId, ...]
    invalidations: tuple[Invalidation, ...]
    blocker_codes: tuple[str, ...]


def build_resume_context(
    checkpoint: CheckpointV1,
    evaluation: EvaluationResult,
) -> ResumeContext: ...
```

- [ ] **Step 1: Write failing ResumeContext contract tests**

Prove canonical ordering of criteria, decisions, work, assignments, invalidations, and blocker codes. Sensitive-local display text may appear in-process but never enters record identity or export.

- [ ] **Step 2: Write failing integration tests**

```python
def test_resume_returns_verified_context_without_mutating_store(tmp_path) -> None:
    continuity = initialized_continuity(tmp_path)
    before = continuity.store.snapshot_heads()
    context = continuity.resume()
    assert context.usable is True
    assert context.checkpoint_id == before.checkpoint
    assert continuity.store.snapshot_heads() == before


def test_resume_refuses_changed_cited_bytes_with_exact_reason(tmp_path) -> None:
    continuity, cited_file = initialized_with_citation(tmp_path)
    cited_file.write_bytes(b"changed by another process")
    context = continuity.resume()
    assert context.usable is False
    assert "citation.file_changed" in context.blocker_codes
```

Also test changed instructions, policy, ruleset, target base, expired Evidence, corrupt audit, explicit historical checkpoint, observe/guard/strict behavior, and clean resume after process restart.

- [ ] **Step 3: Run tests to verify RED**

```bash
python -m pytest -q tests/contract/test_resume_context.py tests/integration/test_resume.py
```

Expected: import or attribute failure because ResumeContext and Continuity.resume are absent.

- [ ] **Step 4: Implement read-only resume orchestration**

```python
def resume(self, checkpoint: str = "latest") -> ResumeContext:
    loaded = self._store.load_verified_checkpoint(checkpoint)
    observations = self._capture.capture_stable(loaded.required_observations)
    result = self._kernel.evaluate(build_resume_case(loaded, observations))
    return build_resume_context(loaded.checkpoint, result)
```

Store heads before and after resume must match exactly.

- [ ] **Step 5: Run GREEN**

```bash
python -m pytest -q tests/contract/test_resume_context.py tests/integration/test_resume.py
python tools/verify_schemas.py
python -m ruff check src/agent_continuity/kernel/resume.py src/agent_continuity/api.py tests/contract/test_resume_context.py tests/integration/test_resume.py
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/kernel/resume.py schemas/v1/resume-context.schema.json src/agent_continuity/api.py src/agent_continuity/capture/coordinator.py
git add src/agent_continuity/store/base.py src/agent_continuity/store/sqlite.py
git add tests/contract/test_resume_context.py tests/integration/test_resume.py
git commit -m "feat: add verified resume context"
```

### Task 5: Add immutable same-machine Assignment contracts

**Files:**

- Create: `schemas/v1/assignment.schema.json`
- Create: `schemas/v1/assignment-result.schema.json`
- Create: `src/agent_continuity/kernel/lineage.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `tests/contract/test_assignment_v1.py`
- Create: `tests/contract/test_assignment_result_v1.py`
- Create: `tests/integration/test_delegate.py`

**Interfaces:**

```python
class AssignmentTerminalState(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class EvidenceRequirementV1:
    requirement_id: RecordId
    kind: EvidenceKind
    subject_digest: Digest
    minimum_authority: EvidenceAuthority


class ChangeKind(StrEnum):
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"


@dataclass(frozen=True, slots=True)
class ChangedPathV1:
    path: PathIdentityV1
    change: ChangeKind
    prior_path: PathIdentityV1 | None


@dataclass(frozen=True, slots=True)
class AssignmentV1:
    assignment_id: RecordId
    parent_checkpoint_id: RecordId
    target_base_id: RecordId
    goal_slice_digest: Digest
    task_digest: Digest
    non_goal_digests: tuple[Digest, ...]
    instruction_id: RecordId
    policy_id: RecordId
    ruleset_id: RecordId
    scopes: tuple[PathScopeV1, ...]
    authority: AssignmentAuthority
    required_evidence: tuple[EvidenceRequirementV1, ...]
    issued_at: LogicalTime
    expires_at: LogicalTime


@dataclass(frozen=True, slots=True)
class AssignmentResultV1:
    result_id: RecordId
    assignment_id: RecordId
    parent_checkpoint_id: RecordId
    child_checkpoint_id: RecordId
    base_target_id: RecordId
    final_target_id: RecordId
    evidence_ids: tuple[RecordId, ...]
    changed_paths: tuple[ChangedPathV1, ...]
    unresolved_codes: tuple[str, ...]
    producer: ProducerIdentity
    terminal_state: AssignmentTerminalState
    summary_digest: Digest | None
```

PathScopeV1 comes from Plan 1 and uses exact PathIdentityV1 plus FILE or component-aware TREE; target-root TREE is the explicit `path=None` case. It has no glob syntax. ACG records SCOPED_WRITE authority but never exercises it.

- [ ] **Step 1: Write failing contract tests**

Test exact parent/target/instruction/policy/ruleset binding, expiry after issue, unique sorted scopes, child authority narrowing, result parent binding, sorted changed paths, rename requiring `prior_path`, non-rename forbidding it, digest-only summary identity, and strict unknown-field rejection.

- [ ] **Step 2: Run contract tests to verify RED**

```bash
python -m pytest -q tests/contract/test_assignment_v1.py tests/contract/test_assignment_result_v1.py
```

Expected: collection fails because Assignment record types do not exist.

- [ ] **Step 3: Implement contracts and derivation validation**

```python
def validate_assignment_derivation(
    assignment: AssignmentV1,
    parent: CheckpointV1,
) -> None:
    require_equal(assignment.parent_checkpoint_id, parent.checkpoint_id)
    require_equal(assignment.target_base_id, parent.target_id)
    require_equal(assignment.instruction_id, parent.instruction_id)
    require_equal(assignment.policy_id, parent.policy_id)
    require_equal(assignment.ruleset_id, parent.ruleset_id)
    require_scopes_within(assignment.scopes, parent.authority_scopes)
```

- [ ] **Step 4: Write failing delegation integration tests**

Cover clean delegation, implicit checkpoint after observed change, no redundant checkpoint when unchanged, wrong target/store refusal, expiry, narrowed authority, broader-authority block, and exact target pre/post manifests.

- [ ] **Step 5: Run delegation tests to verify RED**

```bash
python -m pytest -q tests/integration/test_delegate.py
```

Expected: Continuity.delegate or Assignment.open is absent.

- [ ] **Step 6: Implement same-machine delegation**

```python
def delegate(self, task, scope, required_evidence, expires_in):
    parent = self._checkpoint_if_observed_state_changed("pre_delegation")
    assignment = build_assignment(parent, task, scope, required_evidence, expires_in)
    self._store.append_assignment(assignment, expected_checkpoint=parent.checkpoint_id)
    return assignment
```

Assignment.open loads the canonical assignment from the same StateStore and compares canonical bytes. Do not add export/import.

- [ ] **Step 7: Run GREEN**

```bash
python -m pytest -q tests/contract/test_assignment_v1.py tests/contract/test_assignment_result_v1.py tests/integration/test_delegate.py
python tools/verify_schemas.py
python -m ruff check src/agent_continuity/kernel/lineage.py tests/contract tests/integration
```

Expected: all commands exit 0.

- [ ] **Step 8: Commit**

```bash
git add schemas/v1/assignment.schema.json schemas/v1/assignment-result.schema.json
git add src/agent_continuity/kernel/lineage.py src/agent_continuity/kernel/records.py src/agent_continuity/api.py
git add src/agent_continuity/store/base.py src/agent_continuity/store/sqlite.py
git add tests/contract/test_assignment_v1.py tests/contract/test_assignment_result_v1.py tests/integration/test_delegate.py
git commit -m "feat: add same-machine assignments"
```

### Task 6: Seal child results and enforce acceptance lineage

**Files:**

- Modify: `src/agent_continuity/kernel/lineage.py`
- Modify: `src/agent_continuity/kernel/evaluation.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `tests/contract/test_assignment_lineage.py`
- Create: `tests/integration/test_assignment_acceptance.py`
- Create: `tests/security/test_assignment_scope.py`
- Create: `tests/property/test_assignment_replay.py`

**Interfaces:**

```python
class Assignment:
    @classmethod
    def open(
        cls,
        envelope: AssignmentV1,
        target: Path,
        state_home: Path | None = None,
    ) -> Assignment: ...

    def checkpoint(self, reason: str | None = None) -> CheckpointReceipt: ...

    def complete(
        self,
        summary: SensitiveLocalText | None,
        evidence: Sequence[RecordId],
        unresolved: Sequence[str],
    ) -> AssignmentResultV1: ...


class Continuity:
    def accept_result(self, result: AssignmentResultV1) -> CheckpointReceipt: ...


@dataclass(frozen=True, slots=True)
class AcceptanceCase:
    profile: Profile
    assignment: AssignmentV1
    result: AssignmentResultV1
    parent_checkpoint: CheckpointV1
    child_checkpoint: CheckpointV1
    current_target_id: RecordId
    evidence_states: Mapping[RecordId, EvidenceState]
    recomputed_changed_paths: tuple[ChangedPathV1, ...]
    assignment_is_outstanding: bool
```

Acceptance binds the outstanding Assignment, parent, child descent, target base/final, instructions, policy, ruleset, current Evidence, required Evidence, exact recomputed changed-path manifest, scope, and terminal state.

Store transaction seam:

```python
def accept_assignment_result(
    self,
    *,
    records: Sequence[StoredRecord],
    event: AuditEventDraft,
    checkpoint_head_name: str,
    expected_checkpoint_head: HeadState,
    new_checkpoint_id: RecordId,
    assignment_head_name: str,
    expected_assignment_head: HeadState,
    accepted_assignment_state_id: RecordId,
) -> MultiHeadCommitReceipt:
    return self.commit_many(
        records=records,
        event=event,
        head_updates=(
            HeadUpdate(
                checkpoint_head_name,
                expected_checkpoint_head,
                new_checkpoint_id,
            ),
            HeadUpdate(
                assignment_head_name,
                expected_assignment_head,
                accepted_assignment_state_id,
            ),
        ),
    )
```

- [ ] **Step 1: Write failing pure-lineage decision table**

Cover wrong assignment/parent/base/final/child, instruction/policy/ruleset drift, missing/expired Evidence, out-of-scope add/change/delete/rename, valid read-only result, and valid scoped-write result.

- [ ] **Step 2: Run pure tests to verify RED**

```bash
python -m pytest -q tests/contract/test_assignment_lineage.py
```

Expected: lineage acceptance evaluation is absent.

- [ ] **Step 3: Implement pure result-acceptance evaluation**

```python
def evaluate_result_acceptance(case: AcceptanceCase) -> EvaluationResult:
    checks = (
        check_assignment_open(case),
        check_exact_bindings(case),
        check_child_descent(case),
        check_required_evidence(case),
        check_changed_path_manifest(case),
        check_scope(case),
    )
    return aggregate_checks(checks, case.profile)
```

Changed paths come from immutable target manifests, never caller prose or display-form git diff.

- [ ] **Step 4: Write failing integration, replay, and fault tests**

```python
def test_exact_result_replay_is_idempotent(tmp_path) -> None:
    parent, result = completed_assignment(tmp_path)
    first = parent.accept_result(result)
    before = parent.store.snapshot_heads()
    second = parent.accept_result(result)
    assert second == first
    assert parent.store.snapshot_heads() == before


def test_conflicting_result_for_accepted_assignment_blocks(tmp_path) -> None:
    parent, result = completed_assignment(tmp_path)
    parent.accept_result(result)
    conflict = replace(result, unresolved_codes=("different",))
    receipt = parent.accept_result(conflict)
    assert receipt.verdict is Verdict.BLOCK
```

Inject failures before record insert, audit append, head CAS, and commit. Reopen after each and prove complete old or complete new state.

- [ ] **Step 5: Run integration tests to verify RED**

```bash
python -m pytest -q tests/integration/test_assignment_acceptance.py tests/security/test_assignment_scope.py tests/property/test_assignment_replay.py
```

Expected: acceptance is absent or fails atomic/replay/scope assertions.

- [ ] **Step 6: Implement atomic acceptance**

The facade re-captures target and Evidence, calls pure evaluation, and commits result, new parent checkpoint, retained Findings, audit event, assignment projection, and checkpoint head through Plan 1 `commit_many` in one compare-and-swap transaction. Exact canonical replay returns the original receipt without an event. Conflicting replay returns BLOCK.

- [ ] **Step 7: Run GREEN and focused regression**

```bash
python -m pytest -q tests/contract/test_assignment_lineage.py tests/integration/test_assignment_acceptance.py tests/security/test_assignment_scope.py tests/property/test_assignment_replay.py
python -m pytest -q tests/contract tests/integration tests/security tests/property
python -m ruff check src/agent_continuity tests
```

Expected: all commands exit 0, replay adds no event, conflict blocks, and target manifest proves no ACG-issued mutation.

- [ ] **Step 8: Commit**

```bash
git add src/agent_continuity/kernel/lineage.py src/agent_continuity/kernel/evaluation.py src/agent_continuity/api.py
git add src/agent_continuity/store/base.py src/agent_continuity/store/sqlite.py
git add tests/contract/test_assignment_lineage.py tests/integration/test_assignment_acceptance.py
git add tests/security/test_assignment_scope.py tests/property/test_assignment_replay.py
git commit -m "feat: enforce assignment result lineage"
```

## Plan Completion Gate

Run:

```bash
python -m pytest -q tests/contract tests/integration tests/security tests/property tests/golden
python -m mypy src/agent_continuity
python -m ruff check .
python tools/verify_schemas.py
git status --short
```

Expected: tests, type check, lint, and schema verification exit 0; git status is empty. Generic JSON and cross-machine files remain absent.
