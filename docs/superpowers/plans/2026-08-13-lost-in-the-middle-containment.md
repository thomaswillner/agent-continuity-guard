# Lost-in-the-Middle Containment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that ACG preserves or safely refuses protected continuity across matched beginning, middle, and end long-context cases without claiming to change model attention or guarantee arbitrary recall.

**Architecture:** Keep production trust position-independent: canonical protected records, structured identity probes, and compare-before-continue transitions remain the only authority. Add a separate benchmark package that expands immutable base cases into matched position triplets, records raw product decisions, applies per-position safety floors, and computes a paired middle-versus-edges non-inferiority result. Public corpus supports development; sealed holdout remains unavailable to makers through final result freeze and becomes the primary claim endpoint.

**Tech Stack:** Python 3.11-3.14, standard-library runtime, frozen dataclasses, StrEnum, CanonicalJSON/v1, SHA-256 identities, SQLite StateStore, pytest, Hypothesis, JSON Schema Draft 2020-12, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-13-production-benchmark-design.md`

**Scope boundary:** This plan implements and certifies lost-in-the-middle containment only. It cannot emit the separate category-correct "best in tested scope" superiority claim. Direct-peer adapters, lane-specific scorecards, Holm-corrected pairwise comparisons, and superiority claim derivation require a later comparison plan after ACG production prerequisites and this containment plan pass. Production remediation remains owned by the five dependency-ordered plans in `docs/plans/README.md`.

## Global Constraints

- Read `docs/adr/0002-contain-lost-in-the-middle-with-canonical-projections.md` before execution.
- This plan starts only after Plan 1 Tasks 1-9, Plan 2 Tasks 1-6, and Context Continuity Plan Tasks 1-5 pass from an installed wheel and their independent reviews accept the exact commits.
- Tasks 1-5 execute before Context Continuity Plan Task 6. Task 6 of this plan executes only after Context Continuity Plan Task 6, Governed Improvement Plan Tasks 1-8, and Hardening Plan Tasks 1-8 pass independently; it extends their existing release verifier and CI workflow.
- First repair every confirmed Plan 1 Tasks 1-4 public-contract defect; never waive `AuditEventDraft.details`, `Finding.parameters`, `EvaluationResult`, `AuditVerification`, frozen replay, fail-closed capture, path identity, or ordinary-write performance requirements.
- Prompt position is benchmark metadata, never production authority and never part of `ContextProjectionV1`.
- Retrieval, repeated prompts, summaries, prose acknowledgements, model confidence, and hidden reasoning never establish continuity.
- Beginning, middle, and end variants preserve expected outcome, protected facts, distractor multiset, logical workload, and resource budget. Exact product-visible byte layout places protected spans at <=20%, within 40%-60%, and >=80%; a token-position claim additionally requires an identity-bound exact tokenizer and recorded token offsets.
- Every public, holdout, and combined position bin independently requires zero critical false-PASS, detection at least 90%, and false blocks at most 5%.
- Middle-position macro-balanced accuracy is non-inferior only when the paired 95% bootstrap interval lower bound for `middle - mean(beginning, end)` is at least `-0.02`, using at least 10,000 replicates over immutable base-case IDs.
- Public corpus may guide implementation. Holdout cases, labels, generator configuration, position assignments, and raw mapping remain unavailable to makers until candidate and final result freeze.
- Guarded targets remain byte-and-metadata read-only. Benchmark products run isolated; adapters translate only documented interfaces and never add detection logic.
- All required production gates pass independently on the exact installed artifact. No waiver, suppression, offset, relabeling, omission, or stale evidence is allowed.
- This plan may emit only the scoped containment statement. It must withhold "best in tested scope" until the downstream category-correct comparison plan passes against frozen competitor artifacts.
- Full installed-artifact matrix is Python 3.11, 3.12, 3.13, and 3.14 on macOS, Linux, and Windows.
- No runtime installation, hook activation, daemon, provider enforcement, remote publication, or release is authorized by this plan.

## Dependency admission

The controller records exact prerequisite commits and checker evidence before Task 1 using this closed contract:

```python
@dataclass(frozen=True, slots=True)
class PrerequisiteEvidenceV1:
    scope: Literal["plan1", "plan2", "context_tasks_1_5"]
    head_commit: str
    checker_report_digest: Digest
    installed_artifact_digest: Digest
    accepted: bool


def admit_prerequisites(
    evidence: tuple[PrerequisiteEvidenceV1, ...],
) -> None: ...
```

Require exactly one entry for each closed scope, a 40-character lowercase Git commit, canonical SHA-256 report/artifact digests, `accepted=True`, and the same installed artifact identity referenced by checker evidence. Any absent, duplicate, malformed, rejected, stale, or cross-artifact value is a typed admission failure; execution stops before source mutation.

## File map

- `src/agent_continuity/benchmark/model.py`: immutable benchmark case, variant, observation, and result records.
- `src/agent_continuity/benchmark/position.py`: deterministic beginning/middle/end expansion with matched logical content.
- `src/agent_continuity/benchmark/scoring.py`: confusion matrices, safety floors, paired bootstrap, and containment verdict.
- `src/agent_continuity/benchmark/runner.py`: isolated adapter execution and raw evidence capture; no semantic policy.
- `src/agent_continuity/benchmark/claims.py`: mechanical claim eligibility from frozen gate records.
- `tests/fixtures/context-continuity-public-v2.jsonl`: public development corpus with immutable base-case IDs.
- `tools/benchmark_context_continuity.py`: CLI over frozen cases and raw observations.
- `tools/verify_release.py`: aggregate zero-waiver release gate.

---

### Task 1: Add immutable position-triplet contracts and deterministic expansion

**Files:**

- Create: `src/agent_continuity/benchmark/__init__.py`
- Create: `src/agent_continuity/benchmark/model.py`
- Create: `src/agent_continuity/benchmark/position.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Create: `schemas/v1/benchmark-case.schema.json`
- Create: `schemas/v1/benchmark-variant.schema.json`
- Create: `tests/contract/test_benchmark_case.py`
- Create: `tests/contract/test_benchmark_position.py`
- Create: `tests/property/test_benchmark_position_matching.py`

**Interfaces:**

- Consumes: `RecordId`, `Digest`, `JsonObject`, `Verdict`, `canonical_bytes()`, `digest_bytes()`.
- Produces: `BenchmarkCaseV1`, `BenchmarkPosition`, `BenchmarkVariantV1`, `expand_position_triplet()`.

```python
class BenchmarkPosition(StrEnum):
    BEGINNING = "beginning"
    MIDDLE = "middle"
    END = "end"


class BenchmarkPartition(StrEnum):
    PUBLIC_DEVELOPMENT = "public_development"
    SEALED_HOLDOUT = "sealed_holdout"


@dataclass(frozen=True, slots=True)
class BenchmarkBlockV1:
    block_id: RecordId
    canonical_bytes: bytes
    protected: bool


@dataclass(frozen=True, slots=True)
class BenchmarkCaseV1:
    case_id: RecordId
    corpus_id: RecordId
    lane: str
    stratum: str
    partition: BenchmarkPartition
    expected: Verdict
    expected_transition_allowed: bool
    critical: bool
    protected_blocks: tuple[BenchmarkBlockV1, ...]
    distractor_blocks: tuple[BenchmarkBlockV1, ...]
    resource_budget_id: RecordId


@dataclass(frozen=True, slots=True)
class BenchmarkVariantV1:
    variant_id: RecordId
    base_case_id: RecordId
    position: BenchmarkPosition
    lane: str
    stratum: str
    partition: BenchmarkPartition
    ordered_blocks: tuple[BenchmarkBlockV1, ...]
    protected_start_bps: int
    protected_end_bps: int
    expected: Verdict
    expected_transition_allowed: bool
    critical: bool
    resource_budget_id: RecordId


def expand_position_triplet(case: BenchmarkCaseV1) -> tuple[
    BenchmarkVariantV1,
    BenchmarkVariantV1,
    BenchmarkVariantV1,
]: ...
```

- [ ] **Step 1: Write strict model and schema tests**

```python
def test_position_triplet_preserves_matched_logical_content() -> None:
    case = benchmark_case()
    beginning, middle, end = expand_position_triplet(case)
    assert tuple(item.position for item in (beginning, middle, end)) == (
        BenchmarkPosition.BEGINNING,
        BenchmarkPosition.MIDDLE,
        BenchmarkPosition.END,
    )
    for variant in (beginning, middle, end):
        assert variant.base_case_id == case.case_id
        assert variant.expected is case.expected
        assert variant.expected_transition_allowed is case.expected_transition_allowed
        assert variant.critical is case.critical
        assert variant.resource_budget_id == case.resource_budget_id
        assert sorted(item.block_id for item in variant.ordered_blocks) == sorted(
            item.block_id for item in case.protected_blocks + case.distractor_blocks
        )
```

Reject mutable sequences, mutable block bytes, block ID/byte mismatch, duplicate blocks, unknown fields, noncanonical JSON bytes, unknown positions, unregistered record types, invalid IDs, empty protected blocks, insufficient deterministic padding to satisfy the position bin, and a caller-supplied `variant_id` inconsistent with canonical bytes. Beginning requires `protected_end_bps <= 2000`; middle requires `4000 <= protected_start_bps <= protected_end_bps <= 6000`; end requires `protected_start_bps >= 8000`.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q tests/contract/test_benchmark_case.py tests/contract/test_benchmark_position.py tests/property/test_benchmark_position_matching.py
```

Expected: collection fails because `agent_continuity.benchmark` does not exist.

- [ ] **Step 3: Implement exact placement and content-addressed identities**

Use immutable canonical block bytes for stable ordering and byte-length-aware placement. Split canonically ordered distractors at the first boundary that places the entire protected span in the required normalized byte interval; deterministically generated inert padding blocks supply any missing length and are part of the matched distractor multiset in all three variants. Construct each `variant_id` from the full variant payload. Do not import a provider SDK or expose position through production projection APIs.

```python
def _placed_blocks(
    case: BenchmarkCaseV1,
    position: BenchmarkPosition,
) -> tuple[BenchmarkBlockV1, ...]:
    distractors = tuple(sorted(case.distractor_blocks, key=lambda item: item.block_id))
    protected = tuple(sorted(case.protected_blocks, key=lambda item: item.block_id))
    if position is BenchmarkPosition.BEGINNING:
        return protected + distractors
    if position is BenchmarkPosition.END:
        return distractors + protected
    split = byte_balanced_split(distractors)
    return distractors[:split] + protected + distractors[split:]
```

- [ ] **Step 4: Run GREEN and schema verification**

```bash
.venv/bin/python -m pytest -q tests/contract/test_benchmark_case.py tests/contract/test_benchmark_position.py tests/property/test_benchmark_position_matching.py
.venv/bin/python tools/verify_schemas.py
.venv/bin/python -m mypy src/agent_continuity/benchmark
.venv/bin/python -m ruff check src/agent_continuity/benchmark tests/contract tests/property
```

Expected: triplets are byte-stable and matched-content mutations are killed.

- [ ] **Step 5: Commit**

```bash
git add src/agent_continuity/benchmark src/agent_continuity/kernel/records.py schemas/v1/benchmark-case.schema.json schemas/v1/benchmark-variant.schema.json tests/contract/test_benchmark_case.py tests/contract/test_benchmark_position.py tests/property/test_benchmark_position_matching.py
git commit -m "feat: add position-matched benchmark triplets"
```

---

### Task 2: Implement per-position safety floors and paired non-inferiority scoring

**Files:**

- Create: `src/agent_continuity/benchmark/scoring.py`
- Create: `schemas/v1/benchmark-observation.schema.json`
- Create: `schemas/v1/position-containment-result.schema.json`
- Create: `tests/contract/test_position_scoring.py`
- Create: `tests/property/test_position_bootstrap.py`
- Create: `tests/security/test_position_floor_masking.py`

**Interfaces:**

- Consumes: `BenchmarkVariantV1`, normalized `Verdict`, immutable base-case IDs.
- Produces: `BenchmarkObservationV1`, `PositionBinMetrics`, `PositionContainmentResult`, `score_position_containment()`.

```python
@dataclass(frozen=True, slots=True)
class BenchmarkObservationV1:
    variant_id: RecordId
    base_case_id: RecordId
    position: BenchmarkPosition
    expected: Verdict
    observed: Verdict
    expected_transition_allowed: bool
    observed_transition_allowed: bool
    critical: bool
    stratum: str
    duration_ns: int


@dataclass(frozen=True, slots=True)
class PositionBinMetrics:
    position: BenchmarkPosition
    critical_false_passes: int
    seeded_failures: int
    detected_failures: int
    valid_controls: int
    false_blocks: int
    macro_balanced_accuracy_bps: int


@dataclass(frozen=True, slots=True)
class PositionContainmentResult:
    bins: tuple[PositionBinMetrics, ...]
    middle_minus_edges_bps: int
    interval_lower_bps: int
    interval_upper_bps: int
    bootstrap_replicates: int
    passed: bool
    finding_codes: tuple[str, ...]


def score_position_containment(
    observations: tuple[BenchmarkObservationV1, ...],
    *,
    seed: int,
    replicates: int = 10_000,
) -> PositionContainmentResult: ...
```

- [ ] **Step 1: Write failing floor and bootstrap tests**

```python
def test_combined_pass_cannot_mask_middle_bin_failure() -> None:
    result = score_position_containment(
        observations_with_one_critical_middle_false_pass(), seed=611
    )
    assert result.passed is False
    assert "benchmark.middle.critical_false_pass" in result.finding_codes


def test_exact_negative_two_point_lower_bound_is_non_inferior() -> None:
    result = score_position_containment(
        fixed_triplets(interval_lower_bps=-200), seed=611
    )
    assert result.interval_lower_bps == -200
    assert result.passed is True
```

Also prove `-201` fails, 9,999 replicates reject, missing/duplicate triplet members reject, base-case mismatch rejects, reordered input yields byte-identical output, any `observed_transition_allowed=True` on a critical expected refusal is a critical false-PASS, `UNKNOWN` with continuation refused counts as detection but never as successful recovery, and the false-block denominator contains only controls with `expected_transition_allowed=True`.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q tests/contract/test_position_scoring.py tests/property/test_position_bootstrap.py tests/security/test_position_floor_masking.py
```

Expected: scorer imports fail.

- [ ] **Step 3: Implement integer metrics and paired bootstrap**

Group by immutable base-case ID, require exactly one observation per position, compute confusion matrices per stratum and position, then resample whole triplets with `random.Random(seed)`. A seeded failure has `expected_transition_allowed=False` and is detected only when `observed_transition_allowed=False`; a valid control has `expected_transition_allowed=True` and is falsely blocked when `observed_transition_allowed=False`. Sort replicate deltas and select indices `((n - 1) * 25) // 1000` and `(((n - 1) * 975) + 999) // 1000` for the frozen 2.5% and 97.5% order statistics. Aggregate macro-balanced accuracy with integer basis points; never resample individual variants or use float comparison at a gate.

```python
def _position_floor_passes(metrics: PositionBinMetrics) -> bool:
    detection_bps = metrics.detected_failures * 10_000 // metrics.seeded_failures
    false_block_bps = metrics.false_blocks * 10_000 // metrics.valid_controls
    return (
        metrics.critical_false_passes == 0
        and detection_bps >= 9_000
        and false_block_bps <= 500
    )
```

- [ ] **Step 4: Run GREEN, repeatability, typing, and lint**

```bash
.venv/bin/python -m pytest -q tests/contract/test_position_scoring.py tests/property/test_position_bootstrap.py tests/security/test_position_floor_masking.py
.venv/bin/python tools/verify_schemas.py
.venv/bin/python -m mypy src/agent_continuity/benchmark/scoring.py
.venv/bin/python -m ruff check src/agent_continuity/benchmark/scoring.py tests/contract/test_position_scoring.py tests/property/test_position_bootstrap.py tests/security/test_position_floor_masking.py
```

`test_position_bootstrap.py` invokes `score_position_containment()` twice with identical observations/seed and asserts byte-identical canonical result payloads. No repeat plugin or undeclared dependency is used.

- [ ] **Step 5: Commit**

```bash
git add src/agent_continuity/benchmark/scoring.py schemas/v1/benchmark-observation.schema.json schemas/v1/position-containment-result.schema.json tests/contract/test_position_scoring.py tests/property/test_position_bootstrap.py tests/security/test_position_floor_masking.py
git commit -m "feat: score lost-middle containment"
```

---

### Task 3: Prove structured probes are position-independent and fail closed

**Files:**

- Modify: `src/agent_continuity/kernel/context.py`
- Modify: `src/agent_continuity/kernel/context_evaluation.py`
- Create: `tests/integration/test_context_probe_positions.py`
- Create: `tests/security/test_context_probe_position_poisoning.py`
- Create: `tests/property/test_context_probe_permutations.py`

**Interfaces:**

- Consumes: `ContextContinuityProbeV1`, `ContextContinuityProbeResponseV1`, `ContextProjectionV1`, `evaluate_context_probe()` from Context Plan Task 3.
- Produces: no new production interface; proves existing interface depends only on canonical protected identities and current producer-bound evidence.

- [ ] **Step 1: Write failing matched-position probe tests**

```python
@pytest.mark.parametrize("position", tuple(BenchmarkPosition))
def test_exact_probe_ids_pass_at_every_position(position: BenchmarkPosition) -> None:
    variant = probe_variant(position=position)
    result = evaluate_context_probe(
        variant.probe,
        response_for(variant, include_all_required_ids=True),
        canonical_records(),
        logical_time(100),
    )
    assert result.action is ContextBudgetAction.CONTINUE


def test_middle_confident_prose_without_ids_cannot_continue() -> None:
    variant = probe_variant(position=BenchmarkPosition.MIDDLE)
    result = evaluate_context_probe(
        variant.probe,
        response_for(variant, include_all_required_ids=False),
        canonical_records(),
        logical_time(100),
    )
    assert result.action in {
        ContextBudgetAction.COMPACT_OR_HANDOFF,
        ContextBudgetAction.BLOCK,
    }
```

Permute advisory text, distractor order, lexical paraphrase, multilingual distractors, hash-like poison, fake approval, stale evidence, authority broadening, and unknown record substitution. Exact canonical response yields the same result across positions. Missing or conflicting protected identity never yields `CONTINUE`.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q tests/integration/test_context_probe_positions.py tests/security/test_context_probe_position_poisoning.py tests/property/test_context_probe_permutations.py
```

Expected: position fixtures and complete integration behavior are absent or expose a position-sensitive defect.

- [ ] **Step 3: Make only the minimal production correction**

If tests expose a defect, correct canonical set comparison or freshness/producer binding inside `context_evaluation.py`. Do not add `position` to `ContextContinuityProbeV1`, `ContextProjectionV1`, or any production policy. If existing behavior passes unchanged, commit tests only; passing without a production edit is valid proof, not a reason to manufacture code.

```python
def _required_ids_match(
    probe: ContextContinuityProbeV1,
    response: ContextContinuityProbeResponseV1,
) -> bool:
    return response.returned_record_ids == probe.required_record_ids
```

Use the complete canonical implementation required by the prerequisite contract; this snippet fixes the comparison seam and intentionally contains no position input.

- [ ] **Step 4: Run GREEN and regress canonical probes**

```bash
.venv/bin/python -m pytest -q tests/contract/test_context_probe.py tests/integration/test_context_probe.py tests/integration/test_context_probe_positions.py tests/security/test_context_probe_position_poisoning.py tests/property/test_context_probe_permutations.py
.venv/bin/python -m mypy src/agent_continuity/kernel/context.py src/agent_continuity/kernel/context_evaluation.py
.venv/bin/python -m ruff check src/agent_continuity/kernel/context.py src/agent_continuity/kernel/context_evaluation.py tests/integration/test_context_probe_positions.py tests/security/test_context_probe_position_poisoning.py tests/property/test_context_probe_permutations.py
```

- [ ] **Step 5: Commit**

```bash
git add src/agent_continuity/kernel/context.py src/agent_continuity/kernel/context_evaluation.py tests/integration/test_context_probe_positions.py tests/security/test_context_probe_position_poisoning.py tests/property/test_context_probe_permutations.py
git commit -m "test: prove position-independent continuity probes"
```

---

### Task 4: Prove canonical checkpoint and verified rehydration contain middle loss

**Files:**

- Modify: `src/agent_continuity/context/coordinator.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `tests/integration/test_lost_middle_transition.py`
- Create: `tests/integration/test_lost_middle_handoff.py`
- Create: `tests/security/test_lost_middle_false_pass.py`

**Interfaces:**

- Consumes: `ContextContinuity.prepare()`, `ContextContinuity.verify_rehydration()`, `ContextProjectionV1`, `ContextTransitionV1`, `ContextComparisonResult` from Context Plan Tasks 2-4.
- Produces: no new production interface; complete transition-level containment proof.

- [ ] **Step 1: Write failing transition triplets**

```python
@pytest.mark.parametrize("position", tuple(BenchmarkPosition))
def test_verified_projection_survives_clean_transition(position: BenchmarkPosition) -> None:
    session = initialized_context_session(position=position)
    transition = session.context.prepare(ContextTransitionKind.HANDOFF, metrics())
    result = session.context.verify_rehydration(
        transition.transition_id,
        exact_destination_projection(transition),
    )
    assert result.verdict is Verdict.PASS
    assert result.transition_allowed is True


def test_missing_middle_blocker_cannot_false_pass() -> None:
    session = initialized_context_session(position=BenchmarkPosition.MIDDLE)
    transition = session.context.prepare(ContextTransitionKind.COMPACTION, metrics())
    result = session.context.verify_rehydration(
        transition.transition_id,
        destination_projection_without_required_blocker(transition),
    )
    assert result.verdict is Verdict.BLOCK
    assert result.transition_allowed is False
```

Cover each protected kind: goal, criterion, invariant, authority, decision, evidence, open question, blocker, assignment, failure fingerprint, next action, and work scope. Cover stale required evidence as `UNKNOWN`, changed authority as `BLOCK`, advisory extra narrative as no effect, and exact retry as idempotent.

- [ ] **Step 2: Write crash, source-freeze, and handoff-lineage cases**

Inject failure before checkpoint, after prepared transition, after destination projection, and before accepted lineage append. Source ordinary continuation remains refused until exact VERIFIED receipt. Failed destination retains recoverable source. Child scope keeps root/parent lineage and cannot flatten evidence into a root claim.

```python
@pytest.mark.parametrize(
    "fault_stage",
    (
        "before_checkpoint",
        "after_transition",
        "after_projection",
        "before_lineage",
    ),
)
def test_failed_middle_handoff_never_releases_source(fault_stage: str) -> None:
    session = initialized_context_session(position=BenchmarkPosition.MIDDLE)
    session.inject_fault(fault_stage)
    with pytest.raises(ContextTransitionError):
        session.handoff()
    assert session.source_transition_allowed() is False
    assert session.source_recoverable() is True
```

- [ ] **Step 3: Run RED**

```bash
.venv/bin/python -m pytest -q tests/integration/test_lost_middle_transition.py tests/integration/test_lost_middle_handoff.py tests/security/test_lost_middle_false_pass.py
```

Expected: at least one transition-level containment case fails before correction.

- [ ] **Step 4: Implement minimal coordinator/store corrections**

Rebuild destination projection only from the stored checkpoint, current verified resume, and canonical record registry. Compare protected tuples as complete identity sets; preserve kind, source ID, subject digest, required flag, actor, policy, ruleset, and target. Commit attempt and lineage atomically. Never inspect benchmark position in production code.

```python
def _protected_identity(ref: ProtectedContextRefV1) -> tuple[object, ...]:
    return (
        ref.kind,
        ref.source_record_id,
        ref.subject_digest,
        ref.required,
    )


before_ids = tuple(sorted(map(_protected_identity, before.protected)))
after_ids = tuple(sorted(map(_protected_identity, after.protected)))
```

The actual comparison also binds projection actor, target, instruction, policy, and ruleset IDs before allowing the atomic attempt/lineage commit.

- [ ] **Step 5: Run GREEN and full context regression**

```bash
.venv/bin/python -m pytest -q tests/contract/test_context_*.py tests/integration/test_context_*.py tests/integration/test_lost_middle_*.py tests/security/test_context_*.py tests/security/test_lost_middle_false_pass.py
.venv/bin/python tools/verify_schemas.py
.venv/bin/python -m mypy src/agent_continuity
.venv/bin/python -m ruff check src/agent_continuity tests
```

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/context/coordinator.py src/agent_continuity/store/sqlite.py tests/integration/test_lost_middle_transition.py tests/integration/test_lost_middle_handoff.py tests/security/test_lost_middle_false_pass.py
git commit -m "feat: contain lost-middle transition failures"
```

---

### Task 5: Build public corpus runner and sealed-holdout evidence boundary

**Files:**

- Create: `src/agent_continuity/benchmark/runner.py`
- Create: `schemas/v1/benchmark-product-input.schema.json`
- Create: `schemas/v1/benchmark-environment.schema.json`
- Create: `schemas/v1/product-decision.schema.json`
- Create: `schemas/v1/benchmark-layout-proof.schema.json`
- Create: `tests/fixtures/context-continuity-public-v2.jsonl`
- Create: `tests/contract/test_benchmark_runner.py`
- Create: `tests/integration/test_public_position_benchmark.py`
- Create: `tests/security/test_benchmark_isolation.py`
- Create: `tests/security/test_holdout_leakage.py`
- Create: `tools/benchmark_context_continuity.py`

**Interfaces:**

- Consumes: frozen product adapter, `BenchmarkVariantV1`, `BenchmarkObservationV1`, scorer from Tasks 1-2.
- Produces: `run_frozen_variants()` and a secret-safe canonical evidence bundle.

```python
@dataclass(frozen=True, slots=True)
class BenchmarkProductInputV1:
    input_id: RecordId
    rendered_input: bytes
    resource_budget_id: RecordId


@dataclass(frozen=True, slots=True)
class BenchmarkEnvironmentV1:
    environment_id: RecordId
    platform_id: str
    python_version: str
    runner_digest: Digest
    artifact_digest: Digest
    network_disabled: bool


@dataclass(frozen=True, slots=True)
class RawProductObservation:
    input_id: RecordId
    stdout: bytes
    stderr: bytes
    exit_code: int
    duration_ns: int
    status: Literal["complete", "malformed", "timeout", "resource_exceeded"]


@dataclass(frozen=True, slots=True)
class ProductDecisionV1:
    input_id: RecordId
    verdict: Verdict
    transition_allowed: bool
    raw_stdout_digest: Digest
    raw_stderr_digest: Digest
    adapter_digest: Digest


@dataclass(frozen=True, slots=True)
class BenchmarkLayoutProofV1:
    input_id: RecordId
    rendered_input_digest: Digest
    rendered_input_bytes: int
    protected_start_bps: int
    protected_end_bps: int
    tokenizer_identity_digest: Digest | None
    protected_start_token: int | None
    protected_end_token: int | None
    rendered_input_tokens: int | None


class FrozenProductAdapter(Protocol):
    def execute(
        self,
        product_input: BenchmarkProductInputV1,
        environment: BenchmarkEnvironmentV1,
    ) -> RawProductObservation: ...

    def normalize(self, raw: RawProductObservation) -> ProductDecisionV1: ...


def run_frozen_variants(
    variants: tuple[BenchmarkVariantV1, ...],
    adapter: FrozenProductAdapter,
    environment: BenchmarkEnvironmentV1,
) -> tuple[BenchmarkObservationV1, ...]: ...
```

- [ ] **Step 1: Write runner, adapter-bias, and isolation tests**

Assert one execution per admitted variant; identical budget/environment; no network after artifact acquisition; no expected label, base-case relationship, position label, other-product output, or holdout path in adapter input; bounded stdout/stderr; explicit malformed/timeout/resource results; and target manifest unchanged before/after.

```python
def test_product_input_contains_no_checker_metadata() -> None:
    product_input = serialize_product_input(middle_variant())
    encoded = product_input.rendered_input
    assert b"middle" not in encoded
    assert middle_variant().base_case_id.encode() not in encoded
    assert middle_variant().variant_id.encode() not in encoded
    assert middle_variant().expected.value.encode() not in encoded
```

- [ ] **Step 2: Freeze public corpus and expected digest**

Generate at least 100 seeded material failures and 100 valid controls before triplet expansion. Every protected kind and direct/transitive content-rot family appears in all three positions. Store generator version, seed, case count, stratum counts, and SHA-256 in a checked golden manifest. Review labels independently before freezing.

```python
manifest = freeze_public_corpus(seed=611, material_failures=100, valid_controls=100)
assert manifest.base_case_count >= 200
assert manifest.variant_count == manifest.base_case_count * 3
assert manifest.digest == digest_bytes(PUBLIC_CORPUS_PATH.read_bytes())
```

- [ ] **Step 3: Run RED**

```bash
.venv/bin/python -m pytest -q tests/contract/test_benchmark_runner.py tests/integration/test_public_position_benchmark.py tests/security/test_benchmark_isolation.py tests/security/test_holdout_leakage.py
```

Expected: runner and v2 corpus do not exist.

- [ ] **Step 4: Implement translation-only runner and evidence bundle**

The reviewed runner serializer derives `BenchmarkProductInputV1` from only ordered canonical block bytes and `resource_budget_id`; it never embeds `variant_id`, `base_case_id`, `position`, `partition`, `expected`, `expected_transition_allowed`, `critical`, or `stratum`. It records `BenchmarkLayoutProofV1` from exact product-visible bytes before execution and verifies the frozen position interval. Token offsets are optional only when the exact tokenizer is unavailable; then claim generation labels results byte-layout-only. It captures bounded raw bytes and process metadata, calls the separately reviewed translation-only `normalize()`, computes raw digests, and never retries semantic failures. Raw bytes remain checker-local until secret scan and final-result freeze; portable results contain digests and normalized decisions. Any detected secret invalidates publication evidence and blocks the run rather than silently redacting reproducibility material. Holdout mode accepts an opaque checker-owned manifest digest and output destination; it refuses case enumeration or label access from maker mode.

```python
def _product_input(variant: BenchmarkVariantV1) -> BenchmarkProductInputV1:
    rendered = b"\n".join(block.canonical_bytes for block in variant.ordered_blocks)
    return BenchmarkProductInputV1(
        input_id=RecordId(digest_bytes(rendered)),
        rendered_input=rendered,
        resource_budget_id=variant.resource_budget_id,
    )
```

- [ ] **Step 5: Run GREEN and deterministic public benchmark**

```bash
.venv/bin/python -m pytest -q tests/contract/test_benchmark_runner.py tests/integration/test_public_position_benchmark.py tests/security/test_benchmark_isolation.py tests/security/test_holdout_leakage.py
.venv/bin/python tools/benchmark_context_continuity.py --corpus tests/fixtures/context-continuity-public-v2.jsonl --partition public --replicates 10000
.venv/bin/python -m mypy src/agent_continuity/benchmark tools/benchmark_context_continuity.py
.venv/bin/python -m ruff check src/agent_continuity/benchmark tools/benchmark_context_continuity.py tests
```

Expected: public corpus emits raw per-case mapping, three per-position matrices, paired interval, artifact/environment digests, and an honest pass/fail. It never emits a universal claim.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/benchmark/runner.py schemas/v1/benchmark-product-input.schema.json schemas/v1/benchmark-environment.schema.json schemas/v1/product-decision.schema.json schemas/v1/benchmark-layout-proof.schema.json tests/fixtures/context-continuity-public-v2.jsonl tests/contract/test_benchmark_runner.py tests/integration/test_public_position_benchmark.py tests/security/test_benchmark_isolation.py tests/security/test_holdout_leakage.py tools/benchmark_context_continuity.py
git commit -m "feat: add isolated position benchmark runner"
```

---

### Task 6: Gate containment claims and zero-waiver release evidence

**Files:**

- Create: `src/agent_continuity/benchmark/claims.py`
- Create: `schemas/v1/benchmark-claim.schema.json`
- Create: `tests/contract/test_benchmark_claim.py`
- Create: `tests/security/test_claim_floor_bypass.py`
- Create: `tests/integration/test_installed_position_benchmark.py`
- Modify: `tools/verify_release.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `pyproject.toml`
- Modify: `README.md`
- Create: `docs/lost-in-the-middle-containment.md`

**Interfaces:**

- Consumes: exact candidate artifact manifest, public/holdout/combined results, clean-runner reproduction receipt, installed 12-cell matrix, aggregate production gates.
- Produces: `BenchmarkClaimV1 | None` through mechanical eligibility only.

```python
@dataclass(frozen=True, slots=True)
class ClaimGateInput:
    production_gate_ids: tuple[RecordId, ...]
    public_result_id: RecordId
    holdout_result_id: RecordId
    combined_result_id: RecordId
    holdout_reproduction_id: RecordId | None
    platform_matrix_id: RecordId


def derive_containment_claim(
    gate: ClaimGateInput,
    records: Mapping[RecordId, StoredRecord],
) -> BenchmarkClaimV1 | None: ...
```

- [ ] **Step 1: Write claim refusal matrix**

```python
@pytest.mark.parametrize(
    "missing_gate",
    (
        "production",
        "public_position_floor",
        "holdout_position_floor",
        "combined_position_floor",
        "middle_non_inferiority",
        "holdout_reproduction",
        "platform_matrix",
    ),
)
def test_any_missing_required_gate_withholds_claim(missing_gate: str) -> None:
    assert derive_containment_claim(gate_without(missing_gate), records()) is None
```

Also reject stale evidence, digest mismatch, fewer than 10,000 replicates, incomplete disclosure, one missing OS/Python cell, any critical/high finding, any required `UNKNOWN`/`BLOCK`, source/wheel divergence, and claim text containing `solves attention`, `perfect recall`, `remembers everything`, `best in the world`, or an unscoped `best`.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q tests/contract/test_benchmark_claim.py tests/security/test_claim_floor_bypass.py tests/integration/test_installed_position_benchmark.py
```

Expected: claim contract and installed benchmark proof are absent.

- [ ] **Step 3: Implement mechanical claim derivation and release aggregation**

Build claim fields from canonical gate records, never caller prose. Exact permitted statement is scoped to named artifacts, lanes, corpus versions, context layouts/lengths, position bins, workloads, recovery protocol, platforms, and date. `tools/verify_release.py` requires every gate and returns nonzero for omission, stale identity, false-PASS, disclosure failure, or unsupported required matrix cell.

```python
def derive_containment_claim(
    gate: ClaimGateInput,
    records: Mapping[RecordId, StoredRecord],
) -> BenchmarkClaimV1 | None:
    resolved = resolve_required_claim_gates(gate, records)
    if not all(item.status is GateStatus.PASS for item in resolved):
        return None
    return build_scoped_containment_claim(resolved)
```

- [ ] **Step 4: Add exact 12-cell installed-artifact CI matrix**

```yaml
strategy:
  fail-fast: false
  matrix:
    os: [macos-latest, ubuntu-latest, windows-latest]
    python-version: ["3.11", "3.12", "3.13", "3.14"]
```

Each cell builds the sdist and wheel twice, verifies reproducibility, installs the wheel in a clean environment, runs CLI end-to-end tests, context/position suites, schema checks, target-read-only checks, and uploads raw evidence keyed by artifact digest. Aggregate job fails if any of 12 cells is absent, skipped, cancelled, stale, or non-PASS.

- [ ] **Step 5: Run full local gates**

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m mypy src/agent_continuity
.venv/bin/python -m ruff check .
.venv/bin/python tools/verify_schemas.py
.venv/bin/python tools/benchmark_context_continuity.py --corpus tests/fixtures/context-continuity-public-v2.jsonl --partition public --replicates 10000
.venv/bin/python tools/verify_release.py --scope lost-middle-containment --no-publish
```

Expected: all local gates pass or claim remains withheld. Local macOS cannot prove Linux/Windows or sealed holdout; those gates remain pending until independent CI/checker evidence arrives.

- [ ] **Step 6: Document exact limits and commit**

README and containment document state: ACG contains protected continuity in the named tested scope; it does not alter transformer attention, guarantee arbitrary transcript recall, or infer safety from nominal context capacity.

```bash
git add src/agent_continuity/benchmark/claims.py schemas/v1/benchmark-claim.schema.json tests/contract/test_benchmark_claim.py tests/security/test_claim_floor_bypass.py tests/integration/test_installed_position_benchmark.py tools/verify_release.py .github/workflows/ci.yml pyproject.toml README.md docs/lost-in-the-middle-containment.md
git commit -m "feat: gate lost-middle containment claims"
```

## Final checker gate

Independent checker receives immutable maker commit and artifacts. It must reproduce:

1. all prerequisite plan evidence;
2. public triplet corpus digest and per-position floors;
3. sealed holdout one-shot result and post-freeze complete disclosure;
4. paired middle-versus-edges interval;
5. all 12 installed-artifact platform cells;
6. zero target mutation and zero critical false-PASS;
7. exact claim text from canonical gate records.

Any mismatch withholds the containment claim. This plan never authorizes a superiority claim. Production installation and public release remain separate human approval gates.
