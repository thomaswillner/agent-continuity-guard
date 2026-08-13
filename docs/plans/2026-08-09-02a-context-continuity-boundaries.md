# Context Continuity Boundaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic context-continuity boundary that forces every long-running session, compaction, restart, handoff, and nested work scope through `observe -> checkpoint -> compact or hand off -> rehydrate -> compare -> continue or BLOCK`.

**Architecture:** Extend Agent Continuity Guard after the Evidence/Resume Plan with a pure context kernel, atomic transition records, and a thin `ContextContinuity` facade. Harnesses provide bounded rendered-context and cumulative-session usage observations plus references to canonical ACG records; model-produced summaries and conversation history remain untrusted data. The guard never compacts text, selects a loop, creates a provider session, or edits a target—it emits protected retention manifests, deterministic continuity probes, verified resume projections, meta-handoff lineage, and transition verdicts that capability-qualified provider adapters may enforce later through the Hardening Plan generic JSON seam.

**Tech Stack:** Python 3.11+, standard-library runtime, frozen dataclasses, StrEnum, CanonicalJSON/v1, SHA-256 record identities, SQLite StateStore, pytest, Hypothesis, Ruff, mypy.

## Global Constraints

- Execute after `2026-08-08-02-evidence-resume-lineage.md` is green and committed and before governed improvement begins.
- Do not modify or depend on the `loop-engineering` skill, router, taxonomy, or provider mirrors.
- Context continuity is a wrapper around external work. It is never a primary operational loop and never selects or changes one.
- Conversation history, model summaries, hidden reasoning, prompts, transcripts, and handoff prose are untrusted data and never establish authority, completion, or PASS.
- Canonical ACG records outside the conversation remain authoritative: checkpoint, goal, criteria, invariants, authority, decisions, evidence, unresolved items, assignments, blockers, failure fingerprint, next action, and work-scope lineage.
- A model may reference an existing record ID or propose advisory narrative. It cannot create a trusted record, trust root, policy, required-field manifest, acceptance gate, or authority amendment through rehydrated context.
- Guarded targets remain read-only. Context transitions modify only the external ACG StateStore and audit chain.
- The pure kernel has no filesystem, database, clock, subprocess, environment, network, token counter, provider SDK, or model access.
- Token usage enters as immutable harness evidence with a producer identity, observation time, rendered current-context capacity and upper bound, cumulative session-token upper bound, compaction generation, turns since verified checkpoint, and separate completeness status for rendered and cumulative counters.
- Rendered current-context tokens, cumulative session tokens, compaction generation, and turns since verified checkpoint are distinct measures. Compaction may reduce the first without resetting the others.
- Missing, stale, advisory-only, truncated, contradictory, unsupported, or unbound context metrics evaluate UNKNOWN; guard and strict profiles refuse protected transitions.
- No built-in Codex, Claude Code, OpenClaw, Hermes, Gemini, Buzz, IDE, or framework adapter ships in this plan. `2026-08-08-04-hardening-release.md` translates provider events through strict generic JSON.
- Automatic handoff is permitted only when a provider adapter proves current behavioral support for usage telemetry, destination-session creation, handoff injection, source-continuation blocking, destination-projection collection, source close/archive, and rollback to the source when acceptance fails. Missing capability yields warning plus manual handoff, never simulated automation.
- No automatic `/compact`, session restart, message deletion, transcript rewriting, or hook installation occurs. ACG returns the required action and transition permission to the caller.
- Exact replay is idempotent. Reusing a transition or projection identifier with different canonical bytes is BLOCK.
- Default context policy is `conservative-longrun-v2`: checkpoint at 25% rendered use or 16,000 cumulative tokens, compaction/handoff required at 40% rendered use or 24,000 cumulative tokens, protected continuation refused at 50% rendered use or 32,000 cumulative tokens, minimum 8,192-token reserve, metric age at most 120 seconds, no more than 8 turns since the last verified checkpoint, maximum scope depth 8, and maximum 3 distinct rehydration attempts. The effective action is the strongest action produced by the earliest ratio, absolute ceiling, reserve, turn, probe, or freshness gate.
- The 25%/40%/50% ratios and 16,000/24,000/32,000 absolute ceilings are operator-selected conservative defaults with exact status `PROVISIONAL_UNCALIBRATED`. Checkpoint and handoff occur before the 32K degradation region reported for difficult long-context workloads; 32K is a refusal ceiling, not a claimed universal break point. The values require a frozen provider/model/route/harness/workload/tool-schema/transition profile and behavioral calibration before any production safety claim. `200,000` is not treated as a cross-model safety boundary.
- Built-in default generation `2` and all six v2 thresholds are update invariants. Every source update, installed-artifact update, migration, CI aggregate, and release-candidate gate must reproduce the exact canonical v2 default and fail closed if a missing or higher built-in value is observed. Updates append a new policy/default-generation binding rather than mutating historical policy records. An active session bound to retired `conservative-longrun-v1`, a missing default, or a silently raised built-in threshold cannot continue protected work; its next observation requires checkpoint plus compact/handoff into v2 or returns BLOCK. Explicit custom profiles with equal or lower thresholds remain valid. An update may never silently convert an explicit calibrated profile into the built-in default or raise v2; a later higher default requires a new explicit operator amendment and current calibration evidence.
- Thresholds use integer basis points and integer tokens. Floats are forbidden.
- Deterministic continuity probes run at bounded cadence even below budget thresholds. The agent must return requested canonical record IDs through a structured adapter result; missing protected IDs, contradictions against canonical records, unknown substitutions, or authority broadening require handoff or BLOCK. Confidence, prose acknowledgment, and self-reported recall never pass a probe.
- Lost-in-the-middle is contained, not claimed eliminated: protected-state identity and transition comparison are position-independent, while public and sealed benchmark triplets place matched protected facts at beginning, middle, and end. Prompt position is benchmark metadata and never production authority.
- Task-phase boundaries, high-risk decisions, explicit operator requests, and large tool-output spikes may request an earlier checkpoint or handoff. These event triggers can strengthen but never postpone the action selected by token, reserve, turn, freshness, or probe gates.
- A retry is informative only when its projection, source observation, checkpoint, or evidence set changes. A repeated identical failure fingerprint blocks immediately.
- Every accepted handoff appends meta-lineage containing root lineage ID, parent transition, source and destination actor IDs, checkpoint, verified projection, and accepted logical time. Resume state is materialized from the canonical ledger, never by recursively summarizing an earlier handoff summary.
- The plan introduces no daemon, scheduler, watcher, continuous monitor, UI, remote state, cross-machine envelope, or vendor-specific hook.

---

## File Map

- `src/agent_continuity/kernel/context.py`: immutable context policy, metrics, phase, projection, retention, comparison, and verdict models.
- `src/agent_continuity/kernel/context_defaults.py`: versioned conservative v2 defaults and append-only update/migration decision.
- `src/agent_continuity/kernel/context_evaluation.py`: pure budget and continuity comparison rules.
- `src/agent_continuity/context/coordinator.py`: transition preparation and post-transition orchestration over stable ACG observations.
- `src/agent_continuity/context/__init__.py`: public context package exports.
- `src/agent_continuity/api.py`: `ContextContinuity` facade and `Continuity.context()` entrypoint.
- `src/agent_continuity/store/base.py`: context-transition compare-and-swap interfaces.
- `src/agent_continuity/store/sqlite.py`: atomic transition, attempt, and audit persistence.
- `src/agent_continuity/kernel/records.py`: context record registration.
- `src/agent_continuity/kernel/resume.py`: protected failure fingerprint and next-action projection into ResumeContext.
- `src/agent_continuity/kernel/evaluation.py`: context findings in normal verdict aggregation.
- `schemas/v1/context-budget-policy.schema.json`: strict integer context threshold policy.
- `schemas/v1/context-metrics.schema.json`: immutable bounded harness observation.
- `schemas/v1/context-continuity-probe.schema.json`: structured canonical-ID challenge and response.
- `schemas/v1/context-projection.schema.json`: protected canonical continuity projection.
- `schemas/v1/context-retention-manifest.schema.json`: must-retain and may-prune identities.
- `schemas/v1/context-transition.schema.json`: immutable prepared boundary binding.
- `schemas/v1/context-transition-attempt.schema.json`: immutable append-only rehydration attempt.
- `schemas/v1/context-handoff-lineage.schema.json`: root and parent transition lineage for accepted handoffs.
- `schemas/v1/context-adapter-capabilities.schema.json`: behavioral capability declaration and evidence handles.
- `schemas/v1/failure-fingerprint.schema.json`: canonical failing-gate and evidence signature.
- `schemas/v1/next-action.schema.json`: exact owner, action, expected evidence, gate, and budget charge.
- `schemas/v1/checkpoint.schema.json`: checkpoint references to failure fingerprint and next action.
- `schemas/v1/resume-context.schema.json`: verified resume exposure of those references.
- `schemas/v1/work-scope.schema.json`: bounded parent-child scope/evidence provenance.
- `tests/contract/`: canonical schema, identity, ordering, and decision-table tests.
- `tests/integration/`: prepare, rehydrate, compare, resume, handoff, and atomicity tests.
- `tests/property/`: projection-set, scope-graph, and replay properties.
- `tests/golden/context-default-policy-v2.json`: canonical update-pinned default values.
- `tests/security/`: poisoning, authority broadening, omission, collision, and target-read-only proof.
- `tests/fixtures/context-continuity-benchmark-v1.jsonl`: frozen synthetic failure/control corpus.
- `tools/benchmark_context_continuity.py`: deterministic detection and false-positive scorer.
- `tools/verify_context_defaults.py`: installed/source default parity and anti-regression gate.
- `docs/context-continuity.md`: generic harness contract and evidence boundary.

## Requirement Coverage

| Requirement | Implemented by | Terminal protection |
|---|---|---|
| Context-budget thresholds | Tasks 1 and 4 | Earliest rendered ratio, cumulative ceiling, reserve, turn, or freshness gate controls; stale/missing metrics are UNKNOWN |
| Below-threshold drift probes | Tasks 3 and 4 | Missing/contradictory canonical IDs or broader authority require handoff/BLOCK |
| Canonical checkpoint fields | Tasks 2 and 3 | Required record omission or substitution is BLOCK |
| Source references/hashes | Tasks 2 and 3 | Only verified ACG record IDs and digests satisfy requirements |
| Post-compaction rehydration | Tasks 3 and 4 | Transition remains unusable until comparison passes |
| Deterministic comparison | Task 3 | Goal/invariant/authority change or required omission is BLOCK |
| Freshness/expiry | Tasks 1, 3, and 4 | Expired metrics/evidence are UNKNOWN or BLOCK per existing policy |
| Handoff acceptance | Task 4 | Wrong actor, checkpoint, target, or transition is BLOCK |
| Meta-handoff lineage | Tasks 4 and 5 | Accepted transitions retain root/parent/source/destination/checkpoint/projection/time without summary recursion |
| Adapter feasibility | Task 6 | Automatic handoff requires every behavioral capability; closed apps fall back to manual handoff |
| Measured 90% safeguard target | Task 6 | Frozen synthetic benchmark detects >=90% seeded material failures with <=5% false positives; scope is disclosed |
| BLOCK on unreconstructable continuity | Tasks 3 and 4 | Guard/strict profiles refuse transition |
| Nested child provenance | Task 5 | Cycles, depth overflow, orphan scopes, or collapsed provenance are BLOCK |
| Safe duplicate pruning | Task 2 | Only advisory duplicate digests become `may_prune`; protected IDs never do |

---

### Task 1: Add bounded context policy and usage evidence

**Files:**

- Create: `src/agent_continuity/kernel/context.py`
- Create: `src/agent_continuity/kernel/context_defaults.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Create: `schemas/v1/context-budget-policy.schema.json`
- Create: `schemas/v1/context-metrics.schema.json`
- Create: `tests/contract/test_context_budget_policy.py`
- Create: `tests/contract/test_context_metrics.py`
- Create: `tests/contract/test_context_budget_decision.py`
- Create: `tests/property/test_context_thresholds.py`
- Create: `tests/contract/test_context_default_update.py`
- Create: `tests/golden/context-default-policy-v2.json`
- Create: `tools/verify_context_defaults.py`

**Interfaces:**

```python
class ContextMetricCompleteness(StrEnum):
    COMPLETE = "complete"
    ESTIMATED_UPPER_BOUND = "estimated_upper_bound"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"


class ContextBudgetAction(StrEnum):
    CONTINUE = "continue"
    CHECKPOINT = "checkpoint"
    COMPACT_OR_HANDOFF = "compact_or_handoff"
    BLOCK = "block"


class ContextCalibrationStatus(StrEnum):
    PROVISIONAL_UNCALIBRATED = "provisional_uncalibrated"
    CALIBRATED = "calibrated"


class ContextBoundarySignal(StrEnum):
    PHASE_BOUNDARY = "phase_boundary"
    HIGH_RISK_DECISION = "high_risk_decision"
    OPERATOR_REQUEST = "operator_request"
    TOOL_OUTPUT_SPIKE = "tool_output_spike"


@dataclass(frozen=True, slots=True)
class ContextBudgetPolicyV1:
    policy_id: RecordId
    calibration_status: ContextCalibrationStatus
    profile_identity_digest: Digest
    checkpoint_at_bps: int
    compact_at_bps: int
    block_at_bps: int
    checkpoint_ceiling_tokens: int
    compact_ceiling_tokens: int
    block_ceiling_tokens: int
    minimum_remaining_tokens: int
    metric_max_age_seconds: int
    maximum_uncheckpointed_turns: int
    maximum_scope_depth: int
    maximum_rehydration_attempts: int


@dataclass(frozen=True, slots=True)
class ContextTokenUsageV1:
    completeness: ContextMetricCompleteness
    used_tokens_upper_bound: int | None


@dataclass(frozen=True, slots=True)
class ContextMetricsV1:
    metrics_id: RecordId
    producer: ProducerIdentity
    observed_at: LogicalTime
    rendered_context_capacity_tokens: int
    rendered_context: ContextTokenUsageV1
    cumulative_session: ContextTokenUsageV1
    compaction_generation: int
    turns_since_verified_checkpoint: int
    boundary_signals: tuple[ContextBoundarySignal, ...]


@dataclass(frozen=True, slots=True)
class ContextBudgetDecision:
    action: ContextBudgetAction
    rendered_used_bps: int
    rendered_remaining_tokens: int
    cumulative_session_tokens_upper_bound: int | None
    finding_codes: tuple[str, ...]


def evaluate_context_budget(
    policy: ContextBudgetPolicyV1,
    metrics: ContextMetricsV1,
    logical_time: LogicalTime,
) -> ContextBudgetDecision: ...
```

- [ ] **Step 1: Write failing canonical policy and metric tests**

Require `0 < checkpoint_at_bps < compact_at_bps < block_at_bps <= 10000`, `0 < checkpoint_ceiling_tokens < compact_ceiling_tokens < block_ceiling_tokens`, a canonical profile-identity digest, positive rendered capacity, rendered `0 <= used_tokens_upper_bound <= capacity`, nonnegative cumulative upper bound, compaction generation, and turn count, registered deterministic producer identity, canonical field order, stable golden bytes, and no unknown fields or floats. The profile identity digest binds provider, exact model/version, route, harness build, system and compaction prompt digests, usage-source identity, tool-schema-set digest, workload class, and transition mechanism without storing secret values. `INCOMPLETE` and `UNAVAILABLE` counters require `used_tokens_upper_bound=None`; COMPLETE and ESTIMATED_UPPER_BOUND require an integer. Assert the named seed profile serializes with `calibration_status=provisional_uncalibrated`, 2500/4000/5000 basis points, 16000/24000/32000 cumulative ceilings, 8192 output/tool/checkpoint-recovery reserve tokens, 120 seconds, 8 turns, depth 8, and 3 attempts. `CALIBRATED` requires an external current calibration evidence record bound to the exact profile identity; configuration alone cannot set it.

Write update-contract tests through public policy APIs and the installed verifier. Generation 2 exact values pass. Missing values, generation rollback, or any built-in threshold above 2500/4000/5000 basis points or 16000/24000/32000 tokens fails. Equal/lower explicit profiles pass without becoming the default. A persisted v1 session produces a required checkpoint/compact-handoff migration decision; a verified v2 session continues. Migration appends a generation/policy binding and never rewrites the prior policy row. Run the same fixtures from an installed wheel so source-only constants cannot satisfy the gate.

```python
def test_context_policy_thresholds_are_strictly_ordered() -> None:
    with pytest.raises(RecordSchemaError):
        context_policy(checkpoint_at_bps=6500, compact_at_bps=6500)


def test_metrics_reject_used_tokens_above_capacity() -> None:
    with pytest.raises(RecordSchemaError):
        context_metrics(
            rendered_context_capacity_tokens=100_000,
            rendered_context_used_tokens_upper_bound=100_001,
        )
```

- [ ] **Step 2: Write the complete budget decision table**

Cover rendered boundaries at 24.99%, 25%, 39.99%, 40%, 49.99%, and 50%; cumulative boundaries at 15,999/16,000, 23,999/24,000, and 31,999/32,000 tokens; conflicting ratio/absolute actions where the stronger action wins; reserve-floor breach; turn-count breach; compaction-generation increment; each earlier-boundary signal; exact metric expiry; one second beyond expiry; COMPLETE, ESTIMATED_UPPER_BOUND, INCOMPLETE, and UNAVAILABLE values independently for rendered and cumulative counters; zero/malformed capacity; and producer mismatch. Boundary signals are unique and canonically ordered; phase/tool spikes select at least CHECKPOINT, while high-risk/operator signals select COMPACT_OR_HANDOFF unless a stronger gate applies. `ESTIMATED_UPPER_BOUND` is usable only when its conservative upper bound and deterministic producer are verified. Incomplete, unavailable, expired, or advisory counters emit required UNKNOWN and may not produce CONTINUE under guard.

```python
def test_block_boundary_is_inclusive() -> None:
    decision = evaluate_context_budget(
        provisional_seed_policy(),
        context_metrics(
            rendered_context_capacity_tokens=200_000,
            rendered_context_used_tokens_upper_bound=99_999,
            cumulative_session_tokens_upper_bound=32_000,
        ),
        logical_time(100),
    )
    assert decision.action is ContextBudgetAction.BLOCK
    assert "context.budget_block_threshold" in decision.finding_codes
```

- [ ] **Step 3: Run RED**

```bash
python -m pytest -q tests/contract/test_context_budget_policy.py tests/contract/test_context_metrics.py tests/contract/test_context_budget_decision.py tests/contract/test_context_default_update.py tests/property/test_context_thresholds.py
```

Expected: collection fails because context models and evaluator do not exist.

- [ ] **Step 4: Implement integer-only budget evaluation**

Compute `rendered_used_bps = rendered_context.used_tokens_upper_bound * 10000 // rendered_context_capacity_tokens`. Evaluate rendered ratio, cumulative absolute ceiling, output/tool/checkpoint-recovery reserve floor, probe state, turn cap, and explicit earlier-boundary signal independently, then select the strongest action using `BLOCK > COMPACT_OR_HANDOFF > CHECKPOINT > CONTINUE`; equal boundaries are inclusive. A higher `compaction_generation` never resets cumulative usage or checkpoint age and requires a verified post-compaction projection. Evaluate freshness only from explicit logical time. Never call a tokenizer, infer capacity from a model name, or treat a provider-reported compaction as continuity proof.

- [ ] **Step 5: Run GREEN and mutation proof**

```bash
python -m pytest -q tests/contract/test_context_budget_policy.py tests/contract/test_context_metrics.py tests/contract/test_context_budget_decision.py tests/contract/test_context_default_update.py tests/property/test_context_thresholds.py
python tools/verify_context_defaults.py
python -m mypy src/agent_continuity/kernel/context.py src/agent_continuity/kernel/context_defaults.py
python -m ruff check src/agent_continuity/kernel/context.py src/agent_continuity/kernel/context_defaults.py tests/contract tests/property tools/verify_context_defaults.py
```

Expected: all threshold cases pass and planted `>` versus `>=` mutations fail at exact boundaries.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/kernel/context.py src/agent_continuity/kernel/context_defaults.py src/agent_continuity/kernel/records.py
git add schemas/v1/context-budget-policy.schema.json schemas/v1/context-metrics.schema.json
git add tests/contract/test_context_budget_policy.py tests/contract/test_context_metrics.py tests/contract/test_context_budget_decision.py tests/contract/test_context_default_update.py tests/property/test_context_thresholds.py
git add tests/golden/context-default-policy-v2.json tools/verify_context_defaults.py
git commit -m "feat: add deterministic context budget policy"
```

---

### Task 2: Define protected continuity projection and safe retention manifest

**Files:**

- Modify: `src/agent_continuity/kernel/context.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Modify: `src/agent_continuity/kernel/resume.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `schemas/v1/checkpoint.schema.json`
- Modify: `schemas/v1/resume-context.schema.json`
- Create: `schemas/v1/context-projection.schema.json`
- Create: `schemas/v1/context-retention-manifest.schema.json`
- Create: `schemas/v1/failure-fingerprint.schema.json`
- Create: `schemas/v1/next-action.schema.json`
- Create: `tests/contract/test_checkpoint_v1.py`
- Modify: `tests/contract/test_resume_context.py`
- Modify: `tests/integration/test_checkpoint.py`
- Modify: `tests/integration/test_resume.py`
- Create: `tests/contract/test_context_projection.py`
- Create: `tests/contract/test_context_retention.py`
- Create: `tests/security/test_context_pruning.py`
- Create: `tests/property/test_context_projection_ordering.py`

**Interfaces:**

```python
class ProtectedContextKind(StrEnum):
    GOAL = "goal"
    ACCEPTANCE_CRITERION = "acceptance_criterion"
    INVARIANT = "invariant"
    AUTHORITY = "authority"
    DECISION = "decision"
    EVIDENCE = "evidence"
    OPEN_QUESTION = "open_question"
    FAILURE_FINGERPRINT = "failure_fingerprint"
    NEXT_ACTION = "next_action"
    BLOCKER = "blocker"
    OPEN_ASSIGNMENT = "open_assignment"
    WORK_SCOPE = "work_scope"


@dataclass(frozen=True, slots=True)
class ProtectedContextRefV1:
    kind: ProtectedContextKind
    source_record_id: RecordId
    subject_digest: Digest
    required: bool


@dataclass(frozen=True, slots=True)
class FailureFingerprintV1:
    fingerprint_id: RecordId
    gate_code: str
    symptom_digest: Digest
    evidence_signature_digest: Digest
    hypothesis_digest: Digest | None


@dataclass(frozen=True, slots=True)
class NextActionV1:
    next_action_id: RecordId
    owner_actor_id: RecordId
    action_digest: Digest
    expected_evidence_digest: Digest
    gate_code: str
    budget_charge_digest: Digest


@dataclass(frozen=True, slots=True)
class AdvisoryNarrativeRefV1:
    digest: Digest
    occurrence_count: int


@dataclass(frozen=True, slots=True)
class ContextProjectionV1:
    projection_id: RecordId
    checkpoint_id: RecordId
    target_id: RecordId
    instruction_id: RecordId
    policy_id: RecordId
    ruleset_id: RecordId
    actor_id: RecordId
    protected: tuple[ProtectedContextRefV1, ...]
    advisory_narrative: tuple[AdvisoryNarrativeRefV1, ...]


@dataclass(frozen=True, slots=True)
class ContextRetentionManifestV1:
    manifest_id: RecordId
    projection_id: RecordId
    must_retain: tuple[RecordId, ...]
    may_prune_duplicate_digests: tuple[Digest, ...]


def build_context_projection(
    checkpoint: CheckpointV1,
    resume: ResumeContext,
    actor_id: RecordId,
    advisory_narrative_digests: Sequence[Digest],
) -> ContextProjectionV1: ...


def build_retention_manifest(
    projection: ContextProjectionV1,
) -> ContextRetentionManifestV1: ...
```

This Context Continuity Plan extends existing records before v0.1 release:

```python
@dataclass(frozen=True, slots=True)
class CheckpointV1:
    checkpoint_id: RecordId
    parent_checkpoint_id: RecordId | None
    target_id: RecordId
    goal_id: RecordId
    acceptance_criteria: tuple[CriterionV1, ...]
    constraint_digests: tuple[Digest, ...]
    instruction_id: RecordId
    policy_id: RecordId
    ruleset_id: RecordId
    actor_ids: tuple[RecordId, ...]
    evidence_ids: tuple[RecordId, ...]
    invalidation_ids: tuple[RecordId, ...]
    accepted_decision_ids: tuple[RecordId, ...]
    pending_work: tuple[WorkItemV1, ...]
    unresolved: tuple[UnresolvedItemV1, ...]
    assignment_authority: AssignmentAuthority
    authority_scopes: tuple[PathScopeV1, ...]
    open_assignment_ids: tuple[RecordId, ...]
    audit_parent_id: RecordId | None
    initialization_intent_id: RecordId
    created_at: LogicalTime
    failure_fingerprint_id: RecordId | None
    next_action_id: RecordId


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
    failure_fingerprint_id: RecordId | None
    next_action_id: RecordId
```

`constraint_digests` become protected INVARIANT references sourced from the checkpoint. Authority is the canonical digest of `policy_id`, `assignment_authority`, and `authority_scopes`, also sourced from the checkpoint. Each embedded protected fact uses `source_record_id=checkpoint_id` plus its own `subject_digest`; separately stored records use their own record ID and canonical digest.

- [ ] **Step 1: Write failing required-field projection tests**

First extend Checkpoint/v1 and ResumeContext with `failure_fingerprint_id` and required `next_action_id`. Initialization creates a canonical safe-stop NextAction owned by the initializing actor with `action_digest=digest_bytes(b"await-authorized-next-slice")`, `expected_evidence_digest=digest_bytes(b"new-authorized-checkpoint-input")`, gate code `continuity.next_action_required`, and `budget_charge_digest=digest_bytes(b"zero")`; a checkpoint with no active failure uses a null fingerprint. Later checkpoints must resolve the supplied fingerprint/action IDs from the same StateStore before checkpoint comparison-and-swap. Require exactly one goal and authority reference; every constraint digest is an INVARIANT; every acceptance criterion, accepted decision, current evidence item, unresolved/open question, exact blocker, open assignment, failure fingerprint, next action, and work scope must be represented by verified source identity and digest. Unknown IDs, digest mismatch, duplicate `(kind, source_record_id, subject_digest)`, display text, raw prompt, transcript, hidden reasoning, source excerpt, and caller-created authority fields reject.

```python
def test_projection_cannot_omit_authority() -> None:
    with pytest.raises(ContextProjectionError):
        build_context_projection(
            checkpoint_with_authority(),
            resume_without_kind(ProtectedContextKind.AUTHORITY),
            actor_id(),
            (),
        )
```

- [ ] **Step 2: Write failing safe-pruning decision tests**

Only advisory narrative digests occurring more than once may enter `may_prune_duplicate_digests`. Every protected record ID enters `must_retain`, even when two protected records have equal human-facing text or an advisory digest matches a protected record's display digest. A retention manifest contains identities only; ACG never deletes messages or rewrites context.

```python
def test_duplicate_protected_meaning_is_never_prunable() -> None:
    projection = projection_with_equal_display_text_for_goal_and_decision()
    manifest = build_retention_manifest(projection)
    assert checkpoint_record_id() in manifest.must_retain
    assert decision_record_id() in manifest.must_retain
    assert protected_display_digest() not in manifest.may_prune_duplicate_digests
```

- [ ] **Step 3: Run RED**

```bash
python -m pytest -q tests/contract/test_checkpoint_v1.py tests/contract/test_resume_context.py tests/contract/test_context_projection.py tests/contract/test_context_retention.py tests/integration/test_checkpoint.py tests/integration/test_resume.py tests/security/test_context_pruning.py tests/property/test_context_projection_ordering.py
```

Expected: projection and retention types are absent.

- [ ] **Step 4: Implement projection derivation from verified records**

Derive protected references only from the loaded checkpoint, ResumeContext, and StateStore record registry. Sort by `(kind.value, source_record_id, subject_digest)`. Include the checkpoint in `must_retain` whenever an embedded constraint or authority fact is protected. Treat advisory narrative digests as optional non-authoritative metadata with a maximum of 1,024 entries and occurrence counts from 1 through 1,000,000. Exclude all narrative bytes from canonical output and comparison.

- [ ] **Step 5: Run GREEN and security mutants**

```bash
python -m pytest -q tests/contract/test_checkpoint_v1.py tests/contract/test_resume_context.py tests/contract/test_context_projection.py tests/contract/test_context_retention.py tests/integration/test_checkpoint.py tests/integration/test_resume.py tests/security/test_context_pruning.py tests/property/test_context_projection_ordering.py
python -m mypy src/agent_continuity/kernel/context.py
python -m ruff check src/agent_continuity/kernel/context.py tests/contract tests/security tests/property
```

Expected: omission, digest-substitution, and protected-to-prunable mutants are killed.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/kernel/context.py src/agent_continuity/kernel/records.py src/agent_continuity/kernel/resume.py src/agent_continuity/api.py
git add schemas/v1/checkpoint.schema.json schemas/v1/resume-context.schema.json schemas/v1/context-projection.schema.json schemas/v1/context-retention-manifest.schema.json schemas/v1/failure-fingerprint.schema.json schemas/v1/next-action.schema.json
git add tests/contract/test_checkpoint_v1.py tests/contract/test_resume_context.py tests/contract/test_context_projection.py tests/contract/test_context_retention.py tests/integration/test_checkpoint.py tests/integration/test_resume.py tests/security/test_context_pruning.py tests/property/test_context_projection_ordering.py
git commit -m "feat: add protected context projection"
```

---

### Task 3: Add atomic transition preparation and deterministic rehydration comparison

**Files:**

- Create: `src/agent_continuity/kernel/context_evaluation.py`
- Modify: `src/agent_continuity/kernel/context.py`
- Create: `src/agent_continuity/context/__init__.py`
- Create: `src/agent_continuity/context/coordinator.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `schemas/v1/context-transition.schema.json`
- Create: `schemas/v1/context-transition-attempt.schema.json`
- Create: `schemas/v1/context-continuity-probe.schema.json`
- Create: `tests/contract/test_context_transition.py`
- Create: `tests/contract/test_context_comparison.py`
- Create: `tests/contract/test_context_probe.py`
- Create: `tests/integration/test_context_transition.py`
- Create: `tests/integration/test_context_probe.py`
- Create: `tests/integration/test_context_transition_atomicity.py`
- Create: `tests/security/test_context_poisoning.py`

**Interfaces:**

```python
class ContextTransitionKind(StrEnum):
    COMPACTION = "compaction"
    SESSION_RESTART = "session_restart"
    HANDOFF = "handoff"


class ContextTransitionState(StrEnum):
    PREPARED = "prepared"
    VERIFIED = "verified"
    REFUSED = "refused"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class ContextTransitionV1:
    transition_id: RecordId
    kind: ContextTransitionKind
    checkpoint_id: RecordId
    before_projection_id: RecordId
    retention_manifest_id: RecordId
    source_actor_id: RecordId
    destination_actor_id: RecordId | None
    issued_at: LogicalTime
    expires_at: LogicalTime


@dataclass(frozen=True, slots=True)
class ContextTransitionAttemptV1:
    attempt_id: RecordId
    transition_id: RecordId
    ordinal: int
    after_projection_id: RecordId
    comparison_digest: Digest
    failure_fingerprint: Digest | None
    verdict: Verdict
    observed_at: LogicalTime


@dataclass(frozen=True, slots=True)
class ContextComparisonResult:
    verdict: Verdict
    transition_allowed: bool
    missing_required: tuple[ProtectedContextRefV1, ...]
    changed_required: tuple[ProtectedContextRefV1, ...]
    unexpected_authority: tuple[ProtectedContextRefV1, ...]
    stale_evidence_ids: tuple[RecordId, ...]
    failure_fingerprint: Digest | None
    finding_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContextContinuityProbeV1:
    probe_id: RecordId
    checkpoint_id: RecordId
    projection_id: RecordId
    required_record_ids: tuple[RecordId, ...]
    expected_authority_digest: Digest
    issued_at: LogicalTime
    expires_at: LogicalTime


@dataclass(frozen=True, slots=True)
class ContextContinuityProbeResponseV1:
    response_id: RecordId
    probe_id: RecordId
    producer: ProducerIdentity
    returned_record_ids: tuple[RecordId, ...]
    authority_digest: Digest
    observed_at: LogicalTime


@dataclass(frozen=True, slots=True)
class ContextProbeResult:
    action: ContextBudgetAction
    missing_required_ids: tuple[RecordId, ...]
    unexpected_ids: tuple[RecordId, ...]
    contradiction_ids: tuple[RecordId, ...]
    finding_codes: tuple[str, ...]


def compare_context_projections(
    before: ContextProjectionV1,
    after: ContextProjectionV1,
    evaluation: EvaluationResult,
) -> ContextComparisonResult: ...


def evaluate_context_probe(
    probe: ContextContinuityProbeV1,
    response: ContextContinuityProbeResponseV1,
    canonical_records: Mapping[RecordId, StoredRecord],
    logical_time: LogicalTime,
) -> ContextProbeResult: ...


class ContextContinuity:
    def prepare(
        self,
        kind: ContextTransitionKind,
        metrics: ContextMetricsV1,
        destination_actor_id: RecordId | None = None,
    ) -> ContextTransitionV1: ...

    def verify_rehydration(
        self,
        transition_id: RecordId,
        after: ContextProjectionV1,
    ) -> ContextComparisonResult: ...


def context(self) -> ContextContinuity: ...
```

- [ ] **Step 1: Write failing transition state-machine tests**

Treat ContextTransition/v1 as immutable PREPARED intent and ContextTransitionAttempt/v1 as append-only evidence. Derive status as PREPARED when no terminal attempt exists, VERIFIED after one passing attempt, REFUSED after an unrecoverable/unchanged/exhausted attempt, and EXPIRED from explicit logical time. Exact replay of the same verified attempt bytes is idempotent. Refuse verify-before-prepare, a new attempt after VERIFIED/REFUSED/EXPIRED, changed transition bytes, changed checkpoint head, expired transition, wrong actor, wrong target, wrong policy/ruleset/instruction identity, and destination mismatch.

- [ ] **Step 2: Write failing projection comparison decision table**

PASS requires exact identity for goal, criteria, invariants, authority, accepted decisions, blockers, failure fingerprint, next action, and open assignments; complete presence of required evidence/open questions; and current evidence after normal invalidation evaluation. Missing protected data, changed goal/invariant/authority, new authority, removed blocker, changed next action without a new authorized checkpoint, or evidence identity substitution is BLOCK. Missing/stale required evidence is UNKNOWN and transition-disallowing under guard. Extra advisory narrative has no effect.

```python
def test_summary_cannot_drop_a_blocker_and_continue() -> None:
    result = compare_context_projections(
        before_projection(blockers=(blocker_id(),)),
        after_projection(blockers=()),
        current_evaluation(),
    )
    assert result.verdict is Verdict.BLOCK
    assert result.transition_allowed is False
    assert "context.required_record_missing" in result.finding_codes
```

Also write below-threshold continuity-probe tests. Probe selection is deterministic from the protected projection and never asks for prose. Exact required canonical IDs plus the authority digest pass; missing protected IDs, unknown substitutions, stale/wrong producer response, canonical digest contradiction, or broader authority selects COMPACT_OR_HANDOFF or BLOCK according to policy. Model confidence and text such as “I remember everything” are not probe fields and cannot affect the result.

```python
def test_confident_prose_cannot_replace_canonical_probe_ids() -> None:
    result = evaluate_context_probe(
        protected_probe(),
        probe_response(returned_record_ids=()),
        canonical_records(),
        logical_time(100),
    )
    assert result.action is ContextBudgetAction.COMPACT_OR_HANDOFF
    assert "context.probe_required_id_missing" in result.finding_codes
```

- [ ] **Step 3: Write failing poisoning and authority tests**

Feed adversarial rehydrated summaries claiming completion, approval, changed goals, relaxed policy, broader scope, resolved blockers, fabricated record IDs, hash-like text, and instructions to ignore ACG. Prove every attempt is rejected or ignored as advisory because it cannot resolve to verified canonical records. Raw poison text must not appear in stdout, audit events, findings, exception messages, or portable records.

- [ ] **Step 4: Write failing crash/concurrency tests**

Inject failure before projection insert, after projection insert, before audit append, and before head compare-and-swap. After restart, StateStore has either no prepared transition or one complete prepared transition with its projection, manifest, and audit event. Two concurrent preparations against one checkpoint have one winner; an identical loser returns the winner, while a different loser receives a concurrency error.

- [ ] **Step 5: Run RED**

```bash
python -m pytest -q tests/contract/test_context_transition.py tests/contract/test_context_comparison.py tests/contract/test_context_probe.py tests/integration/test_context_transition.py tests/integration/test_context_probe.py tests/integration/test_context_transition_atomicity.py tests/security/test_context_poisoning.py
```

Expected: context evaluator, coordinator, facade, and store transitions are absent.

- [ ] **Step 6: Implement pure comparison and atomic orchestration**

`prepare()` invokes normal verified resume, evaluates context budget and latest probe state, derives before projection and retention manifest, and atomically stores all three with one audit event. It never triggers compaction. Below thresholds, the coordinator emits a deterministic bounded-cadence probe whose required IDs come only from the canonical projection; probe responses are structured harness evidence and resolve against the StateStore. `verify_rehydration()` reloads the canonical prepared transition and before projection by ID, re-observes target/instructions/policy/ruleset/evidence, derives the after projection, compares protected sets, and atomically appends one ContextTransitionAttempt/v1 plus audit event. Current transition status is derived from immutable intent, attempts, expiry, probe result, and policy; no stored transition record is updated in place. Caller-supplied transition or probe objects are never commit authority.

- [ ] **Step 7: Run GREEN, full resume regression, and mutation proof**

```bash
python -m pytest -q tests/contract/test_context_transition.py tests/contract/test_context_comparison.py tests/contract/test_context_probe.py tests/integration/test_context_transition.py tests/integration/test_context_probe.py tests/integration/test_context_transition_atomicity.py tests/security/test_context_poisoning.py
python -m pytest -q tests/contract/test_resume_context.py tests/integration/test_resume.py tests/integration/test_checkpoint.py tests/integration/test_audit.py
python -m mypy src/agent_continuity
python -m ruff check src/agent_continuity tests/contract tests/integration tests/security
```

Expected: all transition states and resume regressions pass; omission, set-direction, expiry, actor, and CAS mutants are killed.

- [ ] **Step 8: Commit**

```bash
git add src/agent_continuity/kernel/context.py src/agent_continuity/kernel/context_evaluation.py src/agent_continuity/context src/agent_continuity/api.py
git add src/agent_continuity/store/base.py src/agent_continuity/store/sqlite.py schemas/v1/context-transition.schema.json schemas/v1/context-transition-attempt.schema.json schemas/v1/context-continuity-probe.schema.json
git add tests/contract/test_context_transition.py tests/contract/test_context_comparison.py tests/contract/test_context_probe.py tests/integration/test_context_transition.py tests/integration/test_context_probe.py tests/integration/test_context_transition_atomicity.py tests/security/test_context_poisoning.py
git commit -m "feat: enforce context transition continuity"
```

---

### Task 4: Enforce compaction, restart, and handoff boundary acceptance

**Files:**

- Modify: `src/agent_continuity/context/coordinator.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/kernel/evaluation.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `schemas/v1/context-handoff-lineage.schema.json`
- Create: `tests/integration/test_context_compaction.py`
- Create: `tests/integration/test_context_restart.py`
- Create: `tests/integration/test_context_handoff.py`
- Create: `tests/contract/test_context_handoff_lineage.py`
- Create: `tests/integration/test_context_retry_budget.py`
- Create: `tests/security/test_context_actor_binding.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class ContextBoundaryReceipt:
    transition_id: RecordId
    state: ContextTransitionState
    action: ContextBudgetAction
    before_checkpoint_id: RecordId
    verified_projection_id: RecordId | None
    verdict: Verdict
    transition_allowed: bool
    finding_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContextHandoffLineageV1:
    lineage_id: RecordId
    root_lineage_id: RecordId
    parent_transition_id: RecordId | None
    transition_id: RecordId
    source_actor_id: RecordId
    destination_actor_id: RecordId
    checkpoint_id: RecordId
    verified_projection_id: RecordId
    accepted_at: LogicalTime


def transition_status(
    self,
    transition_id: RecordId,
) -> ContextBoundaryReceipt: ...
```

- [ ] **Step 1: Write failing compaction boundary tests**

At CHECKPOINT threshold, `prepare(COMPACTION)` first creates or reuses an exact checkpoint and returns CHECKPOINT without claiming that compaction occurred. At COMPACT_OR_HANDOFF threshold, it returns a prepared transition and forbids normal protected continuation until `verify_rehydration()` passes. At BLOCK threshold or reserve breach, it returns BLOCK and permits only checkpoint/transition recovery calls. Verify that a provider-reported successful compaction with an incomplete after projection remains refused.

- [ ] **Step 2: Write failing restart and handoff tests**

SESSION_RESTART binds the same actor identity or an explicit replacement allowed by policy. HANDOFF requires distinct source/destination actor identities, destination acceptance, the exact transition/checkpoint/target, and a fresh projection. Wrong model/provider labels are advisory; verified actor identity comes from ProducerIdentity. Destination prose such as “I understand” has no effect. The source remains frozen but recoverable until destination acceptance commits; it closes or archives only after the exact VERIFIED receipt exists.

```python
def test_handoff_acknowledgement_without_projection_is_not_acceptance() -> None:
    transition = prepared_handoff()
    result = destination_acknowledges_in_prose(transition)
    assert result.transition_allowed is False
    assert result.verdict is Verdict.UNKNOWN
```

Write meta-handoff lineage tests for a root handoff, a second-generation handoff, wrong parent transition, wrong root lineage, and attempted summary-of-summary construction. Every accepted lineage row binds source/destination actors, canonical checkpoint, verified projection, and accepted logical time. The destination projection is rebuilt from the current canonical ledger; prior handoff narrative may be advisory input but is never the source of protected state.

- [ ] **Step 3: Write failing retry-budget tests**

Allow at most three distinct rehydration attempts. An identical repeated failure fingerprint blocks immediately as non-informative. A changed projection or refreshed evidence consumes the next attempt. Attempt exhaustion sets REFUSED and requires a new explicit checkpoint/session decision; it never silently resets attempt count.

- [ ] **Step 4: Run RED**

```bash
python -m pytest -q tests/contract/test_context_handoff_lineage.py tests/integration/test_context_compaction.py tests/integration/test_context_restart.py tests/integration/test_context_handoff.py tests/integration/test_context_retry_budget.py tests/security/test_context_actor_binding.py
```

Expected: boundary receipt and enforcement behavior are absent.

- [ ] **Step 5: Implement boundary-specific orchestration**

Use one shared comparison kernel for all transition kinds. Boundary-specific code may only validate actor relationships, append verified lineage, and select existing policy actions. It cannot change verdict precedence, protected fields, expiry, retry accounting, or evidence rules. Handoff preparation freezes the source continuation; failure keeps the source available for rollback; successful destination comparison atomically appends `ContextHandoffLineageV1` before source close/archive becomes eligible. A caller must poll `transition_status()` or inspect the canonical receipt; no background process exists.

- [ ] **Step 6: Run GREEN and all transition regressions**

```bash
python -m pytest -q tests/contract/test_context_handoff_lineage.py tests/integration/test_context_compaction.py tests/integration/test_context_restart.py tests/integration/test_context_handoff.py tests/integration/test_context_retry_budget.py tests/security/test_context_actor_binding.py
python -m pytest -q tests/contract/test_context_transition.py tests/contract/test_context_comparison.py tests/integration/test_context_transition.py
python -m mypy src/agent_continuity
python -m ruff check src/agent_continuity tests/integration tests/security
```

Expected: compaction, restart, and handoff all use identical protected-field semantics and fail closed.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/context/coordinator.py src/agent_continuity/api.py src/agent_continuity/kernel/evaluation.py
git add src/agent_continuity/store/base.py src/agent_continuity/store/sqlite.py schemas/v1/context-handoff-lineage.schema.json
git add tests/contract/test_context_handoff_lineage.py tests/integration/test_context_compaction.py tests/integration/test_context_restart.py tests/integration/test_context_handoff.py tests/integration/test_context_retry_budget.py tests/security/test_context_actor_binding.py
git commit -m "feat: guard context lifecycle boundaries"
```

---

### Task 5: Preserve nested work-scope and child evidence provenance

**Files:**

- Modify: `src/agent_continuity/kernel/context.py`
- Modify: `src/agent_continuity/kernel/context_evaluation.py`
- Modify: `src/agent_continuity/kernel/lineage.py`
- Create: `schemas/v1/work-scope.schema.json`
- Create: `tests/contract/test_work_scope.py`
- Create: `tests/contract/test_scope_evidence_merge.py`
- Create: `tests/property/test_work_scope_graph.py`
- Create: `tests/security/test_scope_provenance.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class WorkScopeV1:
    scope_id: RecordId
    namespace: str
    external_key: str
    parent_scope_id: RecordId | None
    owner_actor_id: RecordId
    assignment_id: RecordId | None
    handoff_lineage_id: RecordId | None
    evidence_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class ScopeEvidenceMerge:
    root_scope_id: RecordId
    ordered_scope_ids: tuple[RecordId, ...]
    evidence_by_scope: tuple[tuple[RecordId, tuple[RecordId, ...]], ...]
    finding_codes: tuple[str, ...]


def evaluate_work_scope_graph(
    scopes: Sequence[WorkScopeV1],
    assignments: Mapping[RecordId, AssignmentV1],
    handoff_lineages: Mapping[RecordId, ContextHandoffLineageV1],
    maximum_depth: int,
) -> ScopeEvidenceMerge: ...
```

- [ ] **Step 1: Write failing scope identity and graph tests**

Require bounded ASCII namespace/external key, unique scope ID, one root, existing parent, exact owner, optional matching Assignment, optional verified handoff lineage, canonical evidence ordering, maximum depth 8, and an acyclic connected graph. A scope that continues after handoff must bind its accepted lineage row; child handoffs must retain the same root lineage and exact parent transition. An external loop controller may set `namespace="loop_id"` and place its loop identifier in `external_key`; ACG treats it as opaque provenance and never selects or executes the loop.

- [ ] **Step 2: Write failing evidence-merge tests**

Merge only evidence from accepted AssignmentResults or the owning root actor. Preserve `evidence_by_scope` in canonical parent-before-child order and retain each scope's handoff-lineage identity. Never flatten child evidence into an unsupported root claim, recursively summarize an earlier lineage, drop the originating scope, accept one evidence ID under conflicting scopes, or accept an orphan result.

```python
def test_child_evidence_keeps_originating_scope() -> None:
    merged = evaluate_work_scope_graph(
        parent_and_child_scopes(),
        assignments(),
        handoff_lineages(),
        8,
    )
    assert merged.evidence_by_scope == (
        (root_scope_id(), (root_evidence_id(),)),
        (child_scope_id(), (child_evidence_id(),)),
    )
```

- [ ] **Step 3: Run RED**

```bash
python -m pytest -q tests/contract/test_work_scope.py tests/contract/test_scope_evidence_merge.py tests/property/test_work_scope_graph.py tests/security/test_scope_provenance.py
```

Expected: WorkScope and provenance-preserving merge do not exist.

- [ ] **Step 4: Implement bounded iterative graph evaluation**

Use iterative cycle detection and breadth-first parent-before-child ordering. Reject duplicate external keys within one namespace, self-parenting, unknown parents, depth overflow, multiple roots, disconnected components, assignment mismatch, missing/wrong-root/wrong-parent handoff lineage, and evidence identity conflicts. Emit stable finding codes without embedding external keys in diagnostics.

- [ ] **Step 5: Run GREEN and lineage regression**

```bash
python -m pytest -q tests/contract/test_work_scope.py tests/contract/test_scope_evidence_merge.py tests/property/test_work_scope_graph.py tests/security/test_scope_provenance.py
python -m pytest -q tests/contract/test_assignment.py tests/contract/test_assignment_result.py tests/integration/test_assignment_acceptance.py
python -m mypy src/agent_continuity/kernel
python -m ruff check src/agent_continuity/kernel tests/contract tests/property tests/security
```

Expected: all graph mutants—cycle, orphan, depth, collapsed provenance, and mismatched assignment—are killed.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/kernel/context.py src/agent_continuity/kernel/context_evaluation.py src/agent_continuity/kernel/lineage.py
git add schemas/v1/work-scope.schema.json tests/contract/test_work_scope.py tests/contract/test_scope_evidence_merge.py tests/property/test_work_scope_graph.py tests/security/test_scope_provenance.py
git commit -m "feat: preserve nested context provenance"
```

---

### Task 6: Expose generic integration contract and aggregate acceptance gate

**Files:**

- Create: `docs/context-continuity.md`
- Modify: `docs/plans/2026-08-08-04-hardening-release.md`
- Modify: `src/agent_continuity/adapters/json.py`
- Modify: `schemas/v1/external-event-request.schema.json`
- Create: `schemas/v1/context-adapter-capabilities.schema.json`
- Create: `tests/contract/test_context_external_event.py`
- Create: `tests/contract/test_context_adapter_capabilities.py`
- Create: `tests/integration/test_context_json_boundary.py`
- Create: `tests/integration/test_context_adapter_flow.py`
- Create: `tests/security/test_context_external_poisoning.py`
- Create: `tests/fixtures/context-continuity-benchmark-v1.jsonl`
- Modify: `tools/benchmark_context_continuity.py`
- Modify: `tools/verify_release.py`

**Interfaces:**

The Hardening Plan extends `ExternalEventRequestV1` with these closed event types:

```python
class ContextExternalEventType(StrEnum):
    OBSERVE = "context.observe"
    PREPARE = "context.prepare"
    REHYDRATE = "context.rehydrate"
    STATUS = "context.status"


@dataclass(frozen=True, slots=True)
class ContextExternalEventV1:
    event_type: ContextExternalEventType
    transition_id: RecordId | None
    metrics: ContextMetricsV1 | None
    projection: ContextProjectionV1 | None
    destination_actor_id: RecordId | None


class ContextAdapterCapability(StrEnum):
    USAGE_TELEMETRY = "usage_telemetry"
    CREATE_SESSION = "create_session"
    INJECT_HANDOFF = "inject_handoff"
    BLOCK_SOURCE_CONTINUATION = "block_source_continuation"
    COLLECT_DESTINATION_PROJECTION = "collect_destination_projection"
    CLOSE_OR_ARCHIVE_SOURCE = "close_or_archive_source"
    ROLLBACK_TO_SOURCE = "rollback_to_source"


class CapabilityStatus(StrEnum):
    VERIFIED = "verified"
    MANUAL_ONLY = "manual_only"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ContextAdapterCapabilitiesV1:
    capabilities_id: RecordId
    adapter_id: str
    observed_at: LogicalTime
    statuses: tuple[tuple[ContextAdapterCapability, CapabilityStatus], ...]
    evidence_ids: tuple[RecordId, ...]
```

- [ ] **Step 1: Write the generic harness protocol**

Document the exact sequence:

```text
context.observe(metrics)
  -> CONTINUE | CHECKPOINT | COMPACT_OR_HANDOFF | BLOCK
context.prepare(kind, metrics)
  -> transition_id + retention_manifest + protected ResumeContext
harness compacts, restarts, or hands off outside ACG
context.rehydrate(transition_id, projection references)
  -> PASS/VERIFIED or UNKNOWN|BLOCK/REFUSED
context.status(transition_id)
  -> canonical receipt
```

State the automatic sequence: observe usage/probe; freeze canonical checkpoint; prepare without ending source; create destination; inject canonical handoff; collect destination projection; compare; append accepted meta-lineage; close/archive source only after VERIFIED. If destination acceptance fails, retain or roll back to the frozen source. A provider adapter must block ordinary continuation while a required transition is PREPARED, REFUSED, or EXPIRED. Adapter claims without a current live behavioral test are configuration evidence only. If any required capability is MANUAL_ONLY or UNAVAILABLE, ACG emits the handoff package and warning but never claims automatic handover; this is the required mode for closed chat applications without session APIs/hooks.

- [ ] **Step 2: Write failing capability, external-event schema, and poisoning tests**

Require every capability exactly once, current behavioral evidence for VERIFIED, canonical ordering, bounded adapter identity, and no provider-selected trust path or command. Automatic mode requires all seven capabilities VERIFIED; otherwise result is manual-only/unsupported with exact missing capabilities. Reject source-selected target/state/policy/ruleset/trust-root paths, commands, executables, hook names, adapter imports, raw prompts, transcripts, source excerpts, authority overrides, required-field overrides, and PASS/verdict fields. Structurally valid incomplete metrics or projections translate to UNKNOWN/BLOCK findings, not request exit 2. Unknown event type or malformed top-level schema exits 2.

- [ ] **Step 3: Run RED after Hardening Plan Task 1 is green**

```bash
python -m pytest -q tests/contract/test_context_adapter_capabilities.py tests/contract/test_context_external_event.py tests/integration/test_context_json_boundary.py tests/integration/test_context_adapter_flow.py tests/security/test_context_external_poisoning.py
```

Expected: generic JSON adapter does not yet translate context events.

- [ ] **Step 4: Implement data-only translation through existing facades**

Translation constructs validated immutable models and invokes `ContextContinuity`; it contains no threshold, comparison, authority, pruning, lineage, capability, or verdict policy. It never imports event-selected code, invokes a command, or reads an event-selected path. Capability qualification consumes only canonical evidence handles and exposes `automatic`, `manual_only`, or `unsupported`; it performs no provider action. Maximum external payload remains 8 MiB and depth/entry limits remain those defined by the Hardening Plan.

- [ ] **Step 5: Add aggregate release gates**

`tools/verify_release.py` must run every context contract, property, integration, security, crash, replay, schema, mypy, Ruff, target-read-only, installed-wheel, and benchmark test. Add planted omission, authority-broadening, stale-metric, same-fingerprint retry, wrong-actor, wrong-checkpoint, wrong-lineage, unsupported-capability, orphan-scope, and protected-pruning mutants. Require zero survivors.

It must invoke `tools/verify_context_defaults.py` against source and each installed artifact. The release report binds default generation 2 plus exact 2500/4000/5000 basis points and 16000/24000/32000 token ceilings. Missing, raised, source/wheel-divergent, or migration-unverified defaults fail the aggregate update/release gate.

Freeze a public synthetic benchmark with at least 100 seeded material continuity failures and 100 valid controls spanning required-ID omission, contradiction, authority broadening, stale evidence, actor/checkpoint/lineage substitution, below-threshold probe failure, and clean compaction/restart/handoff cases. `tools/benchmark_context_continuity.py` computes `detected_material_failures / seeded_material_failures` and `false_blocks / valid_controls` using integer counts. Pass requires detection >= 90% and false positives <= 5%. Report corpus version, counts, confusion matrix, and SHA-256; explicitly state that passing measures this frozen synthetic corpus only and is not evidence of universal real-world 90% prevention.

Every protected-field class also receives matched beginning/middle/end variants with one immutable base-case ID. Each position bin independently requires zero critical false-PASS, detection >= 90%, and false blocks <= 5%. A paired bootstrap over base-case IDs uses at least 10,000 replicates; the 95% lower bound for `middle macro-balanced accuracy - mean(beginning, end)` must be >= -0.02. The generator holds expected outcome, distractor multiset, logical workload, and resource budget constant and never exposes position labels or triplet relationships to the product under test.

- [ ] **Step 6: Run GREEN and full v0.1 regression**

```bash
python -m pytest -q
python -m mypy src/agent_continuity
python -m ruff check .
python tools/verify_schemas.py
python tools/verify_context_defaults.py
python tools/benchmark_context_continuity.py tests/fixtures/context-continuity-benchmark-v1.jsonl
python tools/verify_release.py
```

Expected: all commands exit 0; every context-continuity acceptance gate appears in the canonical release report; no target write occurs.

- [ ] **Step 7: Commit**

```bash
git add docs/context-continuity.md docs/plans/2026-08-08-04-hardening-release.md
git add src/agent_continuity/adapters/json.py schemas/v1/external-event-request.schema.json schemas/v1/context-adapter-capabilities.schema.json
git add tests/contract/test_context_adapter_capabilities.py tests/contract/test_context_external_event.py tests/integration/test_context_json_boundary.py tests/integration/test_context_adapter_flow.py tests/security/test_context_external_poisoning.py
git add tests/fixtures/context-continuity-benchmark-v1.jsonl tools/benchmark_context_continuity.py tools/verify_release.py
git commit -m "feat: expose generic context continuity boundary"
```

---

## Acceptance Matrix

| Gate | Evidence | Pass condition |
|---|---|---|
| Pure-kernel | import isolation and monkeypatch tests | No filesystem, database, clock, subprocess, environment, network, tokenizer, provider, or model access |
| Budget | threshold decision tables and boundary mutants | Exact 25/40/50% rendered ratios plus 16K/24K/32K cumulative ceilings, strongest-action precedence, reserve, turn, compaction-generation, and freshness behavior pass |
| Default update | canonical v2 golden, migration fixtures, source/wheel verifier | Generation 2 exact values survive every update; missing or raised built-in values fail closed; retired v1 sessions checkpoint and hand off before continuation |
| Calibration truth | policy identity and evidence tests | Seed policy reports PROVISIONAL_UNCALIBRATED; CALIBRATED requires exact current profile-bound behavioral evidence |
| Drift probe | canonical-ID challenge/response tests | Below-threshold omission, contradiction, substitution, or authority broadening cannot continue |
| Checkpoint completeness | projection contract tests | Every required protected field resolves to a verified canonical record |
| Context poison | hostile summary and external-event corpus | Narrative cannot create authority, remove blockers, fabricate evidence, or produce PASS |
| Rehydration | comparison and integration tests | Only exact protected continuity plus current evidence sets VERIFIED |
| Freshness | evidence/metric expiry tests | Expired or unavailable required proof never becomes PASS |
| Handoff | actor/checkpoint/target tests | Destination accepts exact verified envelope; prose acknowledgement fails |
| Meta-handoff | root/parent/actor/checkpoint/projection/time tests | Every accepted generation links to canonical lineage; no summary-of-summary state materialization |
| Retry | attempt and fingerprint tests | Three distinct attempts maximum; identical failure blocks immediately |
| Nested scopes | graph/property/security tests | Depth <= 8, acyclic lineage, accepted assignments, evidence provenance retained |
| Pruning | retention security tests | Protected IDs never prunable; only duplicate advisory digests may be pruned |
| Atomicity | crash/CAS/audit tests | Prepared/verified transition is fully committed or absent |
| Read-only | before/after target manifest | Target bytes, metadata, refs, index, config, hooks, and permissions are unchanged |
| Portability | installed-wheel matrix | Pure kernel/store/context logic passes on supported Python/macOS/Linux/Windows jobs; unsupported live capability is explicit UNKNOWN |
| Adapter capability | schema and live-evidence contract tests | Automatic mode requires all seven capabilities VERIFIED; otherwise manual-only/unsupported is explicit |
| Continuity benchmark | frozen corpus scorer | Detects >=90% seeded material failures with <=5% false positives and discloses synthetic-only scope |
| Release | `tools/verify_release.py` | All required suites pass, all mutants killed, schemas current, no surviving BLOCK/UNKNOWN gate |

## Rollout and Safe Stop

1. Land Tasks 1-3 behind direct Python APIs with no installed hooks or provider wiring.
2. Run existing checkpoint/resume/assignment suites after every task.
3. Land Tasks 4-5 only after atomic transition proof is green.
4. Add Task 6 to the Hardening Plan generic JSON integration; keep vendor adapters outside v0.1.
5. Before any future provider adapter can enforce continuation, require provider-native behavioral tests proving all seven adapter capabilities, PREPARED/REFUSED/BLOCK prevention of the next ordinary action, destination-session creation and injection, rollback on failed acceptance, and source close/archive only after VERIFIED.
6. Roll back by returning to the last verified package/ruleset generation and ignoring context event types at the external adapter. Existing checkpoints, audit events, and transition records remain append-only evidence.
7. Safe stop at any failing gate: retain current evidence, emit exact PASS/WARN/UNKNOWN/BLOCK plus finding codes, do not advance checkpoint or transition state, and require new evidence or an explicitly new authorized session decision.

## Self-Review Checklist

- [ ] Every user requirement maps to at least one task and acceptance gate.
- [ ] Context continuity remains outside `loop-engineering` and does not select loops.
- [ ] All named types and methods are defined before later tasks consume them.
- [ ] No placeholder, unspecified error handling, or generic “write tests” step remains.
- [ ] Context and model output remain untrusted data throughout.
- [ ] Missing proof is UNKNOWN/BLOCK, never PASS.
- [ ] Provider adapters remain deferred and require live behavioral evidence.
- [ ] Rendered usage, cumulative usage, compaction generation, and checkpoint age are never conflated.
- [ ] The 90% claim is limited to the frozen synthetic benchmark and never stated as universal prevention.
- [ ] Handoff materializes from canonical ledger records, never recursively from earlier summary prose.
- [ ] No implementation, hook, service, commit, publication, or target mutation is included in this planning change.
