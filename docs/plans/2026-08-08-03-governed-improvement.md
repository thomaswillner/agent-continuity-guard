# Governed Deterministic Improvement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retain verified failures, deterministically synthesize bounded additive rules, prove them against a trusted immutable corpus, and promote at most one eligible rule through atomic compare-and-swap before complete transition reevaluation.

**Architecture:** The pure `kernel` owns rule parsing, evaluation, mutation semantics, monotonicity, and verdict rank. The `improvement` package owns untrusted candidate synthesis, trusted-corpus assembly, clean-process proof orchestration, and the `PromotionGovernor` deep module. `store` persists immutable findings, candidates, decisions, proofs, and append-only ruleset generations; `Continuity` invokes automatic improvement only around protected state-changing transitions.

**Tech Stack:** Python 3.11+ standard-library runtime (`dataclasses`, `enum`, `hashlib`, `importlib.metadata`, `json`, `sqlite3`, `subprocess`, `tempfile`), pytest, Hypothesis, jsonschema, mypy, Ruff, build.

## Global Constraints

- Plans 1 and 2 must be green and committed before this plan starts.
- Licence is MIT; runtime dependencies remain zero.
- Default promotion mode is `automatic`; `review` and `disabled` remain explicit policy choices.
- Human approval is optional and cannot override failed or UNKNOWN machine proof.
- Learned rules are additive only and emit fixed WARN or BLOCK findings.
- Candidate rules are strict data. No Python, expression, template, callback, import, path read, environment read, clock, randomness, network, subprocess, suppression, exception, update, deletion, or target write is allowed.
- Corpus-label admission is a release-controlled trust-root action and has no runtime command or Python mutation interface.
- Pure `Continuity.verify` and `Continuity.resume` never persist Findings, synthesize durable candidates, evaluate promotion, change ruleset state, or append audit history.
- Protected checkpoint and result-acceptance operations persist or deduplicate every non-PASS Finding, even when checkpoint/result advancement is refused.
- One protected operation may commit at most one promotion, then must restart capture and complete evaluation under the new ruleset. It may not promote again during that operation.
- Verdict comparison uses `VERDICT_RANK`; direct relational comparison of `Verdict` StrEnum members is forbidden.
- Promotion reloads stored authority by decision identifier and revalidates expected ruleset and audit heads at commit time.
- Editable, source-tree, missing-RECORD, or otherwise unverifiable installations may evaluate and report, but promotion is UNKNOWN.
- Targets remain read-only. No command modifies target content, Git refs, index, configuration, hooks, permissions, or application-controlled metadata.
- No private reference source, prose, names, paths, hashes, datasets, fixtures, or failure narratives enter code, tests, documentation, or Git history.
- No generic JSON adapter, vendor adapter, plugin discovery, hook installer, release publication, or remote action is added in this plan.

---

## File Map

- `src/agent_continuity/kernel/rules.py`: bounded Rule/v1 parser, compiler, evaluator, and resource limits.
- `src/agent_continuity/kernel/classification.py`: promotion-safe fact-field registry shared with Plan 4 export controls.
- `src/agent_continuity/kernel/monotonicity.py`: syntactic and semantic additive-only proof.
- `src/agent_continuity/improvement/synthesis.py`: fixed public-safe Finding-to-Candidate templates.
- `src/agent_continuity/improvement/corpus.py`: immutable cases and trusted label resolution.
- `src/agent_continuity/improvement/installation.py`: installed-wheel RECORD identity and assurance.
- `src/agent_continuity/improvement/mutations.py`: deterministic candidate mutant generation.
- `src/agent_continuity/improvement/proof.py`: gates 1-13 over one immutable PromotionSnapshot.
- `src/agent_continuity/improvement/worker.py`: isolated canonical proof worker.
- `src/agent_continuity/improvement/governor.py`: decision persistence, approval, commit-time gates, promotion, and rollback.
- `src/agent_continuity/store/base.py`: improvement transactions built on Plan 1 multi-head CAS.
- `src/agent_continuity/store/sqlite.py`: immutable catalogs, CAS generations, and readback verification.
- `src/agent_continuity/api.py`: protected-operation integration and one-promotion reevaluation loop.
- `src/agent_continuity/cli.py`: `acg improve` command adapter.
- `schemas/v1/`: Rule, CandidateRule, FindingCatalog, corpus, proof, decision, generation, approval, and receipt contracts.
- `tools/verify_release.py`: installed-wheel promotion proof entrypoint, extended by Plan 4.

### Task 1: Add the bounded additive Rule/v1 kernel

**Files:**

- Create: `src/agent_continuity/kernel/rules.py`
- Create: `src/agent_continuity/kernel/classification.py`
- Modify: `src/agent_continuity/kernel/evaluation.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Create: `schemas/v1/fact-schema-registry.schema.json`
- Create: `schemas/v1/rule.schema.json`
- Create: `tests/contract/test_rule_v1.py`
- Create: `tests/contract/test_rule_evaluation.py`
- Create: `tests/property/test_rule_determinism.py`
- Create: `tests/golden/rule-v1.json`

**Interfaces:**

```python
class RuleOperator(StrEnum):
    EQ = "eq"
    IN = "in"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    GTE = "gte"
    LTE = "lte"
    PRESENT = "present"
    ABSENT = "absent"


class FieldClass(StrEnum):
    PUBLIC = "public"
    SENSITIVE_LOCAL = "sensitive_local"
    SENSITIVE_HASH = "sensitive_hash"
    FORBIDDEN = "forbidden"


@dataclass(frozen=True, slots=True)
class FactFieldDefinitionV1:
    field_path: tuple[str, ...]
    value_type: str
    classification: FieldClass
    allowed_for_rules: bool


@dataclass(frozen=True, slots=True)
class RulePredicateV1:
    field_path: tuple[str, ...]
    operator: RuleOperator
    operands: tuple[JsonScalar, ...]


@dataclass(frozen=True, slots=True)
class RuleV1:
    rule_id: RecordId
    predicates: tuple[RulePredicateV1, ...]
    verdict: Verdict
    code: str
    message_id: str


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    findings: tuple[Finding, ...]
    exhausted: bool
    unknown_code: str | None


FactIndex = Mapping[tuple[str, ...], JsonScalar]


@dataclass(frozen=True, slots=True)
class LearnedRuleInput:
    facts: FactIndex
    active_rules: tuple[RuleV1, ...]


def compile_rule(rule: RuleV1) -> RuleV1: ...
def evaluate_rules(
    rules: Sequence[RuleV1],
    facts: FactIndex,
) -> RuleEvaluation: ...
```

- [ ] **Step 1: Write failing strict-grammar tests**

Cover every allowed operator and reject `any`, `not`, `ne`, regex, glob, recursion, expression, template, import, callback, executable text, unknown fields, PASS/UNKNOWN output, empty predicate lists, duplicate predicates, noncanonical ordering, unregistered fact paths, and fields not marked `allowed_for_rules`.

Exact limits:

```python
MAX_RULE_BYTES = 16 * 1024
MAX_PREDICATES = 16
MAX_FIELD_SEGMENTS = 8
MAX_IDENTIFIER_CHARS = 64
MAX_LITERAL_BYTES = 256
MAX_IN_VALUES = 32
MAX_ACTIVE_RULES = 4_096
MAX_PREDICATE_EVALUATIONS = 65_536
```

`present` and `absent` require zero operands; `in` requires 1-32 scalar operands; every other operator requires exactly one operand. `prefix` and `suffix` require strings. `gte` and `lte` require integers and must reject booleans.

- [ ] **Step 2: Run RED**

```bash
python -m pytest -q tests/contract/test_rule_v1.py tests/contract/test_rule_evaluation.py
```

Expected: collection fails because `agent_continuity.kernel.rules` does not exist.

- [ ] **Step 3: Implement strict compilation and conjunction evaluation**

Compile validates canonical rule size, ASCII identifiers, bounds, operand shape, fixed message/code, WARN/BLOCK output, and exact membership in the identity-bound fact-schema registry. Only PUBLIC and SENSITIVE_HASH fields explicitly marked `allowed_for_rules` may appear. SENSITIVE_LOCAL and FORBIDDEN fields cannot enter candidate predicates.

Evaluation traverses only the supplied immutable `FactIndex`, evaluates predicates in canonical order, and emits one Finding only when every predicate matches. Extend the existing EvaluationCase with one `LearnedRuleInput`; `kernel.evaluate` merges learned-rule Findings with built-in, evidence, and lineage Findings before the existing profile aggregation.

When active-rule or predicate-evaluation limits are exceeded, return `exhausted=True`, no learned PASS result, and stable code `rule.resource_limit_unknown`.

- [ ] **Step 4: Add deterministic and schema parity tests**

Permute input rule, predicate, and fact order and require byte-identical output. Validate produced Rule/v1 and Ruleset/v1 records against strict schemas; added unknown fields must fail.

- [ ] **Step 5: Run GREEN**

```bash
python -m pytest -q tests/contract/test_rule_v1.py tests/contract/test_rule_evaluation.py tests/property/test_rule_determinism.py tests/golden
python -m mypy src/agent_continuity/kernel
python -m ruff check src/agent_continuity/kernel tests/contract tests/property tests/golden
python tools/verify_schemas.py
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/kernel/rules.py src/agent_continuity/kernel/classification.py src/agent_continuity/kernel/evaluation.py src/agent_continuity/kernel/records.py
git add schemas/v1/fact-schema-registry.schema.json schemas/v1/rule.schema.json
git add tests/contract/test_rule_v1.py tests/contract/test_rule_evaluation.py tests/property/test_rule_determinism.py tests/golden/rule-v1.json
git commit -m "feat: add bounded additive rule kernel"
```

### Task 2: Persist Findings and deterministically synthesize candidates

**Files:**

- Create: `src/agent_continuity/improvement/__init__.py`
- Create: `src/agent_continuity/improvement/synthesis.py`
- Modify: `src/agent_continuity/kernel/rules.py`
- Modify: `src/agent_continuity/kernel/findings.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `schemas/v1/finding.schema.json`
- Modify: `schemas/v1/evaluation-result.schema.json`
- Create: `schemas/v1/persisted-finding.schema.json`
- Create: `schemas/v1/finding-catalog.schema.json`
- Create: `schemas/v1/candidate-rule.schema.json`
- Create: `schemas/v1/candidate-catalog.schema.json`
- Create: `tests/contract/test_persisted_finding.py`
- Create: `tests/contract/test_candidate_synthesis.py`
- Create: `tests/integration/test_finding_persistence.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    verdict: Verdict
    subject_id: RecordId
    message_id: str
    parameters: JsonObject
    detector_id: str
    rule_id: RecordId | None
    evidence_ids: tuple[RecordId, ...]
    invalidation_ids: tuple[RecordId, ...]
    violation_fingerprint: Digest
    integrity_failure: bool = False


@dataclass(frozen=True, slots=True)
class PersistedFindingV1:
    finding_id: RecordId
    detector_id: str
    rule_id: RecordId | None
    subject_id: RecordId
    verdict: Verdict
    evidence_ids: tuple[RecordId, ...]
    invalidation_ids: tuple[RecordId, ...]
    violation_fingerprint: Digest
    policy_id: RecordId
    message_id: str
    parameters: JsonObject


@dataclass(frozen=True, slots=True)
class FindingCatalogV1:
    catalog_id: RecordId
    finding_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class CandidateRuleV1:
    candidate_id: RecordId
    source_finding_ids: tuple[RecordId, ...]
    rule: RuleV1
    synthesizer_id: str
    synthesizer_version: str


class CandidateState(StrEnum):
    QUARANTINED = "quarantined"
    VALIDATED = "validated"
    PROVEN = "proven"
    ELIGIBLE = "eligible"
    AWAITING_APPROVAL = "awaiting_approval"
    PROMOTED = "promoted"
    REJECTED = "rejected"
    DEFERRED_UNKNOWN = "deferred_unknown"


@dataclass(frozen=True, slots=True)
class CandidateCatalogEntryV1:
    candidate_id: RecordId
    state: CandidateState
    latest_decision_id: RecordId | None


@dataclass(frozen=True, slots=True)
class CandidateCatalogV1:
    catalog_id: RecordId
    entries: tuple[CandidateCatalogEntryV1, ...]


@dataclass(frozen=True, slots=True)
class ImprovementInputReceipt:
    finding_catalog_id: RecordId
    candidate_catalog_id: RecordId
    audit_event_id: RecordId
    audit_sequence: int


class CandidateSynthesizer:
    def synthesize(
        self,
        findings: Sequence[PersistedFindingV1],
    ) -> tuple[CandidateRuleV1, ...]: ...


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    verdict: Verdict
    transition_allowed: bool
    findings: tuple[Finding, ...]
    candidates: tuple[CandidateRuleV1, ...] = ()
```

Store seam:

```python
def persist_improvement_inputs(
    self,
    *,
    findings: Sequence[PersistedFindingV1],
    candidates: Sequence[CandidateRuleV1],
    expected_checkpoint_head: RecordId,
    expected_ruleset_head: RecordId,
    expected_finding_head: RecordId | None,
    expected_candidate_head: RecordId | None,
    expected_audit_head: RecordId,
    logical_time: LogicalTime,
) -> ImprovementInputReceipt: ...
```

- [ ] **Step 1: Write failing Finding identity and deduplication tests**

Extend the Plan 1 Finding shape with normalized detector/rule/evidence/invalidation/fingerprint fields shown above. Prove the persisted identity key is detector, normalized subject, violation fingerprint, and exact Policy/v1 ID. Repeated equivalent findings deduplicate; a changed policy ID, subject, or fingerprint produces a distinct Finding. PASS is never persisted. Parameters must already be secret-safe canonical data.

- [ ] **Step 2: Write failing deterministic synthesis tests**

`CandidateRuleV1` is a strict declarative kernel record defined beside Rule/v1, so `EvaluationResult.candidates` does not import the `improvement` package. Provide fixed built-in synthesis templates for these generic normalized findings:

```text
evidence.command.terminal_status_missing
  -> absent(evidence.terminal_status), BLOCK

evidence.command.zero_checks
  -> lte(evidence.check_count, 0), BLOCK

evidence.pagination.incomplete
  -> eq(evidence.pagination_complete, false), BLOCK
```

Template output uses fixed field paths, literals, codes, messages, and severities. Finding narrative and arbitrary parameters cannot choose field paths, operators, severity, or message IDs. Unsupported finding codes produce no candidate. Permuted duplicate Findings produce one byte-identical CandidateRule/v1.

- [ ] **Step 3: Run RED**

```bash
python -m pytest -q tests/contract/test_persisted_finding.py tests/contract/test_candidate_synthesis.py tests/integration/test_finding_persistence.py
```

Expected: persistence and synthesis interfaces are absent.

- [ ] **Step 4: Implement immutable catalogs through existing multi-head CAS**

Use Plan 1 `commit_many` to insert immutable Findings/Candidates, create canonically sorted FindingCatalog/v1 and CandidateCatalog/v1 records, append one audit event, and compare checkpoint, ruleset, candidate, finding, and audit heads under `BEGIN IMMEDIATE`.

An exact duplicate batch with unchanged catalogs is idempotent and appends no audit event. A record ID with different canonical bytes is integrity exit 3.

- [ ] **Step 5: Integrate state-changing Finding retention without promotion**

After a valid initialized session performs any state-changing evaluation—Continuity checkpoint/delegate/result acceptance, Assignment checkpoint/completion, or an explicit improve transition—convert every non-PASS Finding into PersistedFinding/v1 and call `persist_improvement_inputs`, whether or not protected advancement is allowed. Include synthesized candidates as QUARANTINED catalog entries. Request/schema errors that never form an EvaluationResult are not Findings.

`Continuity.verify` returns the same ephemeral Findings and deterministic candidate suggestions through `EvaluationResult.candidates` but does not call the store persistence path. `Continuity.resume` remains read-only and does not synthesize candidates. Pre-genesis initialization failures remain returned-only because no authoritative session/policy generation exists.

- [ ] **Step 6: Run GREEN and failure-recovery tests**

```bash
python -m pytest -q tests/contract/test_persisted_finding.py tests/contract/test_candidate_synthesis.py tests/integration/test_finding_persistence.py
python -m pytest -q tests/integration/test_verify.py tests/integration/test_assignment_acceptance.py
python -m mypy src/agent_continuity
python -m ruff check src/agent_continuity tests/contract tests/integration
```

Expected: every initialized state-changing EvaluationResult retains/deduplicates non-PASS Findings; pure verify and resume leave SQLite bytes and every head unchanged.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/improvement src/agent_continuity/kernel/rules.py src/agent_continuity/kernel/findings.py src/agent_continuity/kernel/records.py
git add src/agent_continuity/store/base.py src/agent_continuity/store/sqlite.py src/agent_continuity/api.py
git add schemas/v1/finding.schema.json schemas/v1/evaluation-result.schema.json schemas/v1/persisted-finding.schema.json schemas/v1/finding-catalog.schema.json
git add schemas/v1/candidate-rule.schema.json schemas/v1/candidate-catalog.schema.json
git add tests/contract/test_persisted_finding.py tests/contract/test_candidate_synthesis.py tests/integration/test_finding_persistence.py
git commit -m "feat: retain findings and synthesize candidates"
```

### Task 3: Bind installed identity, trust root, corpus, and ruleset generations

**Files:**

- Modify: `pyproject.toml`
- Create: `src/agent_continuity/improvement/installation.py`
- Create: `src/agent_continuity/improvement/corpus.py`
- Create: `src/agent_continuity/improvement/data/__init__.py`
- Create: `src/agent_continuity/improvement/data/public-corpus.json`
- Modify: `src/agent_continuity/kernel/records.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `schemas/v1/installed-distribution.schema.json`
- Create: `schemas/v1/trust-root.schema.json`
- Create: `schemas/v1/corpus-label.schema.json`
- Create: `schemas/v1/corpus-case.schema.json`
- Create: `schemas/v1/corpus-snapshot.schema.json`
- Create: `schemas/v1/ruleset-generation.schema.json`
- Create: `tests/contract/test_trust_root_v1.py`
- Create: `tests/contract/test_corpus_labels.py`
- Create: `tests/integration/test_installed_identity.py`
- Create: `tests/integration/test_ruleset_generation_head.py`

**Interfaces:**

```python
class InstallationAssurance(StrEnum):
    VERIFIED_WHEEL = "verified_wheel"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class InstalledDistributionV1:
    distribution_name: str
    version: str
    record_digest: Digest | None
    package_digest: Digest | None
    assurance: InstallationAssurance
    unknown_code: str | None


class CorpusLabelOrigin(StrEnum):
    KERNEL_ORACLE = "kernel_oracle"
    RELEASE_ADMITTED = "release_admitted"


@dataclass(frozen=True, slots=True)
class CorpusLabelV1:
    label_id: RecordId
    case_id: RecordId
    origin: CorpusLabelOrigin
    authority_id: RecordId
    independence_group: str
    expected_finding_ids: tuple[RecordId, ...]
    expected_verdict: Verdict
    provenance_digest: Digest


@dataclass(frozen=True, slots=True)
class CorpusCaseV1:
    case_id: RecordId
    facts: tuple[FactV1, ...]
    source_evidence_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class TrustRootV1:
    trust_root_id: RecordId
    installed_distribution_id: RecordId
    canonicalization_version: str
    hash_domain_version: str
    fact_schema_registry_digest: Digest
    dsl_grammar_digest: Digest
    verdict_semantics_digest: Digest
    promotion_semantics_digest: Digest
    trusted_corpus_label_ids: tuple[RecordId, ...]
    adapter_ids: tuple[str, ...]
    state_security_policy_digest: Digest


@dataclass(frozen=True, slots=True)
class CorpusSnapshotV1:
    corpus_id: RecordId
    case_ids: tuple[RecordId, ...]
    label_ids: tuple[RecordId, ...]
    corpus_root: Digest


@dataclass(frozen=True, slots=True)
class RulesetGenerationV1:
    generation_id: RecordId
    parent_generation_id: RecordId | None
    ruleset_id: RecordId
    source_decision_id: RecordId | None
    rollback_of_generation_id: RecordId | None
    logical_time: LogicalTime
```

- [ ] **Step 1: Write failing installed-distribution tests**

Build and install a wheel into an isolated virtual environment. Rehash the installed wheel `RECORD` plus every listed package file and require `VERIFIED_WHEEL`. Editable install, source-tree import, absent RECORD, path escape, missing listed file, or mismatched file digest returns `UNKNOWN` with a stable code and never eligibility.

- [ ] **Step 2: Write failing trust and corpus tests**

Only labels whose IDs are bound by TrustRoot/v1 are authoritative. Safe negative controls require a trusted authority and independence group distinct from candidate/proposer provenance and the positive fixture lineage. A proposer-created fixture, duplicated narrative, operator correction, or unbound label can keep a Candidate QUARANTINED but cannot satisfy positive, negative, boundary, or output-delta proof.

Corpus cases and labels are content-addressed, unique, canonically ordered, and complete. The synthetic public corpus contains one labelled positive, one independently labelled safe negative, one boundary negative per predicate, and baseline output labels. Configure setuptools package data and make source, wheel workers, and tests load the same `agent_continuity.improvement.data/public-corpus.json` through `importlib.resources`.

- [ ] **Step 3: Run RED**

```bash
python -m pytest -q tests/contract/test_trust_root_v1.py tests/contract/test_corpus_labels.py tests/integration/test_installed_identity.py tests/integration/test_ruleset_generation_head.py
```

Expected: installation, corpus, and generation interfaces are absent.

- [ ] **Step 4: Implement wheel identity and trusted label resolution**

Use `importlib.metadata.distribution("agent-continuity-guard")`, parse RECORD as data, reject absolute/escaping paths, and hash exact installed bytes. Never import modules selected by RECORD or candidate data.

Corpus resolution receives a TrustRoot/v1 value and refuses every unbound label. Do not expose `admit_label`, `trust_label`, or any equivalent runtime mutation function or CLI command.

- [ ] **Step 5: Establish append-only ruleset generation heads**

Initialization creates generation zero for the built-in Ruleset/v1 and atomically sets `session:{session_key}:ruleset`. For test stores created by pre-Plan-3 fixtures, one idempotent bootstrap transaction may create the same generation only when the checkpoint's ruleset rehashes and audit verification succeeds.

- [ ] **Step 6: Run GREEN**

```bash
python -m pytest -q tests/contract/test_trust_root_v1.py tests/contract/test_corpus_labels.py tests/integration/test_installed_identity.py tests/integration/test_ruleset_generation_head.py
python tools/verify_schemas.py
python -m mypy src/agent_continuity/improvement src/agent_continuity/store
python -m ruff check src/agent_continuity tests/contract tests/integration
```

Expected: all commands exit 0; editable/source installs report UNKNOWN; no runtime corpus-label admission seam exists.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/agent_continuity/improvement/installation.py src/agent_continuity/improvement/corpus.py src/agent_continuity/improvement/data
git add src/agent_continuity/kernel/records.py src/agent_continuity/api.py src/agent_continuity/store
git add schemas/v1/installed-distribution.schema.json schemas/v1/trust-root.schema.json
git add schemas/v1/corpus-label.schema.json schemas/v1/corpus-case.schema.json schemas/v1/corpus-snapshot.schema.json schemas/v1/ruleset-generation.schema.json
git add tests/contract/test_trust_root_v1.py tests/contract/test_corpus_labels.py tests/integration/test_installed_identity.py tests/integration/test_ruleset_generation_head.py
git commit -m "feat: bind trusted corpus and ruleset generations"
```

### Task 4: Prove candidate behavior, mutants, replay, and monotonicity

**Files:**

- Create: `src/agent_continuity/kernel/monotonicity.py`
- Create: `src/agent_continuity/improvement/mutations.py`
- Create: `src/agent_continuity/improvement/secret_check.py`
- Create: `src/agent_continuity/improvement/proof.py`
- Create: `schemas/v1/promotion-snapshot.schema.json`
- Create: `schemas/v1/promotion-proof-draft.schema.json`
- Create: `tests/contract/test_promotion_gate_table.py`
- Create: `tests/contract/test_monotonicity.py`
- Create: `tests/property/test_candidate_mutations.py`
- Create: `tests/property/test_corpus_replay.py`
- Create: `tests/security/test_candidate_secret_check.py`

**Interfaces:**

```python
class GateOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class GateResultV1:
    gate_number: int
    code: str
    outcome: GateOutcome
    evidence_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class PromotionSnapshot:
    snapshot_id: RecordId
    candidate: CandidateRuleV1
    baseline_generation_id: RecordId
    baseline_ruleset: RulesetV1
    corpus: CorpusSnapshotV1
    trust_root: TrustRootV1
    installed_distribution: InstalledDistributionV1
    target_id: RecordId
    evidence_ids: tuple[RecordId, ...]
    policy_id: RecordId
    logical_time: LogicalTime
    capability_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class PromotionProofDraftV1:
    draft_id: RecordId
    snapshot_id: RecordId
    gate_results_1_to_11: tuple[GateResultV1, ...]
    gate_13_result: GateResultV1
    baseline_output_digest: Digest
    candidate_output_digest: Digest
    mutant_ids: tuple[RecordId, ...]
    killed_mutant_ids: tuple[RecordId, ...]


def prove_candidate(snapshot: PromotionSnapshot) -> PromotionProofDraftV1: ...
def prove_monotonicity(
    baseline: Sequence[EvaluationResult],
    candidate: Sequence[EvaluationResult],
    labels: Sequence[CorpusLabelV1],
) -> GateResultV1: ...
```

- [ ] **Step 1: Write the complete gates 1-11 and gate-13 input decision tables**

Cover strict parse/schema/size, authority confinement, rule/candidate dedup, target/evidence identity, authoritative failure provenance, positive reproduction, safe and per-predicate boundary negatives, candidate-removal mutation, operator/literal/severity mutants, complete corpus replay, syntactic monotonicity, semantic monotonicity, installed assurance, and secret/data classification. The draft carries gates 1-11 plus a precomputed gate-13 result; Task 5 inserts gate 12 between them only after two complete worker bytes match.

Every deterministic failure yields REJECTED input status. Missing, unstable, unsupported, incomplete, or ambiguous proof yields DEFERRED_UNKNOWN input status. Gate execution stops at first non-PASS but retains stable results for all gates already executed.

- [ ] **Step 2: Write failing mutation tests**

For each predicate generate deterministic, unique, non-equivalent operator and literal mutants plus one candidate-removal mutant. Generate WARN for a BLOCK severity-downgrade mutant and forbidden PASS for a WARN severity-downgrade mutant; strict parsing must kill the latter. Require 100 percent generated-mutant kill rate. If no valid non-equivalent mutant can be generated, proof is UNKNOWN rather than silently omitting it.

- [ ] **Step 3: Write failing monotonicity tests using verdict ranks**

```python
def assert_not_weaker(before: Verdict, after: Verdict) -> None:
    assert VERDICT_RANK[after] >= VERDICT_RANK[before]
```

Prove one added content-addressed rule, unchanged existing rule bytes, preserved existing Findings by complete content-addressed Finding ID or full semantic key, no severity decrease, preserved UNKNOWN reasons, only independently labelled output deltas, and nondecreasing enforcement rank. Never collapse Findings into a mapping keyed only by code because one code may apply to multiple subjects. Add a regression test that would fail if code uses `after >= before` directly on StrEnum values.

- [ ] **Step 4: Run RED**

```bash
python -m pytest -q tests/contract/test_promotion_gate_table.py tests/contract/test_monotonicity.py tests/property/test_candidate_mutations.py tests/property/test_corpus_replay.py tests/security/test_candidate_secret_check.py
```

Expected: proof, mutation, and monotonicity modules are absent.

- [ ] **Step 5: Implement deterministic gates and secret-safe failure output**

Evaluate exact immutable corpus cases under baseline and baseline-plus-candidate. Match output to trusted labels, reject unlabelled deltas, and compare severity only through `VERDICT_RANK`.

Candidate secret scanning is defense-in-depth after schema classification. On suspected secret, return code `promotion.candidate_secret_rejected` without echoing the matched value, source string, or surrounding bytes.

- [ ] **Step 6: Run GREEN and planted-mutant proof**

```bash
python -m pytest -q tests/contract/test_promotion_gate_table.py tests/contract/test_monotonicity.py tests/property/test_candidate_mutations.py tests/property/test_corpus_replay.py tests/security/test_candidate_secret_check.py
python -m pytest -q tests/property/test_candidate_mutations.py -k planted
python -m mypy src/agent_continuity/kernel src/agent_continuity/improvement
python -m ruff check src/agent_continuity tests/contract tests/property tests/security
```

Expected: all commands exit 0 and every planted weakening mutant is killed.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/kernel/monotonicity.py src/agent_continuity/improvement
git add schemas/v1/promotion-snapshot.schema.json schemas/v1/promotion-proof-draft.schema.json
git add tests/contract/test_promotion_gate_table.py tests/contract/test_monotonicity.py
git add tests/property/test_candidate_mutations.py tests/property/test_corpus_replay.py tests/security/test_candidate_secret_check.py
git commit -m "feat: prove candidate safety and monotonicity"
```

### Task 5: Produce byte-identical decisions in two clean processes

**Files:**

- Create: `src/agent_continuity/improvement/worker.py`
- Create: `src/agent_continuity/improvement/process.py`
- Create: `src/agent_continuity/improvement/governor.py`
- Create: `schemas/v1/promotion-evaluation.schema.json`
- Create: `schemas/v1/promotion-proof.schema.json`
- Create: `schemas/v1/promotion-decision.schema.json`
- Create: `schemas/v1/promotion-stage-receipt.schema.json`
- Create: `tests/contract/test_promotion_decision.py`
- Create: `tests/integration/test_double_evaluation.py`
- Create: `tests/security/test_promotion_worker_isolation.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class PromotionEvaluationV1:
    snapshot_id: RecordId
    proof_draft: PromotionProofDraftV1
    proposed_ruleset_id: RecordId | None
    deterministic_state: CandidateState


@dataclass(frozen=True, slots=True)
class PromotionDecisionV1:
    decision_id: RecordId
    snapshot_id: RecordId
    candidate_id: RecordId
    baseline_generation_id: RecordId
    proposed_ruleset_id: RecordId | None
    proof_id: RecordId | None
    state: CandidateState
    verdict: Verdict
    gate_results: tuple[GateResultV1, ...]


@dataclass(frozen=True, slots=True)
class PromotionProofV1:
    proof_id: RecordId
    snapshot_id: RecordId
    draft_id: RecordId
    gate_results: tuple[GateResultV1, ...]
    worker_evaluation_digest: Digest


@dataclass(frozen=True, slots=True)
class PromotionStageReceipt:
    decision: PromotionDecisionV1
    post_stage_ruleset_head: RecordId
    post_stage_audit_head: RecordId


class PromotionGovernor:
    def preview(
        self,
        snapshot: PromotionSnapshot,
    ) -> PromotionDecisionV1: ...

    def evaluate(
        self,
        snapshot: PromotionSnapshot,
    ) -> PromotionDecisionV1: ...


class StateStore(Protocol):
    def load_promotion_stage(
        self,
        decision_id: RecordId,
    ) -> PromotionStageReceipt: ...
```

- [ ] **Step 1: Write failing clean-process identity tests**

Run the same snapshot twice through separate processes and require exact canonical PromotionEvaluation/v1 bytes. Change wheel digest, snapshot, corpus, policy, logical time, locale, inherited environment, or worker output and require UNKNOWN or mismatch. No process result may include a timestamp read from ambient time. `PromotionGovernor.preview` must leave SQLite bytes and every head unchanged.

- [ ] **Step 2: Write failing isolation tests**

Worker command is exactly the current verified interpreter with `-I -m agent_continuity.improvement.worker`. Use a sanitized environment with fixed `LC_ALL=C`, `TZ=UTC`, and `PYTHONHASHSEED=0`; a fresh private temporary root; `close_fds=True`; bounded canonical stdin/stdout/stderr; no shell; and a timeout.

Install a worker audit hook that rejects network sockets, subprocess creation, environment reads outside the fixed allowlist, and writes outside its private temporary root. Any rejection produces UNKNOWN without leaking the attempted value.

- [ ] **Step 3: Run RED**

```bash
python -m pytest -q tests/contract/test_promotion_decision.py tests/integration/test_double_evaluation.py tests/security/test_promotion_worker_isolation.py
```

Expected: worker/process/governor modules are absent.

- [ ] **Step 4: Implement two-process evaluation and decision persistence**

Each worker canonical-loads PromotionSnapshot/v1, invokes only pure proof/kernel functions, and emits PromotionEvaluation/v1 containing gates 1-11 plus the candidate's gate-13 result. Parent compares complete bytes and verifies both embedded installed-distribution IDs. It creates PromotionProof/v1 ordered as gates 1-11, gate 12, then gate 13; gate 13 is authoritative only after gate 12 passes. `preview` performs this complete two-process evaluation without writing. `evaluate` repeats preview, requires byte-identical decision bytes, then stages that one decision.

Decision construction records the highest completed state deterministically: strict validation reaches VALIDATED; complete gates 1-11 reach PROVEN; matching gate 12 plus gate 13 reaches ELIGIBLE. Verdict mapping is ELIGIBLE/PROMOTED=PASS, QUARANTINED/VALIDATED/PROVEN/AWAITING_APPROVAL=WARN, DEFERRED_UNKNOWN=UNKNOWN, and REJECTED=BLOCK. This mapping never grants apply authority: only exact ELIGIBLE bytes may apply. Automatic policy retains ELIGIBLE for apply. Review policy maps machine-eligible bytes to AWAITING_APPROVAL. Disabled policy leaves candidate QUARANTINED and performs no apply. Apply alone records PROMOTED.

Persist snapshot, proof, and decision plus candidate-catalog state in one CAS audit transaction. `PromotionGovernor.evaluate` preserves the approved public interface and returns PromotionDecision/v1. Because staging appends audit history, the same transaction stores PromotionStageReceipt/v1 with the exact post-staging ruleset and audit heads; apply and protected orchestration reload it by decision ID. Exact already-current staging is idempotent. A caller must fresh-stage again after any intervening audit event before apply.

- [ ] **Step 5: Run GREEN**

```bash
python -m pytest -q tests/contract/test_promotion_decision.py tests/integration/test_double_evaluation.py tests/security/test_promotion_worker_isolation.py
python -m mypy src/agent_continuity/improvement
python -m ruff check src/agent_continuity/improvement tests/contract tests/integration tests/security
```

Expected: all commands exit 0; two clean processes produce identical bytes; changed or unverifiable inputs cannot become ELIGIBLE.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/improvement/worker.py src/agent_continuity/improvement/process.py src/agent_continuity/improvement/governor.py
git add schemas/v1/promotion-evaluation.schema.json schemas/v1/promotion-proof.schema.json schemas/v1/promotion-decision.schema.json schemas/v1/promotion-stage-receipt.schema.json
git add tests/contract/test_promotion_decision.py tests/integration/test_double_evaluation.py tests/security/test_promotion_worker_isolation.py
git commit -m "feat: evaluate promotions in clean processes"
```

### Task 6: Apply promotion with commit-time CAS and append-only rollback

**Files:**

- Modify: `src/agent_continuity/improvement/governor.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `schemas/v1/promotion-approval.schema.json`
- Create: `schemas/v1/promotion-receipt.schema.json`
- Create: `schemas/v1/rollback-cause.schema.json`
- Create: `schemas/v1/rollback-receipt.schema.json`
- Create: `tests/contract/test_review_approval.py`
- Create: `tests/integration/test_promotion_apply.py`
- Create: `tests/integration/test_ruleset_rollback.py`
- Create: `tests/security/test_promotion_cas.py`
- Create: `tests/security/test_promotion_crash.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class PromotionReceipt:
    decision_id: RecordId
    previous_generation_id: RecordId
    generation_id: RecordId
    ruleset_id: RecordId
    audit_event_id: RecordId
    audit_sequence: int
    readback_verified: bool


@dataclass(frozen=True, slots=True)
class PromotionApprovalV1:
    approval_id: RecordId
    candidate_id: RecordId
    awaiting_decision_id: RecordId
    approved_decision_digest: Digest
    actor_id: RecordId
    logical_time: LogicalTime


@dataclass(frozen=True, slots=True)
class RollbackCauseV1:
    cause_id: RecordId
    code: str
    actor_id: RecordId
    from_generation_id: RecordId
    to_ruleset_id: RecordId
    logical_time: LogicalTime


@dataclass(frozen=True, slots=True)
class RollbackReceipt:
    cause_id: RecordId
    previous_generation_id: RecordId
    generation_id: RecordId
    ruleset_id: RecordId
    audit_event_id: RecordId
    audit_sequence: int
    readback_verified: bool


class PromotionGovernor:
    def apply(
        self,
        decision_id: RecordId,
        expected_ruleset_head: RecordId,
        expected_audit_head: RecordId,
    ) -> PromotionReceipt: ...

    def approve(
        self,
        candidate_id: RecordId,
    ) -> PromotionReceipt: ...

    def rollback(
        self,
        to_ruleset_id: RecordId,
    ) -> RollbackReceipt: ...
```

- [ ] **Step 1: Write failing gates 14-16 and CAS tests**

Apply must reload the stored decision by ID; rehash decision/snapshot/proof/candidate/corpus/trust/policy/target/install identity; repeat current capability checks; compare exact ruleset and audit heads; append one generation; reopen; and verify records, generation head, and audit linkage.

Test stale target, corpus, trust root, policy, installed wheel, decision bytes, ruleset head, audit head, and competing promotions. A caller-supplied PromotionDecision object is ignored and cannot authorize commit.

- [ ] **Step 2: Write failing review-mode tests**

Failed or UNKNOWN decisions cannot be approved. Approval requires an actor ID authorized by the compiled policy and references exact AWAITING_APPROVAL decision and candidate bytes. `approve` records human approval as data, repeats complete machine evaluation, and applies only the new byte-identical ELIGIBLE decision through the same `apply` path. Changed input restarts proof and cannot reuse approval.

- [ ] **Step 3: Write failing crash and rollback tests**

Inject faults after records, after audit, after ruleset head, before commit, after commit, and during readback. Reopen and prove complete old or complete new generation; no mixed ruleset/audit state is accepted.

Rollback accepts only a previously verified Ruleset/v1 in the same generation chain and an actor authorized by compiled operator policy. It creates a new RulesetGeneration/v1 referencing the prior head and `rollback_of_generation_id`, records a structured RollbackCause/v1 with code `operator_requested`, and appends an audit event. It never deletes, edits, or rewinds prior generations. Automatic candidate code cannot call rollback.

- [ ] **Step 4: Run RED**

```bash
python -m pytest -q tests/contract/test_review_approval.py tests/integration/test_promotion_apply.py tests/integration/test_ruleset_rollback.py tests/security/test_promotion_cas.py tests/security/test_promotion_crash.py
```

Expected: apply, approval, rollback, or multi-head promotion transactions are absent.

- [ ] **Step 5: Implement commit-time revalidation and atomic generation commit**

Construct baseline-plus-one-rule Ruleset/v1 and a child RulesetGeneration/v1. Under `BEGIN IMMEDIATE`, repeat expected-head comparison, insert immutable records, append event, update candidate and ruleset heads, commit, reopen, and execute gates 15-16. A committed generation is reported only after readback and audit verification.

If commit outcome cannot be established, return integrity exit 3 and keep protected operations blocked. Do not append a speculative weakening generation.

- [ ] **Step 6: Run GREEN**

```bash
python -m pytest -q tests/contract/test_review_approval.py tests/integration/test_promotion_apply.py tests/integration/test_ruleset_rollback.py tests/security/test_promotion_cas.py tests/security/test_promotion_crash.py
python -m pytest -q tests/integration/test_sqlite_store.py tests/security/test_audit_tamper.py
python -m mypy src/agent_continuity/improvement src/agent_continuity/store
python -m ruff check src/agent_continuity tests/contract tests/integration tests/security
```

Expected: all commands exit 0; only one CAS winner promotes; rollback history is append-only; review cannot override machine proof.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/improvement/governor.py src/agent_continuity/store/base.py src/agent_continuity/store/sqlite.py
git add schemas/v1/promotion-approval.schema.json schemas/v1/promotion-receipt.schema.json schemas/v1/rollback-cause.schema.json schemas/v1/rollback-receipt.schema.json
git add tests/contract/test_review_approval.py tests/integration/test_promotion_apply.py tests/integration/test_ruleset_rollback.py tests/security/test_promotion_cas.py tests/security/test_promotion_crash.py
git commit -m "feat: atomically promote and roll back generations"
```

### Task 7: Integrate automatic improvement and expose `acg improve`

**Files:**

- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/cli.py`
- Modify: `src/agent_continuity/output.py`
- Create: `tests/integration/test_automatic_promotion.py`
- Create: `tests/integration/test_accept_result_promotion.py`
- Create: `tests/integration/test_improve_cli.py`
- Create: `tests/property/test_one_promotion_bound.py`

**Commands:**

```text
acg improve evaluate CANDIDATE
acg improve apply CANDIDATE
acg improve approve CANDIDATE_ID
acg improve rollback --to RULESET_DIGEST
```

- [ ] **Step 1: Write failing automatic-mode tests**

Start from a trusted labelled corpus and a deterministic Finding. Require checkpoint and result acceptance to retain/deduplicate the Finding, synthesize a Candidate, obtain complete proof, promote it under default automatic policy, restart capture/evaluation from the beginning, and bind the resulting checkpoint to the new ruleset generation.

Negative cases cover untrusted label, missing negative, surviving mutant, unlabelled delta, weaker verdict, nondeterministic worker, suspected secret, stale head, and UNKNOWN capability. None may promote.

- [ ] **Step 2: Write the one-promotion bound tests**

```python
def run_protected_transition(...):
    promotion_committed = False
    while True:
        captured = capture_from_start()
        result = evaluate_complete_case(captured)
        persist_non_pass_findings_and_candidates(result)
        if promotion_committed:
            return finish_transition(result, captured)
        receipt = try_one_eligible_promotion(result)
        if receipt is None:
            return finish_transition(result, captured)
        promotion_committed = True
```

Instrument governor calls and prove one operation applies zero or one promotion, never two, even when complete reevaluation exposes another eligible candidate. Prove second pass repeats store verification, Snapshot A/B, evidence collection, kernel evaluation, Finding retention, and Snapshot C before advancement. If reevaluation later refuses checkpoint/result advancement, the committed additive generation remains; refusal cannot trigger automatic weakening rollback.

- [ ] **Step 3: Write failing pure-verify and policy-mode tests**

Pure verify may report non-PASS Findings and candidate suggestions but leaves checkpoint, finding, candidate, decision, ruleset, and audit heads plus SQLite digest unchanged. Review mode pauses at AWAITING_APPROVAL. Disabled mode performs no promotion evaluation or apply. Observe mode never bypasses promotion proof or integrity refusal.

- [ ] **Step 4: Run RED**

```bash
python -m pytest -q tests/integration/test_automatic_promotion.py tests/integration/test_accept_result_promotion.py tests/integration/test_improve_cli.py tests/property/test_one_promotion_bound.py
```

Expected: protected operations do not yet invoke governor and CLI commands are absent.

- [ ] **Step 5: Implement the bounded orchestration loop and CLI adapter**

Preview candidate snapshots without persistence, select the lowest canonical preview decision ID whose state is ELIGIBLE, then call `PromotionGovernor.evaluate` only for that selected snapshot. Require staged bytes to match preview, reload its PromotionStageReceipt/v1, and immediately call `apply` by decision ID plus the exact post-staging ruleset and audit heads. No other decision is staged between evaluate and apply. After a receipt, discard prior capture/evaluation objects and restart the complete protected operation once under the new generation.

`improve evaluate` stores a decision. `improve apply` performs fresh evaluation then applies in automatic mode. `improve approve` is available only in review mode and follows the approval path from Task 6. `improve rollback` resolves an exact previously verified ruleset ID and appends a generation. Canonical stdout never includes candidate-controlled raw values.

- [ ] **Step 6: Run GREEN and regress earlier slices**

```bash
python -m pytest -q tests/integration/test_automatic_promotion.py tests/integration/test_accept_result_promotion.py tests/integration/test_improve_cli.py tests/property/test_one_promotion_bound.py
python -m pytest -q tests/contract tests/integration tests/security tests/property tests/golden
python -m mypy src/agent_continuity
python -m ruff check .
python tools/verify_schemas.py
```

Expected: all commands exit 0; default automatic mode promotes one eligible additive rule; complete reevaluation occurs; pure verify stays byte-for-byte store-read-only.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/api.py src/agent_continuity/cli.py src/agent_continuity/output.py
git add tests/integration/test_automatic_promotion.py tests/integration/test_accept_result_promotion.py tests/integration/test_improve_cli.py tests/property/test_one_promotion_bound.py
git commit -m "feat: integrate automatic governed improvement"
```

### Task 8: Prove governed improvement from an installed wheel

**Files:**

- Create: `tools/verify_release.py`
- Create: `tests/integration/test_installed_wheel_promotion.py`
- Create: `tests/security/test_improvement_target_read_only.py`
- Modify: `README.md`
- Modify: `PROVENANCE.md`

- [ ] **Step 1: Write failing installed-wheel promotion test**

Build a wheel, install it into a new virtual environment, create a synthetic immutable target and trusted public corpus, run `acg improve evaluate`, automatic apply, complete reevaluation, audit verification, and append-only rollback. Assert imports and worker subprocesses resolve only from the installed wheel.

- [ ] **Step 2: Write failing target and secret invariance tests**

Snapshot target content, refs, index, status, config, hooks, modes, and application metadata before every improve command. Require exact equality after success, rejection, UNKNOWN, crash injection, and rollback. Search every surface for planted FORBIDDEN values. Search identity-bearing records, canonical stdout, stderr, audit records, proposal envelopes, and exported receipts for planted SENSITIVE_LOCAL values; they may exist only in the protected local-value rows introduced by the frozen v0.1 store schema.

- [ ] **Step 3: Implement the Plan 3 release verifier**

`tools/verify_release.py` uses argv-only `subprocess.run(shell=False, check=False)`, executes the installed-wheel promotion smoke, complete promotion gate table, generated-mutant suite, two-process equality, CAS/crash suite, audit verification, target-read-only suite, mypy, Ruff, schema verification, and package build. It returns nonzero if any command fails and emits one canonical summary without raw captured output.

Plan 4 extends this verifier with platform matrix, coverage, provenance, SBOM, reproducible-build, and public-release checks.

- [ ] **Step 4: Run full Plan 3 validation**

```bash
python -m pytest -q tests/contract tests/integration tests/security tests/property tests/golden
python -m mypy src/agent_continuity
python -m ruff check .
python tools/verify_schemas.py
python -m build
python tools/verify_release.py --scope governed-improvement
```

Expected: all commands exit 0; generated mutant kill rate is 100 percent; two clean-process decisions match; installed-wheel promotion and rollback pass.

- [ ] **Step 5: Commit**

```bash
git add tools/verify_release.py tests/integration/test_installed_wheel_promotion.py tests/security/test_improvement_target_read_only.py
git add README.md PROVENANCE.md
git commit -m "test: prove governed improvement from wheel"
git status --short
```

Expected: status is clean.

## Plan Completion Gate

Run:

```bash
python -m pytest -q tests/contract tests/integration tests/security tests/property tests/golden
python -m mypy src/agent_continuity
python -m ruff check .
python tools/verify_schemas.py
python -m build
python tools/verify_release.py --scope governed-improvement
git status --short
```

Plan 3 is complete only when every state-changing non-PASS evaluation in an initialized session persists or deduplicates Findings; the fixed synthesizer emits only bounded declarative candidates; untrusted corpus labels confer no authority; all sixteen ordered promotion gates pass for an eligible rule; default automatic mode commits at most one additive rule and completely reevaluates checkpoint/result acceptance; review cannot override proof; pure verify remains store-read-only; generation rollback is append-only; installed-wheel decisions are byte-identical across two clean processes; target manifests remain unchanged; and final Git status is clean.
