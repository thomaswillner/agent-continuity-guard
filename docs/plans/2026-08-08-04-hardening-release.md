# Integration, Hardening, and Public Release Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add vendor-neutral JSON evidence ingestion, enforce field-level privacy, prove truthful cross-platform capability behavior under adversarial conditions, and produce reproducible public-release artifacts with complete local and CI gates.

**Architecture:** The generic JSON adapter translates bounded untrusted input into existing kernel models without owning policy. A shared classification registry controls canonical output, audit, proposal, and portable export. Capture/store adapters report proved capabilities; the pure kernel converts missing capability into UNKNOWN. Independent hardening and release modules verify target-read-only behavior, transactional recovery, provenance, reproducible artifacts, SBOM, installed-package behavior, and aggregate CI status.

**Tech Stack:** Python 3.11-3.14, standard-library runtime, pytest, Hypothesis, coverage.py, jsonschema, mypy, Ruff, build, pip-audit, GitHub Actions, SPDX 2.3 JSON.

## Global Constraints

- Plans 1-3 must be green and committed before this plan starts.
- Licence is MIT; mandatory runtime dependencies remain zero.
- Generic integration is vendor-neutral. No Codex, Claude Code, GitHub Actions, Gemini, OpenClaw, IDE, browser, Slack, MCP, or remote-agent translator ships in v0.1.
- Generic input is data only. It cannot select target paths, state roots, policy paths, trust roots, corpus labels, adapters, commands, executables, or promotion authority.
- Malformed top-level JSON/request/schema is invalid request exit 2. A structurally valid request containing incomplete, unsupported-version, truncated, timed-out, unavailable, or inconsistent external evidence evaluates UNKNOWN under the selected profile.
- Stdout remains canonical ACG JSON. Sanitized diagnostics use stderr. Human reports derive only from validated canonical results.
- PUBLIC fields may export. SENSITIVE_HASH fields export only approved digests. SENSITIVE_LOCAL values stay in the protected local StateStore and are excluded from identity-bearing records, canonical stdout, audit messages, proposals, and portable exports. FORBIDDEN values are rejected without echo.
- Raw prompts, transcripts, source excerpts, environment values, credentials, cookies, tokens, private keys, authorization headers, and secret-file contents are never ingested automatically.
- POSIX live-worktree promotion requires every specified filesystem and StateStore capability to be proved. Windows supports portable kernel/store logic and immutable Git-object verification; v0.1 returns explicit UNKNOWN for Windows live-worktree promotion.
- Capability is data in TargetIdentity/v1 and PromotionSnapshot/v1. No adapter silently lowers requirements based on operating-system name.
- Guarded targets remain read-only through all success, refusal, UNKNOWN, crash, concurrency, export, and release tests.
- Ordinary test jobs require no network. Security advisory lookup and provenance attestation run in separately identified network-enabled jobs.
- CI action references use full 40-character commit SHAs. Tags alone are rejected by repository verification.
- Public CI receives no private source, fixture, token list, similarity output, or failure narrative. Private-reference validation may supply only a secret-safe pass/fail attestation at release time.
- No package upload, GitHub release, tag creation, remote creation, force push, or publication occurs while executing this plan. Release workflow configuration and local dry-run proof are in scope; release execution is not.
- Deferred scope remains deferred: no daemon, scheduler, watcher, hook installer, UI, plugin discovery, arbitrary external executable, network evidence fetch, distributed state, cross-machine assignment envelope, Markdown renderer, target remediation, or schema migration command.

---

## File Map

- `src/agent_continuity/adapters/json.py`: strict bounded JSON/request parsing and external evidence translation.
- `src/agent_continuity/kernel/claims.py`: deterministic Claim/v1 conflict, supersession, and freshness evaluation.
- `src/agent_continuity/kernel/classification.py`: complete field registry and audience rules.
- `src/agent_continuity/export.py`: deterministic portable export/redaction.
- `src/agent_continuity/improvement/proposals.py`: minimal redacted candidate proposal envelopes.
- `src/agent_continuity/capture/capabilities.py`: platform/filesystem capability reports and promotion predicates.
- `src/agent_continuity/kernel/capabilities.py`: closed capability names/statuses and pure capability decisions.
- `src/agent_continuity/store/security.py`: protected StateStore ownership, mode, ACL, reparse, and durability checks.
- `tests/security/`: hostile filesystem, transaction, audit, secret, export, and no-target-write proof.
- `tools/verify_schemas.py`: registry/schema parity and strictness.
- `tools/verify_provenance.py`: SPDX, DCO metadata, public-safe provenance, dependency licence, and action-pin checks.
- `tools/build_sbom.py`: deterministic SPDX 2.3 artifact SBOM.
- `tools/verify_release.py`: complete aggregate release gate with no publication behavior.
- `.github/workflows/`: independent CI, security, and release-candidate workflows plus final aggregate gate.
- `docs/`: architecture, threat model, formats, generic integration, provenance, and decisions.

### Task 1: Add canonical generic JSON and stdin evidence translation

**Files:**

- Create: `src/agent_continuity/adapters/json.py`
- Modify: `src/agent_continuity/adapters/__init__.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/cli.py`
- Create: `schemas/v1/external-event-request.schema.json`
- Create: `schemas/v1/external-evidence.schema.json`
- Create: `schemas/v1/external-fact.schema.json`
- Create: `tests/contract/test_external_event_request.py`
- Create: `tests/contract/test_external_evidence_outcomes.py`
- Create: `tests/integration/test_json_stdin.py`
- Create: `tests/security/test_json_resource_limits.py`

**Interfaces:**

```python
class ExternalCompleteness(StrEnum):
    COMPLETE = "complete"
    TRUNCATED = "truncated"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ExternalFactV1:
    field_path: tuple[str, ...]
    value: JsonScalar


@dataclass(frozen=True, slots=True)
class ExternalEvidenceV1:
    source_schema: str
    source_status_code: str | None
    producer: ProducerIdentity
    observed_at: LogicalTime
    completeness: ExternalCompleteness
    terminal_status: int | None
    declared_output_digest: Digest | None
    observed_output_digest: Digest | None
    check_count: int | None
    pagination_complete: bool | None
    facts: tuple[ExternalFactV1, ...]


@dataclass(frozen=True, slots=True)
class ExternalEventRequestV1:
    schema: Literal["ExternalEventRequest/v1"]
    request_id: str
    evidence: tuple[ExternalEvidenceV1, ...]


@dataclass(frozen=True, slots=True)
class ExternalTranslation:
    evidence: tuple[EvidenceV1, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class ExternalTranslationContext:
    target_id: RecordId
    checkpoint_id: RecordId
    policy_id: RecordId
    logical_time: LogicalTime
    supported_source_schemas: tuple[str, ...]
    deterministic_producer_ids: frozenset[RecordId]


def parse_external_request(data: bytes) -> ExternalEventRequestV1: ...
def translate_external_request(
    request: ExternalEventRequestV1,
    context: ExternalTranslationContext,
) -> ExternalTranslation: ...
```

CLI integration:

```text
acg verify --event-json PATH
acg verify --event-json -
acg checkpoint --event-json PATH
acg checkpoint --event-json -
```

Target, state, session, policy, profile, and promotion mode remain trusted CLI/config inputs. Event JSON cannot set them.

- [ ] **Step 1: Write failing malformed-request exit-2 tests**

Reject empty input, invalid UTF-8, malformed JSON, duplicate or NFC-colliding keys, noncanonical JSON, wrong top-level schema, unknown top-level fields, wrong types, more than 8 MiB, nesting deeper than 64 containers, more than 250,000 aggregate array/object entries, multiple stdin consumers, absolute/raw target paths, state paths, policy paths, adapter selectors, caller-supplied classification overrides, command strings, and executable fields. Require canonical Error/v1 category `request` and exit 2.

- [ ] **Step 2: Write failing valid-evidence UNKNOWN decision table**

A canonical ExternalEventRequest/v1 remains structurally valid when nested evidence declares an unknown `source_schema`, COMPLETE with missing terminal status, truncated output, unavailable observation, digest mismatch, zero checks, incomplete pagination, or bounded source status such as `malformed`, `oversize`, `timeout`, or `unsupported_version`. Translation emits stable UNKNOWN/BLOCK Findings according to existing detector policy; it never raises request exit 2 for those evidence states. Raw offending source bytes are not embedded.

Complete, supported, digest-consistent evidence with terminal status, positive check count, complete pagination, and registered facts may satisfy deterministic requirements. Advisory producer authority never satisfies deterministic requirements.

- [ ] **Step 3: Run RED**

```bash
python -m pytest -q tests/contract/test_external_event_request.py tests/contract/test_external_evidence_outcomes.py tests/integration/test_json_stdin.py tests/security/test_json_resource_limits.py
```

Expected: JSON adapter, schemas, and CLI options are absent.

- [ ] **Step 4: Implement bounded parsing and data-only translation**

Read at most 8 MiB, enforce depth/entry limits during parse, canonical-load through CanonicalJSON/v1, validate the strict top-level schema, and construct immutable values. Treat `source_schema` as bounded untrusted data; a supported registry entry may translate only declared fields into the existing fact registry. Raw malformed, oversize, or rejected external bytes stay ephemeral and are never persisted, logged, echoed, or included in an error record.

The adapter never imports source-selected code, invokes a subprocess, reads environment values, opens source-selected paths, fetches a URL, or creates corpus labels. Unknown source schemas produce `external.schema_unsupported` UNKNOWN.

- [ ] **Step 5: Run GREEN and CLI subprocess proof**

```bash
python -m pytest -q tests/contract/test_external_event_request.py tests/contract/test_external_evidence_outcomes.py tests/integration/test_json_stdin.py tests/security/test_json_resource_limits.py
python tools/verify_schemas.py
python -m mypy src/agent_continuity/adapters src/agent_continuity/api.py src/agent_continuity/cli.py
python -m ruff check src/agent_continuity tests/contract tests/integration tests/security
```

Expected: malformed top-level requests exit 2; valid incomplete/unsupported evidence returns true UNKNOWN and policy-derived exit 0 or 1 without becoming PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/adapters/json.py src/agent_continuity/adapters/__init__.py src/agent_continuity/api.py src/agent_continuity/cli.py
git add schemas/v1/external-event-request.schema.json schemas/v1/external-evidence.schema.json schemas/v1/external-fact.schema.json
git add tests/contract/test_external_event_request.py tests/contract/test_external_evidence_outcomes.py tests/integration/test_json_stdin.py tests/security/test_json_resource_limits.py
git commit -m "feat: add generic JSON evidence adapter"
```

### Task 2: Add Claim/v1 detectors and complete the v0.1 CLI surface

**Files:**

- Create: `src/agent_continuity/kernel/claims.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Modify: `src/agent_continuity/kernel/evaluation.py`
- Modify: `src/agent_continuity/adapters/json.py`
- Modify: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/cli.py`
- Modify: `src/agent_continuity/output.py`
- Create: `schemas/v1/claim.schema.json`
- Create: `schemas/v1/scope-manifest.schema.json`
- Modify: `schemas/v1/external-event-request.schema.json`
- Create: `tests/contract/test_claim_v1.py`
- Create: `tests/contract/test_claim_evaluation.py`
- Create: `tests/integration/test_claim_json.py`
- Create: `tests/integration/test_cli_resume_delegate_accept.py`
- Create: `tests/property/test_claim_graph.py`
- Create: `tests/security/test_claim_mutants.py`

**Interfaces:**

```python
class ClaimState(StrEnum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"


@dataclass(frozen=True, slots=True)
class ClaimV1:
    record_id: RecordId
    claim_id: str
    subject_digest: Digest
    state: ClaimState
    evidence_ids: tuple[RecordId, ...]
    expires_at: LogicalTime | None
    supersedes_id: RecordId | None


@dataclass(frozen=True, slots=True)
class ClaimEvaluationContext:
    logical_time: LogicalTime
    evidence_states: Mapping[RecordId, EvidenceState]


def evaluate_claims(
    claims: Sequence[ClaimV1],
    context: ClaimEvaluationContext,
) -> tuple[Finding, ...]: ...
```

Claim text is external or SENSITIVE_LOCAL narrative and never enters Claim/v1 deterministic identity or comparison.

Remaining CLI:

```text
acg resume [--checkpoint CHECKPOINT_ID]
acg delegate --task-digest DIGEST --scope-manifest PATH --required-evidence RECORD_ID --expires-at RFC3339
acg accept-result RESULT_ID
```

`acg accept-result` resolves immutable AssignmentResult/v1 by ID from the same local StateStore. It never imports a foreign or cross-machine envelope.

- [ ] **Step 1: Write failing Claim/v1 schema and identity tests**

Require stable ASCII `claim_id`, subject digest, canonical unique evidence IDs, valid state, expiry, and optional exact supersedes record ID. Reject claim text, unknown fields, self-supersession, malformed digests, and duplicate evidence references. Equivalent input order produces identical bytes/ID.

- [ ] **Step 2: Write failing conflict, supersession, and freshness decision tables**

Cover identical duplicate records, same stable claim ID with conflicting subject/evidence identity, active claim superseding a still-active predecessor, valid predecessor marked SUPERSEDED, missing/UNKNOWN/invalid Evidence, exact expiry boundary, missing supersedes target, and supersession cycles.

Use stable codes `claim.identifier_conflict`, `claim.superseded_still_active`, `claim.evidence_unknown`, `claim.evidence_invalid`, `claim.expired`, `claim.supersedes_missing`, and `claim.supersession_cycle`. Deterministic conflict is BLOCK; unavailable/missing authority is UNKNOWN. Add positive violation, negative control, and planted comparison/state mutant for each blocking detector.

- [ ] **Step 3: Write failing generic JSON Claim tests**

Extend canonical ExternalEventRequest/v1 with an optional canonically ordered `claims` array. Outer malformed Claim/v1 is request exit 2. A valid Claim whose referenced external evidence is incomplete/unsupported evaluates UNKNOWN. Adapter returns Claim kernel models only and cannot persist or advance them directly.

- [ ] **Step 4: Write failing CLI subprocess tests**

Resume emits canonical ResumeContext/v1 and changes no store bytes/heads. Delegate loads strict ScopeManifest/v1 with raw PathIdentity values, creates one same-store Assignment, and emits only its canonical ID/receipt. Accept-result reloads one same-store result ID, preserves exact/conflicting replay semantics, and rejects missing/foreign IDs with exit 2 without accepting serialized envelopes.

- [ ] **Step 5: Run RED**

```bash
python -m pytest -q tests/contract/test_claim_v1.py tests/contract/test_claim_evaluation.py tests/integration/test_claim_json.py tests/integration/test_cli_resume_delegate_accept.py tests/property/test_claim_graph.py tests/security/test_claim_mutants.py
```

Expected: Claim module/schema and remaining CLI commands are absent.

- [ ] **Step 6: Implement pure Claim evaluation and thin CLI adapters**

Claim graph evaluation is bounded and iterative. It compares complete record/semantic identities, never display text or mappings keyed only by claim code. Integrate resulting Findings into `kernel.evaluate`, evidence invalidation, checkpoint/resume, and Finding retention.

CLI parses trusted command options, invokes existing `Continuity`/`Assignment` interfaces, and renders validated canonical results. It contains no lineage, claim, or verdict policy.

- [ ] **Step 7: Run GREEN and earlier-lineage regression**

```bash
python -m pytest -q tests/contract/test_claim_v1.py tests/contract/test_claim_evaluation.py tests/integration/test_claim_json.py tests/integration/test_cli_resume_delegate_accept.py tests/property/test_claim_graph.py tests/security/test_claim_mutants.py
python -m pytest -q tests/integration/test_resume.py tests/integration/test_delegate.py tests/integration/test_assignment_acceptance.py
python tools/verify_schemas.py
python -m mypy src/agent_continuity
python -m ruff check src/agent_continuity tests/contract tests/integration tests/property tests/security
```

Expected: all commands exit 0; conflicting/superseded active Claims cannot pass; CLI preserves same-machine/read-only boundaries.

- [ ] **Step 8: Commit**

```bash
git add src/agent_continuity/kernel/claims.py src/agent_continuity/kernel/records.py src/agent_continuity/kernel/evaluation.py
git add src/agent_continuity/adapters/json.py src/agent_continuity/api.py src/agent_continuity/cli.py src/agent_continuity/output.py
git add schemas/v1/claim.schema.json schemas/v1/scope-manifest.schema.json schemas/v1/external-event-request.schema.json
git add tests/contract/test_claim_v1.py tests/contract/test_claim_evaluation.py tests/integration/test_claim_json.py tests/integration/test_cli_resume_delegate_accept.py tests/property/test_claim_graph.py tests/security/test_claim_mutants.py
git commit -m "feat: add claims and remaining CLI commands"
```

### Task 3: Enforce field classification, local storage, and export redaction

**Files:**

- Modify: `src/agent_continuity/kernel/classification.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `src/agent_continuity/export.py`
- Create: `src/agent_continuity/report.py`
- Modify: `src/agent_continuity/cli.py`
- Create: `src/agent_continuity/improvement/proposals.py`
- Create: `schemas/v1/field-classification-registry.schema.json`
- Create: `schemas/v1/export-envelope.schema.json`
- Create: `schemas/v1/proposal-envelope.schema.json`
- Create: `tests/contract/test_field_classification.py`
- Create: `tests/contract/test_export_redaction.py`
- Create: `tests/integration/test_sensitive_local_store.py`
- Create: `tests/security/test_forbidden_fields.py`
- Create: `tests/security/test_output_secret_leakage.py`

**Interfaces:**

```python
class ExportAudience(StrEnum):
    CANONICAL_STDOUT = "canonical_stdout"
    PORTABLE_EXPORT = "portable_export"
    PROPOSAL = "proposal"
    AUDIT = "audit"


@dataclass(frozen=True, slots=True)
class FieldPolicyV1:
    record_type: str
    field_path: tuple[str, ...]
    classification: FieldClass
    allowed_audiences: tuple[ExportAudience, ...]


def classify_field(record_type: str, field_path: tuple[str, ...]) -> FieldPolicyV1: ...
def export_record(
    record: StoredRecord,
    audience: ExportAudience,
) -> JsonObject: ...
def make_proposal_envelope(
    finding: PersistedFindingV1,
    candidate: CandidateRuleV1,
) -> JsonObject: ...
def render_human_report(record: StoredRecord) -> str: ...
```

- [ ] **Step 1: Write the complete field-by-audience decision matrix**

Classify every field in every v0.1 schema as PUBLIC, SENSITIVE_LOCAL, SENSITIVE_HASH, or FORBIDDEN. Registry coverage test fails when a schema field lacks one exact policy or a stale policy references a missing field.

PUBLIC copies only to allowed audiences. SENSITIVE_HASH emits an approved digest/reference. SENSITIVE_LOCAL stores only through explicit caller approval and exports only its digest reference where schema allows. FORBIDDEN rejects before persistence/display and never echoes input.

- [ ] **Step 2: Write failing sensitive-local storage tests**

Explicit caller-supplied goal, acceptance criterion, task, summary, and pending-work text may be stored in protected local rows keyed by digest. Harness prompts, transcripts, arbitrary source excerpts, environment values, and implicitly discovered text reject regardless of caller narrative.

Sensitive-local bytes are excluded from content-addressed record bodies, audit canonical bytes, stdout, portable exports, proposal envelopes, and deterministic comparison. Their approved digest may bind identity.

- [ ] **Step 3: Write failing secret placement matrix**

Plant synthetic token, cookie, private-key marker, authorization header, credential URL, control character, and high-entropy secret in every external string field, including fields otherwise classified SENSITIVE_LOCAL. Require rejection without matched value in exception, stdout, stderr, audit, proposal, export, local-value row, or logs. Separately plant a benign unique SENSITIVE_LOCAL sentinel and prove it remains only in protected local storage, never authoritative or exported.

- [ ] **Step 4: Run RED**

```bash
python -m pytest -q tests/contract/test_field_classification.py tests/contract/test_export_redaction.py tests/integration/test_sensitive_local_store.py tests/security/test_forbidden_fields.py tests/security/test_output_secret_leakage.py
```

Expected: complete registry, export module, proposal redaction, and protected local storage are absent.

- [ ] **Step 5: Implement protected local rows and audience-driven export**

Harden the Plan 1 `SensitiveLocalValueDraft` path and `sensitive_local_values` table with schema-classified allowed kinds, explicit caller approval, digest verification, 0600/ACL protection, and existing UPDATE/DELETE triggers. All local rows join the owning state transition transaction. This remains initial schema version 1, not a runtime migration path.

Export traverses validated record models with registry policies; it never recursively dumps dataclasses or `__dict__`. Unknown record/field policy is an internal integrity failure, not permissive export.

`render_human_report` derives only from the CANONICAL_STDOUT projection plus a fixed message catalog. CLI option `--human-report PATH` writes it by exclusive create to a caller-selected path outside target and StateStore while canonical stdout remains unchanged. The report never becomes evidence.

- [ ] **Step 6: Run GREEN**

```bash
python -m pytest -q tests/contract/test_field_classification.py tests/contract/test_export_redaction.py tests/integration/test_sensitive_local_store.py tests/security/test_forbidden_fields.py tests/security/test_output_secret_leakage.py
python -m pytest -q tests/integration/test_improve_cli.py tests/contract/test_cli_output.py
python tools/verify_schemas.py
python -m mypy src/agent_continuity
python -m ruff check .
python -m ruff format --check .
```

Expected: all commands exit 0; forbidden values appear nowhere; sensitive-local bytes appear only in protected local rows.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/kernel/classification.py src/agent_continuity/store src/agent_continuity/export.py src/agent_continuity/report.py src/agent_continuity/cli.py src/agent_continuity/improvement/proposals.py
git add schemas/v1/field-classification-registry.schema.json schemas/v1/export-envelope.schema.json schemas/v1/proposal-envelope.schema.json
git add tests/contract/test_field_classification.py tests/contract/test_export_redaction.py tests/integration/test_sensitive_local_store.py tests/security/test_forbidden_fields.py tests/security/test_output_secret_leakage.py
git commit -m "feat: enforce classified redacted exports"
```

### Task 4: Make platform and promotion capabilities explicit

**Files:**

- Create: `src/agent_continuity/capture/capabilities.py`
- Modify: `src/agent_continuity/kernel/capabilities.py`
- Create: `src/agent_continuity/store/security.py`
- Modify: `src/agent_continuity/capture/base.py`
- Modify: `src/agent_continuity/capture/filesystem.py`
- Modify: `src/agent_continuity/capture/git.py`
- Modify: `src/agent_continuity/improvement/governor.py`
- Create: `schemas/v1/capability-report.schema.json`
- Create: `schemas/v1/promotion-capability.schema.json`
- Modify: `schemas/v1/promotion-snapshot.schema.json`
- Create: `tests/contract/test_capability_decision.py`
- Create: `tests/integration/test_posix_state_security.py`
- Create: `tests/integration/test_windows_immutable_git.py`
- Create: `tests/security/test_capability_downgrade.py`

**Interfaces:**

```python
class Capability(StrEnum):
    RAW_PATH_IDENTITY = "raw_path_identity"
    DIRECTORY_FD_WALK = "directory_fd_walk"
    NOFOLLOW_COMPONENTS = "nofollow_components"
    STABLE_FILE_IDENTITY = "stable_file_identity"
    HARDLINK_COUNT = "hardlink_count"
    CASE_COLLISION_DETECTION = "case_collision_detection"
    IMMUTABLE_GIT_OBJECTS = "immutable_git_objects"
    PRIVATE_OWNER = "private_owner"
    PRIVATE_ACL = "private_acl"
    REPARSE_POINT_REJECTION = "reparse_point_rejection"
    ATOMIC_REPLACE = "atomic_replace"
    DURABLE_FILE_FLUSH = "durable_file_flush"
    DURABLE_DIRECTORY_FLUSH = "durable_directory_flush"


class CapabilityStatus(StrEnum):
    PROVEN = "proven"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CapabilityEvidenceV1:
    capability: Capability
    status: CapabilityStatus
    adapter_id: str
    adapter_version: str
    evidence_code: str
    evidence_digest: Digest | None


@dataclass(frozen=True, slots=True)
class CapabilityReportV1:
    report_id: RecordId
    platform_id: str
    filesystem_id: str
    target_kind: str
    evidence: tuple[CapabilityEvidenceV1, ...]


@dataclass(frozen=True, slots=True)
class PromotionCapabilityDecision:
    allowed: bool
    verdict: Verdict
    missing: tuple[Capability, ...]
    codes: tuple[str, ...]


def assess_promotion_capability(
    report: CapabilityReportV1,
) -> PromotionCapabilityDecision: ...
```

- [ ] **Step 1: Write failing capability decision table**

Cover immutable Git-object target, POSIX clean/live worktree, Windows immutable Git target, Windows live worktree, missing owner/ACL, missing no-follow/reparse protection, missing atomic replace, and missing durable flush.

The v0.1 contract is:

- portable kernel/store evaluation on Linux, macOS, and Windows;
- immutable Git-object verification on all three;
- POSIX live-worktree promotion only when every required capability is proved;
- Windows immutable Git-object promotion only when immutable-object and StateStore capability sets are proved;
- Windows live-worktree promotion is explicit UNKNOWN in v0.1;
- any missing required capability is UNKNOWN, never an automatic downgrade to a weaker path.

- [ ] **Step 2: Write failing POSIX state-security tests**

Require state directories 0700 and files 0600; reject group/world-writable root, wrong owner, symlink component, hardlinked guard file, special file, directory replacement, or non-durable commit capability before promotion. Read-only verify may report capabilities but cannot claim promotion assurance.

- [ ] **Step 3: Write failing Windows capability tests**

On Windows CI, create an immutable Git-object fixture and verify raw UTF-16LE PathIdentity/v1, case collision behavior, reparse-point refusal where available, private ACL evidence, atomic replace, and durable file flush. Missing directory-flush or live-worktree no-follow capability yields named UNKNOWN. Tests never mark unsupported behavior PASS.

- [ ] **Step 4: Run RED**

```bash
python -m pytest -q tests/contract/test_capability_decision.py tests/integration/test_posix_state_security.py tests/integration/test_windows_immutable_git.py tests/security/test_capability_downgrade.py
```

Expected: capability models and StateStore security adapter are absent.

- [ ] **Step 5: Implement feature-probed capability evidence**

Adapters prove individual behavior through actual operations against their opened root/store and record stable evidence codes. Kernel consumes only CapabilityReport/v1. It does not branch on `sys.platform` to waive a requirement.

PromotionGovernor binds content-addressed CapabilityReport/v1 IDs in PromotionSnapshot, then repeats capability capture and verification at apply. Unsupported Windows live-worktree path always returns `promotion.live_worktree_capability_unknown` in v0.1.

- [ ] **Step 6: Run GREEN on the current platform and simulated matrices**

```bash
python -m pytest -q tests/contract/test_capability_decision.py tests/integration/test_posix_state_security.py tests/integration/test_windows_immutable_git.py tests/security/test_capability_downgrade.py
python -m pytest -q tests/integration/test_promotion_apply.py
python -m mypy src/agent_continuity/capture src/agent_continuity/store src/agent_continuity/improvement
python -m ruff check src/agent_continuity tests/contract tests/integration tests/security
```

Expected: native applicable tests pass; unsupported native tests skip only with explicit capability reason; pure decision tables cover every platform outcome.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/capture src/agent_continuity/store/security.py src/agent_continuity/improvement/governor.py
git add schemas/v1/capability-report.schema.json schemas/v1/promotion-capability.schema.json schemas/v1/promotion-snapshot.schema.json
git add tests/contract/test_capability_decision.py tests/integration/test_posix_state_security.py tests/integration/test_windows_immutable_git.py tests/security/test_capability_downgrade.py
git commit -m "feat: enforce truthful platform capabilities"
```

### Task 5: Complete hostile filesystem and target-read-only proof

**Files:**

- Modify: `src/agent_continuity/capture/filesystem.py`
- Modify: `src/agent_continuity/capture/coordinator.py`
- Modify: `src/agent_continuity/capture/git.py`
- Create: `tests/security/test_filesystem_adversary_matrix.py`
- Create: `tests/security/test_capture_concurrent_mutation.py`
- Create: `tests/security/test_resource_exhaustion.py`
- Create: `tests/security/test_all_commands_target_read_only.py`
- Create: `tests/property/test_path_identity_adversarial.py`
- Create: `tests/fixtures/adversarial/public-tree-manifest.json`

- [ ] **Step 1: Write the hostile-object and path matrix**

Cover symlink leaf, symlink ancestor, hardlink, FIFO, socket, device where supported, reparse point, junction, alternate data stream, case collision, non-UTF-8 POSIX name, invalid UTF-16, absolute path, dot-dot, empty segment, NUL, overlong segment, ancestor rename/swap, leaf replacement, truncate/extend during read, chmod/ACL change, and object-type change.

Every case has planted violation, negative control, and implementation mutant. Unsupported observation is UNKNOWN with exact capability code.

- [ ] **Step 2: Write concurrent capture and ABA-limit tests**

Race path census, cited file, authority-critical instruction, Git index, local exclude file, and worktree inventory between Snapshot A/B/C. One instability permits one complete retry; a second returns UNKNOWN. Identical bytes restored with every observed identity restored are documented as outside v0.1 hostile same-UID threat model, not claimed detected.

- [ ] **Step 3: Write resource-limit tests**

Exercise 250,000 observed paths, 1 GiB individual file, 20 GiB aggregate hashed bytes, 4 MiB analyzer text, 8 MiB JSON input, subprocess output cap, and operation timeout through fakes/sparse fixtures without allocating full physical limits. Boundary value passes; boundary plus one returns UNKNOWN or request exit 2 according to input layer.

- [ ] **Step 4: Write all-command no-target-write tests**

For init, checkpoint, verify, resume, delegate, accept-result, verify-audit, audit-anchor export, every improve command, JSON event input, export, and release smoke, compare before/after content, HEAD, refs, index, status, config, repository/local excludes, hooks, modes/ACLs, xattrs where supported, and application metadata. Exercise PASS, WARN, UNKNOWN, BLOCK, exit 2, exit 3, crash, and CAS loss.

- [ ] **Step 5: Run RED**

```bash
python -m pytest -q tests/security/test_filesystem_adversary_matrix.py tests/security/test_capture_concurrent_mutation.py tests/security/test_resource_exhaustion.py tests/security/test_all_commands_target_read_only.py tests/property/test_path_identity_adversarial.py
```

Expected: at least one planted adversarial case exposes incomplete hardening.

- [ ] **Step 6: Harden descriptor-pinned capture without expanding interface**

Keep the existing `CaptureCoordinator.capture_stable` interface. Concentrate no-follow walking, pinned-descriptor hashing, before/after identity, bounded census reconciliation, retry, and ephemeral cleanup inside capture modules. Do not add target-write methods or caller-visible race primitives.

- [ ] **Step 7: Run GREEN and planted mutants**

```bash
python -m pytest -q tests/security/test_filesystem_adversary_matrix.py tests/security/test_capture_concurrent_mutation.py tests/security/test_resource_exhaustion.py tests/security/test_all_commands_target_read_only.py tests/property/test_path_identity_adversarial.py
python -m pytest -q tests/security -k mutant
python -m mypy src/agent_continuity/capture
python -m ruff check src/agent_continuity/capture tests/security tests/property
```

Expected: all supported planted attacks are detected/refused; unsupported capability is explicit UNKNOWN; target manifests remain equal.

- [ ] **Step 8: Commit**

```bash
git add src/agent_continuity/capture
git add tests/security/test_filesystem_adversary_matrix.py tests/security/test_capture_concurrent_mutation.py tests/security/test_resource_exhaustion.py tests/security/test_all_commands_target_read_only.py
git add tests/property/test_path_identity_adversarial.py tests/fixtures/adversarial/public-tree-manifest.json
git commit -m "test: harden adversarial target capture"
```

### Task 6: Complete transaction, audit, concurrency, and leakage hardening

**Files:**

- Modify: `src/agent_continuity/store/sqlite.py`
- Modify: `src/agent_continuity/kernel/audit.py`
- Modify: `src/agent_continuity/output.py`
- Create: `tests/security/test_all_transactions_crash.py`
- Create: `tests/security/test_all_heads_concurrency.py`
- Create: `tests/security/test_audit_adversary_matrix.py`
- Create: `tests/security/test_store_file_attacks.py`
- Create: `tests/security/test_cross_surface_leakage.py`
- Create: `tests/property/test_operation_replay.py`

- [ ] **Step 1: Write the complete transaction fault matrix**

For initialization, checkpoint, finding/candidate retention, assignment creation, result acceptance, decision staging, approval, promotion, rollback, and anchor export, inject failure after each record set, audit append, projection update, before commit, after commit, reopen, and readback. After process restart require complete prior or complete new transaction and a valid audit chain; uncertain state is exit 3 and blocks protected work.

- [ ] **Step 2: Write the concurrency and replay matrix**

Run byte-identical and conflicting pairs for initialization, checkpoint, Finding batch, AssignmentResult, PromotionDecision, apply, rollback, and anchor export. Exact canonical replay is idempotent; stale expected heads lose; same ID/different bytes is integrity exit 3; conflicting assignment result is BLOCK; only one promotion generation wins.

- [ ] **Step 3: Write audit/store attack tests**

Mutate, reorder, delete, duplicate, truncate, or relink audit events; replace a record; point a head at missing/wrong record; shorten below external anchor; replace SQLite file or parent directory; open through symlink/hardlink; change owner/mode/ACL; and simulate partial durable flush capability. Full verification detects every supported attack.

- [ ] **Step 4: Write cross-surface leakage tests**

Plant unique PUBLIC, SENSITIVE_HASH, SENSITIVE_LOCAL, and FORBIDDEN sentinels. Inspect canonical stdout, stderr, exceptions, audit bytes, immutable records, proposal/export envelopes, human reports, anchor, SQLite local rows, worker stdin/stdout, build logs, and test reports. Assert each sentinel appears only on audiences permitted by the classification matrix. Sanitized errors carry stable message IDs and safe parameters only.

- [ ] **Step 5: Run RED**

```bash
python -m pytest -q tests/security/test_all_transactions_crash.py tests/security/test_all_heads_concurrency.py tests/security/test_audit_adversary_matrix.py tests/security/test_store_file_attacks.py tests/security/test_cross_surface_leakage.py tests/property/test_operation_replay.py
```

Expected: missing fault labels, projection checks, or output redaction make at least one case fail.

- [ ] **Step 6: Harden shared transaction and output implementations**

Use one internal multi-record/multi-head CAS transaction implementation for every state transition. Reuse canonical audit/readback verification rather than operation-specific shortcuts. Output construction accepts only validated public result models and registry-filtered parameters.

- [ ] **Step 7: Run GREEN and full security regression**

```bash
python -m pytest -q tests/security/test_all_transactions_crash.py tests/security/test_all_heads_concurrency.py tests/security/test_audit_adversary_matrix.py tests/security/test_store_file_attacks.py tests/security/test_cross_surface_leakage.py tests/property/test_operation_replay.py
python -m pytest -q tests/security tests/property
python -m mypy src/agent_continuity/store src/agent_continuity/kernel/audit.py src/agent_continuity/output.py
python -m ruff check src/agent_continuity tests/security tests/property
```

Expected: all commands exit 0; all transaction and audit invariants survive crash/concurrency/adversarial cases.

- [ ] **Step 8: Commit**

```bash
git add src/agent_continuity/store/sqlite.py src/agent_continuity/kernel/audit.py src/agent_continuity/output.py
git add tests/security/test_all_transactions_crash.py tests/security/test_all_heads_concurrency.py tests/security/test_audit_adversary_matrix.py tests/security/test_store_file_attacks.py tests/security/test_cross_surface_leakage.py tests/property/test_operation_replay.py
git commit -m "test: prove state and audit hardening"
```

### Task 7: Add public governance, architecture, and CI gates

**Files:**

- Modify: `pyproject.toml`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `CONTRIBUTING.md`
- Modify: `SECURITY.md`
- Modify: `PROVENANCE.md`
- Create: `THIRD_PARTY_NOTICES.md`
- Create: `CONTEXT.md`
- Create: `docs/architecture.md`
- Create: `docs/threat-model.md`
- Create: `docs/formats/canonical-json-v1.md`
- Create: `docs/formats/generic-event-v1.md`
- Create: `docs/integrations/generic-json.md`
- Create: `docs/provenance/public-safe-development.md`
- Create: `docs/adr/0001-external-state.md`
- Create: `docs/adr/0002-deterministic-automatic-promotion.md`
- Create: `examples/policies/strict.toml`
- Create: `examples/long-session/checkpoint_resume.py`
- Create: `examples/delegation/same_machine.py`
- Create: `.github/CODEOWNERS`
- Create: `.github/dependabot.yml`
- Create: `.github/pull_request_template.md`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/security.yml`
- Create: `.github/workflows/release.yml`
- Create: `tests/contract/test_public_docs_claims.py`
- Create: `tests/contract/test_workflow_pins.py`
- Create: `tests/integration/test_public_examples.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Add development-only proof dependencies and offline test guard**

Retain Plan 1 Hypothesis and add bounded development dependencies `coverage>=7.6,<8`, `pip-audit>=2.7,<3`, and `detect-secrets>=1.5,<2` while keeping `[project].dependencies = []`. An autouse test fixture rejects socket creation and network subprocess arguments in ordinary test jobs. Tests requiring advisory-database access carry a separate `network_security` marker and never run in the ordinary matrix.

- [ ] **Step 2: Write truthful documentation claim tests**

Require docs and executable public examples to state/show: standalone/vendor-neutral; no daemon/hook install/target remediation; explicit Citation byte ranges rather than general Markdown inference; same-machine assignments; tamper-evident audit limitations; automatic promotion proof requirements; human approval non-override; immutable-Git Windows versus live-worktree UNKNOWN; external local state; zero runtime dependencies; no claim of being first; MIT public-safe provenance-controlled reimplementation.

Reject claims of remote attestation, tamper-proof storage, semantic truth, arbitrary Markdown correctness, distributed lineage, or complete hostile same-UID protection.

- [ ] **Step 3: Create independent CI jobs**

`ci.yml` defines Python 3.11, 3.12, 3.13, and 3.14 across Ubuntu, macOS, and Windows. Test, type, lint/format, schema, branch coverage, critical decision tables, and build jobs are independent. Final `required` job uses `if: always()` and fails unless every required job succeeded, so one early failure cannot hide other status.

`security.yml` runs `pip-audit` dependency audit, pinned official `github/codeql-action` Python SAST, `detect-secrets scan --all-files`, action-pin verification, adversarial/security suites, and provenance checks. Only advisory lookup and official CodeQL setup/upload are network-enabled; neither is canonical runtime evidence.

`release.yml` builds release-candidate artifacts and attestations after required gates. It has no package-upload or release-creation step in this plan.

- [ ] **Step 4: Pin and verify workflow actions**

Resolve each official action tag to its current official full commit SHA during implementation, record repository/tag/SHA in PROVENANCE.md, and use only the SHA in `uses:`. `test_workflow_pins.py` rejects tags, branches, short SHAs, unrecorded actions, third-party mutable Docker tags, and workflow `pull_request_target` execution.

- [ ] **Step 5: Run RED then GREEN**

```bash
python -m pytest -q tests/contract/test_public_docs_claims.py tests/contract/test_workflow_pins.py tests/integration/test_public_examples.py
python -m pytest -q tests/contract
python -m mypy src/agent_continuity
python -m ruff check .
python -m ruff format --check .
```

Expected after implementation: all commands exit 0; ordinary tests fail immediately on attempted network; workflow references are full recorded SHAs.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml README.md CHANGELOG.md CODE_OF_CONDUCT.md CONTRIBUTING.md SECURITY.md PROVENANCE.md THIRD_PARTY_NOTICES.md CONTEXT.md
git add docs examples .github tests/contract/test_public_docs_claims.py tests/contract/test_workflow_pins.py tests/integration/test_public_examples.py tests/conftest.py
git commit -m "docs: add public governance and CI gates"
```

### Task 8: Build reproducible artifacts, SBOM, and provenance evidence

**Files:**

- Modify: `pyproject.toml`
- Modify: `tools/verify_schemas.py`
- Create: `tools/verify_provenance.py`
- Create: `tools/build_sbom.py`
- Create: `tools/verify_decision_coverage.py`
- Create: `tools/verify_trust_transition.py`
- Modify: `tools/verify_context_defaults.py`
- Modify: `tools/verify_release.py`
- Create: `schemas/v1/private-validation-attestation.schema.json`
- Create: `schemas/v1/trust-transition-attestation.schema.json`
- Create: `schemas/v1/release-manifest.schema.json`
- Create: `tests/contract/test_tool_outputs.py`
- Create: `tests/integration/test_reproducible_build.py`
- Create: `tests/integration/test_sdist_wheel_install.py`
- Create: `tests/security/test_public_provenance.py`
- Create: `tests/security/test_dependency_licences.py`
- Create: `tests/golden/release-manifest-v1.json`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class ReleaseArtifactV1:
    filename: str
    sha256: Digest
    size: int
    kind: str


@dataclass(frozen=True, slots=True)
class ReleaseManifestV1:
    source_commit: str
    source_tree: str
    source_date_epoch: int
    artifacts: tuple[ReleaseArtifactV1, ...]
    sbom_sha256: Digest
    provenance_attestation_sha256: Digest | None
    private_validation_status: str


@dataclass(frozen=True, slots=True)
class TrustTransitionAttestationV1:
    previous_trust_root_id: RecordId | None
    new_trust_root_id: RecordId
    installed_distribution_id: RecordId
    verifier_identity_digest: Digest
    independent: bool
    status: Literal["pass", "fail"]
    logical_time: LogicalTime


def verify_release(
    *,
    source_root: Path,
    artifact_root: Path,
    private_attestation: Path | None,
    publish: Literal[False] = False,
) -> ReleaseManifestV1: ...
```

- [ ] **Step 1: Write failing schema/provenance tool tests**

`verify_schemas.py` loads every schema, verifies registry parity, validates golden positives, rejects generated unknown-field negatives, and emits canonical summary.

`verify_provenance.py` requires SPDX MIT identifiers where applicable, clean public manifest, DCO/provenance PR checklist, dependency-licence allowlist, third-party notices, full action pins, invented public fixtures, and forbidden-token scan. It consumes no private token list in public mode.

Private release mode accepts only canonical `PrivateValidationAttestation/v1` containing `status=pass`, public source commit/tree, validator identity digest, logical time, and attestation digest. Unknown fields or embedded private detail reject; absence prevents release readiness but does not fail ordinary CI.

`verify_trust_transition.py` requires either a byte-verified previous trusted release cross-check or canonical independent TrustTransitionAttestation/v1. Initial v0.1 has no previous trusted release, so release readiness requires an independent verifier binding exact new TrustRoot and installed-distribution IDs. The current kernel, a promotion decision, corpus-label admission, operator approval, or private-reference attestation cannot self-issue this proof. Candidate mode validates identities/schema and may report `attestation_status=missing` with exit 0; release mode fails closed until pass evidence exists.

`verify_context_defaults.py` loads the canonical v2 golden plus the source or installed distribution and requires default generation 2, 2500/4000/5000 basis points, 16000/24000/32000 token ceilings, and append-only v1-to-v2 migration behavior. Any missing, raised, source/wheel-divergent, or mutable-history result fails. The aggregate release verifier invokes this gate; an update cannot silently restore retired v1 values.

- [ ] **Step 2: Write failing reproducible-build tests**

Require a clean committed source identity and record exact HEAD/tree. Export tracked source twice into different private temporary roots from that identity, set `SOURCE_DATE_EPOCH` to the commit timestamp, build wheel and sdist in separate empty artifact directories with the same sanitized verified build environment, and require byte-identical filenames and SHA-256 digests. Open archives and reject absolute paths, dot-dot, unexpected files, nondeterministic timestamps, missing licence, or missing schemas/package data.

- [ ] **Step 3: Write failing installed-artifact tests**

Configure wheel data so every public schema is listed in wheel RECORD under `share/agent-continuity-guard/schemas/v1`; locate it through `importlib.metadata.Distribution.files`, never a source-relative path. Install each wheel and sdist offline into separate clean virtual environments on every declared Python/platform matrix entry, using only the just-built artifact and a preverified local build-tool wheelhouse for sdist isolation. Run CLI help, init/checkpoint/verify/resume/delegate/accept, JSON evidence, audit anchor, automatic promotion, rollback, schema asset load, context-default verification/migration, and installed distribution rehash. Replay the installed-smoke StateStore audit from genesis through its final release-test head. Prove imports never resolve to source checkout. On Windows, an expected explicit promotion UNKNOWN for an unproved capability is a passing capability-contract result; silent downgrade or false PASS fails.

- [ ] **Step 4: Implement deterministic SPDX SBOM and artifact manifest**

`build_sbom.py` emits canonical SPDX 2.3 JSON for distribution, every packaged file digest, MIT licence, Python requirement, and zero runtime dependency relationships. ReleaseManifest/v1 binds source commit/tree, deterministic epoch, artifact names/sizes/hashes, SBOM hash, provenance-attestation hash when supplied, and private validation status.

The tool never uploads, signs with an unavailable key, creates a tag, or publishes. GitHub release workflow may attach platform provenance attestation only after all aggregate gates.

- [ ] **Step 5: Enforce coverage and decision proof thresholds**

Run branch coverage and require at least 90 percent overall. `verify_decision_coverage.py` reads explicit tables for canonicalization, verdict, invalidation, lineage, promotion, context defaults/migration, and audit and requires 100 percent exercised outcomes. Require 100 percent generated-candidate mutant kill, all planted critical mutants killed, positive/negative/mutation proof for every blocking detector, and byte-identical full corpus replay in two clean processes.

- [ ] **Step 6: Run GREEN**

```bash
python -m pytest -q tests/contract/test_tool_outputs.py tests/integration/test_reproducible_build.py tests/integration/test_sdist_wheel_install.py tests/security/test_public_provenance.py tests/security/test_dependency_licences.py
python tools/verify_schemas.py
python tools/verify_context_defaults.py
python tools/verify_provenance.py --mode public
python tools/verify_decision_coverage.py
python tools/verify_trust_transition.py --mode candidate
python tools/verify_release.py --scope public-release --no-publish
```

Expected: public gates and reproducible artifact proof pass; release readiness remains false when no private attestation is supplied; no publication occurs.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml tools schemas/v1/private-validation-attestation.schema.json schemas/v1/trust-transition-attestation.schema.json schemas/v1/release-manifest.schema.json
git add tests/contract/test_tool_outputs.py tests/integration/test_reproducible_build.py tests/integration/test_sdist_wheel_install.py
git add tests/security/test_public_provenance.py tests/security/test_dependency_licences.py tests/golden/release-manifest-v1.json
git commit -m "build: prove reproducible public artifacts"
```

### Task 9: Execute the no-publication release-candidate gate

**Files:**

- Modify: `pyproject.toml`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `PROVENANCE.md`
- Modify: `docs/threat-model.md`
- Modify: `docs/provenance/public-safe-development.md`
- Create: `docs/release/v0.1-gate.md`
- Create: `tests/integration/test_release_candidate.py`

- [ ] **Step 1: Write failing end-to-end release-candidate test**

Set distribution version to `0.1.0` with `requires-python >=3.11`, SPDX MIT metadata, and zero runtime dependencies. From a clean detached checkout, run every public gate, build twice, install both artifact types, exercise all public interfaces, replay audit from genesis, verify external anchor, verify corpus twice in clean processes, run crash/concurrency/adversarial/secret suites, generate SBOM/manifest, and assert source/target trees remain unchanged.

The test inspects Git config and command trace and fails if any command can create a remote, tag, release, upload, push, or package publication.

- [ ] **Step 2: Create acceptance-to-evidence ledger**

`docs/release/v0.1-gate.md` maps each design acceptance criterion 1-20 to exact test node IDs, CI jobs, artifact evidence, expected outcome, and owner. It separately records:

```text
public_code_gates
platform_matrix
installed_artifacts
promotion_corpus
mutation_proof
audit_from_genesis
target_read_only
field_redaction
public_provenance
trust_transition_attestation
private_validation_attestation
publication_authorized = false
```

No row may use coverage percentage as sole evidence.

- [ ] **Step 3: Run full local release-candidate validation**

```bash
python -m pytest -q tests/contract tests/integration tests/security tests/property tests/golden
python -m coverage run --branch -m pytest -q
python -m coverage report --fail-under=90
python -m mypy src/agent_continuity
python -m ruff check .
python -m ruff format --check .
python tools/verify_schemas.py
python tools/verify_context_defaults.py
python tools/verify_provenance.py --mode public
python tools/verify_decision_coverage.py
python tools/verify_trust_transition.py --mode candidate
python tools/verify_release.py --scope public-release --no-publish
git diff --check
git status --short
```

Expected: all public code/artifact gates pass; status is clean. Without a secret-safe external private-validation pass attestation, output truthfully reports `release_ready=false`; it does not weaken or skip the gate.

- [ ] **Step 4: Validate CI aggregate behavior without releasing**

Run workflow syntax/static tests and, where a caller-owned CI branch exists, observe every matrix/security/build job plus final required aggregate. Do not tag, enable package publishing, create a GitHub release, or upload to PyPI. Record only public-safe job URLs/digests in caller-owned release evidence, not repository source files.

- [ ] **Step 5: Commit release-candidate documentation**

```bash
git add pyproject.toml README.md CHANGELOG.md PROVENANCE.md docs/threat-model.md docs/provenance/public-safe-development.md docs/release/v0.1-gate.md tests/integration/test_release_candidate.py
git commit -m "docs: record v0.1 release candidate gates"
git status --short
```

Expected: clean status. Repository is release-capable but nothing is published.

## Plan Completion Gate

Run:

```bash
python -m pytest -q tests/contract tests/integration tests/security tests/property tests/golden
python -m coverage run --branch -m pytest -q
python -m coverage report --fail-under=90
python -m mypy src/agent_continuity
python -m ruff check .
python -m ruff format --check .
python tools/verify_schemas.py
python tools/verify_context_defaults.py
python tools/verify_provenance.py --mode public
python tools/verify_decision_coverage.py
python tools/verify_trust_transition.py --mode candidate
python tools/verify_release.py --scope public-release --no-publish
git diff --check
git status --short
```

Plan 4 is complete only when malformed request versus valid UNKNOWN evidence is proven; every schema field has an enforced classification; forbidden/sensitive-local data stays off disallowed surfaces; POSIX and immutable-Git Windows capability behavior is truthful; hostile filesystem, crash, concurrency, audit, replay, and secret matrices pass; all commands leave targets unchanged; CI covers Python 3.11-3.14 on Ubuntu/macOS/Windows with independent aggregate gates; wheel and sdist are reproducible and installed-smoke-tested; SBOM, artifact manifest, public provenance, decision coverage, and trust-transition mechanism pass; private validation is accepted only as a secret-safe release attestation; actual release readiness still requires both external attestations; and no release, tag, remote, upload, or publication has occurred.
