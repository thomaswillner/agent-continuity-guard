# Safe, Simple Completion and Maintainability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete ACG as a maintainable, vendor-neutral continuity guard by
finishing the existing Foundation, delivering one installed-wheel
`checkpoint -> handoff -> rehydrate -> verify` path, splitting oversized
internals only where feature work already touches them, completing governed
deterministic improvement, and passing public release gates without weakening
any existing invariant.

**Architecture:** Preserve `Continuity`, `GitTargetAdapter`, `StateStore`, and
the pure kernel as the stable interfaces. Finish a complete vertical continuity
path before broadening features. Move process execution, pinned filesystem
observation, Git proof construction, SQLite lifecycle, transaction/audit logic,
and application operations behind internal seams only when their owning
approved task already changes that code.

**Tech Stack:** Python 3.11-3.14, Python standard-library runtime, frozen
dataclasses, `sqlite3`, CanonicalJSON/v1, SHA-256 identities, pytest,
Hypothesis, JSON Schema Draft 2020-12, strict mypy, Ruff, setuptools/build,
GitHub Actions, SPDX 2.3 JSON.

**Spec:** `docs/specs/v0.1-design.md`

**Detailed task sources:**

- `docs/plans/2026-08-08-01-foundation-checkpoint.md`
- `docs/plans/2026-08-08-02-evidence-resume-lineage.md`
- `docs/plans/2026-08-09-02a-context-continuity-boundaries.md`
- `docs/plans/2026-08-08-03-governed-improvement.md`
- `docs/plans/2026-08-08-04-hardening-release.md`
- `docs/superpowers/plans/2026-08-13-lost-in-the-middle-containment.md`
- `docs/superpowers/specs/2026-08-13-production-benchmark-design.md`

This document is an execution overlay. Detailed plans above continue to own
record schemas, exact production interfaces, RED tests, minimal GREEN changes,
and acceptance commands. This overlay owns dependency order, maintainability
constraints, evidence gates, budgets, and safe stops. It does not silently
supersede approved behavior.

## Planning evidence baseline — 2026-09-01

- `BEHAVIORALLY_PROVEN`: Foundation Task 9 is complete at immutable HEAD
  `90b94814ac8147bcf833947cd1693bdb852682c8`. Controller evidence passes 549
  tests, strict mypy across 26 source files, Ruff, 25 schemas, wheel and sdist
  builds, and clean installed-artifact probes. Current preserved Plan 1
  final-review remediation passes its 11 focused tests; full dirty-worktree
  regression is not claimed.
- `BEHAVIORALLY_PROVEN`: active project environment is Python 3.11.5. Host
  discovery also reports Python 3.14.7, Git 2.55.0, and GitHub CLI 2.96.0.
- `OFFICIALLY_SUPPORTED`: current Python developer documentation lists active
  3.11-3.14 branches; GitHub's official Python workflow documentation was
  reachable in this session.
- `OFFICIALLY_SUPPORTED`: official repositories reported current releases
  `actions/setup-python` v7.0.0 and `actions/checkout` v7.0.1. These mutable tags
  are discovery evidence only; implementation must resolve the then-current
  official tags to immutable full commit SHAs.
- `LOCAL_INTEGRATION`: planned GitHub workflows and public governance files do
  not exist yet. Repository has no configured `origin`; no publication state is
  inferred.
- `UNSUPPORTED_OR_UNKNOWN`: full resume, rehydration, evidence invalidation,
  assignment lineage, governed improvement, cross-platform release, and
  benchmark behavior remain unproven end to end.
- `BEHAVIORALLY_PROVEN`: bounded GLM `glm-5.2` challenge returned
  `ACCEPT_WITH_CHANGES` at
  `sha256:b4fa318c650a19a33768615d64849cce9b31a83ce5b138fa6e6c8e60e8333dd1`;
  controller reconciliation confirmed its four findings against current plan,
  task, and Superpowers evidence. The served GLM 5.3 alias is not exposed and
  remains `UNSUPPORTED_OR_UNKNOWN` rather than inferred from model prose.

Official sources:

- <https://devguide.python.org/versions/>
- <https://docs.github.com/en/actions/how-tos/writing-workflows/building-and-testing/building-and-testing-python>
- <https://github.com/actions/setup-python/releases/tag/v7.0.0>
- <https://github.com/actions/checkout/releases/tag/v7.0.1>

## Global Constraints

- Python support remains 3.11 or newer; declared release matrix is Python
  3.11-3.14 on macOS, Linux, and Windows.
- Mandatory runtime dependencies remain zero.
- Licence remains MIT and implementation remains public-safe and clean-room.
- Do not copy proprietary SPX source, prose, fixtures, paths, names, hashes, or
  datasets. SPX is a potential consumer, never an ACG dependency.
- Do not add or call Kimi API routes, probes, fallbacks, or qualification paths.
- Guarded repositories remain read-only. ACG state remains outside target and
  Git directories.
- Missing, stale, unstable, truncated, unsupported, or inconsistent proof is
  `UNKNOWN`, never `PASS`.
- Default promotion remains deterministic `automatic`. Human review is
  optional and cannot override failed or `UNKNOWN` machine proof.
- Model summaries, transcripts, prompts, acknowledgements, and hidden reasoning
  remain untrusted and cannot be authority or verification evidence.
- No daemon, watcher, hook installer, scheduler, UI, provider-specific adapter,
  OpenClaw integration, target remediation, or distributed state enters v0.1.
- Preserve all pre-existing dirty work. Never reset, clean, stash, or overwrite
  another task's files to make a gate pass.
- Resolve every GitHub Action tag to the current official full commit SHA during
  implementation; never copy mutable tags from this dated plan.
- No tag, remote creation, package upload, GitHub release, or public claim occurs
  before every release gate passes and Thomas separately authorizes publication.

---

## Contract and state

**Measurable outcome:** An installed ACG wheel completes one generic local-Git
continuity journey: initialize, checkpoint, prepare a protected handoff,
rehydrate from verified records, compare protected fields, and either continue
or return a deterministic refusal. The same release candidate then passes all
required implementation, security, cross-platform, benchmark, review, and
publication-preflight gates without waiver.

**Success measure:**

1. All 38 implementation-plan tasks are complete with immutable evidence.
2. The full installed-wheel continuity journey passes positive, direct-drift,
   stale-evidence, tampering, lineage-substitution, and crash-recovery cases.
3. `GitTargetAdapter`, `StateStore`, and `Continuity` public boundary tests pass
   before and after internal extraction.
4. Python 3.11-3.14 x macOS/Linux/Windows CI completes every applicable job and
   reports unsupported capabilities as `UNKNOWN`.
5. Public, sealed-holdout, and combined benchmark gates meet their frozen
   safety floors; otherwise the result truthfully reports tie, loss, or no
   claim.

**Frozen invariants:** Global Constraints above plus canonical record identity,
append-only audit/ruleset history, exact retry idempotency, atomic multi-head
CAS, field-level privacy, and no target writes.

**Authority:** Planning, repository-local edits, tests, builds, local temporary
wheel installation, and commits inside an isolated ACG worktree are allowed.
Runtime activation, hooks, services, credentials, remote publication, release,
and production enforcement require separate authority.

**Budget:**

- Preserve loop-state implementation budget: 38 tasks total, 9 recorded used,
  29 remaining. Foundation Task 9 is complete; current dirty work remediates
  three subsequent whole-Plan-1 Important findings and consumes no new
  implementation-plan task.
- Refactors consume no additional standalone implementation task. They occur
  only inside the first approved task that already changes the affected module.
- Maximum two informative retries per unchanged failure fingerprint.
- Maximum two Self-Refine passes per plan or documentation artifact.
- Run one maker at a time on the shared hot modules.
- The six lost-in-the-middle benchmark tasks require an explicit benchmark-task
  budget in loop state before execution. Until recorded, benchmark execution
  and publication remain `BLOCKED`; ordinary implementation may continue.

**Persisted state:** Continue
`docs/loop-state/2026-08-09-context-continuity-build.json`. Before execution,
append this overlay path to current evidence, increment its revision, preserve
completed evidence, and record the selected next task. Do not rewrite prior
delta or failure history.

## Topology and independence

- **Controller:** owns contract, dependency order, task admission, loop-state
  writeback, and final verdict. It does not certify maker output.
- **Maker:** one fresh context owns exactly one admitted task and its isolated
  worktree changes. No concurrent makers may edit `capture/git.py`,
  `store/sqlite.py`, `api.py`, shared schemas, or the loop-state file.
- **Checker:** a fresh independent context receives the committed immutable
  base/head package plus maker receipts, inspects specification and quality,
  and accepts or rejects. It never edits the maker's task or duplicates the
  maker's complete gate suite. It may independently run only a named focused
  canary needed to resolve a concrete unanswered doubt.
- **Execution:** sequential by dependency. Read-only research may run in
  parallel only when it has no shared mutation surface.
- **Join:** ordered. A dependent task cannot start until its predecessor is
  committed, independently accepted, and recorded in loop state.

Primary operational loop is `plan-execute-replan`. Each implementation task
uses RED -> GREEN TDD as a bounded micro-loop. Maker-checker wraps every task
and every plan-completion gate. Self-Refine applies only to reversible plan,
documentation, and report artifacts; it never certifies security or release
readiness.

Rejected routes:

- Tree of Thoughts: no unresolved material architecture branches remain.
- Monitor/retry: current work is deterministic implementation, not a transient
  asynchronous condition.
- META optimization: governed product improvement is specified in Plan 3, but
  development execution itself has no admitted candidate-search corpus.
- Concurrent makers: all near-term work overlaps shared hot modules.

## Bounded evidence loop

Every admitted task follows:

1. Reconcile Git SHA, dirty paths, worktrees, ownership, loop-state revision,
   detailed task plan, and current official external facts.
2. Write or confirm the expected RED test through a public seam.
3. Run the exact focused test and record why it failed.
4. Implement the smallest change that can satisfy that test.
5. Run focused tests, public-boundary tests, full applicable suite, strict mypy,
   Ruff, schemas, build, and installed-wheel checks.
6. Commit only maker-owned files with DCO sign-off after maker self-review.
7. Produce an immutable review package from the recorded base to committed
   head.
8. Obtain independent checker acceptance from the immutable package and
   receipts; run only named focused canaries required for independent
   reproduction.
9. Update loop state and admit the next dependency only after acceptance.

Named gates:

- **Ownership gate** — evidence: `git status`, `git worktree list`, task
  inventory, and claimed paths; pass: no overlapping active owner and no
  unrelated dirty path is modified.
- **Behavior gate** — evidence: RED and GREEN test output; pass: RED fails for
  expected missing behavior and GREEN passes through the same public seam.
- **Regression gate** — evidence: full applicable pytest, mypy, Ruff, schema,
  build, and installed-wheel receipts; pass: every required command exits zero
  and result counts are non-empty.
- **Read-only gate** — evidence: before/after target and Git manifests; pass:
  exact equality for all protected target surfaces.
- **Continuity gate** — evidence: installed-wheel end-to-end cases; pass:
  protected fields match exactly or continuation refuses with the expected
  canonical finding.
- **Maintainability gate** — evidence: public-boundary tests and source import
  graph; pass: stable public exports, no new caller knowledge, and extracted
  internals have one named change axis each.
- **Checker gate** — evidence: independent inspection of immutable base/head,
  task brief, maker report, and receipts plus any justified focused canary;
  pass: no unresolved blocking standards or specification finding.
- **Release gate** — evidence: aggregate CI, provenance, SBOM, security,
  reproducibility, benchmark, and clean-runner receipts; pass: all required
  gates pass independently without suppression or waiver.

Reroute when target/source SHA, ownership, authority, supported runtime,
official action release, failure fingerprint, public interface, or accepted
specification changes. One local defect repairs the remaining plan; a changed
invariant or architecture contract requires a versioned plan revision.

## Learning and verdict

Development learning uses the existing loop-state `delta`, gate evidence, and
`failure_fingerprint`; do not create a duplicate memory track. Product
self-learning remains the governed Plan 3 mechanism and may promote only
bounded additive rules after immutable-corpus proof.

At each task close:

1. Record what failed, what evidence changed, and why the gate caught it.
2. Classify lesson as one-off task evidence or reusable prevention rule.
3. Promote a reusable rule only after recurrence or independent proof; never
   promote model preference or checker agreement as truth.
4. Preserve rejected candidates and rollback information.

**PASS:** Every named terminal gate passes on current exact-SHA evidence,
checker independence is complete, invariants hold, and loop-state revision
cites the receipts.

**FAIL:** A frozen acceptance criterion is disproved or an authorized finite
budget is exhausted without a valid safe replan.

**BLOCKED:** Required authority, current evidence, ownership, checker,
platform, benchmark budget, or external release gate is unavailable.

**Safe stop:** Preserve dirty work, immutable evidence, last accepted commit,
current failure fingerprint, and one exact next action. Never weaken a gate,
rewrite history, or broaden scope to obtain green output.

---

The numbered headings below are execution work packages, not eleven additional
implementation-plan tasks. They order and gate the 29 remaining tasks already
authorized by the persisted 38-task implementation budget. Maintainability
steps are folded into the approved task that first changes each hot module.

### Task 1: Close Plan 1 final-review remediation

**Files:**

- Preserve current modifications in `src/agent_continuity/api.py`
- Preserve current modifications in `src/agent_continuity/capture/base.py`
- Preserve current modifications in `src/agent_continuity/capture/git.py`
- Preserve current modifications in `src/agent_continuity/policy.py`
- Preserve current modifications in `src/agent_continuity/store/sqlite.py`
- Review `tests/integration/test_policy_target_coexistence.py`
- Review `tests/security/test_facade_target_admission.py`
- Review `tests/security/test_read_only_store_mode.py`
- Read the accepted Foundation Task 9 evidence and Plan 1 final review under
  `.superpowers/sdd/2026-08-08-01-foundation-checkpoint/`

**Interfaces:**

- Consumes: accepted Foundation Task 9 SHA
  `90b94814ac8147bcf833947cd1693bdb852682c8`, its controller/re-review
  receipts, the three Important Plan 1 final-review findings, and the current
  preserved worktree delta.
- Produces: clean, independently accepted Plan 1 head with installed-wheel
  proof and truthful README/PROVENANCE boundaries.

- [ ] **Step 1: Freeze adoption evidence**

```bash
git status --short --branch
git rev-parse HEAD
git diff --check
git diff --stat
git worktree list --porcelain
```

Expected before plan-admission commit: HEAD remains `90b94814...`; current five
modified source files and three untracked tests are visible; no unrelated path
is changed. After the plan-admission commit, record that new HEAD as the maker
base while retaining `90b94814...` as the immutable behavioral baseline.

- [ ] **Step 2: Reconstruct genuine RED against the immutable baseline**

Create a tests-only temporary checkout at `90b94814...`, copy only the three
current remediation test files into it, and run their focused command against
the unmodified baseline source. Record the expected missing-behavior failures
for policy/snapshot binding, original-path admission, and read-only SQLite.
Never copy current production modifications into the RED checkout; remove only
the tool-owned temporary checkout after its receipt is sealed.

- [ ] **Step 3: Adopt the preserved remediation and reproduce GREEN**

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/integration/test_policy_target_coexistence.py \
  tests/security/test_facade_target_admission.py \
  tests/security/test_read_only_store_mode.py
```

Expected current baseline: 11 tests pass. Any different result creates a new
failure fingerprint before editing.

- [ ] **Step 4: Run the complete Plan 1 remediation gate**

```bash
.venv/bin/python -m pytest -v -p no:cacheprovider
acg_mypy_bin="$(command -v mypy)"
acg_ruff_bin="$(command -v ruff)"
test -n "$acg_mypy_bin" && test -n "$acg_ruff_bin"
"$acg_mypy_bin" --no-incremental src/agent_continuity
"$acg_ruff_bin" check src tests tools
.venv/bin/python tools/verify_schemas.py
.venv/bin/python -m build
git diff --check
```

Expected: all required checks exit zero; installed-wheel tests report non-empty
cases; target manifests remain identical.

- [ ] **Step 5: Commit the maker-owned remediation**

After RED/GREEN, complete gates, and maker self-review pass, commit only the
five production files and three remediation tests with DCO sign-off. Do not
include this overlay, loop state, reports, or unrelated paths in the maker
commit.

- [ ] **Step 6: Generate immutable package and review**

Generate the Superpowers review package from the plan-admission base to the
committed maker head. A fresh checker reviews the package, task brief, maker
report, and gate receipts against the three Plan 1 findings. It does not rerun
the complete maker suite; it may run one named focused canary only when a
concrete doubt requires independent reproduction. Record exact accepted SHA
and receipts in loop state; otherwise enter the bounded fix loop.

### Task 2: Deepen Git capture and add stable live observation

**Files:**

- Modify: `src/agent_continuity/capture/git.py`
- Create: `src/agent_continuity/capture/_git_process.py`
- Create: `src/agent_continuity/capture/_git_locator.py`
- Create: `src/agent_continuity/capture/_git_proof.py`
- Modify: `tests/contract/test_capture_public_boundary.py`
- Modify: `tests/integration/test_git_capture.py`
- Create/modify the live-worktree and race tests owned by Plan 2 Task 1.

**Interfaces:**

- Consumes: existing `GitTargetAdapter(target)`, `read_target_policy()`,
  `capture(instruction_paths)`, context-manager, and close behavior.
- Produces: the same public interface with internal modules that callers cannot
  import through `agent_continuity.capture`, plus Plan 2 Task 1 stable
  live-worktree observations.

- [ ] **Step 1: Characterize public behavior before moving code**

Add contract assertions that `agent_continuity.capture.__all__` and public
signatures remain unchanged and that integration/security tests do not import
underscore-prefixed implementation modules.

- [ ] **Step 2: Extract bounded process execution**

Move `_BoundedResult`, process stop/drain logic, bounded invocation, executable
identity checks, sanitized environment construction, and deadline enforcement
to `_git_process.py`. Keep the internal interface limited to executing the
fixed ACG Git command vocabulary and returning bounded bytes/status evidence.

- [ ] **Step 3: Extract locator and proof logic**

Move descriptor-pinned directory/file observation and locator revalidation to
`_git_locator.py`. Move tree/index parsing, HEAD-index-worktree equivalence, and
canonical manifest construction to `_git_proof.py`. Do not export either module
from `agent_continuity.capture`.

After each extraction, run:

```bash
.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/contract/test_capture_public_boundary.py \
  tests/integration/test_git_capture.py \
  tests/security/test_no_target_writes.py
```

- [ ] **Step 4: Keep `GitTargetAdapter` as the deep module**

`git.py` continues to own orchestration and the public interface. Do not add a
second public adapter, generic command runner, plugin system, or configuration
surface merely to justify extraction.

- [ ] **Step 5: Implement stable live-worktree observation**

Execute Plan 2 Task 1 using its exact race, capability, and ephemeral-capture
RED/GREEN tests. New behavior belongs behind the internal locator/proof seams;
callers continue using `GitTargetAdapter` and the public capture coordinator.

- [ ] **Step 6: Verify locality and regressions**

Plan 2 live-worktree behavior must require changes in the responsible internal
module plus `GitTargetAdapter` orchestration, not duplicated parsing or direct
subprocess logic in callers. Run Plan 2 Task 1 completion gates plus all Plan 1
capture, target-read-only, and installed-wheel regressions before independent
review.

### Task 3: Complete evidence invalidation and verified resume

**Files:** Detailed behavior ownership is
`docs/plans/2026-08-08-02-evidence-resume-lineage.md` Tasks 2-4. The first
ResumeContext touch also owns the internal StateStore/Continuity extraction in
`src/agent_continuity/store/sqlite.py`, new `_sqlite_*` modules,
`src/agent_continuity/api.py`, new `_operations/*` modules, and their public
boundary tests.

**Interfaces:**

- Consumes: accepted stable live-worktree capture plus Plan 1 public kernel,
  store, and `Continuity` interfaces.
- Produces: `Citation`, `Evidence`, deterministic invalidation, and
  `ResumeContext` behavior through unchanged public seams, with SQLite
  lifecycle/transaction knowledge and Continuity operations localized behind
  private internal modules at their first feature touch.

- [ ] **Step 1:** Execute Plan 2 Task 2 strict Citation/v1 and Evidence/v1
  contracts.
- [ ] **Step 2:** Execute Plan 2 Task 3 direct/transitive invalidation with
  negative controls and planted mutants.
- [ ] **Step 3:** Before changing `api.py` or SQLite for ResumeContext, freeze
  public exports, signatures, exception and context-manager semantics, and
  canonical output in contract tests. Extract descriptor/connection/schema
  lifecycle and commit/reconcile/audit verification behind private SQLite
  seams; extract Continuity operation bodies by use case while keeping
  `Continuity` as the single public facade. Every internal module must hide one
  named invariant or change axis; reject shallow pass-through layers.
- [ ] **Step 4:** Execute Plan 2 Task 4 read-only ResumeContext and stale
  checkpoint refusal through those internal seams without changing public
  behavior.
- [ ] **Step 5:** Run Plan 2 focused gates plus all Plan 1, public-boundary,
  installed-wheel, concurrency, tampering, replay, and privacy regressions;
  obtain independent review before admitting lineage work.

### Task 4: Complete assignment and result lineage

**Files:** Detailed ownership is Plan 2 Tasks 5-6 only.

**Interfaces:**

- Consumes: accepted Citation/Evidence/ResumeContext records and existing
  StateStore multi-head CAS.
- Produces: same-machine `Assignment`, `AssignmentResult`, exact replay, and
  conflicting replay refusal.

- [ ] **Step 1:** Implement immutable same-machine Assignment contracts through
  Plan 2 Task 5 RED/GREEN gates.
- [ ] **Step 2:** Implement result acceptance, exact replay, conflicting replay,
  and atomic fault recovery through Plan 2 Task 6.
- [ ] **Step 3:** Run lineage substitution,
  parent/target/policy/ruleset-mismatch, crash, and replay regressions.
- [ ] **Step 4:** Obtain independent review before any context-handoff claim.

### Task 5: Deliver checkpoint to verified rehydration vertically

**Files:** Detailed ownership is Context Continuity Tasks 1-4.

**Interfaces:**

- Consumes: verified ResumeContext plus accepted `Assignment` and
  `AssignmentResult` records.
- Produces: bounded context policy, protected projection, retention manifest,
  atomic transition preparation, exact rehydration comparison, and
  continue-or-BLOCK result. Context Task 4 also produces the immutable
  `ContextHandoffLineageV1` consumed by Task 6.

- [ ] **Step 1:** Implement integer-only context threshold evaluation through
  Context Task 1 without claiming calibrated universal protection.
- [ ] **Step 2:** Implement protected projection and safe retention manifest
  through Context Task 2; untrusted summary text cannot enter authority.
- [ ] **Step 3:** Implement transition state machine and exact projection
  comparison through Context Task 3.
- [ ] **Step 4:** Enforce compaction, restart, and handoff acceptance through
  Context Task 4 with bounded retries and deterministic refusal.
- [ ] **Step 5: Add one installed-wheel vertical acceptance case**

The case must initialize a generic synthetic Git target, checkpoint protected
state, prepare a handoff, re-open from external SQLite state in a fresh process,
rehydrate canonical records, compare protected fields, and admit continuation.
Matched negative cases mutate one protected field, stale one required evidence
record, replace lineage, and truncate audit history; each must refuse.

- [ ] **Step 6:** Run full Plan 1, Plan 2, and context tests plus installed-wheel
  proof; independent checker reproduces raw positive and refusal cases.

### Task 6: Complete nested lineage and maintainability acceptance

**Files:** Detailed behavior ownership is Context Continuity Task 5. This task
also owns acceptance evidence for the StateStore/Continuity internal seams
introduced at their first feature touch in Task 3; it does not postpone or
repeat that extraction.

**Interfaces:**

- Consumes: accepted `Assignment`/`AssignmentResult`, Task 5
  `ContextHandoffLineageV1`, and unchanged public `SQLiteStateStore` and
  `Continuity` interfaces.
- Produces: bounded nested work-scope graph, parent/child provenance merge, and
  maintainability acceptance showing the internal modules preserve public
  exports and isolate their named change axes.

- [ ] **Step 1:** Implement bounded nested work-scope graph and provenance merge
  through Context Continuity Task 5.
- [ ] **Step 2:** Run cycle/depth, parent, target, policy, ruleset, lineage
  substitution, replay, crash, and evidence-merge regressions.
- [ ] **Step 3:** Re-run public-boundary and source-import-graph tests proving
  Task 3's SQLite and Continuity internal seams remain private, non-pass-through,
  and behaviorally identical at the public facade.
- [ ] **Step 4:** Obtain independent behavior and maintainability acceptance
  before generic integration work.

### Task 7: Complete generic integration needed by context boundaries

**Files:** Detailed ownership is Hardening Plan Task 1 and Context Continuity
Task 6.

**Interfaces:**

- Consumes: accepted context facade and existing canonical kernel records.
- Produces: bounded data-only generic JSON/stdin translation and aggregate
  generic capability contract.

- [ ] **Step 1:** Execute Hardening Task 1 malformed-request and valid-UNKNOWN
  RED/GREEN matrices.
- [ ] **Step 2:** Execute Context Task 6 capability, poisoning, external-event,
  and generic harness protocol tests.
- [ ] **Step 3:** Prove adapters translate data only and cannot select target,
  state, trust root, policy, command, or promotion authority.
- [ ] **Step 4:** Run the installed-wheel vertical acceptance path only through
  public CLI/facade/generic seams.

### Task 8: Implement governed deterministic improvement

**Files:** Detailed ownership is
`docs/plans/2026-08-08-03-governed-improvement.md` Tasks 1-8.

**Interfaces:**

- Consumes: immutable Findings, verified continuity transitions, installed
  artifact identity, and existing multi-head CAS.
- Produces: bounded additive Rule/v1 candidates, immutable-corpus proof,
  deterministic automatic promotion, one-promotion-per-operation, and
  append-only rollback.

- [ ] **Step 1:** Implement strict Rule/v1 grammar and deterministic evaluation.
- [ ] **Step 2:** Persist/deduplicate Findings and synthesize only fixed
  public-safe candidate templates.
- [ ] **Step 3:** Bind installed identity, trust root, corpus, and append-only
  ruleset generations.
- [ ] **Step 4:** Prove candidate behavior, mutants, replay, monotonicity, and
  byte-identical clean-process decisions.
- [ ] **Step 5:** Implement commit-time CAS promotion and append-only rollback.
- [ ] **Step 6:** Integrate automatic mode with the one-promotion bound and prove
  pure verify/resume remain side-effect free.
- [ ] **Step 7:** Run installed-wheel target/privacy invariance and independent
  checker gates. No model-generated code, open-ended rule, or human override is
  admitted.

### Task 9: Complete hardening and open-source readiness

**Files:** Detailed ownership is Hardening Plan Tasks 2-9.

**Interfaces:**

- Consumes: feature-complete generic ACG package.
- Produces: claims, privacy classification, capability evidence, hostile
  filesystem/transaction proof, public governance, CI, reproducible artifacts,
  SBOM, provenance, and no-publication release-candidate evidence.

- [ ] **Step 1:** Complete Claim/v1, conflict/supersession/freshness, CLI,
  privacy, and export-redaction tasks.
- [ ] **Step 2:** Complete explicit platform capability, hostile filesystem,
  no-target-write, transaction, audit, concurrency, and leakage gates.
- [ ] **Step 3:** Add `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`,
  public architecture, threat model, examples, CODEOWNERS, Dependabot,
  pull-request template, and independent CI/security/release-candidate
  workflows through Hardening Task 7. `SUPPORT.md` must direct security reports
  to `SECURITY.md`, separate support from vulnerability disclosure, and make no
  response-time promise that is not operationally staffed.
- [ ] **Step 4:** Resolve official action tags to current official 40-character
  commit SHAs during implementation and bind each repository/tag/SHA in
  `PROVENANCE.md`.
- [ ] **Step 5:** Build reproducible wheel/sdist, SPDX SBOM, artifact manifest,
  coverage/decision evidence, and installed-package proof.
- [ ] **Step 6:** Execute the local no-publication release-candidate gate and
  independently verify aggregate CI behavior. Do not upload or release.

### Task 10: Prove lost-in-the-middle containment and benchmark honestly

**Files:** Detailed ownership is
`docs/superpowers/plans/2026-08-13-lost-in-the-middle-containment.md` Tasks 1-6
and the frozen production benchmark specification.

**Interfaces:**

- Consumes: feature-complete installed release candidate and frozen benchmark
  contracts.
- Produces: immutable position triplets, per-position floors, paired
  non-inferiority scores, public corpus evidence, sealed-holdout evidence, and
  mechanically derived claim wording.

- [ ] **Step 1:** Before execution, record a six-task benchmark budget through
  an authorized loop-state amendment. Without it, stop `BLOCKED`.
- [ ] **Step 2:** Build position triplets and scoring without changing
  production trust semantics.
- [ ] **Step 3:** Prove structured probes and canonical rehydration are
  position-independent or safely refuse.
- [ ] **Step 4:** Freeze public corpus and run deterministic public evidence.
- [ ] **Step 5:** Freeze candidate and scoring contract before independent
  sealed-holdout execution; never feed holdout cases or labels back to makers.
- [ ] **Step 6:** Emit only claim wording mechanically supported by public,
  holdout, combined, position-specific, statistical, and safety gates.

### Task 11: Final exact-SHA release certification

**Files:** Release evidence and documentation paths defined by Hardening Task 9
and benchmark Task 6.

**Interfaces:**

- Consumes: one frozen candidate SHA, complete CI receipts, independent review,
  and benchmark results.
- Produces: `PASS`, `FAIL`, or `BLOCKED` release verdict. Publication remains a
  separate authorized action.

- [ ] **Step 1:** Freeze candidate SHA and reject any later byte change without
  rerunning all affected gates.
- [ ] **Step 2:** Reproduce build/install/smoke on clean runners for every
  supported platform cell.
- [ ] **Step 3:** Verify provenance, SBOM, action pins, source/public residue,
  licence, security, privacy, target-read-only, recovery, and benchmark
  evidence independently.
- [ ] **Step 4:** Confirm no critical false-PASS and every named comparator
  passes. Do not offset a failed gate with another metric.
- [ ] **Step 5:** Record final loop-state revision and exact evidence handles.
- [ ] **Step 6:** Stop before remote publication. Present the frozen release
  candidate and supported claim for Thomas's separate publication decision.

---

## Self-Refine checklist for this plan

Maximum two passes. Revise only the plan artifact.

1. **Coverage:** Every weak rating maps to tasks and gates: maintainability
   Tasks 3/6, feature completeness Tasks 1-8, open-source readiness Task 9,
   practical continuity Task 5, benchmarks/release Tasks 10-11.
2. **Simplicity:** No new framework, runtime dependency, service, tracker,
   daemon, provider, UI, or second public facade.
3. **Safety:** No target writes, gate weakening, dirty-work deletion, remote
   publication, hidden authority broadening, or maker self-certification.
4. **Vertical value:** Installed checkpoint/handoff/rehydrate/verify proof lands
   before governed improvement, broad public infrastructure, or benchmark
   claims.
5. **Maintainability:** Internal extraction follows feature touch, preserves
   public seams, and names one change axis per internal module.
6. **Evidence:** Every terminal claim has a current exact-SHA raw gate and an
   independent checker.
7. **Placeholder scan:** Reject unresolved placeholder language or unnamed
   future proof.
8. **Type/interface consistency:** Names used here match approved detailed plan
   contracts; detailed plans remain authoritative where this overlay does not
   repeat a signature.

## Execution handoff

Recommended execution is sequential subagent-driven development: one fresh
maker per admitted task and one fresh independent checker per immutable task
package. Inline execution is acceptable only with the same ownership,
checkpoint, and independent-review gates. First executable action is Task 1,
Step 1; no later task is ready until the three Plan 1 final-review findings are
committed, independently accepted, and recorded in loop state. Task 9 remains
complete and must not be re-dispatched.
