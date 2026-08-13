# Agent Continuity Guard production and benchmark design

Status: approved design decisions; written specification pending user review

Date: 2026-08-13

## 1. Objective

Deliver Agent Continuity Guard (ACG) as a production-ready, vendor-agnostic drift and continuity detector. Establish any superiority claim through a reproducible, category-correct comparison against frozen competitor artifacts and a public development corpus plus an independently controlled sealed holdout.

Production readiness and comparative superiority are separate gates:

1. ACG is production-ready only when every required release gate passes. No required production gate may be waived, suppressed, relabeled informational, or offset by another result.
2. ACG may claim "best in tested scope" only after it is production-ready and independently wins the applicable frozen comparison under this specification.
3. Failure to win does not weaken production requirements. Winning before production readiness cannot authorize a release or claim.

## 2. Approved decisions

- Use category-correct leaderboards and separate capability scorecards.
- Permit no production-gate waiver; every required gate must pass independently.
- Use only the qualified claim "best in tested scope."
- Use an inspectable public development corpus and an independently controlled sealed holdout.
- Support and verify the full 12-cell matrix of Python 3.11, 3.12, 3.13, and 3.14 on macOS, Linux, and Windows.
- Keep the core contract provider, model, operating-system, harness, and tool neutral.
- Keep provider-specific and harness-native adapters outside the neutral core and evaluate them in named lanes.

## 3. Current baseline and required remediation

The current baseline is commit `0e72273d4b79e9f3568365476fc9a1cf19ae3be0`. It contains foundation work through Plan 1 Task 4. Fresh evidence shows:

- 393 tests pass; strict mypy, Ruff, and the 12-schema verifier pass.
- A wheel builds and imports in an isolated Python 3.12 environment.
- Installed `acg --help` exits 1 because `agent_continuity.cli` does not exist.
- Public dataclass contracts for `AuditEventDraft` and `Finding` are broken.
- Frozen `AuditEvent/v1` schema compatibility and audit-details compatibility are incomplete.
- Contradictory `EvaluationResult` and `AuditVerification` objects are constructible.
- Public capture and foundational records accept invalid states by construction.
- malformed Git output can produce false-clean evidence.
- case-insensitive path identity and collision enforcement are incomplete.
- ordinary SQLite writes replay full history and scale linearly per commit.
- resource limits differ from the approved design and are not identity-bound.
- implementation plans 1 through 5 contain 38 dependency-ordered tasks; four are implemented.

These are release blockers. Existing green tests are supporting evidence, not proof of production readiness.

## 4. System boundaries

### 4.1 Neutral core

The neutral core owns:

- canonical records and identities;
- evidence freshness and invalidation;
- protected continuity projection;
- drift and continuity findings;
- deterministic verdict and transition rules;
- assignment, result, checkpoint, handoff, and meta-handoff lineage;
- append-only audit and trusted anchors;
- adapter capability truth;
- field classification and redaction;
- benchmark case, observation, and result schemas.

The neutral core does not import provider SDKs, inspect provider configuration, call models, install hooks, select operational loops, or grant authority.

### 4.2 Capture and store adapters

Capture adapters translate read-only environment observations into neutral records. Store adapters persist canonical records and audit evidence outside guarded targets. Missing platform guarantees produce explicit `UNKNOWN` or an unsupported capability; they never silently downgrade a requirement.

### 4.3 Product benchmark adapters

Each comparator receives a separate process adapter with this conceptual interface:

```text
prepare(frozen_artifact, environment_manifest) -> PreparedProduct
execute(prepared_product, BenchmarkCase/v1) -> RawObservation/v1
normalize(raw_observation) -> ProductDecision/v1
```

Adapters may only install the frozen artifact, translate a common-core case into its documented public interface, capture raw output, and map documented outcome fields into the neutral result schema. They may not add detection logic, repair inputs, infer missing results, tune per-case thresholds, retry semantic failures, or read expected labels.

Every adapter is independently reviewed. Raw stdout, stderr, exit code, duration, resource use, artifact identity, and environment identity are retained. An adapter error is not converted into a correct detection.

## 5. Comparison taxonomy

### 5.1 Direct intent/session-drift leaderboard

- Agent Continuity Guard: candidate installed wheel and source commit.
- Radogast: source commit `bcdc28d8d9facba960848263ca71b7bd4d8dbea8`; distribution identity must be selected explicitly because source reports 0.1.10 while PyPI latest is 0.1.9.
- context-drift-guard: source commit `e471f9f3d0ca0b0e9083b6efd65e135c6ef91ec2`; source installation only because the advertised PyPI distribution is absent.

### 5.2 Harness-native lane

- Djinn: source commit `775eeb2fa703fc4e098f924a9ae8d2c62be15539`; evaluated only in a pinned Claude Code harness because its hooks and compaction lifecycle are product-native.

Harness-native results may not be merged into the neutral leaderboard.

### 5.3 Code-state-staleness subset

- Agent Continuity Guard.
- Context Fabric tag `v1.2.2`, commit `0462552938161f858f31a631d99e40c7d4fc9ade`, npm integrity `sha512-xfnrpCkc/6LToIGgM7kXDRiVXGTIahDcm1YqlkXd8rk++RIMnSt8+QqpQhy2UGLLug7EwOIN5aosbefPCn9kCw==`.

Context Fabric runs only in disposable repositories because its documented initialization installs a Git hook and writes project-local state. Target-write behavior is reported separately and cannot satisfy ACG's read-only safety gate.

### 5.4 Capability scorecards, not rankings

- barekit OmniContext 0.4.0: task persistence, blockers, summaries, locks, and handoff state.
- DriftGuard: semantic failure/success recurrence memory.
- DataHub context-drift agent: schema and documentation drift in a DataHub environment.
- steeltroops OmniContext, h4sht OmniContext, DjinnBot, and unrelated name collisions are excluded from continuity rankings.

### 5.5 Evaluation source

`agenteval611/context-drift-mas-artifact` commit `961e1dc676c475b3607ee41a09308ae19046177a` supplies attack classes, propagation modes, ASR/PVR/BTSR separation, topology cases, raw-evidence conventions, and reproducibility patterns. It is not a product competitor.

## 6. Benchmark corpus

### 6.1 Case schema

Every `BenchmarkCase/v1` is content-addressed and contains only neutral data:

- case ID and corpus version;
- comparison lane and required common capabilities;
- protected goal, acceptance criteria, authority, lineage, and evidence identities;
- ordered observations or transition events;
- expected decision class;
- critical-safety stratum, if applicable;
- deterministic-oracle provenance or release-admitted human label provenance;
- resource budget and platform applicability;
- public-development or sealed-holdout partition marker without revealing holdout labels.

Case order is randomized from a committed seed after artifact freeze. Products receive identical logical cases and budgets within a lane.

### 6.2 Public development corpus

The repository contains at least 100 seeded material failures and 100 valid controls, expanded across these strata:

- goal omission, substitution, contradiction, and scope drift;
- authority broadening and instruction substitution;
- stale, missing, unstable, truncated, or contradictory evidence;
- direct and transitive content rot;
- checkpoint, actor, target, policy, ruleset, and lineage mismatch;
- clean compaction, restart, rehydration, and handoff controls;
- nested-scope cycles, orphaning, depth overflow, and provenance loss;
- poisoned summaries and acknowledgements;
- code-state staleness and unrelated-change controls;
- lexical paraphrase, vocabulary shift, multilingual text, and adversarial overlap;
- empty, malformed, oversized, and resource-exhaustion cases.

Labels, generator code, corpus digest, and expected public results are reviewable. Threshold tuning and implementation iteration may use only this partition.

### 6.3 Sealed holdout

The holdout is controlled by an independent checker outside the implementation repository and maker context. Before the checker receives the candidate:

1. candidate wheel, source commit, configuration, thresholds, adapters, scorer, environment images, and public-corpus results are frozen and hashed;
2. the maker declares implementation complete for evaluation purposes;
3. the checker verifies no holdout case, label, generator seed, or derived expected output is present in maker artifacts or session context.

The checker runs the frozen artifacts once, subject only to predeclared infrastructure retry rules. Cases, labels, generator, generator configuration and seed material, manifest digest, and the mapping from case IDs to raw outputs remain sealed through candidate freeze and final result freeze. Any leak before final result freeze invalidates the holdout and requires a new independently generated set.

After final result freeze, the complete holdout reproducibility package is published: cases, labels, generator and configuration, manifest digest, environment identity, per-case raw-output mapping, normalized decisions, scoring inputs, and aggregate results. A clean runner must be able to reproduce deterministic tables from this package. If law, privacy, licensing, or third-party restrictions prevent complete disclosure, the result may be reported only as an independent certification; ACG must withhold the "best in tested scope" claim.

## 7. Metrics and scoring

### 7.1 Outcome mapping

Each case maps product output into `PASS`, `WARN`, `UNKNOWN`, or `BLOCK`. A missing or malformed decision is `UNKNOWN`, never a correct detection. For a required protected transition, `UNKNOWN` cannot count as safe continuation.

### 7.2 Safety-first ordering

Comparison is lexicographic:

1. zero critical false-PASS results;
2. detection rate at least 90 percent and false-block rate at most 5 percent;
3. highest holdout macro-averaged balanced accuracy across predeclared common-core strata;
4. no statistically significant regression on any critical stratum;
5. secondary operational metrics.

The first two safety floors and every predeclared performance floor must pass separately on the public development corpus, the sealed holdout, and their combined results. A combined pass cannot mask a partition failure. The public corpus establishes development readiness; the sealed holdout is the primary superiority endpoint. A product that overblocks benign controls fails the false-block floor. A product that returns `UNKNOWN` for all cases cannot win.

### 7.3 Statistical rule

The scorer uses paired bootstrap resampling over immutable holdout case IDs with a predeclared deterministic seed and at least 10,000 replicates. ACG wins the primary endpoint only when:

- the paired 95 percent confidence interval for macro-balanced-accuracy difference has a lower bound above zero; and
- the point advantage is at least 0.02 absolute; and
- every preceding safety and performance floor passes.

Otherwise the comparison is a tie or loss. Multiple direct competitors require Holm correction for the family of primary pairwise comparisons. Confidence intervals and corrected p-values are reported with raw confusion matrices; significance cannot replace the practical-effect threshold.

### 7.4 Secondary metrics

- false-PASS and false-block counts by stratum;
- calibration error where confidence is exposed;
- correct recovery/refocus behavior;
- p50 and p95 cold/warm latency;
- latency slope across history sizes and total session work;
- peak resident memory, storage growth, installed bytes, and runtime dependencies;
- install success from documented instructions;
- deterministic repeatability;
- macOS, Linux, Windows, and Python-version coverage;
- target mutation and external side effects.

Secondary metrics may break an otherwise exact tie only under a predeclared ordering. They cannot compensate for a failed safety floor.

## 8. Production-readiness gates

No release candidate exists until all gates pass on the exact installed artifact:

1. all 20 v0.1 acceptance outcomes and the context-continuity extension pass;
2. no unresolved critical or high specification, security, compatibility, or standards finding;
3. public models are valid immutable states by construction or are explicitly private/factory-only;
4. frozen record versions replay and validate, or a versioned migration proves the boundary;
5. installed CLI commands work from a clean wheel with canonical output and documented exit codes;
6. every cell in the Python 3.11-3.14 by macOS/Linux/Windows matrix installs and passes on the exact candidate artifact; an unavailable required capability fails that cell, while an explicitly optional live capability is reported as unsupported and excluded from broader claims;
7. ordinary tests require no network and guarded targets remain byte-and-metadata read-only;
8. strict mypy, Ruff, schema verification, dependency audit, SAST, secret scan, and license/provenance checks pass;
9. at least 90 percent overall branch coverage and complete decision-outcome coverage for enumerated security decisions;
10. 100 percent generated-candidate mutant kill rate and every critical planted mutant killed;
11. crash, concurrency, CAS, audit mutation, reorder, link-loss, and anchored-truncation suites pass;
12. performance ceilings and history-scaling slopes pass on named reference hardware;
13. wheel and source distribution build twice reproducibly, install, and run end to end;
14. SBOM, wheel RECORD rehash, canonical artifact manifest, and CI provenance attestation are generated;
15. full audit verification reaches the release head;
16. independent standards and specification checkers accept immutable maker artifacts;
17. public development benchmark safety and performance floors pass independently;
18. sealed holdout safety and performance floors pass independently, combined-result floors pass, and the frozen holdout primary endpoint has a tie, loss, or win verdict;
19. final source tree and release artifact contain no private residue or holdout leakage;
20. aggregate release verifier reports no required `BLOCK`, `UNKNOWN`, omission, or stale evidence.

Every gate names raw proof. A planned test, a source edit, CI configuration, or a maker assertion is not passing evidence.

## 9. Performance contract

Correctness remains primary, but unbounded verification work is a denial-of-service risk. The implementation plan must replace full-history verification on ordinary commits with trusted-anchor/head plus affected-suffix verification while retaining explicit full replay.

Before implementation, performance fixtures will freeze:

- history sizes, record sizes, target sizes, and concurrency levels;
- reference hardware and OS identity;
- warmup, repetitions, statistic, and environmental controls;
- absolute p95 ceilings and permitted latency/storage slopes;
- failure behavior when resource limits are exceeded.

Resource limits are policy- and target-identity-bound. Changing a limit creates a new identity and cannot silently change evidence semantics.

## 10. Error handling and isolation

- Invalid case, schema, adapter, or product output fails closed with a typed record.
- Infrastructure failures are distinct from product `UNKNOWN` and semantic failure.
- Retry is permitted only for classified transient, idempotent infrastructure operations under a fixed attempt and deadline budget.
- Product semantic failures are never retried into success.
- Every product runs in an isolated environment with network disabled after artifact acquisition unless its declared lane requires a separately recorded provider call.
- No benchmark product may read another product's files, outputs, expected labels, or holdout material.
- Time, locale, encoding, CPU allocation, memory allocation, and random seeds are recorded and normalized where supported.

## 11. Evidence artifacts

Every comparison run produces:

- benchmark and scorer version;
- source commit, tag/version, distribution URL, license status, and artifact digest for each product;
- adapter source and digest;
- environment image/runner identity;
- case-manifest digest and partition identity;
- per-case raw observation and normalized decision;
- confusion matrices and stratum tables;
- bootstrap inputs, seed, replicates, intervals, corrections, and tie verdict;
- performance and resource tables;
- target-mutation manifest;
- command transcript stripped of secrets;
- independent checker identity and decision;
- one machine-readable final claim record.

Results are reproducible only when a clean runner can verify artifact hashes and regenerate the same deterministic tables. Public-development evidence is published when frozen. Holdout evidence is published as the complete reproducibility package only after final result freeze, as required by section 6.3. Model-backed lanes report observed distributions and provider identities separately; they never inherit deterministic claims.

## 12. Claim contract

Permitted:

> Agent Continuity Guard was best in the tested scope documented by this report. The report names every lane, competitor artifact, corpus version, platform, and evaluation date. ACG passed every required safety and performance floor and exceeded each direct competitor on the predeclared holdout primary metric under the published statistical rule.

Forbidden:

- best drift detector;
- best in the world;
- prevents 90 percent of real-world drift;
- vendor-agnostic because one provider adapter worked;
- production-ready based only on source tests;
- zero false positives without naming corpus and confidence interval.

If the holdout primary interval or practical threshold does not establish a win, the report says tie or loss. If any public, holdout, or combined safety or performance floor fails, no superiority claim is emitted. If the complete post-freeze holdout reproducibility package cannot be published, the report may state an independent certification but cannot claim "best in tested scope."

## 13. Delivery sequence

1. Repair confirmed Tasks 1-4 public contracts, frozen compatibility, fail-closed capture, constructor invariants, and ordinary-write verification boundary using red regression tests.
2. Complete Plan 1 Tasks 5-9, including working installed CLI and Plan 1 end-to-end proof.
3. Complete evidence invalidation, resume, assignment, and replay plan.
4. Complete context thresholds, protected projections, handoff, nested provenance, generic capability contract, and public development corpus.
5. Complete governed improvement and immutable promotion proof.
6. Complete generic JSON integration, privacy, cross-platform behavior, hardening, provenance, and release automation.
7. Freeze neutral comparator adapters and public benchmark results.
8. Freeze candidate and run sealed holdout through an independent checker.
9. Freeze final results, publish the complete holdout reproducibility package, and verify clean-runner reproduction.
10. Run aggregate release certification.
11. Publish only the claim supported by final evidence.

Each slice uses red test, minimal implementation, focused verification, full applicable gates, immutable maker handoff, and independent checker review. A later slice cannot waive or weaken an earlier invariant.

## 14. Safe stop and rollback

At any failed gate:

- retain current evidence and exact failure fingerprint;
- do not advance checkpoint, transition, release, or comparison claim;
- restore only through an append-only compatible transition or the last verified artifact;
- never rewrite frozen history or expected labels;
- invalidate contaminated benchmark or holdout results;
- require new evidence or an explicit authorized contract amendment.

No production installation, provider enforcement, remote publication, or release execution is authorized by this design.

## 15. Acceptance of this written specification

The specification is ready for implementation planning only after the user confirms that this committed document accurately captures the approved decisions. Implementation then begins with exact regression tests for the confirmed Tasks 1-4 defects; it does not skip to the benchmark harness while the product is incomplete.
