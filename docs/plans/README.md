# Agent Continuity Guard v0.1 Implementation Roadmap

Specification: ../specs/v0.1-design.md

Accepted context-continuity extension:
2026-08-09-02a-context-continuity-boundaries.md

Accepted lost-in-the-middle containment extension:
../superpowers/plans/2026-08-13-lost-in-the-middle-containment.md

Implementation is split into five dependency-ordered plans. Each plan ends in
working, independently testable software. Plans must execute in order.

1. 2026-08-08-01-foundation-checkpoint.md
   - Repository and package foundation
   - Canonical records and pure verdict kernel
   - External StateStore and audit anchors
   - Read-only filesystem/Git capture
   - Working policy-template, init, checkpoint, verify, and verify-audit commands

2. 2026-08-08-02-evidence-resume-lineage.md
   - Citation and Evidence records
   - Direct/transitive invalidation
   - Verified ResumeContext
   - Same-machine Assignment and AssignmentResult lineage
   - Exact and conflicting replay behavior

3. 2026-08-09-02a-context-continuity-boundaries.md
   - Deterministic rendered-ratio and cumulative-token thresholds
   - Versioned conservative-longrun-v2 defaults: 25/40/50% and 16K/24K/32K
   - Update/migration gates that fail closed on missing or raised built-in defaults
   - Below-threshold canonical-ID drift probes
   - Protected checkpoint projection and safe retention manifest
   - Compaction, restart, rehydration, and handoff boundaries
   - Verified meta-handoff lineage and adapter capability contract
   - Frozen synthetic >=90% detection / <=5% false-positive benchmark
   - Context-poison and authority-broadening refusal
   - Bounded nested work scopes with evidence provenance

   Lost-in-the-middle extension Tasks 1-5 execute after this plan's Tasks 1-5
   and before its Task 6. They add position-matched contracts, scoring, probe and
   transition containment proof, and isolated corpus execution.

4. 2026-08-08-03-governed-improvement.md
   - Finding persistence and deduplication
   - Bounded additive rule DSL
   - Trusted corpus labels and mutation proof
   - Deterministic automatic/review promotion
   - Ruleset compare-and-swap, audit, and append-only rollback

5. 2026-08-08-04-hardening-release.md
   - Generic JSON integration
   - Structured Claim detectors and remaining CLI commands
   - Field classification and export redaction
   - Cross-platform capability truthfulness
   - Adversarial, crash, concurrency, and installed-wheel tests
   - CI, provenance, packaging, and public-release gates

   Lost-in-the-middle extension Task 6 executes only after this plan passes. It
   adds claim derivation, full position gates, and exact 12-cell installed-artifact
   aggregation without weakening any existing release gate.

Acceptance ownership:

| Design acceptance | Primary plan |
|---|---|
| 1-3 cited-byte and evidence invalidation | Plan 2 |
| 4 verified resume | Plan 2 |
| 5-6 assignment lineage and replay | Plan 2 |
| Context budget, protected projection, rehydration, and handoff | Context Continuity Plan |
| Nested work-scope provenance and safe pruning | Context Continuity Plan |
| 7 Finding retention and deduplication | Governed Improvement Plan |
| 8-12 governed promotion, rollback, and deterministic replay | Governed Improvement Plan |
| 13 and 16 target read-only and state separation | Foundation and Hardening Plans |
| 14 public-safe provenance | Hardening Plan |
| 15 installed artifacts and platform matrix | Hardening Plan |
| 17 profile/verdict decision table | Plan 1 |
| 18 atomic crash recovery | All plans, finalized in Hardening Plan |
| 19 field classification and redaction | Hardening Plan |
| 20 explicit platform capability | Foundation and Hardening Plans |

Global execution rules:

- Use TDD at each named interface.
- Commit after every task, not after every small step.
- Do not start a later plan while an earlier plan is red.
- Guarded targets remain read-only in every test and command.
- No private reference source, prose, path, name, dataset, or fixture enters
  this repository.
- No release or remote publication occurs until Hardening Plan gates pass.
