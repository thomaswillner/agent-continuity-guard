# Agent Continuity Guard v0.1 Implementation Roadmap

Specification: ../specs/v0.1-design.md

Implementation is split into four dependency-ordered plans. Each plan ends in
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

3. 2026-08-08-03-governed-improvement.md
   - Finding persistence and deduplication
   - Bounded additive rule DSL
   - Trusted corpus labels and mutation proof
   - Deterministic automatic/review promotion
   - Ruleset compare-and-swap, audit, and append-only rollback

4. 2026-08-08-04-hardening-release.md
   - Generic JSON integration
   - Structured Claim detectors and remaining CLI commands
   - Field classification and export redaction
   - Cross-platform capability truthfulness
   - Adversarial, crash, concurrency, and installed-wheel tests
   - CI, provenance, packaging, and public-release gates

Acceptance ownership:

| Design acceptance | Primary plan |
|---|---|
| 1-3 cited-byte and evidence invalidation | Plan 2 |
| 4 verified resume | Plan 2 |
| 5-6 assignment lineage and replay | Plan 2 |
| 7 Finding retention and deduplication | Plan 3 |
| 8-12 governed promotion, rollback, and deterministic replay | Plan 3 |
| 13 and 16 target read-only and state separation | Plans 1 and 4 |
| 14 public-safe provenance | Plan 4 |
| 15 installed artifacts and platform matrix | Plan 4 |
| 17 profile/verdict decision table | Plan 1 |
| 18 atomic crash recovery | Plans 1-4, finalized in Plan 4 |
| 19 field classification and redaction | Plan 4 |
| 20 explicit platform capability | Plans 1 and 4 |

Global execution rules:

- Use TDD at each named interface.
- Commit after every task, not after every small step.
- Do not start a later plan while an earlier plan is red.
- Guarded targets remain read-only in every test and command.
- No private reference source, prose, path, name, dataset, or fixture enters
  this repository.
- No release or remote publication occurs until Plan 4 gates pass.
