# Agent Continuity Guard

Agent Continuity Guard defines deterministic evidence and decisions for preserving long-running agent work across drift, compaction, restart, and handoff.

## Language

**Continuity**:
Preservation of verified goal, authority, evidence, lineage, and protected work state across a session boundary.
_Avoid_: Memory, context persistence

**Drift**:
A material divergence between current agent state or behavior and the verified protected continuity state.
_Avoid_: Any change, generic model error

**Lost-in-the-middle containment**:
Preservation or safe refusal of protected continuity when the same required fact appears at the beginning, middle, or end of otherwise equivalent long context. Containment does not claim to remove a model's positional-attention weakness.
_Avoid_: Solving attention, perfect recall

**Critical false-PASS**:
A result that permits continuation despite authority broadening, tampering, stale required evidence, lineage substitution, or an invalid protected handoff.
_Avoid_: False negative

**Common-core case**:
A benchmark case whose inputs and expected outcome are representable without product-specific capabilities by every product in its declared comparison lane.
_Avoid_: Universal case

**Comparison lane**:
A set of products with sufficiently overlapping purpose and observable behavior to share common-core cases and metrics.
_Avoid_: Market category, feature bucket

**Capability scorecard**:
A non-ranking evaluation of a specialized or adjacent product against only the capabilities it claims and exposes.
_Avoid_: Leaderboard

**Public development corpus**:
A versioned, inspectable set of benchmark cases available during implementation and calibration.
_Avoid_: Test set, holdout

**Sealed holdout**:
An independently controlled evaluation corpus whose labels and cases are unavailable to makers until the candidate, scoring contract, and final results are frozen, after which the complete reproducibility material is published.
_Avoid_: Private benchmark

**Best in tested scope**:
A qualified comparison claim earned only under the frozen products, artifacts, lanes, corpus, metrics, safety floors, platforms, and statistical rule named by the report.
_Avoid_: Best, best in the world

**Production-ready**:
All required release, security, compatibility, installed-artifact, platform, performance, mutation, and independent-review gates pass independently, with no waiver, suppression, offset, or stale evidence.
_Avoid_: Tests pass, release candidate
