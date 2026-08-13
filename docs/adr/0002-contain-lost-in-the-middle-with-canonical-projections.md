---
status: accepted
---

# Contain lost-in-the-middle with canonical projections

Agent Continuity Guard will contain positional long-context failure through an external canonical protected projection, structured identity probes, and compare-before-continue transitions. Prompt duplication or reordering may improve recall but cannot establish continuity. Full-history retrieval may provide advisory evidence but cannot become authority because retrieval can omit, stale, or conflict records.

Prompt position remains benchmark metadata rather than a production trust field. The production kernel verifies record identities, digests, evidence freshness, authority, blockers, next action, assignments, and lineage independently of where narrative appeared in a provider context.

## Consequences

- Protected state is rebuilt from canonical records, never recursively from a summary or retrieval result.
- Missing or contradictory protected identity produces `UNKNOWN` or `BLOCK`; confident prose cannot produce `PASS`.
- Beginning, middle, and end variants share one immutable base-case identity and differ only in deterministic placement and distractors.
- Position is proven from exact product-visible byte offsets; token-position claims additionally require exact tokenizer identity and offsets from the frozen adapter.
- A tested containment claim requires zero critical false-PASS in every position bin, per-bin safety floors, and statistical non-inferiority of middle-position results to edge-position results.
- ACG may claim containment only in named tested lanes, artifacts, context layouts, lengths, workloads, and dates. It never claims to change transformer attention or guarantee arbitrary transcript recall.
