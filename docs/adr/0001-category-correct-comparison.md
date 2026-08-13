---
status: accepted
---

# Use category-correct comparison lanes

Agent Continuity Guard will not use one aggregate leaderboard for products with different purposes. ACG, Radogast, and context-drift-guard share the direct intent/session-drift lane; Djinn receives a Claude-specific lane; Context Fabric receives a code-state-staleness subset; barekit OmniContext, DriftGuard, and the DataHub context-drift agent receive capability scorecards. The MAS context-drift artifact supplies evaluation patterns and cases but is not ranked. This prevents a broad continuity guard, a memory product, a code-retrieval engine, and a domain agent from gaining or losing rank on capabilities they do not claim.

## Consequences

- A product appears in a leaderboard only when every scored case is common-core for that lane.
- Missing a claimed common-core capability is a measured failure, not an adapter workaround.
- Unsupported non-common capabilities are reported as not comparable and cannot affect rank.
- The only permitted superiority phrase is "best in tested scope," bound to frozen artifacts and results.
