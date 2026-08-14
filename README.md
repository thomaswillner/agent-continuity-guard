# Agent Continuity Guard

Agent Continuity Guard (ACG) is an independent MIT-licensed implementation of
deterministic continuity checks for long-running agent work.

Status: design approved; implementation is not yet complete. No operational or
security claim should be inferred until the corresponding implementation task
and acceptance gate have landed.

ACG targets Python 3.11 or newer and will have no runtime dependencies.

## Plan 1 boundary

Plan 1 is limited to a clean local Git target. ACG observes that target; it
does not fetch, check out, reset, edit content, modify refs or index, change
configuration, install hooks, alter permissions, or write application metadata.
Its SQLite state must be placed outside both target and Git directory.

Available commands are `policy-template`, `init`, `checkpoint`, `verify`,
`verify-audit`, and `audit-anchor export`. Target commands require explicit
`--target` and external `--state-home` arguments. Repeating an identical `init`
is idempotent; changed initialization inputs refuse. `verify` evaluates the
selected checkpoint without advancing state.

`audit-anchor export --output PATH` writes canonical anchor data to an external
caller-selected path. An anchor is unsigned and tamper-evident, not authentic:
an attacker able to replace both the SQLite history and anchor can evade it.

Installed-artifact identity is the package name and version embedded in its
wheel (`agent-continuity-guard` / `0.1.0.dev0`) plus the installer-managed wheel
metadata. Build and inspect the exact wheel being evaluated; this repository
does not make a release or production-readiness claim.
