# Task 8 maker report

## Loop state — revision 1

- Contract: expose `acg` subprocess commands `init`, `checkpoint`, `verify`,
  `verify-audit`, `audit-anchor export`, and `policy-template` with one canonical
  JSON value on stdout; success has empty stderr and no trailing newline.
- Success measure: brief-owned contract and integration tests pass; command output,
  exit mappings, anchor safeguards, schema parity, static checks, full suite, and
  installed-wheel smoke produce current evidence.
- Invariants: preserve public `Continuity.verify(checkpoint="latest") ->
  EvaluationResult`; use `verification_result_payload`; no target writes, network,
  shell, kernel impurity, raw diagnostics, runtime dependencies, overwrite, or
  unauthorised scope expansion.
- Authority: maker owns only Task 8 brief files plus additive `Error/v1` schema
  registry/verifier changes. Controller owns independent acceptance, Task 9, push,
  merge, install, and activation.
- Seams agreed by task brief: public `acg` subprocess command boundary and public
  `Continuity` facade/store behavior. The brief explicitly requires failing
  subprocess/public tests before production implementation.
- Primary loop: TDD. Outer loop: contract-control. Wrapper: controller-owned
  maker-checker evaluation. Rejected: plan-execute-replan (no admitted replanning
  contract), monitor-retry (no classified transient operation), and META
  optimization (no isolated evaluation corpus).
- Budget: 12 bounded evidence attempts; one full suite; stop on required
  out-of-scope file, irreversible/security/external effect, or exhausted evidence
  budget with unchanged failure fingerprint.
- Gates: RED command must fail because `agent_continuity.cli` is absent; GREEN
  focused tests, schema verifier, mypy, Ruff, Plan 1 compatibility/security,
  full suite, diff/secret scan, and isolated installed-wheel smoke must each have
  captured results. Independent checker status remains pending controller action.
- Learning: no memory promotion; user did not authorize a memory write.

## Evidence log

- Baseline: `38c236f6f0108c35879411280e3d02ea630a26ff` on
  `agent/task4-dataclass-remediation`; worktree status was clean before Task 8
  changes.
- RED: `.venv/bin/python -m pytest tests/contract/test_cli_output.py
  tests/integration/test_cli_plan1.py -v` collected five tests: one explicit
  missing-module assertion passed and four intended command-contract tests failed
  because `agent_continuity.cli` did not exist. No production file was changed
  before this command.
- GREEN: same focused command passed all five tests after command/output/schema
  implementation. A dirty worktree initially surfaced `CaptureUnknownError` as
  exit 3; diagnostic invocation proved that exception class, and the CLI now maps
  protected UNKNOWN capture to the required exit 1.
- Static/schema: `.venv/bin/python tools/verify_schemas.py` passed with 25
  schemas; `.venv/bin/python -m mypy src` passed for 26 source files; and
  `.venv/bin/python -m ruff check .` passed.
- Plan 1 compatibility/security command was launched with `test_plan1_schemas`,
  policy, initialize, checkpoint, verify, and security tests. Harness captured
  progress through 38 percent but did not return a terminal summary.
- Full suite: `.venv/bin/python -m pytest -q` was launched once at final HEAD in
  an attached terminal. It remained silent beyond the bounded observation window
  and was terminated without a terminal verdict. This is an incomplete gate, not
  a passing claim.
- Installed artifact: isolated wheel build and isolated `pip install` succeeded.
  First all-command smoke harness stopped before command invocation because its
  local executable-path variable was not exported. Corrected all-command smoke
  was launched but this harness again supplied no terminal verdict. Treat installed
  command proof as incomplete; do not infer a PASS from build/install.
- Hygiene: `git diff --check` passed. Exact changed-path secret-candidate scan
  returned no matches; scan emitted file names only by design.

## Scope and concerns

- Scope: only files authorized in maker task payload and this required report.
- Concern: command argument spellings and JSON response envelopes are not fully
  enumerated by brief. Rule locally from existing public API/schema conventions;
  cost if wrong is contract incompatibility, bounded by subprocess tests and
  controller checker.
- Concern: full-suite and installed-command terminal gates lack a terminal result
  from this execution harness. Controller should rerun them independently before
  acceptance. Independent checker remains controller-owned and pending.
