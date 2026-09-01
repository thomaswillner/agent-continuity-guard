# Task 2 Maker Report

## Loop state revision 1

- Goal: preserve `GitTargetAdapter` public behavior while extracting bounded Git internals and adding stable live-worktree capture through the specified public interfaces.
- Success: genuine RED evidence, focused and complete gates exit zero with non-empty counts, exact target pre/post manifests match, owned source/tests/report are committed together with DCO.
- Invariants: exact pinned base at admission; target read-only; public `agent_continuity.capture` boundary preserved except specified additions; private Git modules remain unexported; no runtime/network/provider/OpenClaw/remotes/releases/publication activity; only brief-authorized paths mutate.
- Authority: local owned source/tests/report edits and one signed-off commit only. No target writes or external activation.
- Owner/topology: one sequential maker; no subagents or reviewers by binding brief.
- Primary implementation loop: TDD. Final conformance follow-up: PDCA. Rejected: Tree of Thoughts, monitor/retry, plan-execute-replan, META optimization, multi-agent coordination, runtime enforcement.
- Budget: one RED cycle per behavior cluster; at most two diagnostic attempts per distinct failure fingerprint; stop on base/ownership drift, target-write evidence, repeated unchanged failure, or need for a non-owned path.
- Gates: public-boundary characterization; live/race RED; live/race GREEN; mypy; Ruff; Plan 1 capture/security; full pytest; strict mypy; schemas; build; installed-wheel capture; exact target manifest; self-review; clean DCO commit.
- Current evidence: brief SHA-256 `941be94f8bc98a003e4572a9c93a78a30c9282d9c73d100437afc03c2a9d0b6b`; clean source HEAD `10219bd8b7b51e670b858d2949de866b7d7af3b8`.
- Verdict: `PASS` for the maker slice after the exact staged tree becomes the single DCO commit described below. Controller-owned independent review remains the next ordered gate.

## RED evidence

Public-boundary characterization preceded production work:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider tests/contract/test_capture_public_boundary.py
....                                                                     [100%]
4 passed in 0.12s
```

Production change named before tests: stable live Git/filesystem capture plus
race refusal/retry behavior did not exist; adding the detailed live/race test
files would fail at their public module boundary before any production
extraction or implementation.

Genuine pre-production RED, exact brief command:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
ERROR collecting tests/integration/test_live_worktree_capture.py
ImportError: cannot import name 'CaptureCoordinator' from 'agent_continuity.capture'
ERROR collecting tests/security/test_live_capture_races.py
ImportError: cannot import name 'CaptureCoordinator' from 'agent_continuity.capture'
2 errors in 0.12s
exit 2
```

This is the detailed brief's expected missing-filesystem/captured-view RED. The
single collection boundary gates all named behavior clusters in those files:
dirty tracked and nonignored-untracked Git, deterministic non-Git, raw-byte
identity, exact exclusions, symlink leaf, special-file refusal, bounded retry,
immutable cited bytes, leaf/ancestor replacement, hardlink, truncation,
path-census change, case collision, repeated instability, and non-capable
promotion.

## GREEN and focused gates

Initial live/race GREEN before extraction:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
...........s..                                                           [100%]
13 passed, 1 skipped in 2.11s
```

The skip was macOS case-insensitive filesystem inability to create two
case-distinct entries. It was replaced with platform-independent
case-colliding required identities. Fresh focused result:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
..............                                                           [100%]
14 passed in 1.94s
$ .venv/bin/python -m mypy src/agent_continuity/capture
Success: no issues found in 8 source files
$ .venv/bin/python -m ruff check src/agent_continuity/capture tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
All checks passed!
```

Failure-fingerprint accounting: one test-environment correction for macOS raw
filename legality, one behavioral correction for retry-aware repeated
truncation, one type correction for locator digests, and one formatting pass.
No unchanged fingerprint received two retries.

## Complete regression gates

Extraction and preserved-boundary regression receipt:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider tests/contract/test_capture_public_boundary.py tests/integration/test_git_capture.py tests/security/test_no_target_writes.py
230 passed, 1 skipped in 192.77s
```

The skip belonged to the pre-correction case-sensitive-filesystem setup; the
platform-independent replacement is part of the final tree and the focused
live/race gate subsequently passed all 14 cases.

Fresh complete repository suite before final report sealing:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider
576 passed in 337.13s (0:05:37)
```

The first full Ruff gate then found one owned-test formatting defect only:

```text
$ .venv/bin/python -m ruff check .
E501 Line too long (90 > 88)
tests/contract/test_capture_public_boundary.py:152:89
Found 1 error.
```

The signature assertion was line-wrapped without changing behavior. Final
static, schema, and complete final-tree gates:

```text
$ .venv/bin/python -m mypy src/agent_continuity
Success: no issues found in 30 source files

$ .venv/bin/python -m ruff check .
All checks passed!

$ .venv/bin/python tools/verify_schemas.py
{"schema":"SchemaVerification/v1","schema_count":25,"status":"pass"}

$ .venv/bin/python -m pytest -q -p no:cacheprovider
576 passed in 336.04s (0:05:36)
```

Wheel and sdist were built outside the worktree to an explicit unique
directory; both artifacts were non-empty and named by the build backend:

```text
$ .venv/bin/python -m build --outdir /tmp/acg-task2-build.aWfOYb
Successfully built agent_continuity_guard-0.1.0.dev0.tar.gz and agent_continuity_guard-0.1.0.dev0-py3-none-any.whl
/tmp/acg-task2-build.aWfOYb/agent_continuity_guard-0.1.0.dev0-py3-none-any.whl
/tmp/acg-task2-build.aWfOYb/agent_continuity_guard-0.1.0.dev0.tar.gz
```

Installed-wheel public workflow receipt:

```text
$ .venv/bin/python -m pytest -v -p no:cacheprovider tests/integration/test_installed_wheel_plan1.py
tests/integration/test_installed_wheel_plan1.py::test_installed_wheel_runs_complete_plan1_public_workflow PASSED [100%]
1 passed in 12.92s
```

Exact pre/post target-manifest assertions were rerun as named, non-empty
cases for dirty Git, non-Git filesystem, and public CLI target preservation:

```text
$ .venv/bin/python -m pytest -v -p no:cacheprovider tests/integration/test_live_worktree_capture.py::test_git_stable_capture_promotes_dirty_tracked_and_nonignored_untracked tests/integration/test_live_worktree_capture.py::test_filesystem_capture_is_deterministic_identity_bound_and_read_only tests/security/test_no_target_writes.py::test_public_cli_commands_preserve_target_and_keep_raw_inputs_external
tests/integration/test_live_worktree_capture.py::test_git_stable_capture_promotes_dirty_tracked_and_nonignored_untracked PASSED [ 33%]
tests/integration/test_live_worktree_capture.py::test_filesystem_capture_is_deterministic_identity_bound_and_read_only PASSED [ 66%]
tests/security/test_no_target_writes.py::test_public_cli_commands_preserve_target_and_keep_raw_inputs_external PASSED [100%]
3 passed in 10.53s
```

## Files and commit evidence

- Commit contract: one local commit with subject `feat: add stable live target capture` and `Signed-off-by` trailer; this report is committed in the same atomic change. The containing commit hash is necessarily recorded by the post-commit receipt, not self-referenced inside its own bytes.
- Production files: `src/agent_continuity/capture/base.py`, `src/agent_continuity/capture/coordinator.py`, `src/agent_continuity/capture/git.py`, `src/agent_continuity/capture/_git_process.py`, `src/agent_continuity/capture/_git_locator.py`, `src/agent_continuity/capture/_git_proof.py`, `src/agent_continuity/capture/filesystem.py`.
- Test files: `tests/contract/test_capture_public_boundary.py`, `tests/integration/test_live_worktree_capture.py`, `tests/security/test_live_capture_races.py`.
- Report: `.superpowers/sdd/2026-09-01-safe-simple-completion/task-2-report.md`.
- Authorized `tests/integration/test_git_capture.py` required no change and is not part of the commit.

## Self-review and concerns

- `git diff --check` exited zero before staging. Dirty source/test cardinality was exactly ten paths, all brief-authorized; no unrelated tracked or untracked path appeared.
- `src/agent_continuity/capture/__init__.py` has no diff. Its seven-name `__all__` remains unchanged; `_git_process`, `_git_locator`, `_git_proof`, `filesystem`, `CaptureCoordinator`, `CapturedView`, and `FileObservation` are not added to that root export list.
- Private Git modules own bounded process, descriptor locator, and proof construction respectively. `GitTargetAdapter` remains the orchestration/public deep module; no generic runner, plugin, daemon, provider, runtime dependency, or network route was added.
- Descriptor-pinned reads reject special files, hardlinks, leaf/ancestor replacement, truncation, path-census drift, case collisions, and repeated instability. Stable capture includes dirty tracked and nonignored-untracked Git identities and writes required analyzer bytes only under caller-owned external ephemeral storage.
- No target, remote, runtime, provider, OpenClaw, release, publication, or unrelated workspace mutation occurred. External build artifacts remain at `/tmp/acg-task2-build.aWfOYb`; they are intentionally outside the worktree.
- Failure-fingerprint budget: one full-Ruff formatting fingerprint was corrected once and passed on the next invocation. No unchanged fingerprint reached two attempts.
- Remaining concern: controller-owned fresh read-only checker and downstream package/release decisions remain pending. Maker does not certify those gates.

## Fix Round 1 — four Important findings

### Admission and RED

- Exact fix base: `dea9a865f62aed1036e143044dccf266b64eda50`; branch source status was clean before mutation.
- Review artifact: `.superpowers/sdd/2026-09-01-safe-simple-completion/task-2-review.md`; it remained read-only.
- Authorized fix paths: implicated capture source, existing focused tests, `tests/helpers/git_repo.py`, this report, and controller-authorized new contract path `tests/contract/test_git_process_vocabulary.py`.

All tests were added before production changes. Combined genuine RED:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider tests/contract/test_git_process_vocabulary.py tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
FFFFFF..F.............FFFFFFF                                            [100%]
14 failed, 15 passed in 2.99s
```

Failure allocation was exact: five arbitrary Git commands were admitted and
the generic `run_bounded` seam remained present; stable capture rejected one
tracked deletion as census drift; six materialization operations leaked raw
`OSError` (cleanup replaced the original failure); and same-byte leaf
replacement produced an equal target manifest.

### Finding 1 — separate index and tracked-worktree inventories

- Production: `src/agent_continuity/capture/git.py` now uses raw index entries as the index inventory, derives present tracked-worktree paths from the separately observed `ls-files --deleted -z` set, inventories nonignored untracked paths separately, and binds deleted tracked paths explicitly in the canonical inventory.
- Stability: before/after deleted, present tracked, and untracked censuses must all match. Missing tracked worktree bytes remain absent from `CapturedView.files`; requesting such missing bytes raises `CaptureRequestError`.
- Test: `tests/integration/test_live_worktree_capture.py::test_git_stable_capture_separates_index_and_tracked_worktree_census` covers modified, present, deleted, and untracked identities plus missing-required refusal.

### Finding 2 — fixed Git process vocabulary

- Production: `src/agent_continuity/capture/_git_process.py` retains bounded lifecycle mechanics only as private implementation. Imported seam `run_git` owns the sanitized environment and admits only the exact ACG observation vocabulary. Dynamic commit/tree/blob operands require lowercase 40- or 64-hex object IDs before argv construction.
- Integration: `src/agent_continuity/capture/git.py` no longer supplies arbitrary argv environments, allowed-code sets, or stdin to a generic process runner.
- Test: `tests/contract/test_git_process_vocabulary.py` rejects status, config injection, symbolic `HEAD`, cat-file option injection, and the retired cached census; it also proves no generic `run_bounded` attribute and admits a validated dynamic object ID.

### Finding 3 — sanitized ephemeral filesystem failures

- Production: `src/agent_continuity/capture/coordinator.py` maps mkdtemp/open/mkdir/write/fsync/close failures to the single sanitized `CaptureUnknownError` boundary, removes partial ephemeral roots when possible, suppresses cleanup replacement errors, and preserves the original `OSError` as cause.
- Test: `tests/security/test_live_capture_races.py::test_ephemeral_filesystem_failures_are_sanitized_unknown` covers six cases: mkdtemp, root open, nested mkdir, write, fsync, and cleanup failure masking.

### Finding 4 — exact target manifest

- Helper: `tests/helpers/git_repo.py::repository_write_manifest` now includes root plus every descendant and binds kind, device, inode, full mode/type, link count, UID/GID where available, size, ctime, mtime, and content or symlink-target digest.
- Test: `tests/security/test_live_capture_races.py::test_repository_write_manifest_detects_same_byte_leaf_replacement` preserves bytes, size, mode, and mtime across replacement and proves the leaf manifest still changes; it also proves root inclusion.

### GREEN and completion gates

Same combined focused command after minimal production fixes:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider tests/contract/test_git_process_vocabulary.py tests/integration/test_live_worktree_capture.py tests/security/test_live_capture_races.py
29 passed in 3.36s
```

After deterministic import formatting, the same focused gate remained green:

```text
29 passed in 3.47s
```

Complete final-tree gates:

```text
$ .venv/bin/python -m pytest -q -p no:cacheprovider
591 passed in 344.95s (0:05:44)

$ .venv/bin/python -m mypy src/agent_continuity
Success: no issues found in 30 source files

$ .venv/bin/python -m ruff check .
All checks passed!

$ .venv/bin/python tools/verify_schemas.py
{"schema":"SchemaVerification/v1","schema_count":25,"status":"pass"}
```

External-output package build:

```text
$ .venv/bin/python -m build --outdir /tmp/acg-task2-fix1-build.2sX6vU
Successfully built agent_continuity_guard-0.1.0.dev0.tar.gz and agent_continuity_guard-0.1.0.dev0-py3-none-any.whl
/tmp/acg-task2-fix1-build.2sX6vU/agent_continuity_guard-0.1.0.dev0-py3-none-any.whl
/tmp/acg-task2-fix1-build.2sX6vU/agent_continuity_guard-0.1.0.dev0.tar.gz
```

Installed-wheel and exact target-manifest receipts:

```text
$ .venv/bin/python -m pytest -v -p no:cacheprovider tests/integration/test_installed_wheel_plan1.py
tests/integration/test_installed_wheel_plan1.py::test_installed_wheel_runs_complete_plan1_public_workflow PASSED [100%]
1 passed in 13.48s

$ .venv/bin/python -m pytest -v -p no:cacheprovider tests/security/test_live_capture_races.py::test_repository_write_manifest_detects_same_byte_leaf_replacement tests/integration/test_live_worktree_capture.py::test_git_stable_capture_promotes_dirty_tracked_and_nonignored_untracked tests/integration/test_live_worktree_capture.py::test_filesystem_capture_is_deterministic_identity_bound_and_read_only tests/security/test_no_target_writes.py::test_public_cli_commands_preserve_target_and_keep_raw_inputs_external
tests/security/test_live_capture_races.py::test_repository_write_manifest_detects_same_byte_leaf_replacement PASSED [ 25%]
tests/integration/test_live_worktree_capture.py::test_git_stable_capture_promotes_dirty_tracked_and_nonignored_untracked PASSED [ 50%]
tests/integration/test_live_worktree_capture.py::test_filesystem_capture_is_deterministic_identity_bound_and_read_only PASSED [ 75%]
tests/security/test_no_target_writes.py::test_public_cli_commands_preserve_target_and_keep_raw_inputs_external PASSED [100%]
4 passed in 10.91s
```

### Fix-round self-review and commit contract

- Pre-report dirty cardinality was seven exact authorized paths; report is the eighth. `git diff --check` passed and `src/agent_continuity/capture/__init__.py` remains unchanged.
- Ruff initially found two import-order defects and one regex-style defect. Manual correction left one import-order fingerprint; the two-strike rule triggered a deterministic Ruff organizer pivot for that single authorized file, after which full Ruff passed.
- No deferred Minor undecodable-path fixture was changed. No loop state, brief, ledger, review package, unrelated path, subagent, network, provider, OpenClaw, remote, release, or publication action occurred.
- Fix commit contract: one local commit with subject `fix: close stable capture review gaps`, DCO trailer, and exactly the eight fix-owned paths. Containing hash is recorded by the post-commit receipt rather than self-referenced in this report.
- Maker verdict: `PASS` for Fix Round 1 once this exact report/source/test tree becomes that DCO commit. Fresh controller re-review remains required; maker does not certify independent acceptance.
