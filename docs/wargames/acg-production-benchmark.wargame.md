# ACG production and benchmark wargame

- Source plan: `docs/superpowers/specs/2026-08-13-production-benchmark-design.md`
- Prepared: 2026-08-13T00:00:00+02:00
- Decision deadline: none
- Scope: ACG repository implementation, isolated release artifacts, comparator adapters, public development corpus, sealed holdout, and release claims
- Out of scope: production runtime installation, provider enforcement, remote publication, credentials, private transcripts, and unrelated agent systems
- Protected state: guarded targets, frozen schemas and histories, competitor artifacts, holdout secrecy through final result freeze, raw benchmark evidence, and user-owned repository changes

## Objective and exit criteria

**Objective:** Reach a zero-waiver production release candidate and independently establish whether ACG is best in the frozen tested scope.

| Exit criterion | Verification proof | Owner | Status |
|---|---|---|---|
| Production artifact works | Clean installed-wheel end-to-end 12-cell Python/OS matrix and aggregate release report with every required gate passing | Maker then independent checker | open |
| Critical safety is preserved | Zero critical false-PASS rows and all planted critical mutants killed on public, holdout, and combined results | Independent checker | open |
| Comparison is fair | Reviewed translation-only adapters and common-core case manifest | Benchmark checker | open |
| Public benchmark passes | Raw per-case outputs, confusion matrices, floors, and statistics | Benchmark controller | open |
| Holdout remains independent | Candidate/result-freeze manifests, leak scan, checker custody, and signed result | Holdout checker | open |
| Holdout result is reproducible | Post-freeze cases, labels, generator, manifest, raw-output mapping, and clean-runner reproduction | Benchmark checker | open |
| Claim is truthful | Machine-readable claim record derived from final gate table | Release checker | open |

## Evidence and assumptions

### Verified current evidence

| Fact | Evidence source | Observed at |
|---|---|---|
| Current HEAD is `0e72273d4b79e9f3568365476fc9a1cf19ae3be0` and worktree was clean | `git rev-parse HEAD`; `git status --short --branch` | 2026-08-13 |
| 393 tests, mypy, Ruff, and 12 schemas pass but public-contract defects remain | Current test outputs and independent reviews | 2026-08-13 |
| Wheel builds and imports; installed `acg --help` fails with missing CLI module | Isolated Python 3.12 wheel smoke | 2026-08-13 |
| Direct comparison lane is ACG, Radogast, and context-drift-guard | Official repositories and category audit | 2026-08-13 |
| MAS artifact is an evaluation source, not a product competitor | Official repository scope | 2026-08-13 |

### Assumptions requiring validation

| Assumption | Current evidence | Confidence | Validation method | Owner | Deadline |
|---|---|---|---|---|---|
| Every direct product can consume enough common-core cases without semantic adapter logic | Public interfaces inspected | medium | Implement minimal adapters, then independent adapter review | Benchmark maker/checker | Before corpus freeze |
| Sealed holdout custody can exclude maker access through final result freeze | Process design only | medium | Checker proves separate storage, access log, and leak scan | Holdout checker | Before candidate freeze |
| Cross-platform live guarantees can be tested consistently | Specification requires matrix | medium | Clean CI runners plus platform-specific adversarial fixtures | Release maker/checker | Before RC |
| Performance ceilings can be portable and non-gameable | Current linear-write benchmark only | low | Freeze reference hardware, workloads, statistic, and slope rules | Performance checker | Before implementation plan approval |
| Radogast source/distribution mismatch can be resolved to one artifact | README and PyPI disagree | low | Pin one reviewed artifact and record rationale/digest | Benchmark controller | Before comparator freeze |

## Scenario response matrix

| Scenario | Trigger | Signal | Reaction | Counteraction | Owner | Rollback | Proof |
|---|---|---|---|---|---|---|---|
| Expected production pass | Every gate passes on frozen wheel | Aggregate report has all required PASS entries and matching digests | Send immutable artifact to independent checker | Preserve reproducible build and evidence bundle | Release controller; escalate any mismatch to user | Restore last verified artifact if checker rejects | Checker reproduces report and artifact hashes |
| Installed/source divergence | Wheel behavior differs from source tests | Installed smoke, schema, defaults, or output digest differs | Stop release and benchmark | Make installed artifact the authoritative test surface | Packaging owner; escalate after first mismatch | Discard candidate build, keep source history | Clean rebuild and installed matrix match |
| Critical false-PASS | Protected invalid case continues | Any public, holdout, or combined critical-stratum confusion row is false-PASS | Fail release and superiority claim immediately | Add regression and critical mutant before a new candidate | Safety checker; escalate immediately to user | Return to last verified commit; invalidate candidate | Zero critical false-PASS on public, holdout, and combined results |
| Middle-position loss is hidden by edge cases | Combined position result passes while middle bin fails or regresses | Per-position matrix or paired interval violates the frozen floor | Withhold containment claim and block RC | Immutable beginning/middle/end triplets and partition-local gates | Benchmark checker; escalate on first failure | Restore last verified candidate; never tune on holdout | Every position bin passes and middle-versus-edges lower bound is at least -0.02 |
| Position metadata leaks into product input | Adapter input contains position, base-triplet, partition, or expected-result metadata | Serialized product-input digest differs from reviewed neutral schema | Invalidate run and adapter | Separate label-free product input from checker mapping | Adapter checker; escalate immediately | Revert to reviewed adapter digest | Input inspection and planted leak mutants pass |
| Overblocking games score | Benign controls are blocked | False-block rate exceeds 5 percent or `UNKNOWN` dominates | Reject ranking result | Lexicographic floors and per-stratum reporting | Benchmark checker | Restore pre-tuning thresholds | Re-run shows floor pass without holdout tuning |
| Adapter adds intelligence | Adapter repairs, infers, or uses labels | Review finds semantic branch not required for interface translation | Exclude result and adapter | Translation-only contract plus mutation tests | Adapter checker | Revert adapter to last reviewed digest | Independent review and planted adapter mutants pass |
| Competitor artifact drifts | Retrieved bytes differ from frozen digest | Package/source checksum mismatch | Abort product run | Mirror exact allowed artifact or refreeze with new comparison version | Benchmark controller | Use prior verified artifact cache | Artifact digest matches manifest |
| Harness-native asymmetry | Product needs proprietary lifecycle | Neutral runner cannot reproduce documented behavior | Move product to named native lane | Separate lane and prohibit aggregate merge | Benchmark controller | Remove invalid neutral results | Lane manifest identifies harness and limits |
| Holdout leaks before result freeze | Maker artifact or context contains holdout material before final result freeze | Access log, similarity scan, or manifest detects exposure | Invalidate holdout and stop claim | Generate new holdout under new checker custody | Holdout checker; escalate immediately to user | Not reversible; replace holdout | New corpus ID, clean leak scan, independent custody proof |
| Holdout cannot be disclosed after result freeze | Legal, privacy, licensing, or third-party restriction blocks complete reproducibility package | Publication inventory lacks any case, label, generator, manifest, raw-output mapping, or scoring input | Withhold superiority claim and report independent certification only | Use a future fully publishable holdout for any superiority attempt | Release checker; escalate before claim approval | Withdraw draft claim record | Claim record says certification only and names disclosure limit |
| Checker contamination | Checker edits maker files or sees tuning loop | Git/provenance or session record shows role overlap | Reject certification | Fresh independent checker and immutable handoff | Controller | Re-run certification from frozen candidate | Checker provenance proves read-only independence |
| Performance denial of service | Latency or storage grows beyond frozen ceiling/slope | Benchmark table exceeds p95 or slope limit | Block RC; profile bounded failing workload | Anchor/suffix verification, resource admission, regression fixtures | Performance owner | Restore prior implementation artifact | Repeated controlled benchmark passes |
| Platform capability overclaim | Unsupported OS behavior reports verified | Platform adversarial case passes without required primitive | Block platform and RC claim | Explicit capability truth and `UNKNOWN` | Platform checker | Disable claim, not invariant | Platform matrix reports exact supported capability |
| Model-backed result is irreproducible | Provider/model output changes materially | Repeat distribution or identity falls outside contract | Keep result out of deterministic leaderboard | Separate nondeterministic lane and report distributions | Benchmark controller | Retain deterministic results only | Provider manifest and repeated observations published |
| Rollback corrupts frozen history | Fix rewrites schema/audit/corpus history | Historical digest or replay changes | Stop and recover from immutable base | Append-only migration and version boundary | Store checker; escalate immediately | Restore verified database/artifact copy | Full replay and historical digest match |

## Execution gates

- No-go conditions: any failed, waived, suppressed, or stale required production gate; unresolved critical/high defect; missing CLI; frozen compatibility failure; critical false-PASS on any partition or position; middle-position non-inferiority failure; product-input position leakage; pre-freeze holdout exposure; incomplete post-freeze holdout disclosure for a superiority claim; adapter semantic logic; artifact digest mismatch; checker contamination; required platform `UNKNOWN`; unreproducible installed artifact
- Required human approvals: written specification approval before implementation plan; production/runtime installation; provider enforcement; remote publication; any contract weakening
- Pre-execution checks: clean worktree, exact HEAD, ownership, plan dependency, red regression, artifact/corpus digest, authority and budget
- Minimum monitoring: focused test each edit, full applicable gates each slice, worktree/target manifest before and after, persisted loop-state revision at handoff
- Abort thresholds: first critical false-PASS, first target mutation, first holdout leak, first unauthorized artifact change, repeated unchanged failure fingerprint within fixed budget
- Rollback authority: controller may restore only through reversible repository changes or last verified artifact; frozen histories require append-only repair; user approves authority changes

## Priorities

| Priority | Scenario | Impact | Likelihood | Detectability | Recovery difficulty | Required decision |
|---|---|---|---|---|---|---|
| 1 | Critical false-PASS | critical; unsafe continuation | medium until full corpus exists | high with planted cases | medium | fail candidate immediately |
| 2 | Holdout leak before result freeze | critical; superiority evidence invalid | medium without custody controls | medium | high; corpus replacement | independent custody through result freeze |
| 3 | Installed/source divergence | high; users receive untested behavior | currently observed at CLI | high | medium | installed artifact becomes authoritative |
| 4 | Adapter adds intelligence | high; comparison becomes biased | medium | medium through review/mutants | medium | enforce translation-only seam |
| 5 | Performance denial of service | high for long sessions | current linear evidence makes likely | high with scaling fixture | high if store boundary is wrong | repair before RC |
| 6 | Platform overclaim | high; vendor-neutral claim false | medium | high with platform fixtures | medium | explicit capability truth |

## Cheaper-agent handoffs

| Task | Agent capability | Inputs | Bounded scope | Expected evidence | Timeout | Review owner |
|---|---|---|---|---|---|---|
| Comparator version refresh | Read-only repository auditor | Official URLs and prior manifest | Metadata, tags, releases, licenses, digests only | Signed refresh table | 30 minutes | Benchmark controller |
| Platform test execution | CI runner | Frozen wheel and test manifest | One OS/Python cell, no code edits | Raw command log and artifact digest | 45 minutes | Platform checker |
| Adapter standards review | Independent code reviewer | One adapter and public product docs | Translation seam only | Findings plus accept/reject | 30 minutes | Benchmark controller |
| Performance reproduction | Read-only performance runner | Frozen workloads and artifact | Named hardware/environment only | Raw samples and summary digest | 60 minutes | Performance checker |
| Holdout execution and disclosure | Independent checker | Frozen candidate and sealed corpus | One admitted run, no maker communication before result freeze; full package after freeze | Frozen result, raw digest, access proof, publication inventory | Fixed by holdout policy | Release controller |

## Decision

- Recommended action: proceed to implementation planning only after user approves the committed written specification
- Highest-priority no-go conditions: critical false-PASS, holdout leak, installed/source divergence, semantic adapter logic, target mutation, and unresolved critical/high findings
- Unresolved assumptions: common-core adapter feasibility, sealed custody implementation, portable performance ceilings, and Radogast artifact choice
- Next decision and owner: user reviews the committed specification; controller then writes the dependency-ordered implementation plan
