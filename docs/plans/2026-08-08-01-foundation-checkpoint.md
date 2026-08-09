# Foundation and First Honest Checkpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an installable zero-runtime-dependency Python package that captures a clean immutable Git target, commits atomic external checkpoints, verifies its audit chain, and exports/verifies external audit anchors.

**Architecture:** Pure `kernel` owns canonical identities, immutable records, and verdict aggregation. `capture` observes targets read-only. `store` owns SQLite transactions and audit linkage. `Continuity` orchestrates those deep modules. Plan 1 supports clean Git targets; Plan 2 adds live-worktree evidence and cited-byte invalidation.

**Tech Stack:** Python 3.11+, standard-library runtime (`argparse`, `dataclasses`, `hashlib`, `json`, `sqlite3`, `subprocess`, `tomllib`), setuptools, pytest, Hypothesis, jsonschema, mypy, Ruff, build.

## Global Constraints

- Licence: MIT.
- Runtime dependencies: none.
- State is external and disjoint from target and Git directory.
- ACG issues no target, Git-ref, index, configuration, hook, permission, or application-controlled metadata write.
- Git execution uses argv only, no shell or network, with lazy fetch, replacement objects, optional locks, global config, system config, and global ignores disabled.
- Kernel has no filesystem, clock, subprocess, environment, database, or network access.
- Canonical JSON has no floats, duplicate keys, control characters, unknown fields, or trailing newline.
- Identity-bearing paths retain exact raw bytes; display strings never define identity.
- Raw target and instruction bytes are never persisted.
- Stdout contains canonical ACG JSON only; diagnostics use stderr.
- No private reference source, prose, names, paths, hashes, datasets, or fixtures.
- Plan 1 creates and verifies checkpoints but does not implement Evidence, ResumeContext, Assignment, or promotion.

---

## File Map

- `pyproject.toml`: package, tool, and development dependency configuration.
- `src/agent_continuity/kernel/`: canonical records, models, and pure verdict evaluation.
- `src/agent_continuity/capture/`: read-only clean-Git observation.
- `src/agent_continuity/store/`: external path policy, SQLite CAS transactions, and audit.
- `src/agent_continuity/api.py`: Continuity facade.
- `src/agent_continuity/cli.py`: canonical JSON command adapter.
- `schemas/v1/`: strict public record schemas.
- `tests/`: golden, contract, integration, and security proof.

### Task 1: Add typed package and CanonicalJSON/v1

**Files:**

- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `README.md`
- Create: `CHANGELOG.md`
- Create: `PROVENANCE.md`
- Create: `SECURITY.md`
- Create: `src/agent_continuity/__init__.py`
- Create: `src/agent_continuity/py.typed`
- Create: `src/agent_continuity/kernel/__init__.py`
- Create: `src/agent_continuity/kernel/model.py`
- Create: `src/agent_continuity/kernel/canonical.py`
- Create: `tests/golden/test_canonical_v1.py`

**Interfaces:**

```python
JsonScalar = None | bool | int | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]
RecordId = NewType("RecordId", str)
Digest = NewType("Digest", str)
LogicalTime = NewType("LogicalTime", str)
SensitiveLocalText = NewType("SensitiveLocalText", str)


@dataclass(frozen=True, slots=True)
class StoredRecord:
    record_id: RecordId
    record_type: str
    schema_version: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class SensitiveLocalRef:
    digest: Digest
    kind: str


def canonical_bytes(value: JsonValue) -> bytes: ...
def canonical_loads(data: bytes) -> JsonObject: ...
def digest_bytes(data: bytes) -> Digest: ...
def validate_logical_time(value: str) -> LogicalTime: ...
def record_id(
    record_type: str,
    schema_version: str,
    payload: JsonObject,
) -> RecordId: ...
```

- [ ] **Step 1: Add packaging and public-boundary files**

Set distribution version `0.1.0.dev0`, `requires-python = ">=3.11"`, no runtime dependencies, `acg = "agent_continuity.cli:main"`, setuptools discovery under `src`, strict mypy, and Ruff target `py311`.

Development extras:

```toml
dev = [
  "build>=1.2,<2",
  "hypothesis>=6.112,<7",
  "jsonschema>=4.23,<5",
  "mypy>=1.11,<2",
  "pytest>=8,<9",
  "ruff>=0.6,<1",
]
```

README states design-only status until tasks land. PROVENANCE declares original ACG implementation and separates development-only dependencies from zero runtime dependencies. SECURITY states no private vulnerability details in public issues.

- [ ] **Step 2: Write failing canonicalization tests**

```python
def test_canonical_json_normalizes_semantic_strings_and_sorts_keys() -> None:
    value = {"z": 2, "name": "e\u0301"}
    assert canonical_bytes(value) == b'{"name":"\xc3\xa9","z":2}'


def test_domain_separated_record_id_matches_golden_vector() -> None:
    value = {"z": 2, "name": "e\u0301"}
    assert record_id("Example", "v1", value) == (
        "sha256:82b307ef376f1e81dc3ba17b2ab503c0bceef10dcf29d1136fe7150faa0d3422"
    )


def test_digest_and_logical_time_are_strict() -> None:
    assert digest_bytes(b"value").startswith("sha256:")
    assert validate_logical_time("2026-08-08T12:00:00Z") == (
        "2026-08-08T12:00:00Z"
    )
    with pytest.raises(CanonicalJSONError):
        validate_logical_time("2026-08-08 12:00:00")


@pytest.mark.parametrize("value", [1.5, float("nan"), "line\nbreak"])
def test_canonical_json_rejects_forbidden_values(value: object) -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_bytes({"value": value})  # type: ignore[dict-item]


def test_loader_rejects_noncanonical_or_duplicate_input() -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_loads(b'{"b":2, "a":1}')
    with pytest.raises(CanonicalJSONError):
        canonical_loads(b'{"a":1,"a":2}')
```

- [ ] **Step 3: Run RED**

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest tests/golden/test_canonical_v1.py -v
```

Expected: collection fails with ModuleNotFoundError for `agent_continuity.kernel.canonical`.

- [ ] **Step 4: Implement canonicalization**

```python
preimage = (
    b"acg\x00"
    + record_type.encode("ascii")
    + b"\x00"
    + schema_version.encode("ascii")
    + b"\x00"
    + canonical_bytes(payload)
)
return RecordId("sha256:" + hashlib.sha256(preimage).hexdigest())
```

Normalize semantic strings with NFC, reject U+0000-U+001F, floats, unsupported objects, and normalized-key collisions. Parse with `object_pairs_hook`, reject duplicates, and require `canonical_bytes(loaded) == input`. Digest strings are exactly `sha256:` plus 64 lowercase hexadecimal characters. LogicalTime is UTC RFC 3339 with `Z`, whole seconds, and canonical zero padding; ambient time is never read by validation.

- [ ] **Step 5: Run GREEN**

```bash
.venv/bin/python -m pytest tests/golden/test_canonical_v1.py -v
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
```

Expected: all commands pass.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .gitignore README.md CHANGELOG.md PROVENANCE.md SECURITY.md
git add src tests/golden
git commit -m "build: add typed Python package foundation"
```

### Task 2: Add PathIdentity/v1, strict records, and pure verdict kernel

**Files:**

- Modify: `src/agent_continuity/kernel/model.py`
- Create: `src/agent_continuity/kernel/paths.py`
- Create: `src/agent_continuity/kernel/records.py`
- Create: `src/agent_continuity/kernel/evaluation.py`
- Create: `src/agent_continuity/kernel/findings.py`
- Create: `schemas/v1/path-identity.schema.json`
- Create: `schemas/v1/path-scope.schema.json`
- Create: `schemas/v1/producer-identity.schema.json`
- Create: `schemas/v1/fact.schema.json`
- Create: `schemas/v1/finding.schema.json`
- Create: `schemas/v1/evaluation-result.schema.json`
- Create: `tests/contract/test_path_identity.py`
- Create: `tests/contract/test_kernel_evaluation.py`
- Create: `tests/contract/test_plan1_schemas.py`
- Create: `tools/verify_schemas.py`

**Interfaces:**

```python
class Verdict(StrEnum):
    PASS = "pass"
    WARN = "warn"
    UNKNOWN = "unknown"
    BLOCK = "block"


VERDICT_RANK = {
    Verdict.PASS: 0,
    Verdict.WARN: 1,
    Verdict.UNKNOWN: 2,
    Verdict.BLOCK: 3,
}


class Profile(StrEnum):
    OBSERVE = "observe"
    GUARD = "guard"
    STRICT = "strict"


class AssignmentAuthority(StrEnum):
    READ_ONLY = "read_only"
    SCOPED_WRITE = "scoped_write"


@dataclass(frozen=True, slots=True)
class ProducerIdentity:
    name: str
    version: str
    digest: Digest


@dataclass(frozen=True, slots=True)
class FactV1:
    field_path: tuple[str, ...]
    value: JsonScalar


@dataclass(frozen=True, slots=True)
class PathIdentityV1:
    encoding: Literal["posix-bytes", "git-path-bytes", "windows-utf16le"]
    raw_b64: str
    segment_offsets: tuple[int, ...]
    case_key_b64: str | None


class PathScopeKind(StrEnum):
    FILE = "file"
    TREE = "tree"


@dataclass(frozen=True, slots=True)
class PathScopeV1:
    path: PathIdentityV1 | None
    kind: PathScopeKind


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    verdict: Verdict
    subject_id: RecordId
    message_id: str
    parameters: JsonObject
    integrity_failure: bool = False


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    profile: Profile
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    verdict: Verdict
    transition_allowed: bool
    findings: tuple[Finding, ...]


def evaluate(case: EvaluationCase) -> EvaluationResult: ...
def make_record(record_type: str, payload: JsonObject) -> StoredRecord: ...
```

- [ ] **Step 1: Write failing raw-path tests**

Test round-trip for non-UTF-8 POSIX bytes, exact segment offsets, traversal/absolute/NUL/empty-segment rejection, case collision detection, and display text exclusion from identity. PathScope/v1 is exact FILE or component-aware TREE with no glob syntax; `path=None` is permitted only for TREE and denotes the target root. ProducerIdentity requires bounded public name/version plus digest. Fact/v1 requires a nonempty bounded field path and scalar canonical value.

- [ ] **Step 2: Write failing profile decision table**

Cover no findings, every single verdict under observe/guard/strict, integrity failure under all profiles, finding-order invariance, and stable canonical output.

```python
@pytest.mark.parametrize(
    ("profile", "verdict", "allowed"),
    [
        (Profile.OBSERVE, Verdict.BLOCK, True),
        (Profile.GUARD, Verdict.WARN, True),
        (Profile.GUARD, Verdict.UNKNOWN, False),
        (Profile.STRICT, Verdict.WARN, False),
    ],
)
def test_profile_decision_table(profile, verdict, allowed) -> None:
    result = evaluate(EvaluationCase(profile, (finding(verdict),)))
    assert result.verdict is verdict
    assert result.transition_allowed is allowed
```

- [ ] **Step 3: Run RED**

```bash
.venv/bin/python -m pytest tests/contract/test_path_identity.py tests/contract/test_kernel_evaluation.py -v
```

Expected: imports fail for path and evaluation modules.

- [ ] **Step 4: Implement path records and verdict aggregation**

```python
def evaluate(case: EvaluationCase) -> EvaluationResult:
    findings = tuple(
        sorted(
            case.findings,
            key=lambda item: (
                VERDICT_RANK[item.verdict],
                item.code,
                str(item.subject_id),
            ),
        )
    )
    verdict = max(
        (item.verdict for item in findings),
        key=VERDICT_RANK.__getitem__,
        default=Verdict.PASS,
    )
    if any(item.integrity_failure for item in findings):
        allowed = False
    elif case.profile is Profile.OBSERVE:
        allowed = True
    elif case.profile is Profile.GUARD:
        allowed = verdict in {Verdict.PASS, Verdict.WARN}
    else:
        allowed = verdict is Verdict.PASS
    return EvaluationResult(verdict, allowed, findings)
```

- [ ] **Step 5: Add schema parity verification and run GREEN**

Produced schema records validate; an added unknown field fails. `tools/verify_schemas.py` loads every schema, compares registered record types to schema IDs, validates golden positives, generates one unknown-field negative per object schema, emits canonical JSON, and exits nonzero on any mismatch. Run:

```bash
.venv/bin/python -m pytest tests/contract tests/golden -v
.venv/bin/python tools/verify_schemas.py
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/kernel schemas/v1 tests/contract tools/verify_schemas.py
git commit -m "feat: add canonical records and verdict kernel"
```

### Task 3: Add external state-root policy and read-only clean-Git capture

**Files:**

- Create: `src/agent_continuity/capture/__init__.py`
- Create: `src/agent_continuity/capture/base.py`
- Create: `src/agent_continuity/capture/git.py`
- Create: `src/agent_continuity/capture/coordinator.py`
- Create: `src/agent_continuity/kernel/capabilities.py`
- Create: `src/agent_continuity/store/__init__.py`
- Create: `src/agent_continuity/store/paths.py`
- Create: `schemas/v1/target-identity.schema.json`
- Create: `schemas/v1/capability-claim.schema.json`
- Create: `schemas/v1/instruction-manifest.schema.json`
- Create: `tests/helpers/git_repo.py`
- Create: `tests/contract/test_capture_public_boundary.py`
- Create: `tests/integration/test_git_capture.py`
- Create: `tests/security/test_state_root_separation.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class CapabilityClaimV1:
    name: str
    status: Literal["proven", "unsupported", "unknown"]
    adapter_id: str
    adapter_version: str
    evidence_digest: Digest | None


@dataclass(frozen=True, slots=True)
class TargetIdentityV1:
    adapter_id: str
    adapter_version: str
    sanitized_remote_identity_digest: Digest | None
    head_oid: str
    tree_oid: str
    index_manifest_digest: str
    worktree_manifest_digest: str
    inventory_digest: str
    status_digest: str
    git_object_manifest_digest: Digest
    ignore_provenance_digest: Digest
    platform_id: str
    filesystem_id: str
    physical_root_fingerprint: str
    capabilities: tuple[CapabilityClaimV1, ...]


@dataclass(frozen=True, slots=True)
class InstructionFileV1:
    path: PathIdentityV1
    blob_oid: str
    byte_digest: str


@dataclass(frozen=True, slots=True)
class CaptureSnapshot:
    target: TargetIdentityV1
    instructions: tuple[InstructionFileV1, ...]


class TargetAdapter(Protocol):
    def capture(self, instruction_paths: Sequence[bytes]) -> CaptureSnapshot: ...


def resolve_state_home(override: str | Path | None) -> Path: ...
def assert_external_state(
    target: Path,
    git_directory: Path | None,
    state_home: Path,
) -> None: ...
```

- [ ] **Step 1: Write failing state-root and capture tests**

Create a clean temporary Git repo with tracked README and AGENTS. Record HEAD, tree, status, index digest, refs digest, content manifest, config digest, hooks manifest, and permissions. Assert capture changes none.

Test deterministic repeat capture, dirty target UNKNOWN, missing instruction error, exact explicit instruction order, Git object type/mode and symlink-target identity, repository/local ignore provenance, sanitized remote identity, structured capability ordering, distinction between `unsupported` and `unknown`, and rejection of state inside target/.git or symlink aliases before directory creation. Remote credentials, query strings, and fragments must reject rather than enter identity.

The round-three RED set must exercise behavior, not source text:

- pin the requested top-level directory before the first Git command; a pathname replacement before or during discovery may yield the originally pinned target or UNKNOWN, but never a replacement target;
- prove all three clean-state equalities: captured HEAD tree equals the captured index, the captured index equals descriptor-read worktree bytes and modes, and no non-index path exists; staged, unstaged, mode-only, symlink-target, untracked, and ignored-only changes each yield UNKNOWN;
- install hostile clean/process-filter configuration and attributes at every capture phase and assert the sentinel program is never executed; adding another preflight sample is not an acceptable fix;
- classify an absent `.git` locator or a plainly invalid requested directory as a request error, while malformed, inaccessible, changing, or linked-worktree metadata and every abnormal, signalled, timed-out, overflowing, or malformed initial Git result yield UNKNOWN;
- return UNKNOWN for conversion-sensitive attributes/configuration, sparse or split indexes, skip-worktree, intent-to-add, unmerged stages, gitlinks/submodules, unsupported modes or object types, unknown or dual object formats, and filesystems whose executable-mode semantics cannot be proved;
- bind each tracked leaf plus every tracked-parent directory across repeated descriptor-rooted observations so ordinary writes and rename swaps yield UNKNOWN; do not claim atomic-snapshot or adversarial ABA protection;
- bound traversal depth, entry count, total path bytes, file bytes, Git stdout/stderr, and elapsed time; never follow a symlink directory; and
- keep these policies behind `TargetAdapter.capture()` so callers cannot opt into weaker hashing, ignore, conversion, or race behavior.

After the first direct-observer residual fix remained red, boundary hardening must use centralized validators and exhaustive public-interface matrices rather than isolated case checks:

- all nonempty NUL-delimited Git output passes through one canonical frame parser that requires exactly one terminal delimiter, forbids empty records anywhere, and rejects truncation or extra delimiters; an empty byte stream is the only valid zero-record frame;
- caller target input passes one validator before `Path`, encoding, or OS calls. It accepts only supported text path-like input, rejects empty/NUL/surrogate/unencodable values and over-budget bytes/components as request errors, and maps only positively invalid filesystem input classes to request errors; inaccessible or changing proof remains UNKNOWN;
- symbolic-ref content and each resolved ref path pass one strict grammar plus independent chain-count, total-byte, and component-count budgets no greater than the capture traversal limits. Cycles, malformed content, depth excess, and loose/packed terminal ambiguity are UNKNOWN, and every resolved dependency is re-observed;
- remote identity parsing examines every `remote.<name>.url` and `remote.<name>.pushurl`, rejects raw or encoded control/whitespace, credentials, query, fragment, helper syntax, unsupported schemes, names, ports, or grammar, and hashes canonical tuples containing remote name, fetch/push role, and normalized value. Swapping fetch and push roles must change identity;
- create `tests/contract/test_capture_public_boundary.py` as an AST architecture gate over Task 3 integration/security tests. Those tests may import and invoke only exported capture APIs and test-owned helpers; any direct production-private import, attribute, parser, runner, constant, or monkeypatch is a failure. Every removed private test retains an equal-or-stronger public wrapper/repository behavior probe, with collected-case inventory proving no silent coverage deletion.

The RED matrix must include single/extra/missing/interior NUL frames; empty and multi-record controls; NUL, lone-surrogate, unencodable, overlong-component, over-depth, missing, nondirectory, inaccessible, and symlink target inputs; ref grammar at and one beyond every byte/component/chain boundary; URL and pushurl schemes, roles, whitespace/control encodings, credentials, ports, queries, fragments, helper forms, duplicates, and role swaps. Use hand-derived literal outcomes and public `GitTargetAdapter` calls only.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest tests/integration/test_git_capture.py tests/security/test_state_root_separation.py -v
```

Expected: imports fail for capture and store paths.

- [ ] **Step 3: Implement descriptor-pinned conservative Git observer**

```python
environment = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
}
argv = [
    "git",
    "--no-pager",
    "-c",
    f"core.excludesFile={os.devnull}",
    "-C",
    os.fspath(target),
]
```

The example environment remains a minimum, not the containment mechanism. Resolve a trusted Git executable before entering target context. Open the requested directory component-by-component with no-follow directory descriptors before any Git discovery. Run every Git subprocess through constant Python `-I` bootstrap code that inherits only the pinned root descriptor, calls `fchdir`, closes the descriptor, and executes Git without a shell. Descriptor-read and pin a `.git` gitfile target, Git directory, and common Git directory component-by-component. Recheck their identities before returning.

Run with `shell=False`, a 30-second deadline, bounded in-flight stdout/stderr, disabled lazy fetch/replacements/hooks/fsmonitor/pager/prompt/network protocols, and sanitized system/global configuration roots. Only conversion-free plumbing may observe repository metadata. Allowed operations include bounded `rev-parse` identity/object-format queries, unfiltered object reads, `ls-files --stage -z`, and `ls-tree -rz --full-tree HEAD`. Never invoke `status`, `diff`, `check-attr`, `hash-object --path`, textconv, checkout, filtered object conversion, submodule traversal, or another command that can execute target-selected programs.

Pin raw index bytes and their digest, HEAD commit/tree OIDs, object-format identity, repository/local configuration and attribute sources, and all Git/common-directory evidence used by the decision. Compare canonical HEAD tree entries to index entries so staged additions, removals, content, type, and mode changes yield UNKNOWN. Support only index semantics proved safe by the adapter; sparse/split indexes, skip-worktree, intent-to-add, unmerged stages, unknown required extensions, gitlinks, and unsupported types yield UNKNOWN.

Compare each eligible index entry to descriptor-read worktree state. For regular modes `100644` and `100755`, hash exactly `b"blob " + decimal_length + b"\0" + content` using the proved repository SHA-1 or SHA-256 object format and compare executable semantics exactly. For `120000`, hash raw link-target bytes without following. Reject unknown or compatibility/dual object formats. Enumerate the worktree descriptor-rooted without following symlink directories; permit only tracked entries, their parent directories, and the pinned Git locator. Any other path, including an ignored path, yields UNKNOWN.

Conversion eligibility is fail closed. Any tracked or worktree `.gitattributes`, common/local/info attributes, config include, `filter.*.clean/process`, non-disabled `core.autocrlf`, non-default `core.eol`, or semantics involving `text`, `eol`, `ident`, `working-tree-encoding`, sparse checkout, or an unknown conversion source yields UNKNOWN. This eligibility check controls whether cleanliness can be proved; non-execution correctness comes mechanically from never invoking worktree-converting Git commands.

Repeat descriptor-rooted file, index, Git-metadata, configuration/attribute, and tracked-parent-directory observations before returning. Any device, inode, type, mode, link count, size, `ctime`, `mtime`, directory entry, digest, or relevant locator change yields UNKNOWN. This is a bounded seqlock, not an atomic snapshot; retain descriptor-pinned-read, immutable-object, network, and atomic-snapshot capability claims as `unknown` unless independently proved.

Derive `status_digest` from a canonical direct-proof record covering HEAD/index equality, index/worktree equality, absence of untracked paths, observer version, and eligibility evidence; do not store `git status` output. Git-object manifests retain raw path identity, object type, mode, OID, and symlink-target blob bytes. Every capability claim binds adapter identity/version and an evidence digest when proved. `unsupported` means a known adapter limitation; `unknown` means proof could not be established. Neither is equivalent to `proven`.

Only positively identified caller input faults are request errors. If `.git` exists but proof is unavailable, Git exits abnormally, output is malformed, or metadata changes, return UNKNOWN without exposing target bytes or unbounded diagnostics.

Implement these rules through one validator per boundary, not duplicated parser branches. Consolidate common/local Git metadata enumeration behind one descriptor-rooted helper so both worktree forms observe the same source set. The public adapter remains the only decision seam; helper functions are implementation details and receive no direct integration-test calls.

- [ ] **Step 4: Implement state path resolution**

Resolve macOS, Linux/XDG, Windows/LOCALAPPDATA, and absolute ACG_STATE_HOME override. Resolve existing ancestors without creating state. Refuse target/Git descendants and aliases.

- [ ] **Step 5: Run GREEN**

```bash
.venv/bin/python -m pytest tests/integration/test_git_capture.py tests/security/test_state_root_separation.py -v
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
```

Expected: all pass; target pre/post manifest is identical.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/capture src/agent_continuity/kernel/capabilities.py src/agent_continuity/store/paths.py
git add schemas/v1/capability-claim.schema.json schemas/v1/target-identity.schema.json schemas/v1/instruction-manifest.schema.json
git add tests/helpers tests/integration/test_git_capture.py tests/security/test_state_root_separation.py
git add tests/contract/test_capture_public_boundary.py
git commit -m "feat: capture clean git target identity"
```

### Task 4: Add atomic SQLite StateStore and audit anchors

**Files:**

- Create: `src/agent_continuity/store/base.py`
- Create: `src/agent_continuity/store/sqlite.py`
- Create: `src/agent_continuity/store/memory.py`
- Create: `src/agent_continuity/store/schema.sql`
- Create: `src/agent_continuity/kernel/audit.py`
- Create: `schemas/v1/audit-event.schema.json`
- Create: `schemas/v1/audit-anchor.schema.json`
- Create: `schemas/v1/audit-verification.schema.json`
- Create: `tests/integration/test_sqlite_store.py`
- Create: `tests/security/test_audit_tamper.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class HeadState:
    record_id: RecordId
    audit_event_id: RecordId
    audit_sequence: int


@dataclass(frozen=True, slots=True)
class AuditHeadState:
    audit_event_id: RecordId
    audit_sequence: int


@dataclass(frozen=True, slots=True)
class AuditEventDraft:
    kind: str
    subject_id: RecordId
    logical_time: LogicalTime
    details: JsonObject


@dataclass(frozen=True, slots=True)
class SensitiveLocalValueDraft:
    digest: Digest
    kind: str
    value: bytes
    caller_approved: bool


@dataclass(frozen=True, slots=True)
class CommitReceipt:
    head: HeadState
    inserted_record_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class HeadUpdate:
    name: str
    expected: HeadState | None
    new_record_id: RecordId


@dataclass(frozen=True, slots=True)
class MultiHeadCommitReceipt:
    heads: tuple[tuple[str, HeadState], ...]
    inserted_record_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class AuditAnchorV1:
    store_id: str
    audit_sequence: int
    audit_head_id: RecordId
    created_at: LogicalTime
    label: str | None


@dataclass(frozen=True, slots=True)
class AuditVerification:
    store_id: str
    audit_sequence: int
    audit_head_id: RecordId
    supplied_anchor_matched: bool
    valid: bool


class StateStore(Protocol):
    @property
    def store_id(self) -> str: ...
    def read_head(self, name: str) -> HeadState | None: ...
    def read_audit_head(self) -> AuditHeadState | None: ...
    def load_record(self, record_id: RecordId) -> StoredRecord: ...
    def commit(
        self,
        *,
        records: Sequence[StoredRecord],
        local_values: Sequence[SensitiveLocalValueDraft] = (),
        event: AuditEventDraft,
        head_name: str,
        expected_head: HeadState | None,
        new_head_id: RecordId,
    ) -> CommitReceipt: ...
    def commit_many(
        self,
        *,
        records: Sequence[StoredRecord],
        local_values: Sequence[SensitiveLocalValueDraft] = (),
        event: AuditEventDraft,
        head_updates: Sequence[HeadUpdate],
    ) -> MultiHeadCommitReceipt: ...
    def verify_audit(self, anchor: AuditAnchorV1 | None = None) -> AuditVerification: ...
    def make_anchor(
        self,
        *,
        created_at: LogicalTime,
        label: str | None,
    ) -> AuditAnchorV1: ...
```

- [ ] **Step 1: Write failing atomicity and tamper tests**

Prove genesis commit with caller-approved sensitive-local rows, the same approved bytes stored independently under both allowed goal and criterion kinds, atomic two-head commit, immutable ordered receipt heads, duplicate head-name rejection, reopen rehash, idempotent same bytes, same ID/different bytes integrity error, stale CAS on any expected head, missing new-head record rejection, immutable UPDATE/DELETE triggers, injected failure at each transaction stage, after-commit reconciliation, audit mutation detection, anchor match, and anchored truncation detection. Audit bytes bind only local-value digest/kind, never value bytes. Mutating a caller-owned nested `AuditEventDraft.details` object after construction must not change committed canonical bytes.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest tests/integration/test_sqlite_store.py tests/security/test_audit_tamper.py -v
```

Expected: store imports fail.

- [ ] **Step 3: Create frozen schema version 1**

```sql
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE records (
    record_id TEXT PRIMARY KEY,
    record_type TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    canonical_bytes BLOB NOT NULL
) STRICT;

CREATE TABLE sensitive_local_values (
    digest TEXT NOT NULL,
    kind TEXT NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (digest, kind)
) STRICT;

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    previous_event_id TEXT,
    canonical_bytes BLOB NOT NULL,
    FOREIGN KEY (previous_event_id) REFERENCES audit_events(event_id)
) STRICT;

CREATE TABLE heads (
    name TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    audit_event_id TEXT NOT NULL,
    audit_sequence INTEGER NOT NULL,
    FOREIGN KEY (record_id) REFERENCES records(record_id),
    FOREIGN KEY (audit_event_id) REFERENCES audit_events(event_id)
) STRICT;
```

Add BEFORE UPDATE/DELETE triggers for records, sensitive_local_values, and audit_events. Plan 1 may persist only explicitly supplied goal and acceptance-criteria text as `SensitiveLocalValueDraft` rows during genesis; raw prompts, transcripts, source excerpts, and secrets remain forbidden. Configure `journal_mode=DELETE`, `synchronous=FULL`, `foreign_keys=ON`. Unsupported schema version is integrity exit 3; migrations are deferred.

- [ ] **Step 4: Implement CAS transaction and fault labels**

Use `BEGIN IMMEDIATE`. `commit_many` validates unique ordered head names, compares every expected head before any update, requires every new head record to exist in the same transaction or current store, inserts approved sensitive-local rows plus records/event, and changes every projection atomically. It verifies each local digest against exact bytes and rejects unapproved/unknown kinds. Frozen models defensively snapshot nested canonical data and receipts expose ordered immutable tuples, never caller-owned mappings. `commit` is a one-head wrapper. Invoke optional fault injector at `after_records`, `after_audit`, `after_head`, `before_commit`, and `after_commit`. An `after_commit` exception is reconciled by reopening and verifying the exact intended committed state; retry remains idempotent and never reports a second logical event. Reopen and verify inserted bytes plus every resulting head and audit head.

- [ ] **Step 5: Implement full audit and AuditAnchor/v1**

Rehash immutable records, replay event sequence/linkage, validate heads, and compare optional anchor store ID/sequence/head. Reject current history shorter than anchor.

- [ ] **Step 6: Run GREEN**

```bash
.venv/bin/python -m pytest tests/integration/test_sqlite_store.py tests/security/test_audit_tamper.py -v
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/store src/agent_continuity/kernel/audit.py
git add schemas/v1/audit-*.schema.json tests/integration/test_sqlite_store.py tests/security/test_audit_tamper.py
git commit -m "feat: add atomic state store and audit chain"
```

### Task 5: Compile strict TOML policy into canonical Policy/v1

**Files:**

- Create: `src/agent_continuity/policy.py`
- Modify: `src/agent_continuity/kernel/model.py`
- Modify: `src/agent_continuity/kernel/records.py`
- Create: `schemas/v1/policy.schema.json`
- Create: `schemas/v1/policy-template.schema.json`
- Create: `tests/contract/test_policy_v1.py`
- Create: `tests/integration/test_policy_precedence.py`
- Create: `tests/security/test_policy_read_only.py`
- Create: `examples/policies/guard.toml`

**Interfaces:**

```python
class PromotionMode(StrEnum):
    AUTOMATIC = "automatic"
    REVIEW = "review"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class ResourceLimitsV1:
    max_paths: int
    max_file_bytes: int
    max_aggregate_bytes: int
    max_analyzer_text_bytes: int
    max_external_json_bytes: int


@dataclass(frozen=True, slots=True)
class CompiledPolicyV1:
    policy_id: RecordId
    authoring_digest: Digest
    profile: Profile
    promotion_mode: PromotionMode
    limits: ResourceLimitsV1
    required_adapter_capabilities: tuple[str, ...]
    max_assignment_authority: AssignmentAuthority
    approval_operator_ids: tuple[RecordId, ...]
    rollback_operator_ids: tuple[RecordId, ...]
    evidence_expiry_seconds: int
    enabled_detectors: tuple[str, ...]
    severity_by_code: tuple[tuple[str, Verdict], ...]


@dataclass(frozen=True, slots=True)
class LoadedPolicy:
    compiled: CompiledPolicyV1
    source: str
    source_digest: Digest


def load_policy(
    *,
    target: Path,
    explicit: Path | None,
) -> LoadedPolicy: ...
def render_policy_template() -> JsonObject: ...
```

- [ ] **Step 1: Write failing strict-policy contract tests**

Use `tomllib` and reject unknown/duplicate keys, wrong types, unsupported version, relative explicit path, invalid raw paths, unknown profile/promotion mode/detector/capability, PASS/UNKNOWN configured rule severity, and values outside compile-time resource bounds.

Guard defaults are exact:

```text
profile = guard
promotion_mode = automatic
max_assignment_authority = read_only
approval_operator_ids = []
rollback_operator_ids = []
max_paths = 250000
max_file_bytes = 1073741824
max_aggregate_bytes = 21474836480
max_analyzer_text_bytes = 4194304
max_external_json_bytes = 8388608
```

- [ ] **Step 2: Write failing precedence and identity tests**

Precedence is explicit absolute path, target-root `acg.toml`, then built-in guard defaults. The selected authoring-byte digest and complete compiled form bind Policy/v1 identity. A comment-only authoring change changes authoring digest; any compiled limit/profile/mode/detector/severity change changes policy identity and invalidates dependent Evidence.

- [ ] **Step 3: Write failing read-only and template tests**

Capture target policy through the same descriptor-pinned read seam as instructions and prove target bytes/mode/timestamps observed by the write manifest remain unchanged. Missing target policy falls back to defaults; an explicitly requested missing file is request exit 2.

`render_policy_template` returns canonical PolicyTemplate/v1 JSON containing ordered control-character-free `toml_lines` plus the digest of their UTF-8 newline-joined form. This preserves CanonicalJSON/v1 while giving callers a complete template to join deliberately. It never writes target policy. Candidate or external JSON data cannot select policy source or alter compiled keys.

- [ ] **Step 4: Run RED**

```bash
.venv/bin/python -m pytest tests/contract/test_policy_v1.py tests/integration/test_policy_precedence.py tests/security/test_policy_read_only.py -v
```

Expected: policy module and schemas are absent.

- [ ] **Step 5: Implement strict compilation and source precedence**

Read the selected source once through a pinned descriptor, parse with `tomllib`, validate a closed key tree, normalize canonical tuples, apply no implicit coercions, and create Policy/v1. Built-in defaults use the same compilation path as authored TOML.

Raw authoring bytes are not persisted; only approved compiled fields and authoring digest are stored. Sanitized errors never echo TOML values.

- [ ] **Step 6: Run GREEN**

```bash
.venv/bin/python -m pytest tests/contract/test_policy_v1.py tests/integration/test_policy_precedence.py tests/security/test_policy_read_only.py -v
.venv/bin/python tools/verify_schemas.py
.venv/bin/python -m mypy src/agent_continuity
.venv/bin/python -m ruff check .
```

Expected: all commands pass; precedence and Policy/v1 identities are deterministic; target manifest is unchanged.

- [ ] **Step 7: Commit**

```bash
git add src/agent_continuity/policy.py src/agent_continuity/kernel/model.py src/agent_continuity/kernel/records.py
git add schemas/v1/policy.schema.json schemas/v1/policy-template.schema.json
git add tests/contract/test_policy_v1.py tests/integration/test_policy_precedence.py tests/security/test_policy_read_only.py examples/policies/guard.toml
git commit -m "feat: compile strict continuity policy"
```

### Task 6: Create Continuity initialization and first checkpoint

**Files:**

- Create: `src/agent_continuity/adapters/__init__.py`
- Create: `src/agent_continuity/adapters/clock.py`
- Create: `src/agent_continuity/api.py`
- Modify: `src/agent_continuity/__init__.py`
- Modify: `src/agent_continuity/store/base.py`
- Modify: `src/agent_continuity/store/sqlite.py`
- Create: `schemas/v1/checkpoint.schema.json`
- Create: `schemas/v1/checkpoint-receipt.schema.json`
- Create: `schemas/v1/actor.schema.json`
- Create: `schemas/v1/goal.schema.json`
- Create: `schemas/v1/ruleset.schema.json`
- Create: `schemas/v1/initialization-intent.schema.json`
- Create: `schemas/v1/criterion.schema.json`
- Create: `schemas/v1/work-item.schema.json`
- Create: `schemas/v1/unresolved-item.schema.json`
- Create: `tests/integration/test_initialize.py`

**Interfaces:**

```python
class Clock(Protocol):
    def now(self) -> LogicalTime: ...


@dataclass(frozen=True, slots=True)
class ActorV1:
    actor_id: RecordId
    producer: ProducerIdentity
    authority: AssignmentAuthority
    scope_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class GoalV1:
    goal_id: RecordId
    digest: Digest


@dataclass(frozen=True, slots=True)
class RulesetV1:
    ruleset_id: RecordId
    rule_ids: tuple[RecordId, ...]


@dataclass(frozen=True, slots=True)
class InitializationIntentV1:
    intent_id: RecordId
    session_key: str
    target_id: RecordId
    goal_id: RecordId
    criterion_ids: tuple[RecordId, ...]
    instruction_id: RecordId
    policy_id: RecordId
    ruleset_id: RecordId


@dataclass(frozen=True, slots=True)
class CriterionV1:
    criterion_id: RecordId
    ordinal: int
    digest: Digest


@dataclass(frozen=True, slots=True)
class WorkItemV1:
    work_item_id: RecordId
    kind: str
    status_code: str
    digest: Digest


@dataclass(frozen=True, slots=True)
class UnresolvedItemV1:
    unresolved_id: RecordId
    code: str
    digest: Digest | None


@dataclass(frozen=True, slots=True)
class CheckpointV1:
    checkpoint_id: RecordId
    parent_checkpoint_id: RecordId | None
    target_id: RecordId
    goal_id: RecordId
    acceptance_criteria: tuple[CriterionV1, ...]
    constraint_digests: tuple[Digest, ...]
    instruction_id: RecordId
    policy_id: RecordId
    ruleset_id: RecordId
    actor_ids: tuple[RecordId, ...]
    evidence_ids: tuple[RecordId, ...]
    invalidation_ids: tuple[RecordId, ...]
    accepted_decision_ids: tuple[RecordId, ...]
    pending_work: tuple[WorkItemV1, ...]
    unresolved: tuple[UnresolvedItemV1, ...]
    assignment_authority: AssignmentAuthority
    authority_scopes: tuple[PathScopeV1, ...]
    open_assignment_ids: tuple[RecordId, ...]
    audit_parent_id: RecordId | None
    initialization_intent_id: RecordId
    created_at: LogicalTime


@dataclass(frozen=True, slots=True)
class CheckpointReceipt:
    checkpoint_id: RecordId
    target_id: RecordId
    audit_event_id: RecordId
    audit_sequence: int
    verdict: Verdict
    transition_allowed: bool


class Continuity:
    @classmethod
    def open(
        cls,
        target: str | Path,
        *,
        profile: Profile | None = None,
        promotion_mode: PromotionMode | None = None,
        state_home: str | Path | None = None,
        policy: str | Path | None = None,
        session_key: str = "default",
        clock: Clock | None = None,
        target_adapter: TargetAdapter | None = None,
    ) -> "Continuity": ...

    def initialize(
        self,
        goal: str,
        acceptance_criteria: Sequence[str],
        *,
        instruction_paths: Sequence[str | os.PathLike[str]] = (),
    ) -> CheckpointReceipt: ...
```

`None` means use the selected compiled policy. Built-in policy supplies logical defaults Profile.GUARD and PromotionMode.AUTOMATIC. Non-None facade arguments are explicit overrides and are recompiled into the effective Policy/v1 identity; they never bypass policy validation.

- [ ] **Step 1: Write failing initialization tests**

Matching A/B/C creates one checkpoint/genesis event; receipt fields are exact; checkpoint binds goal/criteria/instructions/policy/ruleset/actor/target; identical init is idempotent; changed init raises AlreadyInitialized; A/B or A/C mismatch writes no head; concurrent identical init produces one event and identical receipts.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest tests/integration/test_initialize.py -v
```

Expected: Continuity import fails.

- [ ] **Step 3: Implement content-addressed initialization records**

Create Goal/v1, Criterion/v1, WorkItem/v1, UnresolvedItem/v1, InstructionManifest/v1, Policy/v1, Ruleset/v1, Actor/v1, InitializationIntent/v1, and Checkpoint/v1. InitializationIntent excludes timestamp and provides idempotency identity. Checkpoint fields use `instruction_id` consistently. Assignment authority/scopes come from compiled policy; guard defaults to READ_ONLY over the explicit target-root TREE scope. Initial invalidations, accepted decisions, pending work, unresolved items, and open assignments are empty canonical tuples. Explicit caller-supplied goal/criteria text becomes SensitiveLocalValueDraft rows in the same genesis transaction; deterministic records bind only their digests.

- [ ] **Step 4: Implement A/B/C orchestration**

```python
snapshot_a = adapter.capture(instruction_path_bytes)
snapshot_b = adapter.capture(instruction_path_bytes)
result = evaluate(snapshot_findings(snapshot_a, snapshot_b, profile))
if not result.transition_allowed:
    raise TransitionRefused(result)

records, checkpoint = build_initialization_records(
    snapshot=snapshot_a,
    goal=goal,
    acceptance_criteria=tuple(acceptance_criteria),
    profile=profile,
    promotion_mode=promotion_mode,
    session_key=session_key,
    logical_time=clock.now(),
)

snapshot_c = adapter.capture(instruction_path_bytes)
if snapshot_c != snapshot_a:
    raise TransitionRefused(snapshot_changed_result(profile))
```

Commit once with expected head None. On CAS loss, reload and return success only when InitializationIntent bytes match.

- [ ] **Step 5: Run GREEN**

```bash
.venv/bin/python -m pytest tests/integration/test_initialize.py -v
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/api.py src/agent_continuity/__init__.py src/agent_continuity/adapters src/agent_continuity/store/base.py src/agent_continuity/store/sqlite.py
git add schemas/v1/actor.schema.json schemas/v1/goal.schema.json schemas/v1/ruleset.schema.json schemas/v1/initialization-intent.schema.json
git add schemas/v1/checkpoint*.schema.json schemas/v1/criterion.schema.json schemas/v1/work-item.schema.json schemas/v1/unresolved-item.schema.json tests/integration/test_initialize.py
git commit -m "feat: create first continuity checkpoint"
```

### Task 7: Add subsequent checkpoint and pure verify

**Files:**

- Modify: `src/agent_continuity/api.py`
- Create: `src/agent_continuity/kernel/checkpoint.py`
- Create: `schemas/v1/verification-result.schema.json`
- Create: `tests/integration/test_checkpoint.py`
- Create: `tests/integration/test_verify.py`

**Interfaces:**

```python
class Continuity:
    def checkpoint(self, reason: str | None = None) -> CheckpointReceipt: ...
    def verify(self, checkpoint: str = "latest") -> EvaluationResult: ...
```

- [ ] **Step 1: Write failing checkpoint tests**

Test unchanged checkpoint append, correct parent, reason digest, A/B/C mismatch refusal, stale expected head CAS, two concurrent writers with one winner/retry, and no target mutation.

- [ ] **Step 2: Write failing pure-verify tests**

Verify latest and explicit checkpoint; confirm checkpoint/finding/ruleset/audit heads and SQLite file digest are unchanged. Dirty target in Plan 1 returns UNKNOWN and exit-policy refusal rather than a false clean result.

- [ ] **Step 3: Run RED**

```bash
.venv/bin/python -m pytest tests/integration/test_checkpoint.py tests/integration/test_verify.py -v
```

Expected: methods are absent.

- [ ] **Step 4: Implement checkpoint and verify**

Checkpoint loads verified head, captures A/B, evaluates, captures C, and commits parent-linked Checkpoint/v1 plus audit event. Verify loads/rechecks but writes nothing. Automatic promotion hook remains a no-op until Plan 3.

- [ ] **Step 5: Run GREEN**

```bash
.venv/bin/python -m pytest tests/integration/test_checkpoint.py tests/integration/test_verify.py -v
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
```

Expected: all pass and pure verify leaves store bytes/heads unchanged.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/api.py src/agent_continuity/kernel/checkpoint.py
git add schemas/v1/verification-result.schema.json tests/integration/test_checkpoint.py tests/integration/test_verify.py
git commit -m "feat: add checkpoint and pure verification"
```

### Task 8: Expose policy, checkpoint, verify, audit, and anchor CLI

**Files:**

- Create: `src/agent_continuity/cli.py`
- Create: `src/agent_continuity/output.py`
- Create: `schemas/v1/error.schema.json`
- Create: `tests/contract/test_cli_output.py`
- Create: `tests/integration/test_cli_plan1.py`

**Commands:**

```text
acg init
acg checkpoint
acg verify
acg verify-audit
acg audit-anchor export
acg policy-template
```

- [ ] **Step 1: Write failing subprocess CLI tests**

Run policy-template, init, checkpoint, verify, verify-audit, anchor export, and anchored verify. Assert exit 0, canonical JSON stdout, sanitized/empty stderr on success, complete PolicyTemplate/v1 content, exclusive anchor output outside target/state, and pure verify store invariance.

Test invalid request/schema exit 2, dirty/UNKNOWN protected transition exit 1, and audit/store integrity exit 3.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest tests/contract/test_cli_output.py tests/integration/test_cli_plan1.py -v
```

Expected: console invocation fails because CLI module is absent.

- [ ] **Step 3: Implement argparse command tree and error records**

```json
{
  "schema": "Error/v1",
  "category": "request",
  "code": "state_root_overlaps_target",
  "message_id": "acg.request.state_root_overlaps_target",
  "parameters": {}
}
```

Success/error stdout uses canonical_bytes. Never echo raw secrets or Git stderr.

- [ ] **Step 4: Implement secure anchor output**

Resolve target/Git/state/output parent; reject output inside target/state and existing output; open with O_CREAT|O_EXCL|O_WRONLY mode 0600; write, flush, fsync file and parent directory where supported.

- [ ] **Step 5: Run GREEN**

```bash
.venv/bin/python -m pytest tests/contract/test_cli_output.py tests/integration/test_cli_plan1.py -v
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/agent_continuity/cli.py src/agent_continuity/output.py schemas/v1/error.schema.json
git add tests/contract/test_cli_output.py tests/integration/test_cli_plan1.py
git commit -m "feat: expose checkpoint and audit CLI"
```

### Task 9: Prove Plan 1 through installed package

**Files:**

- Create: `tests/security/test_no_target_writes.py`
- Create: `tests/security/test_anchor_truncation.py`
- Create: `tests/integration/test_installed_wheel_plan1.py`
- Modify: `README.md`
- Modify: `PROVENANCE.md`

- [ ] **Step 1: Write failing end-to-end security tests**

Prove target content, refs, HEAD, index, status, config, hooks, permissions, and application metadata remain equal after all commands; anchor detects rewritten/truncated history; overlap rejects before SQLite creation; target/instruction bytes do not occur in SQLite or anchor.

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest tests/security/test_no_target_writes.py tests/security/test_anchor_truncation.py tests/integration/test_installed_wheel_plan1.py -v
```

Expected: installed-wheel test fails until build/install fixture and exports are complete.

- [ ] **Step 3: Add installed-wheel fixture and truthful README**

Build wheel, install into clean temporary venv, run init/checkpoint/verify/anchor/audit against a clean Git fixture, and ensure imports come from installed wheel. README states clean-Git limitation, external state, available commands, and unsigned/tamper-evident anchor boundary.

- [ ] **Step 4: Run full validation**

```bash
.venv/bin/python -m pytest -v
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
.venv/bin/python -m build
```

Expected: all pass; wheel and source distribution exist.

- [ ] **Step 5: Install and smoke**

```bash
python3.11 -m venv /tmp/acg-plan1-venv
/tmp/acg-plan1-venv/bin/python -m pip install dist/agent_continuity_guard-0.1.0.dev0-py3-none-any.whl
/tmp/acg-plan1-venv/bin/acg --help
```

Expected: help lists policy-template, init, checkpoint, verify, verify-audit, and audit-anchor.

- [ ] **Step 6: Commit**

```bash
git add README.md PROVENANCE.md tests/security tests/integration/test_installed_wheel_plan1.py
git commit -m "test: prove checkpoint integrity end to end"
git status --short
```

Expected final status: clean.

## Plan Completion Gate

Run:

```bash
.venv/bin/python -m pytest -v
.venv/bin/python -m mypy src
.venv/bin/python -m ruff check .
.venv/bin/python -m build
git status --short
```

Plan 1 is complete only when installed wheel initializes and advances checkpoints against a clean Git target; repeated initialization is idempotent; pure verify is store-read-only; A/B/C drift refuses; SQLite CAS is atomic; audit and anchors detect supported tampering/truncation; target pre/post manifests are identical; persisted/exported data contains no target bytes; and final Git status is clean.
