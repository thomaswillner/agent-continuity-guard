from __future__ import annotations

import ast
import json
import os
import sqlite3
import subprocess
import sys
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from threading import Lock

import pytest

from agent_continuity import Continuity, ContinuityRequestError, Profile
from agent_continuity.capture import CaptureSnapshot, GitTargetAdapter
from agent_continuity.kernel.canonical import digest_bytes
from agent_continuity.kernel.evaluation import EvaluationResult, Verdict
from agent_continuity.kernel.model import LogicalTime
from agent_continuity.store import StoreIntegrityError
from tests.helpers.git_repo import make_git_repo, repository_write_manifest
from tools import verify_schemas


class FixedClock:
    def now(self) -> LogicalTime:
        return LogicalTime("2026-08-14T12:00:00Z")


class CaptureSequence:
    def __init__(self, snapshots: tuple[CaptureSnapshot, ...]) -> None:
        self._snapshots = snapshots
        self._index = 0
        self._lock = Lock()

    def capture(self, instruction_paths: tuple[bytes, ...]) -> CaptureSnapshot:
        assert instruction_paths == (b"AGENTS.md",)
        with self._lock:
            if self._index >= len(self._snapshots):
                raise AssertionError("unexpected capture")
            snapshot = self._snapshots[self._index]
            self._index += 1
            return snapshot


def _snapshot(tmp_path: Path) -> tuple[Path, CaptureSnapshot]:
    repo = make_git_repo(tmp_path)
    with GitTargetAdapter(repo.root) as adapter:
        snapshot = adapter.capture((b"AGENTS.md",))
    return repo.root, snapshot


def _continuity(
    target: Path,
    state_home: Path,
    snapshots: tuple[CaptureSnapshot, ...],
) -> Continuity:
    return Continuity.open(
        target,
        state_home=state_home,
        session_key="verify",
        clock=FixedClock(),
        target_adapter=CaptureSequence(snapshots),
    )


def _database(state_home: Path) -> Path:
    databases = tuple(state_home.glob("*.sqlite3"))
    assert len(databases) == 1
    return databases[0]


def _projection(database: Path) -> tuple[bytes, int, tuple[object, ...]]:
    with sqlite3.connect(database) as connection:
        heads = tuple(
            connection.execute(
                "SELECT name, record_id, audit_event_id, audit_sequence "
                "FROM heads ORDER BY name"
            )
        )
        audit = tuple(
            connection.execute(
                "SELECT sequence, event_id, canonical_bytes "
                "FROM audit_events ORDER BY sequence"
            )
        )
        record_counts = tuple(
            connection.execute(
                "SELECT record_type, COUNT(*) FROM records "
                "GROUP BY record_type ORDER BY record_type"
            )
        )
    return (
        database.read_bytes(),
        database.stat().st_mtime_ns,
        (
            heads,
            audit,
            record_counts,
        ),
    )


@contextmanager
def _mutable_records(connection: sqlite3.Connection) -> Iterator[None]:
    rows = connection.execute(
        "SELECT name, sql FROM sqlite_schema "
        "WHERE type = 'trigger' AND tbl_name = 'records' ORDER BY name"
    ).fetchall()
    assert rows and all(sql is not None for _name, sql in rows)
    for name, _sql in rows:
        connection.execute(f'DROP TRIGGER "{name}"')
    try:
        yield
    finally:
        for _name, sql in rows:
            connection.execute(str(sql))


def test_verify_latest_and_explicit_checkpoint_are_pure_and_deterministic(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    continuity = _continuity(target, state_home, (snapshot,) * 14)
    initial = continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))
    latest = continuity.checkpoint()
    database = _database(state_home)
    before_store = _projection(database)
    before_target = repository_write_manifest(target)

    latest_result = continuity.verify()
    explicit_latest = continuity.verify(latest.checkpoint_id)
    explicit_initial = continuity.verify(initial.checkpoint_id)
    repeated = continuity.verify()

    assert type(latest_result) is EvaluationResult
    assert latest_result.verdict.value == "pass"
    assert latest_result.transition_allowed is True
    assert explicit_latest == latest_result
    assert explicit_initial == latest_result
    assert repeated == latest_result
    assert _projection(database) == before_store
    assert repository_write_manifest(target) == before_target


def test_verify_dirty_target_returns_unknown_refusal_without_writes(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    dirty = replace(
        snapshot,
        target=replace(snapshot.target, status_digest=digest_bytes(b"dirty")),
    )
    state_home = tmp_path / "state"
    continuity = _continuity(
        target,
        state_home,
        (snapshot,) * 3 + (dirty, dirty),
    )
    continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))
    database = _database(state_home)
    before_store = _projection(database)
    before_target = repository_write_manifest(target)

    result = continuity.verify()

    assert result.verdict.value == "unknown"
    assert result.transition_allowed is False
    assert "target.dirty" in tuple(item.code for item in result.findings)
    assert _projection(database) == before_store
    assert repository_write_manifest(target) == before_target


@pytest.mark.parametrize(
    "selector",
    ["../raw-selector-marker", "sha256:" + "f" * 64],
)
def test_verify_missing_or_malformed_checkpoint_is_sanitized_and_pure(
    tmp_path: Path,
    selector: str,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    continuity = _continuity(
        target,
        state_home,
        (snapshot,) * 3 + (snapshot,),
    )
    continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))
    database = _database(state_home)
    before_store = _projection(database)
    before_target = repository_write_manifest(target)

    with pytest.raises(ContinuityRequestError) as captured:
        continuity.verify(selector)

    rendered = "".join(traceback.format_exception(captured.value))
    assert selector not in rendered
    assert os.fspath(target) not in rendered
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert _projection(database) == before_store
    assert repository_write_manifest(target) == before_target


def test_verify_uninitialized_session_does_not_create_state(tmp_path: Path) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "must-not-exist"
    before_target = repository_write_manifest(target)

    with pytest.raises(ContinuityRequestError):
        _continuity(target, state_home, (snapshot,)).verify()

    assert not state_home.exists()
    assert repository_write_manifest(target) == before_target


def test_verify_malformed_checkpoint_record_refuses_without_raw_bytes(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    continuity = _continuity(target, state_home, (snapshot,) * 4)
    receipt = continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))
    database = _database(state_home)
    marker = "raw-malformed-checkpoint-marker"
    with sqlite3.connect(database) as connection, _mutable_records(connection):
        connection.execute(
            "UPDATE records SET canonical_bytes = ? WHERE record_id = ?",
            (json.dumps({"marker": marker}).encode(), receipt.checkpoint_id),
        )

    with pytest.raises(StoreIntegrityError) as captured:
        continuity.verify()

    rendered = "".join(traceback.format_exception(captured.value))
    assert marker not in rendered
    assert os.fspath(target) not in rendered


def test_verification_result_v1_matches_runtime_payload_and_schema() -> None:
    from agent_continuity.kernel.checkpoint import verification_result_payload

    result = EvaluationResult(Verdict.PASS, True, ())
    payload = verification_result_payload(result)

    assert payload == {
        "findings": [],
        "schema": "VerificationResult/v1",
        "transition_allowed": True,
        "verdict": "pass",
    }
    schemas = verify_schemas._load()
    verify_schemas.validate_schema_instance(
        "verification-result.schema.json",
        payload,
        schemas,
    )


def test_default_facade_repeated_verify_closes_temporary_descriptors(
    tmp_path: Path,
) -> None:
    target, _snapshot_value = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    continuity = Continuity.open(
        target,
        state_home=state_home,
        session_key="descriptor-lifecycle",
        clock=FixedClock(),
    )
    continuity.initialize("goal", (), instruction_paths=("AGENTS.md",))
    before = len(os.listdir("/dev/fd"))

    first = continuity.verify()
    second = continuity.verify()

    assert first == second
    assert len(os.listdir("/dev/fd")) == before


def test_verify_reports_compiled_policy_drift_without_store_write(
    tmp_path: Path,
) -> None:
    target, snapshot = _snapshot(tmp_path)
    state_home = tmp_path / "state"
    _continuity(target, state_home, (snapshot,) * 3).initialize(
        "goal", (), instruction_paths=("AGENTS.md",)
    )
    database = _database(state_home)
    before = _projection(database)
    changed_policy = Continuity.open(
        target,
        state_home=state_home,
        session_key="verify",
        clock=FixedClock(),
        target_adapter=CaptureSequence((snapshot, snapshot)),
        profile=Profile.STRICT,
    )

    result = changed_policy.verify()

    assert result.verdict.value == "unknown"
    assert result.transition_allowed is False
    assert _projection(database) == before


_KERNEL_PURE_STDLIB_ROOTS = frozenset(
    {
        "__future__",
        "base64",
        "collections",
        "dataclasses",
        "datetime",
        "enum",
        "hashlib",
        "json",
        "re",
        "typing",
        "unicodedata",
    }
)

_KERNEL_RUNTIME_FORBIDDEN = (
    "ctypes",
    "ftplib",
    "glob",
    "http",
    "locale",
    "multiprocessing",
    "pathlib",
    "platform",
    "random",
    "resource",
    "secrets",
    "selectors",
    "shutil",
    "signal",
    "socket",
    "socketserver",
    "sqlite3",
    "ssl",
    "subprocess",
    "sysconfig",
    "tempfile",
    "threading",
    "urllib",
)


def _kernel_module_identity(path: Path, source_root: Path) -> tuple[str, bool]:
    relative = path.relative_to(source_root)
    if relative.suffix != ".py":
        raise AssertionError("kernel source must be Python")
    parts = list(relative.with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts.pop()
    return ".".join(parts), is_package


def _canonical_import_modules(
    node: ast.Import | ast.ImportFrom,
    *,
    module_name: str,
    is_package: bool,
) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)
    if node.level == 0:
        return () if node.module is None else (node.module,)

    package_parts = module_name.split(".")
    if not is_package:
        package_parts.pop()
    if node.level > len(package_parts):
        return (f"<invalid-relative:{node.level}>",)
    base = package_parts[: len(package_parts) - node.level + 1]
    if node.module is not None:
        return (".".join((*base, *node.module.split("."))),)
    if any(alias.name == "*" for alias in node.names):
        return (".".join(base),)
    return tuple(".".join((*base, alias.name)) for alias in node.names)


def _kernel_source_violations(
    sources: tuple[tuple[Path, str], ...],
    *,
    source_root: Path,
) -> list[str]:
    violations: list[str] = []
    for path, source in sources:
        module_name, is_package = _kernel_module_identity(path, source_root)
        tree = ast.parse(source, filename=os.fspath(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imported = _canonical_import_modules(
                    node,
                    module_name=module_name,
                    is_package=is_package,
                )
            else:
                imported = ()
            for name in imported:
                project_dependency = name == "agent_continuity" or name.startswith(
                    "agent_continuity."
                )
                kernel_dependency = (
                    name == "agent_continuity.kernel"
                    or name.startswith("agent_continuity.kernel.")
                )
                external_root = name.partition(".")[0]
                if (project_dependency and not kernel_dependency) or (
                    not project_dependency
                    and external_root not in _KERNEL_PURE_STDLIB_ROOTS
                ):
                    violations.append(f"{path.name}:{node.lineno}:{name}")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"__import__", "eval", "exec", "open"}
            ):
                violations.append(f"{path.name}:{node.lineno}:{node.func.id}()")
    return violations


def test_every_public_kernel_module_standard_import_loads_no_io_helpers() -> None:
    source_root = Path(__file__).parents[2] / "src"
    kernel_root = source_root / "agent_continuity" / "kernel"
    public_sources = tuple(
        path
        for path in sorted(kernel_root.rglob("*.py"))
        if path.name == "__init__.py" or not path.name.startswith("_")
    )
    module_names = tuple(
        _kernel_module_identity(path, source_root)[0] for path in public_sources
    )
    assert module_names
    assert len(module_names) == len(set(module_names))

    for module_name in module_names:
        script = (
            "import sys\n"
            f"sys.path.insert(0, {os.fspath(source_root)!r})\n"
            f"__import__({module_name!r})\n"
            f"forbidden = {_KERNEL_RUNTIME_FORBIDDEN!r}\n"
            "project = [name for name in sys.modules "
            "if name.startswith('agent_continuity.') "
            "and name != 'agent_continuity.kernel' "
            "and not name.startswith('agent_continuity.kernel.')]\n"
            "helpers = [name for name in sys.modules "
            "if any(name == item or name.startswith(item + '.') "
            "for item in forbidden)]\n"
            "loaded = sorted(set(project).union(helpers))\n"
            "print('\\n'.join(loaded))\n"
            "raise SystemExit(bool(loaded))\n"
        )
        result = subprocess.run(
            [sys.executable, "-S", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"{module_name}: {result.stdout}"
        assert result.stderr == ""
        assert result.stdout == "\n"

    baseline = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "import sys, typing, dataclasses\n"
                "print('\\n'.join(name for name in ('os', 'os.path') "
                "if name in sys.modules))\n"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert baseline.returncode == 0
    assert baseline.stderr == ""
    assert baseline.stdout == "os\nos.path\n"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "from ..capture import CaptureSnapshot\n",
            "synthetic.py:1:agent_continuity.capture",
        ),
        (
            "from ..adapters import Clock\n",
            "synthetic.py:1:agent_continuity.adapters",
        ),
        (
            "from ..store import SQLiteStateStore\n",
            "synthetic.py:1:agent_continuity.store",
        ),
        (
            "from agent_continuity.api import Continuity\n",
            "synthetic.py:1:agent_continuity.api",
        ),
        (
            "import agent_continuity.api\n",
            "synthetic.py:1:agent_continuity.api",
        ),
        (
            "import fractions\n",
            "synthetic.py:1:fractions",
        ),
    ],
)
def test_kernel_source_analyzer_rejects_dependency_outside_kernel(
    source: str,
    expected: str,
) -> None:
    source_root = Path("src")
    path = Path("src/agent_continuity/kernel/synthetic.py")

    assert _kernel_source_violations(
        ((path, source),), source_root=source_root
    ) == [expected]


def test_kernel_source_import_graph_has_no_io_capability_edges() -> None:
    source_root = Path(__file__).parents[2] / "src"
    kernel_root = source_root / "agent_continuity" / "kernel"
    sources = tuple(
        (path, path.read_text(encoding="utf-8"))
        for path in sorted(kernel_root.rglob("*.py"))
    )
    assert sources

    assert _kernel_source_violations(sources, source_root=source_root) == []


def test_lazy_root_exports_preserve_public_identity_and_behavior() -> None:
    import agent_continuity
    from agent_continuity.api import (
        AlreadyInitialized as ApiAlreadyInitialized,
    )
    from agent_continuity.api import CheckpointReceipt as ApiCheckpointReceipt
    from agent_continuity.api import Continuity as ApiContinuity
    from agent_continuity.api import ContinuityError as ApiContinuityError
    from agent_continuity.api import (
        ContinuityRequestError as ApiContinuityRequestError,
    )
    from agent_continuity.api import TransitionRefused as ApiTransitionRefused
    from agent_continuity.kernel.evaluation import Profile as KernelProfile
    from agent_continuity.kernel.model import PromotionMode as KernelPromotionMode

    assert agent_continuity.__version__ == "0.1.0.dev0"
    assert agent_continuity.__all__ == [
        "AlreadyInitialized",
        "CheckpointReceipt",
        "Continuity",
        "ContinuityError",
        "ContinuityRequestError",
        "Profile",
        "PromotionMode",
        "TransitionRefused",
    ]
    assert agent_continuity.AlreadyInitialized is ApiAlreadyInitialized
    assert agent_continuity.CheckpointReceipt is ApiCheckpointReceipt
    assert agent_continuity.Continuity is ApiContinuity
    assert agent_continuity.ContinuityError is ApiContinuityError
    assert agent_continuity.ContinuityRequestError is ApiContinuityRequestError
    assert agent_continuity.TransitionRefused is ApiTransitionRefused
    assert agent_continuity.Profile is KernelProfile
    assert agent_continuity.PromotionMode is KernelPromotionMode
