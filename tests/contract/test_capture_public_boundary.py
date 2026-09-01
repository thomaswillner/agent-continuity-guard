from __future__ import annotations

import ast
import inspect
from pathlib import Path

import agent_continuity.capture as capture
from agent_continuity.capture import GitTargetAdapter

TASK3_TESTS = (
    Path(__file__),
    Path(__file__).with_name("test_plan1_schemas.py"),
    Path(__file__).parents[1] / "integration" / "test_git_capture.py",
    Path(__file__).parents[1] / "security" / "test_state_root_separation.py",
)
BASELINE_COLLECTED_CASES = 117
PUBLIC_CAPTURE_EXPORTS = frozenset(
    {
        "CaptureRequestError",
        "CaptureSnapshot",
        "CaptureUnknownError",
        "GitTargetAdapter",
        "TargetAdapter",
        "TargetIdentityV1",
        "target_identity_payload",
    }
)
PUBLIC_GIT_SIGNATURES = {
    "GitTargetAdapter": "(target: 'str | os.PathLike[str]') -> 'None'",
    "capture": "(self, instruction_paths: 'Sequence[bytes]') -> 'CaptureSnapshot'",
    "read_target_policy": "(self) -> 'bytes | None'",
    "close": "(self) -> 'None'",
    "__enter__": "(self) -> 'GitTargetAdapter'",
    "__exit__": "(self, *_args: 'object') -> 'None'",
}


def _source_tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=path.name)


def _is_single_private(name: str) -> bool:
    return name.startswith("_") and not name.startswith("__")


def _public_boundary_violations(path: Path) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(_source_tree(path)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("agent_continuity.capture."):
                    violations.append(
                        f"{path.name}:{node.lineno}: private capture module import"
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("agent_continuity.capture"):
                if module != "agent_continuity.capture":
                    violations.append(
                        f"{path.name}:{node.lineno}: non-export capture import"
                    )
                for alias in node.names:
                    if (
                        _is_single_private(alias.name)
                        or alias.name not in PUBLIC_CAPTURE_EXPORTS
                    ):
                        violations.append(
                            f"{path.name}:{node.lineno}: non-public capture name"
                        )
        elif isinstance(node, ast.Attribute) and _is_single_private(node.attr):
            violations.append(
                f"{path.name}:{node.lineno}: private member access {node.attr}"
            )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "setattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and _is_single_private(node.args[1].value)
        ):
            violations.append(
                f"{path.name}:{node.lineno}: private monkeypatch target"
            )
    return violations


def _private_capture_import_violations(path: Path) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(_source_tree(path)):
        modules: tuple[str, ...] = ()
        if isinstance(node, ast.Import):
            modules = tuple(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules = (node.module or "",)
        for module in modules:
            if any(
                component.startswith("_")
                for component in module.split(".")[2:]
            ) and module.startswith("agent_continuity.capture."):
                violations.append(
                    f"{path.name}:{node.lineno}: private capture module import"
                )
    return violations


def _parametrize_size(decorator: ast.expr) -> int:
    if not isinstance(decorator, ast.Call) or len(decorator.args) < 2:
        return 1
    function = decorator.func
    if not isinstance(function, ast.Attribute) or function.attr != "parametrize":
        return 1
    values = decorator.args[1]
    if not isinstance(values, (ast.List, ast.Tuple)):
        raise AssertionError("Task 3 parametrization must use explicit cases")
    if any(isinstance(value, ast.Starred) for value in values.elts):
        raise AssertionError("Task 3 parametrization cannot expand cases")
    return len(values.elts)


def _collected_case_count(path: Path) -> int:
    total = 0
    for node in _source_tree(path).body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        ):
            multiplier = 1
            for decorator in node.decorator_list:
                multiplier *= _parametrize_size(decorator)
            total += multiplier
    return total


def test_task3_tests_use_only_public_capture_boundary() -> None:
    violations = [
        violation
        for path in TASK3_TESTS
        for violation in _public_boundary_violations(path)
    ]

    assert violations == []


def test_capture_exports_and_git_adapter_signatures_are_characterized() -> None:
    assert frozenset(capture.__all__) == PUBLIC_CAPTURE_EXPORTS
    assert len(capture.__all__) == len(PUBLIC_CAPTURE_EXPORTS)
    assert {
        "GitTargetAdapter": str(inspect.signature(GitTargetAdapter)),
        "capture": str(inspect.signature(GitTargetAdapter.capture)),
        "read_target_policy": str(
            inspect.signature(GitTargetAdapter.read_target_policy)
        ),
        "close": str(inspect.signature(GitTargetAdapter.close)),
        "__enter__": str(inspect.signature(GitTargetAdapter.__enter__)),
        "__exit__": str(inspect.signature(GitTargetAdapter.__exit__)),
    } == PUBLIC_GIT_SIGNATURES


def test_integration_and_security_tests_do_not_import_private_capture_modules() -> None:
    test_root = Path(__file__).parents[1]
    checked = tuple(
        sorted(
            (
                *test_root.joinpath("integration").glob("test_*.py"),
                *test_root.joinpath("security").glob("test_*.py"),
            ),
            key=lambda path: path.name,
        )
    )

    assert checked
    assert [
        violation
        for path in checked
        for violation in _private_capture_import_violations(path)
    ] == []


def test_task3_collected_case_inventory_does_not_regress() -> None:
    assert sum(_collected_case_count(path) for path in TASK3_TESTS) >= (
        BASELINE_COLLECTED_CASES
    )
