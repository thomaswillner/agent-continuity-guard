from __future__ import annotations

import ast
from pathlib import Path

TASK3_TESTS = (
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


def test_task3_collected_case_inventory_does_not_regress() -> None:
    assert sum(_collected_case_count(path) for path in TASK3_TESTS) >= (
        BASELINE_COLLECTED_CASES
    )
