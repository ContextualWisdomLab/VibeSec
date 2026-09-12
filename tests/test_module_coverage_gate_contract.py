"""Contracts for the dependency-free changed-module statement coverage gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.verify_module_coverage import (
    CoverageTarget,
    _execute_tests,
    executable_lines,
    parse_args,
    verify_coverage,
)


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "tests.yml"


def test_executable_lines_excludes_explicit_no_cover_lines(tmp_path: Path) -> None:
    """The gate must measure executable statements while honoring reviewed exclusions."""
    module_path = tmp_path / "sample_module.py"
    module_path.write_text(
        '"""Sample module."""\n\n'
        "def covered(value):\n"
        '    """Return a value."""\n'
        "    return value\n\n"
        "if __name__ == '__main__':  # pragma: no cover\n"
        "    raise SystemExit(covered(1))  # pragma: no cover\n",
        encoding="utf-8",
    )

    lines = executable_lines(module_path)

    assert 5 in lines
    assert 7 not in lines
    assert 8 not in lines


def test_verify_coverage_reports_missing_lines_without_rounding(
    tmp_path: Path,
) -> None:
    """A single unexecuted statement must fail instead of rounding to 100%."""
    module_path = tmp_path / "sample_module.py"
    module_path.write_text(
        '"""Sample module."""\n\n'
        "def first():\n"
        '    """Return one."""\n'
        "    return 1\n\n"
        "def second():\n"
        '    """Return two."""\n'
        "    return 2\n",
        encoding="utf-8",
    )
    executable = executable_lines(module_path)
    target = CoverageTarget(module_path.resolve(), executable, frozenset({3, 5}))

    with pytest.raises(RuntimeError, match="100% statement coverage") as exc_info:
        verify_coverage((target,))

    assert "sample_module.py" in str(exc_info.value)
    assert "7" in str(exc_info.value) or "9" in str(exc_info.value)


def test_execute_tests_does_not_ignore_package_initializers_by_basename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Directory ignores must not hide every package ``__init__.py`` from coverage."""
    observed: dict[str, object] = {}

    class FakeResults:
        """Return an empty deterministic trace-count mapping."""

        counts: dict[tuple[str, int], int] = {}

    class FakeTrace:
        """Capture the tracer configuration without running nested pytest."""

        def __init__(
            self,
            *,
            count: bool,
            trace: bool,
            ignoredirs: tuple[str, ...],
        ) -> None:
            """Record whether the gate delegates basename filtering to ``trace``."""
            observed.update(
                count=count,
                trace=trace,
                ignoredirs=ignoredirs,
            )

        def runfunc(self, _function: object, _arguments: list[str]) -> int:
            """Return a successful focused-test result for this configuration test."""
            return 0

        def results(self) -> FakeResults:
            """Return the deterministic empty result object."""
            return FakeResults()

    monkeypatch.setattr(
        "scripts.ci.verify_module_coverage.trace.Trace",
        FakeTrace,
    )

    assert _execute_tests(["tests/placeholder.py"]) == {}
    assert observed == {
        "count": True,
        "trace": False,
        "ignoredirs": (),
    }


def test_parse_args_requires_modules_and_tests() -> None:
    """The CLI contract must name every measured module and focused test file."""
    args = parse_args(
        [
            "--module",
            "appguardrail_core/code_scanning.py",
            "--test",
            "tests/test_code_scanning_core.py",
        ]
    )

    assert args.modules == ["appguardrail_core/code_scanning.py"]
    assert args.tests == ["tests/test_code_scanning_core.py"]


def test_tests_workflow_enforces_exact_100_percent_for_new_modules() -> None:
    """Exact-head CI must run the durable statement-coverage verifier."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "python -m scripts.ci.verify_module_coverage" in workflow
    assert "appguardrail_core/code_scanning.py" in workflow
    assert "scripts/ci/collect_code_scanning_drift.py" in workflow
    assert "appguardrail_core/claude_plugin_detector.py" in workflow
    assert "appguardrail_core/claude_plugin_scan_cli.py" in workflow
    assert "appguardrail_core/claude_plugin_sarif.py" in workflow
    assert "appguardrail_core/github_actions_poll_loop.py" not in workflow
    assert "appguardrail_core/github_workflow_orphans.py" not in workflow
    assert "100% statement coverage" in workflow
