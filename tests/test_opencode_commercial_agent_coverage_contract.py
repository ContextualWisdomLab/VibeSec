"""Exact coverage workflow contracts for the hourly commercial builder."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "tests.yml"


def test_coverage_workflow_tracks_every_agent_test_surface() -> None:
    """The consolidated exact gate retains every commercial-agent test."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    required_paths = (
        "scripts/ci/commercial_readiness_loop.py",
        "scripts/ci/commercial_readiness_reconcile.py",
        "tests/test_commercial_readiness_loop.py",
        "tests/test_commercial_readiness_loop_handoff.py",
        "tests/test_commercial_readiness_reconcile.py",
        "tests/test_commercial_readiness_coverage_edges.py",
        "tests/test_opencode_commercial_agent_trust_boundary.py",
        "tests/test_opencode_commercial_agent_coverage_contract.py",
    )
    assert all(path in workflow for path in required_paths)


def test_coverage_workflow_runs_focused_tests_and_both_modules() -> None:
    """Both selector modules must reach exact unrounded statement coverage."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "python -m pytest -q" in workflow
    assert "python -m scripts.ci.verify_module_coverage" in workflow
    assert "--module scripts/ci/commercial_readiness_loop.py" in workflow
    assert "--module scripts/ci/commercial_readiness_reconcile.py" in workflow
    for test_path in (
        "tests/test_commercial_readiness_loop.py",
        "tests/test_commercial_readiness_loop_handoff.py",
        "tests/test_commercial_readiness_reconcile.py",
        "tests/test_commercial_readiness_coverage_edges.py",
        "tests/test_opencode_commercial_agent_trust_boundary.py",
        "tests/test_opencode_commercial_agent_coverage_contract.py",
    ):
        assert f"--test {test_path}" in workflow


def test_coverage_workflow_is_read_only_and_immutably_pinned() -> None:
    """Coverage evidence cannot write repository state or float action versions."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in workflow
    assert "--require-hashes -r requirements-test.txt" in workflow
    assert "pull_request_target:" not in workflow
    assert "contents: write" not in workflow
    assert "secrets." not in workflow
