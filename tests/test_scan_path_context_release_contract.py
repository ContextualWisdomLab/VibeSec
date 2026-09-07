"""Release contracts for scanner path-context and comment-rule hardening."""

from __future__ import annotations

from pathlib import Path

import appguardrail_core


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
DOCUMENTATION = ROOT / "docs" / "scanner-path-context.md"
CHANGELOG = ROOT / "CHANGELOG.d" / "893-scan-path-context.md"


def test_core_package_exports_immutable_scan_path_context() -> None:
    """Standalone, organization-service, and naruon consumers share one core contract."""
    expected = {"ScanPathContext", "build_scan_path_context"}

    assert expected <= set(appguardrail_core.__all__)
    assert all(hasattr(appguardrail_core, name) for name in expected)


def test_exact_coverage_workflow_is_least_privilege_and_complete() -> None:
    """The reusable core has exact coverage and all integration regressions run."""
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "push:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "python-version: ['3.11', '3.13']" in workflow
    assert "appguardrail_core/scan_paths.py" in workflow
    for test_name in (
        "test_scan_path_context_core.py",
        "test_scan_path_context_integration.py",
        "test_auth_deferral_comment_rule.py",
        "test_scan_path_context_release_contract.py",
    ):
        assert test_name in workflow


def test_documentation_records_deterministic_benchmark_and_source_contract() -> None:
    """Performance claims remain bounded by reproducible operation-count evidence."""
    documentation = DOCUMENTATION.read_text(encoding="utf-8")

    required = (
        "10,000",
        "10,000 → 1",
        "operation-count",
        "no wall-clock speedup claim",
        "standalone",
        "naruon",
        "comment",
        "block comment",
        "## References",
        "Python Software Foundation",
    )
    assert all(item in documentation for item in required)


def test_changelog_records_buyer_visible_performance_and_false_positive_fix() -> None:
    """The release fragment explains both large-scan cost and security-signal precision."""
    changelog = CHANGELOG.read_text(encoding="utf-8")

    assert changelog.startswith("### Changed\n")
    assert "scan-root" in changelog
    assert "10,000" in changelog
    assert "authentication-deferral" in changelog
    assert "executable" in changelog
