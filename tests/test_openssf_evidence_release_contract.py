"""Release, documentation, public API, and autonomous-handoff contracts."""

from __future__ import annotations

from pathlib import Path

from appguardrail_core import (
    OpenSSFEvidence,
    collect_openssf_evidence,
    evidence_to_finding,
    parse_openssf_project_matches,
)
from scripts.ci.commercial_readiness_loop import COMMERCIAL_GAPS


ROOT = Path(__file__).resolve().parents[1]


def test_openssf_evidence_is_available_from_public_core_api() -> None:
    """Standalone and MSA consumers must not import private implementation paths."""
    assert OpenSSFEvidence.__module__ == "appguardrail_core.openssf_evidence"
    assert callable(collect_openssf_evidence)
    assert callable(evidence_to_finding)
    assert callable(parse_openssf_project_matches)


def test_operator_documentation_records_official_and_conservative_semantics() -> None:
    """Beginners must be able to operate the feature without reading source code."""
    documentation = (ROOT / "docs" / "openssf-best-practices-evidence.md").read_text(
        encoding="utf-8"
    )
    historical_origins = [
        line
        for line in documentation.splitlines()
        if line == "https://bestpractices.coreinfrastructure.org"
    ]

    assert "https://www.bestpractices.dev/projects.json?url=" in documentation
    assert historical_origins == ["https://bestpractices.coreinfrastructure.org"]
    assert "in_progress" in documentation
    assert "passing" in documentation
    assert "silver" in documentation
    assert "gold" in documentation
    assert "does not prove" in documentation
    assert "--source-json" in documentation
    assert "buyer-diligence" in documentation
    assert "OpenSSF Best Practices Badge API" in documentation
    assert "OpenSSF Best Practices badge contributors" in documentation
    assert "CDLA-Permissive-2.0" in documentation
    assert "CC-BY-3.0" in documentation
    assert "2024-08-23" in documentation


def test_operator_documentation_cites_primary_standards_in_apa_seventh_style() -> None:
    """The evidence design must retain auditable APA-style primary references."""
    documentation = (ROOT / "docs" / "openssf-best-practices-evidence.md").read_text(
        encoding="utf-8"
    )

    assert "## References (APA 7th)" in documentation
    assert "https://doi.org/10.17487/RFC3986" in documentation
    assert "https://doi.org/10.17487/RFC6839" in documentation
    assert "https://doi.org/10.17487/RFC8259" in documentation
    assert "Open Source Security Foundation. (n.d.)." in documentation
    assert "Retrieved August 4, 2026" in documentation


def test_changelog_fragment_describes_buyer_visible_evidence() -> None:
    """The next release must include the evidence collection and report behavior."""
    changelog = (ROOT / "CHANGELOG.d" / "865-openssf-evidence.md").read_text(
        encoding="utf-8"
    )

    assert "OpenSSF Best Practices" in changelog
    assert "buyer-diligence" in changelog
    assert "unavailable" in changelog
    assert "permission" in changelog
    assert "CDLA-Permissive-2.0" in changelog


def test_evidence_module_uses_explicit_utc_timezone() -> None:
    """Evidence timestamps use a timezone-aware UTC clock before serialization."""
    source = (ROOT / "appguardrail_core" / "openssf_evidence.py").read_text(
        encoding="utf-8"
    )

    assert "datetime.now(timezone.utc)" in source


def test_package_metadata_matches_the_tested_python_floor() -> None:
    """Published compatibility must not claim an unsupported interpreter."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    lockfile = (ROOT / "uv.lock").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    tests_workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )

    assert 'requires-python = ">=3.11"' in pyproject
    assert '"Programming Language :: Python :: 3.9"' not in pyproject
    assert '"Programming Language :: Python :: 3.10"' not in pyproject
    assert '"Programming Language :: Python :: 3.11"' in pyproject
    assert 'requires-python = ">=3.11"' in lockfile
    assert "Requires Python 3.11 or newer." in readme
    assert "python-version: ['3.11', '3.13']" in tests_workflow


def test_exact_coverage_workflow_tracks_every_openssf_test_surface() -> None:
    """New production code must retain an exact unrounded 100% coverage gate."""
    workflow = (
        ROOT / ".github" / "workflows" / "tests.yml"
    ).read_text(encoding="utf-8")

    assert "appguardrail_core/__init__.py" in workflow
    assert "appguardrail_core/openssf_evidence.py" in workflow
    assert "appguardrail_core/openssf_report.py" in workflow
    for path in (
        "tests/test_openssf_evidence.py",
        "tests/test_openssf_evidence_transport.py",
        "tests/test_openssf_evidence_cli.py",
        "tests/test_openssf_evidence_report.py",
        "tests/test_openssf_evidence_release_contract.py",
        "tests/test_openssf_evidence_coverage_edges.py",
        "tests/test_openssf_evidence_validation_edges.py",
    ):
        assert path in workflow
    assert "python -m scripts.ci.verify_module_coverage" in workflow
    assert "permissions:\n  contents: read" in workflow


def test_commercial_readiness_registry_preserves_the_next_gap_order() -> None:
    """Closing issue #865 makes retention controls the next deterministic slice."""
    gap_ids = tuple(gap.id for gap in COMMERCIAL_GAPS)

    assert gap_ids[:2] == (
        "openssf-best-practices-evidence",
        "enterprise-retention-audit-policy",
    )
