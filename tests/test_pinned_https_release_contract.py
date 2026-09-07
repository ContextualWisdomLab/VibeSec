"""Release and documentation contracts for DNS-pinned HTTPS delivery."""

from __future__ import annotations

from pathlib import Path

import appguardrail_core


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
DOCUMENTATION = ROOT / "docs" / "pinned-https-control-plane-delivery.md"
CHANGELOG = ROOT / "CHANGELOG.d" / "892-pinned-control-plane-delivery.md"


def test_core_package_exports_pinned_https_boundary() -> None:
    """Standalone and MSA consumers receive the reviewed transport API."""
    expected = {
        "DestinationValidationError",
        "HTTPSDestination",
        "PinnedHTTPSConnection",
        "PinnedHTTPSFailure",
        "PinnedHTTPSResponse",
        "ResolvedAddress",
        "post_json_pinned_https",
        "resolve_public_https_destination",
    }

    assert expected <= set(appguardrail_core.__all__)
    assert all(hasattr(appguardrail_core, name) for name in expected)


def test_pinned_https_workflow_enforces_exact_read_only_coverage() -> None:
    """The transport has an immutable least-privilege exact-coverage gate."""
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "push:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "python-version: ['3.11', '3.13']" in workflow
    assert "persist-credentials: false" in workflow
    assert "appguardrail_core/pinned_https.py" in workflow
    for test_name in (
        "test_pinned_https_resolution.py",
        "test_pinned_https_redirects.py",
        "test_pinned_https_cli_integration.py",
        "test_pinned_https_validation_edges.py",
        "test_pinned_https_coverage_edges.py",
        "test_pinned_https_release_contract.py",
    ):
        assert test_name in workflow


def test_operator_documentation_records_security_boundary_and_apa_sources() -> None:
    """Operators receive a complete architecture, rollback, and source record."""
    documentation = DOCUMENTATION.read_text(encoding="utf-8")

    required = (
        "DNS rebinding",
        "TLS SNI",
        "certificate",
        "307",
        "308",
        "Proxy-Authorization",
        "egress",
        "naruon",
        "## References",
        "RFC 3986",
        "RFC 9110",
        "RFC 9525",
        "Python Software Foundation",
    )
    assert all(item in documentation for item in required)
    assert "```mermaid" in documentation


def test_changelog_records_buyer_visible_transport_hardening() -> None:
    """The release fragment describes the user-visible security guarantee."""
    changelog = CHANGELOG.read_text(encoding="utf-8")

    assert changelog.startswith("### Security\n")
    assert "DNS-pinned" in changelog
    assert "Authorization" in changelog
    assert "Proxy-Authorization" in changelog
