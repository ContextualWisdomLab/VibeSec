"""Public API, documentation, standards, and exact-coverage contracts."""

from __future__ import annotations

from pathlib import Path

from appguardrail_core import (
    AuditEvent,
    PurgePreview,
    PurgeReceipt,
    RetentionPolicy,
    create_audit_event,
    create_purge_receipt,
    sanitize_audit_summary,
    update_retention_policy,
    verify_audit_chain,
    verify_purge_preview,
)


ROOT = Path(__file__).resolve().parents[1]


def test_retention_and_audit_types_are_public_modular_core_api() -> None:
    """Standalone, organization, and naruon consumers share documented core symbols."""
    assert AuditEvent.__module__ == "appguardrail_core.audit_events"
    assert RetentionPolicy.__module__ == "appguardrail_core.retention_policy"
    assert PurgePreview.__module__ == "appguardrail_core.retention_policy"
    assert PurgeReceipt.__module__ == "appguardrail_core.retention_policy"
    for symbol in (
        create_audit_event,
        create_purge_receipt,
        sanitize_audit_summary,
        update_retention_policy,
        verify_audit_chain,
        verify_purge_preview,
    ):
        assert callable(symbol)


def test_operator_documentation_records_limits_and_apa_seventh_references() -> None:
    """Operators can understand policy and evidence boundaries without reading code."""
    documentation = (ROOT / "docs" / "retention-audit-policy.md").read_text(
        encoding="utf-8"
    )

    for phrase in (
        "product defaults, not legal advice",
        "tamper-evident",
        "not physically immutable",
        "Tail-truncation detection",
        "current policy and legal-hold revisions",
        "legal hold",
        "optimistic concurrency",
        "idempotent",
        "NIST SP 800-53",
        "NIST SP 800-92",
        "ISO/IEC 27001:2022",
        "Article 5(1)(e)",
        "Article 17",
        "## References (APA 7th)",
        "https://doi.org/10.6028/NIST.SP.800-53r5",
        "https://doi.org/10.6028/NIST.SP.800-92",
    ):
        assert phrase in documentation


def test_changelog_fragment_names_buyer_visible_governance_evidence() -> None:
    """The next release notes retain the retention and audit buyer value."""
    changelog = (ROOT / "CHANGELOG.d" / "871-retention-audit-core.md").read_text(
        encoding="utf-8"
    )

    for phrase in (
        "tenant-scoped retention",
        "tamper-evident audit",
        "purge preview",
        "legal-hold",
        "trusted count or head-hash checkpoints",
        "exact 100% statement coverage",
    ):
        assert phrase in changelog


def test_exact_coverage_workflow_tracks_every_core_surface() -> None:
    """The new production modules remain behind exact unrounded coverage evidence."""
    workflow = (
        ROOT / ".github" / "workflows" / "tests.yml"
    ).read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in workflow
    assert "appguardrail_core/audit_events.py" in workflow
    assert "appguardrail_core/retention_policy.py" in workflow
    assert "tests/test_audit_events.py" in workflow
    assert "tests/test_audit_checkpoint_edges.py" in workflow
    assert "tests/test_retention_policy.py" in workflow
    assert "tests/test_retention_policy_edges.py" in workflow
    assert "tests/test_retention_audit_release_contract.py" in workflow
    assert "tests/test_module_coverage_gate_contract.py" in workflow
    assert "python -m scripts.ci.verify_module_coverage" in workflow


def test_implementation_plan_preserves_bounded_follow_up_slices() -> None:
    """The first modular core PR does not pretend persistence and APIs already exist."""
    plan = (
        ROOT
        / "docs"
        / "superpowers"
        / "plans"
        / "2026-08-04-retention-audit-policy.md"
    ).read_text(encoding="utf-8")

    assert "Phase 1: dependency-free policy and audit core" in plan
    assert "Phase 2: descriptive SQLite schema migration" in plan
    assert "Phase 3: owner API and atomic purge execution" in plan
    assert "Phase 4: buyer-diligence and organization evidence" in plan
    assert "trusted event-count and head-hash checkpoints" in plan
    assert "Closes #871 only after Phase 4" in plan
