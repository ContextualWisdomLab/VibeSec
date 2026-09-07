"""Documentation, workflow, and release contracts for schema migration."""

from __future__ import annotations

from pathlib import Path

import appguardrail_core


ROOT = Path(__file__).resolve().parents[1]


def test_operator_documentation_records_safety_and_phase_boundary() -> None:
    """Operators can rehearse migration without reading production source code."""
    documentation = (ROOT / "docs" / "controlplane-schema-migration.md").read_text(
        encoding="utf-8"
    )

    for required_text in (
        "BEGIN IMMEDIATE",
        "PRAGMA foreign_key_check",
        "PRAGMA user_version = 2",
        "does not use `PRAGMA writable_schema`",
        "Phase boundary",
        "Python Software Foundation. (2026)",
        "SQLite Consortium. (2026a)",
    ):
        assert required_text in documentation
    assert "TODO" not in documentation
    assert "TBD" not in documentation


def test_changelog_records_buyer_visible_migration_behavior() -> None:
    """The next release notes include data preservation and fail-closed behavior."""
    changelog = (
        ROOT / "CHANGELOG.d" / "871-retention-schema-migration.md"
    ).read_text(encoding="utf-8")

    assert "multiword `snake_case`" in changelog
    assert "preserving tenant" in changelog
    assert "append-only audit triggers" in changelog
    assert "fail-closed" in changelog


def test_public_exports_list_every_schema_migration_symbol() -> None:
    """Package wildcard and direct imports expose the reusable migration boundary."""
    expected = {
        "CANONICAL_INDEX_NAMES",
        "CANONICAL_TABLE_NAMES",
        "CANONICAL_TRIGGER_NAMES",
        "CURRENT_SCHEMA_VERSION",
        "SchemaInspection",
        "SchemaMigrationError",
        "SchemaMigrationResult",
        "inspect_controlplane_schema",
        "migrate_controlplane_schema",
    }

    assert expected <= set(appguardrail_core.__all__)
    assert all(hasattr(appguardrail_core, name) for name in expected)


def test_exact_coverage_workflow_is_least_privilege_and_complete() -> None:
    """Schema production statements are gated by all dedicated contract tests."""
    workflow = (
        ROOT / ".github" / "workflows" / "tests.yml"
    ).read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "appguardrail_core/controlplane_schema.py" in workflow
    for test_path in (
        "tests/test_controlplane_schema_migration.py",
        "tests/test_controlplane_schema_failure_edges.py",
        "tests/test_controlplane_schema_contract.py",
        "tests/test_controlplane_schema_coverage_edges.py",
        "tests/test_controlplane_schema_release_contract.py",
    ):
        assert test_path in workflow
    assert "python -m scripts.ci.verify_module_coverage" in workflow
