"""Regression coverage for finding-category secret boundaries."""

from scanner.cli.appguardrail import _finding_category


def test_sensitive_database_credentials_are_secret_findings() -> None:
    """Credential-bearing database rule IDs must not fall through to misconfig/storage."""
    assert _finding_category("frontend-database-dsn-exposure") == "secrets"
    assert _finding_category("hardcoded-db-url") == "secrets"
    assert _finding_category("supabase-service-role-client") == "secrets"


def test_redaction_provider_token_does_not_reclassify_github_actions_rule() -> None:
    """Provider names used for redaction must not redefine unrelated finding categories."""
    assert _finding_category("github-actions-sarif-missing-pull-request-trigger") == "misconfig"
