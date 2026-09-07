"""Precision tests for password indirection, test-file context, and auth comments."""

from __future__ import annotations

from pathlib import Path

from appguardrail_core.findings import is_deploy_blocking
from scanner.cli.appguardrail import _scan_file


def _by_rule(path: Path, base: Path, rule_id: str) -> list[dict]:
    """Return findings for one rule from the shipped file scanner."""
    return [
        finding
        for finding in _scan_file(path, base)
        if finding["rule_id"] == rule_id
    ]


def test_literal_password_remains_detected(tmp_path: Path) -> None:
    """A real embedded password literal must still produce hardcoded-password."""
    target = tmp_path / "app.py"
    target.write_text("password='secret123'\n", encoding="utf-8")
    findings = _by_rule(target, tmp_path, "hardcoded-password")

    assert len(findings) == 1
    assert is_deploy_blocking(findings[0])


def test_shell_password_indirection_is_not_hardcoded(tmp_path: Path) -> None:
    """Self/variable assignment is not a committed secret literal."""
    target = tmp_path / "upgrade-legacy-local.sh"
    target.write_text(
        "POSTGRES_PASSWORD=\"$POSTGRES_PASSWORD\"\n"
        "PGPASSWORD=\"$LEGACY_POSTGRES_PASSWORD\"\n",
        encoding="utf-8",
    )
    assert _by_rule(target, tmp_path, "hardcoded-password") == []


def test_psql_password_variable_is_not_hardcoded(tmp_path: Path) -> None:
    """psql named-variable syntax is operator-provided, not a literal secret."""
    target = tmp_path / "notification-runtime.psql"
    target.write_text("ALTER ROLE runtime PASSWORD :'runtime_password';\n", encoding="utf-8")
    assert _by_rule(target, tmp_path, "hardcoded-password") == []


def test_test_filename_under_src_is_non_blocking_context(tmp_path: Path) -> None:
    """Explicit *.test.ts / *.test.mjs files are test context even under src/."""
    ts_target = tmp_path / "apps" / "notification-service" / "src" / "notification-http.test.ts"
    ts_target.parent.mkdir(parents=True)
    ts_target.write_text(
        'DATABASE_URL="postgresql://runtime.invalid/notifications"\n',
        encoding="utf-8",
    )
    mjs_target = (
        tmp_path
        / "packages"
        / "commercial-development-agent"
        / "src"
        / "compose-runtime-workflow-regression.test.mjs"
    )
    mjs_target.parent.mkdir(parents=True)
    mjs_target.write_text("password='secret123'\n", encoding="utf-8")

    ts_findings = _scan_file(ts_target, tmp_path)
    mjs_findings = _by_rule(mjs_target, tmp_path, "hardcoded-password")

    assert mjs_findings
    assert mjs_findings[0]["context"] == "test"
    assert not is_deploy_blocking(mjs_findings[0])
    for finding in ts_findings:
        if finding["rule_id"] == "hardcoded-database-url":
            assert finding["context"] == "test"
            assert not is_deploy_blocking(finding)


def test_credential_bearing_production_database_url_remains_blocking(
    tmp_path: Path,
) -> None:
    """A production URL with userinfo remains a deploy-blocking secret."""
    target = tmp_path / "src" / "config.ts"
    target.parent.mkdir(parents=True)
    target.write_text(
        'DATABASE_URL="postgresql://app:s3cret@db.example.com/prod"\n',
        encoding="utf-8",
    )
    findings = _by_rule(target, tmp_path, "hardcoded-database-url")
    assert findings
    assert findings[0]["context"] == "app-code"
    assert is_deploy_blocking(findings[0])


def test_authority_prototype_comments_are_not_auth_deferrals(tmp_path: Path) -> None:
    """Ordinary comments about prototypes or authority are not skip-auth findings."""
    target = tmp_path / "notification-data-rights-http-boundary.ts"
    target.write_text(
        "// Requires one ordinary JSON object so prototypes cannot add hidden authority fields.\n"
        "export const parseBody = JSON.parse\n",
        encoding="utf-8",
    )
    assert _by_rule(target, tmp_path, "todo-skip-auth") == []


def test_explicit_skip_auth_comment_remains_detected(tmp_path: Path) -> None:
    """True-positive authentication deferral comments must still fire."""
    target = tmp_path / "app.py"
    target.write_text("# TODO: add authentication before release\n", encoding="utf-8")
    findings = _by_rule(target, tmp_path, "todo-skip-auth")
    assert len(findings) == 1
    assert findings[0]["context"] == "app-code"
