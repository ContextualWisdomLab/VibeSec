from appguardrail_core.reports import (
    ReportContext,
    render_agency_report,
    render_buyer_diligence_report,
    render_fix_pack,
    render_founder_friendly_report,
    render_report,
    supported_report_types,
)


def sample_findings():
    return [
        {
            "rule_id": "python-requests-verify-false",
            "severity": "HIGH",
            "message": "HTTP client disables TLS certificate verification.",
            "file": "client.py",
            "line": 7,
            "snippet": "requests.get(url, verify=False)",
            "category": "misconfig",
            "context": "app-code",
            "references": (
                "CWE-295 - Improper Certificate Validation",
                "OWASP A05:2021 - Security Misconfiguration",
            ),
            "remediation": "Keep certificate verification enabled.",
            "verification": "Rerun AppGuardrail and unit tests.",
        },
        {
            "rule_id": "docs-hardcoded-demo-secret",
            "severity": "CRITICAL",
            "message": "Demo secret in docs.",
            "file": "docs/example.md",
            "line": 3,
            "snippet": "[REDACTED: sensitive match suppressed]",
            "category": "secrets",
            "context": "doc",
            "references": ("CWE-798 - Use of Hard-coded Credentials",),
        },
    ]


def test_render_buyer_diligence_report_groups_findings_by_risk():
    context = ReportContext(
        app_name="Demo SaaS",
        repository="ContextualWisdomLab/demo",
        commit="abc123",
        generated_at="2026-07-02T00:00:00Z",
    )

    report = render_buyer_diligence_report(sample_findings(), context)

    assert "# AppGuardrail Buyer Diligence Report" in report
    assert "**App:** Demo SaaS" in report
    assert (
        "**Launch posture:** Conditional; resolve high findings before launch" in report
    )
    assert "**Deploy-blocking findings:** 1" in report
    assert "| Critical | 1 |" in report
    assert "| High | 1 |" in report
    assert "BD-001" in report
    assert "CWE-295 - Improper Certificate Validation" in report
    assert "Keep certificate verification enabled." in report
    assert "[REDACTED: sensitive match suppressed]" in report


def test_render_buyer_diligence_report_truncates_long_snippets():
    report = render_buyer_diligence_report(
        [
            {
                "rule_id": "long-snippet",
                "severity": "INFO",
                "message": "Long evidence.",
                "file": "app.py",
                "line": 1,
                "snippet": "x" * 500,
            }
        ],
        ReportContext(generated_at="2026-07-02T00:00:00Z"),
    )

    assert "...[truncated]" in report
    assert "x" * 450 not in report


def test_render_buyer_diligence_report_handles_empty_findings():
    report = render_buyer_diligence_report(
        [],
        ReportContext(
            app_name="Clean App",
            repository="ContextualWisdomLab/clean",
            generated_at="2026-07-02T00:00:00Z",
        ),
    )

    assert (
        "**Launch posture:** No deploy-blocking findings in supplied evidence" in report
    )
    assert "No findings were provided for this report." in report
    assert "No detailed findings." in report


def test_render_founder_friendly_report_creates_plain_language_fix_prompts():
    report = render_founder_friendly_report(
        sample_findings(),
        ReportContext(
            app_name="Demo SaaS",
            commit="abc123",
            generated_at="2026-07-02T00:00:00Z",
        ),
    )

    assert "# AppGuardrail Security Review Report" in report
    assert "**Overall Status:** Launch only after high-risk items are fixed" in report
    assert "## What We Checked" in report
    assert "Fix AppGuardrail finding `python-requests-verify-false`" in report
    assert "Fix `python-requests-verify-false` before launch" in report


def test_render_agency_report_groups_by_severity_and_priority():
    report = render_agency_report(
        sample_findings(),
        ReportContext(
            app_name="Demo SaaS",
            client_name="Demo Client",
            reviewer="Demo Agency",
            engagement_type="Retainer review",
            repository="ContextualWisdomLab/demo",
            commit="abc123",
            generated_at="2026-07-02T00:00:00Z",
        ),
    )

    assert "# AppGuardrail Agency Security Review Report" in report
    assert "**Client:** Demo Client" in report
    assert (
        "**Recommendation:** Approved for launch only after high findings are resolved"
        in report
    )
    assert "### High Findings" in report
    assert (
        "| AG-002 | HTTP client disables TLS certificate verifica... | High | Review | Before launch |"
        in report
    )
    assert "### Informational Findings" in report


def test_render_fix_pack_outputs_only_actionable_findings():
    report = render_fix_pack(
        [
            *sample_findings(),
            {
                "rule_id": "info-only",
                "severity": "INFO",
                "message": "Document useful context.",
                "file": "README.md",
                "line": 1,
            },
        ],
        ReportContext(
            app_name="Demo SaaS",
            generated_at="2026-07-02T00:00:00Z",
            based_on="review-123",
        ),
    )

    assert "# AppGuardrail Fix Pack" in report
    assert "**Based on review:** review-123" in report
    assert "FIX-001" in report
    assert "python-requests-verify-false" in report
    assert "info-only" not in report


def test_render_report_dispatches_supported_report_types():
    assert set(supported_report_types()) == {
        "buyer-diligence",
        "founder-friendly",
        "agency",
        "fix-pack",
    }
    report = render_report(
        "fix-pack",
        sample_findings(),
        ReportContext(generated_at="2026-07-02T00:00:00Z"),
    )

    assert "# AppGuardrail Fix Pack" in report


def test_reports_surface_assurance_and_fail_closed() -> None:
    """Every report type preserves assurance state before claiming launch readiness."""
    for outcome in ("clean", "findings_present", "incomplete", "failed", "untrusted"):
        assurance = {
            "schema": "appguardrail.scan-assurance.v1",
            "scan_outcome_code": outcome,
            "reasons": ["evidence_stale"] if outcome != "clean" else [],
        }
        context = ReportContext(
            generated_at="2026-07-02T00:00:00Z", assurance=assurance
        )
        buyer = render_buyer_diligence_report([], context)
        founder = render_founder_friendly_report([], context)
        agency = render_agency_report([], context)
        fix_pack = render_fix_pack([], context)

        assert f"**Scan assurance:** `{outcome}`" in buyer
        assert f"**Scan assurance:** `{outcome}`" in founder
        assert f"**Scan assurance:** `{outcome}`" in agency
        assert f"**Scan assurance:** `{outcome}`" in fix_pack
        if outcome == "clean":
            assert "Qualified clean scan evidence" in buyer
            assert "Cleared by qualified clean scan evidence" in founder
            assert "Cleared by qualified clean scan evidence" in agency
        elif outcome in {"incomplete", "failed", "untrusted"}:
            assert f"scan assurance is {outcome}" in buyer
            assert f"scan assurance is {outcome}" in founder
            assert f"scan assurance is {outcome}" in agency

    hostile = render_buyer_diligence_report(
        [],
        ReportContext(
            generated_at="2026-07-02T00:00:00Z",
            assurance={"schema": "wrong", "reasons": "do not trust this"},
        ),
    )
    assert "**Scan assurance:** `untrusted`" in hostile
    assert "do not trust this" not in hostile

    sanitized = render_buyer_diligence_report(
        [],
        ReportContext(
            generated_at="2026-07-02T00:00:00Z",
            assurance={
                "schema": "appguardrail.scan-assurance.v1",
                "scan_outcome_code": "incomplete",
                "reasons": ["bad <tag>\nline", 7],
            },
        ),
    )
    assert "bad &lt;tag&gt; line" in sanitized
    assert "<tag>" not in sanitized

    malformed_outcome = render_buyer_diligence_report(
        [],
        ReportContext(
            generated_at="2026-07-02T00:00:00Z",
            assurance={
                "schema": "appguardrail.scan-assurance.v1",
                "scan_outcome_code": [],
                "reasons": [],
            },
        ),
    )
    assert "**Scan assurance:** `untrusted`" in malformed_outcome

    critical = [
        {
            "rule_id": "critical-demo",
            "severity": "CRITICAL",
            "message": "Critical production issue.",
            "file": "app.py",
            "line": 1,
            "context": "app-code",
        }
    ]
    assert "Hold pending critical remediation" in render_buyer_diligence_report(critical)
    assert "Not ready for public launch" in render_founder_friendly_report(critical)
    assert "Hold pending critical fixes" in render_agency_report(critical)
