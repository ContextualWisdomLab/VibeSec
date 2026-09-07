"""Report builders backed by normalized AppGuardrail findings."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from appguardrail_core.findings import (
    SEVERITIES,
    finding_sort_key,
    is_deploy_blocking,
    normalize_finding,
    severity_counts,
)


@dataclass(frozen=True)
class ReportContext:
    """Context shown in generated diligence reports."""

    app_name: str = "AppGuardrail scan target"
    repository: str = "n/a"
    commit: str = "n/a"
    generated_at: str = ""
    scan_command: str = "appguardrail scan ."
    scope: str = "Application source, configuration, and security workflow evidence."
    client_name: str = "n/a"
    reviewer: str = "AppGuardrail"
    engagement_type: str = "Pre-launch review"
    based_on: str = "AppGuardrail findings JSON"
    assurance: Mapping[str, Any] | None = None


REPORT_TYPE_LABELS = {
    "buyer-diligence": "Buyer diligence report",
    "founder-friendly": "Founder-friendly report",
    "agency": "Agency report",
    "fix-pack": "Fix pack",
}


def supported_report_types() -> tuple[str, ...]:
    """Return CLI-visible report types."""
    return tuple(REPORT_TYPE_LABELS)


def render_report(
    report_type: str,
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render any supported report type from normalized findings."""
    renderers = {
        "buyer-diligence": render_buyer_diligence_report,
        "founder-friendly": render_founder_friendly_report,
        "agency": render_agency_report,
        "fix-pack": render_fix_pack,
    }
    try:
        renderer = renderers[report_type]
    except KeyError as exc:
        raise ValueError(f"Unsupported report type: {report_type}") from exc
    return renderer(findings, context)


def render_buyer_diligence_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render a buyer-diligence markdown report from normalized findings."""
    context = context or ReportContext()
    normalized = [
        _sanitize_for_markdown(normalize_finding(finding)) for finding in findings
    ]
    normalized.sort(key=finding_sort_key)
    counts = severity_counts(normalized)
    blockers = [finding for finding in normalized if is_deploy_blocking(finding)]

    generated_at = context.generated_at or datetime.now(UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    lines = [
        "# AppGuardrail Buyer Diligence Report",
        "",
        f"**App:** {context.app_name}",
        f"**Repository:** {context.repository}",
        f"**Commit:** {context.commit}",
        f"**Generated:** {generated_at}",
        f"**Scan command:** `{context.scan_command}`",
        "",
        "## Executive Readout",
        "",
        f"**Launch posture:** {_launch_posture(blockers, context.assurance)}",
        f"**Deploy-blocking findings:** {len(blockers)}",
        *_assurance_report_lines(context.assurance),
        "",
        "| Severity | Count |",
        "|---|---:|",
        *[f"| {severity.title()} | {counts[severity]} |" for severity in SEVERITIES],
        "",
        "## Scope And Evidence Handling",
        "",
        f"- Scope: {context.scope}",
        "- Raw customer code, secrets, tokens, and authorization values are not included.",
        "- Findings are grouped by public security taxonomy where available.",
        "- Suggested remediation is generated from AppGuardrail normalized metadata.",
        "",
        "## Findings Summary",
        "",
    ]

    if normalized:
        lines.extend(_summary_table(normalized))
    else:
        lines.append("No findings were provided for this report.")

    lines.extend(["", "## Detailed Findings", ""])
    if normalized:
        for index, finding in enumerate(normalized, start=1):
            lines.extend(_finding_detail(index, finding))
    else:
        lines.append("No detailed findings.")

    lines.extend(
        [
            "",
            "## Buyer Follow-Up Checklist",
            "",
            "- Confirm critical and high app-code findings are fixed or formally accepted.",
            "- Re-run AppGuardrail and external engines used in the sale-readiness plan.",
            "- Preserve GitHub Actions links and issue history for audit evidence.",
            "- Confirm privacy retention, redaction policy, and authorized DAST targets.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_founder_friendly_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render a plain-language launch readiness report for founders."""
    context, normalized, counts, blockers, generated_at = _prepare_report(
        findings, context
    )
    lines = [
        "# AppGuardrail Security Review Report",
        "",
        f"**App:** {context.app_name}",
        f"**Reviewed by:** {context.reviewer}",
        f"**Date:** {generated_at}",
        f"**Version / Commit:** {context.commit}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
        *[f"| {severity.title()} | {counts[severity]} |" for severity in SEVERITIES],
        "",
        f"**Overall Status:** {_founder_status(blockers, context.assurance)}",
        *_assurance_report_lines(context.assurance),
        "",
        "## What We Checked",
        "",
        "- Authentication and protected routes",
        "- Authorization and ownership checks",
        "- Secrets and environment variables",
        "- Database security and query construction",
        "- File uploads and user-controlled paths",
        "- Payments, webhooks, CORS, headers, and deployment configuration",
        "",
        "## Findings",
        "",
    ]
    if normalized:
        for index, finding in enumerate(normalized, start=1):
            lines.extend(_founder_finding(index, finding))
    else:
        lines.append("No findings were provided for this report.")

    lines.extend(
        [
            "",
            "## What's Good",
            "",
            "- AppGuardrail evidence is normalized for repeatable review.",
            "- Report snippets are trimmed to avoid carrying raw secrets or oversized logs.",
            "- Public taxonomy references are included when findings provide them.",
            "",
            "## Recommended Next Steps",
            "",
        ]
    )
    lines.extend(_next_steps(normalized, blockers))
    lines.extend(
        [
            "",
            "## Scope And Limitations",
            "",
            f"- Scope: {context.scope}",
            "- This report summarizes supplied AppGuardrail findings and does not replace a full penetration test.",
            "- Third-party service internals and social engineering are outside this report unless separately reviewed.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_agency_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render a client-ready agency security review report."""
    context, normalized, counts, blockers, generated_at = _prepare_report(
        findings, context
    )
    lines = [
        "# AppGuardrail Agency Security Review Report",
        "",
        f"**Client:** {context.client_name}",
        f"**Project:** {context.app_name}",
        f"**Reviewed by:** {context.reviewer}",
        f"**Date:** {generated_at}",
        f"**Engagement type:** {context.engagement_type}",
        "",
        "## Executive Summary",
        "",
        f"**Critical findings requiring immediate action:** {counts['CRITICAL']}",
        f"**High-severity findings:** {counts['HIGH']}",
        f"**Total findings:** {len(normalized)}",
        f"**Recommendation:** {_agency_recommendation(blockers, context.assurance)}",
        *_assurance_report_lines(context.assurance),
        "",
        "## Methodology",
        "",
        "1. Static analysis of source, config, and workflow evidence.",
        "2. External engine ingestion when Bandit, Ruff, Semgrep, Trivy, or ZAP findings are supplied.",
        "3. Normalization to AppGuardrail severity, context, remediation, and verification metadata.",
        "4. Client-ready prioritization by deploy-blocking risk.",
        "",
        "## Findings",
        "",
    ]
    if normalized:
        for severity in SEVERITIES:
            severity_findings = [
                finding for finding in normalized if finding["severity"] == severity
            ]
            lines.extend(_agency_severity_section(severity, severity_findings))
    else:
        lines.append("No findings were provided for this report.")

    lines.extend(
        [
            "",
            "## Remediation Priority Matrix",
            "",
        ]
    )
    if normalized:
        lines.extend(_priority_matrix(normalized))
    else:
        lines.append("No remediation items.")

    lines.extend(
        [
            "",
            "## Retest Notes",
            "",
            "| ID | Status | Notes |",
            "|---|---|---|",
        ]
    )
    if normalized:
        for index, finding in enumerate(normalized, start=1):
            lines.append(
                f"| AG-{index:03d} | Pending | Rerun {finding['rule_id']} evidence. |"
            )
    else:
        lines.append("| n/a | n/a | No findings. |")

    lines.extend(
        [
            "",
            "## Appendix A: Tools Used",
            "",
            f"- `{context.scan_command}`",
            "- AppGuardrail normalized findings contract",
            "",
            "## Appendix B: Scope",
            "",
            f"- Repository: {context.repository}",
            f"- Commit: {context.commit}",
            f"- Scope: {context.scope}",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_fix_pack(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None = None,
) -> str:
    """Render AI-ready remediation prompts and verification steps."""
    context, normalized, _counts, _blockers, generated_at = _prepare_report(
        findings, context
    )
    actionable = [
        finding
        for finding in normalized
        if finding["severity"] in {"CRITICAL", "HIGH", "WARNING"}
    ]
    lines = [
        "# AppGuardrail Fix Pack",
        "",
        "A Fix Pack turns AppGuardrail findings into AI-ready remediation work items.",
        "",
        f"**App:** {context.app_name}",
        f"**Fix Pack generated:** {generated_at}",
        f"**Based on review:** {context.based_on}",
        *_assurance_report_lines(context.assurance),
        "",
        "## How To Use This Fix Pack",
        "",
        "1. Work through each item from top to bottom: Critical, High, then Warning.",
        "2. Copy the Fix Prompt into Claude Code, Cursor, Codex, or another coding assistant.",
        "3. Apply the change in a branch, then run the Verification Test.",
        "4. Re-run AppGuardrail before marking the item fixed.",
        "",
        "## Fix Items",
        "",
    ]
    if actionable:
        for index, finding in enumerate(actionable, start=1):
            lines.extend(_fix_item(index, finding))
    else:
        lines.append("No critical, high, or warning findings were provided.")

    lines.extend(
        [
            "",
            "## Fix Pack Status",
            "",
        ]
    )
    if actionable:
        lines.extend(_fix_status_table(actionable))
    else:
        lines.append("No open fix items.")

    lines.extend(
        [
            "",
            "## Post-Fix Checklist",
            "",
            "- Run `appguardrail scan .` and confirm no new deploy-blocking issues.",
            "- Run the project test suite and confirm no regressions.",
            "- Deploy to staging and repeat the listed verification tests.",
            "- Keep the report and scan JSON as remediation evidence.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


_ASSURANCE_OUTCOMES = frozenset(
    {"clean", "findings_present", "incomplete", "failed", "untrusted"}
)


def _assurance_outcome(assurance: Mapping[str, Any] | None) -> str | None:
    """Return a validated assurance outcome, or fail closed for bad input."""
    if assurance is None:
        return None
    if assurance.get("schema") != "appguardrail.scan-assurance.v1":
        return "untrusted"
    outcome = assurance.get("scan_outcome_code")
    if isinstance(outcome, str) and outcome in _ASSURANCE_OUTCOMES:
        return outcome
    return "untrusted"


def _assurance_report_lines(assurance: Mapping[str, Any] | None) -> list[str]:
    """Render optional scan-assurance state without exposing untrusted detail."""
    outcome = _assurance_outcome(assurance)
    if outcome is None:
        return []
    reasons = assurance.get("reasons") if assurance is not None else None
    safe_reasons = (
        ", ".join(
            _md_prose(str(reason)[:120].replace("\n", " "))
            for reason in reasons
            if isinstance(reason, str)
        )
        if isinstance(reasons, list)
        else ""
    )
    suffix = f" — {safe_reasons}" if safe_reasons else ""
    return [f"**Scan assurance:** `{outcome}`{suffix}"]


def _launch_posture(
    blockers: list[dict[str, Any]], assurance: Mapping[str, Any] | None = None
) -> str:
    """Summarize whether blocker severity and evidence assurance permit launch."""
    outcome = _assurance_outcome(assurance)
    if outcome in {"incomplete", "failed", "untrusted"}:
        return f"Hold; scan assurance is {outcome}"
    if outcome == "clean":
        return "Qualified clean scan evidence"
    if any(finding["severity"] == "CRITICAL" for finding in blockers):
        return "Hold pending critical remediation"
    if blockers:
        return "Conditional; resolve high findings before launch"
    return "No deploy-blocking findings in supplied evidence"


def _summary_table(findings: list[dict[str, Any]]) -> list[str]:
    """Render the buyer diligence summary table."""
    rows = [
        "| ID | Severity | Category | Location | References |",
        "|---|---|---|---|---|",
    ]
    for index, finding in enumerate(findings, start=1):
        references = ", ".join(
            finding["references"] or finding["owasp"] or finding["cwe"]
        )
        rows.append(
            "| {id} | {severity} | {category} | `{location}` | {references} |".format(
                id=f"BD-{index:03d}",
                severity=finding["severity"].title(),
                category=finding["category"],
                location=f"{finding['file']}:{finding['line']}",
                references=references or "n/a",
            )
        )
    return rows


def _finding_detail(index: int, finding: dict[str, Any]) -> list[str]:
    """Render one detailed buyer diligence finding section."""
    references = ", ".join(finding["references"] or finding["owasp"] or finding["cwe"])
    return [
        f"### BD-{index:03d}: {_short_title(finding['message'])}",
        "",
        f"- Severity: {finding['severity'].title()}",
        f"- Rule: `{finding['rule_id']}`",
        f"- Category: `{finding['category']}`",
        f"- Context: `{finding['context']}`",
        f"- Location: `{finding['file']}:{finding['line']}`",
        f"- References: {references or 'n/a'}",
        "",
        "**Evidence:**",
        "",
        f"```text\n{finding['snippet'] or '(snippet unavailable)'}\n```",
        "",
        f"**Risk:** {finding['message']}",
        "",
        f"**Remediation:** {finding['remediation']}",
        "",
        f"**Verification:** {finding['verification']}",
        "",
    ]


_PROSE_FIELDS = ("message", "remediation", "verification")


def _md_prose(value: Any) -> str:
    """HTML-neutralize free text so a hostile finding message can't inject
    markup when a generated markdown report is later rendered as HTML."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_fence(value: Any) -> str:
    """Prevent a snippet from breaking out of its ``` code fence."""
    return str(value).replace("```", "`\u200b``")


def _sanitize_for_markdown(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a render-safe copy: prose fields HTML-escaped, snippet fence-safe.

    rule_id/category/context/severity are constrained identifiers used in gate
    logic and are left untouched.
    """
    safe = dict(finding)
    for field in _PROSE_FIELDS:
        if field in safe:
            safe[field] = _md_prose(safe[field])
    if "snippet" in safe:
        safe["snippet"] = _md_fence(safe["snippet"])
    return safe


def _short_title(message: str, max_len: int = 84) -> str:
    """Return a compact report heading derived from a finding message."""
    title = message.split(".", 1)[0].strip() or "Security finding"
    if len(title) <= max_len:
        return title
    return title[: max_len - 3].rstrip() + "..."


def _prepare_report(
    findings: Iterable[dict[str, Any]],
    context: ReportContext | None,
) -> tuple[
    ReportContext,
    list[dict[str, Any]],
    dict[str, int],
    list[dict[str, Any]],
    str,
]:
    """Normalize findings and compute shared report metadata."""
    context = context or ReportContext()
    normalized = [
        _sanitize_for_markdown(normalize_finding(finding)) for finding in findings
    ]
    normalized.sort(key=finding_sort_key)
    counts = severity_counts(normalized)
    blockers = [finding for finding in normalized if is_deploy_blocking(finding)]
    generated_at = context.generated_at or datetime.now(UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return context, normalized, counts, blockers, generated_at


def _founder_status(
    blockers: list[dict[str, Any]], assurance: Mapping[str, Any] | None = None
) -> str:
    """Return the founder-facing launch status and fail closed on weak evidence."""
    outcome = _assurance_outcome(assurance)
    if outcome in {"incomplete", "failed", "untrusted"}:
        return f"Not ready; scan assurance is {outcome}"
    if outcome == "clean":
        return "Cleared by qualified clean scan evidence"
    if any(finding["severity"] == "CRITICAL" for finding in blockers):
        return "Not ready for public launch"
    if blockers:
        return "Launch only after high-risk items are fixed"
    return "Cleared for launch based on supplied findings"


def _founder_finding(index: int, finding: dict[str, Any]) -> list[str]:
    """Render one founder-friendly finding section."""
    return [
        f"### Finding {index}: {_short_title(finding['message'])}",
        "",
        f"**Severity:** {finding['severity'].title()}",
        "",
        f"**What we found:** {finding['message']}",
        "",
        f"**Why it matters:** {_plain_risk(finding)}",
        "",
        "**Fix prompt:**",
        "",
        f"```text\n{_fix_prompt(finding)}\n```",
        "",
        f"**How to verify the fix:** {finding['verification']}",
        "",
    ]


def _plain_risk(finding: dict[str, Any]) -> str:
    """Translate severity into plain-language business risk."""
    severity = finding["severity"]
    if severity == "CRITICAL":
        return "This can expose sensitive data, credentials, money movement, or remote execution risk if reachable in production."
    if severity == "HIGH":
        return "This is likely to become a launch blocker if the affected code is reachable by users or automated workflows."
    if severity == "WARNING":
        return "This may be safe in context, but it needs a deliberate review before launch."
    return "This is useful context for hardening and buyer diligence."


def _fix_prompt(finding: dict[str, Any]) -> str:
    """Render a focused remediation prompt for one finding."""
    return "\n".join(
        [
            f"Fix AppGuardrail finding `{finding['rule_id']}` in `{finding['file']}:{finding['line']}`.",
            "",
            f"Problem: {finding['message']}",
            f"Recommended remediation: {finding['remediation']}",
            "",
            f"After applying the fix, verify with: {finding['verification']}",
        ]
    )


def _next_steps(
    findings: list[dict[str, Any]], blockers: list[dict[str, Any]]
) -> list[str]:
    """Choose the next recommended operator actions for a report."""
    if not findings:
        return ["1. Re-run AppGuardrail with current production-bound code."]
    steps = []
    if blockers:
        first = blockers[0]
        steps.append(
            f"1. Fix `{first['rule_id']}` before launch because it is deploy-blocking."
        )
        steps.append("2. Re-run AppGuardrail and keep the findings JSON as evidence.")
        steps.append("3. Review warning and info items before the next release.")
    else:
        steps.append("1. Keep this clean findings snapshot with release evidence.")
        steps.append("2. Re-run AppGuardrail on every security-sensitive pull request.")
        steps.append("3. Schedule periodic external engine checks for drift.")
    return steps


def _agency_recommendation(
    blockers: list[dict[str, Any]], assurance: Mapping[str, Any] | None = None
) -> str:
    """Return the agency recommendation and fail closed on weak evidence."""
    outcome = _assurance_outcome(assurance)
    if outcome in {"incomplete", "failed", "untrusted"}:
        return f"Hold; scan assurance is {outcome}"
    if outcome == "clean":
        return "Cleared by qualified clean scan evidence"
    if any(finding["severity"] == "CRITICAL" for finding in blockers):
        return "Hold pending critical fixes"
    if blockers:
        return "Approved for launch only after high findings are resolved"
    return "Cleared based on supplied AppGuardrail evidence"


def _agency_severity_section(
    severity: str, findings: list[dict[str, Any]]
) -> list[str]:
    """Render all agency report findings for one severity bucket."""
    heading = severity.title() if severity != "INFO" else "Informational"
    lines = [f"### {heading} Findings", ""]
    if not findings:
        lines.append(f"No {heading.lower()} findings.")
        lines.append("")
        return lines
    for finding in findings:
        lines.extend(
            [
                f"#### {_short_title(finding['message'])}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Severity | {finding['severity'].title()} |",
                f"| Category | `{finding['category']}` |",
                f"| Affected Component | `{finding['file']}:{finding['line']}` |",
                f"| Rule | `{finding['rule_id']}` |",
                f"| References | {_references(finding)} |",
                "",
                f"**Description:** {finding['message']}",
                "",
                f"**Remediation:** {finding['remediation']}",
                "",
                f"**Verification:** {finding['verification']}",
                "",
            ]
        )
    return lines


def _priority_matrix(findings: list[dict[str, Any]]) -> list[str]:
    """Render the agency prioritization table."""
    lines = [
        "| ID | Title | Severity | Effort | Priority |",
        "|---|---|---|---|---|",
    ]
    for index, finding in enumerate(findings, start=1):
        priority = _priority_for(finding)
        lines.append(
            "| {id} | {title} | {severity} | {effort} | {priority} |".format(
                id=f"AG-{index:03d}",
                title=_short_title(finding["message"], max_len=48),
                severity=finding["severity"].title(),
                effort="Review",
                priority=priority,
            )
        )
    return lines


def _priority_for(finding: dict[str, Any]) -> str:
    """Map a finding to a remediation priority label."""
    if is_deploy_blocking(finding):
        return "Immediate" if finding["severity"] == "CRITICAL" else "Before launch"
    if finding["severity"] == "WARNING":
        return "Within 30 days"
    return "Backlog"


def _fix_item(index: int, finding: dict[str, Any]) -> list[str]:
    """Render one actionable fix-pack checklist item."""
    return [
        f"### [ ] FIX-{index:03d}: {_short_title(finding['message'])}",
        "",
        f"**Severity:** {finding['severity'].title()}",
        "",
        f"**Problem:** {finding['message']}",
        "",
        f"**Risk:** {_plain_risk(finding)}",
        "",
        "**Fix Prompt:**",
        "",
        f"```text\n{_fix_prompt(finding)}\n```",
        "",
        "**Verification Test:**",
        "",
        f"{finding['verification']}",
        "",
    ]


def _fix_status_table(findings: list[dict[str, Any]]) -> list[str]:
    """Render the fix-pack status tracking table."""
    lines = [
        "| ID | Title | Severity | Status | Fixed By | Verified |",
        "|---|---|---|---|---|---|",
    ]
    for index, finding in enumerate(findings, start=1):
        lines.append(
            "| {id} | {title} | {severity} | Open | | |".format(
                id=f"FIX-{index:03d}",
                title=_short_title(finding["message"], max_len=48),
                severity=finding["severity"].title(),
            )
        )
    return lines


def _references(finding: dict[str, Any]) -> str:
    """Return a comma-separated reference list for a finding."""
    return (
        ", ".join(finding["references"] or finding["owasp"] or finding["cwe"]) or "n/a"
    )
