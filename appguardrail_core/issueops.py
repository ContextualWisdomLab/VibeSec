"""Reusable IssueOps helpers for security workflow failure handling."""

from __future__ import annotations

import json
import re
from typing import Any

FAILURES = {"failure", "cancelled", "timed_out", "action_required"}
SECURITY_TERMS = (
    "strix",
    "opencode",
    "appguardrail",
    "trivy",
    "codeql",
    "security process",
)
MARKER_PREFIX = "<!-- appguardrail-org-security-failure:"
MARKER_SUFFIX = "-->"
DEFAULT_MAX_LOG_CHARS = 30_000
DEFAULT_MAX_LOG_LINES = 200
MAX_GITHUB_RUN_ID_DIGITS = 20

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TS_RE = re.compile(
    r"^\ufeff?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z[^\S\r\n]*",
    re.MULTILINE,
)
WORKFLOW_DISPATCH_SUFFIX_RE = re.compile(
    r"\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*@[0-9a-f]{40}$",
    re.IGNORECASE,
)
_LINE_SEPARATOR_TRANSLATION = str.maketrans(
    {
        separator: "\n"
        for separator in ("\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
    }
)
SECRET_RE = [
    re.compile(r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"),
    re.compile(
        r"(?im)\b((?:api[_-]?key|token|secret|password|private[_-]?key)\s*[:=]\s*)"
        r"(?:'(?:\\.|[^'\\\r\n])*(?:'|(?=\r?$))|"
        r'"(?:\\.|[^"\\\r\n])*(?:"|(?=\r?$))|'
        r"[^'\"\s]+['\"]?)"
    ),
    re.compile(
        r"\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9]{20,})\b"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
]
PRIMARY_LOG_RE = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"^\s*::error::",
        r"traceback",
        r"vuln-",
        r"\bcritical\b",
        r"\bhigh\b",
        r"ratelimiterror",
        r"unable to map strix findings",
        r"\btimeout\b|\btimed out\b",
    )
]
FALLBACK_LOG_RE = [re.compile(r"\bfailed\b|\berror\b|\bfatal\b", re.IGNORECASE)]


def is_failure(conclusion: str | None) -> bool:
    """Return whether a GitHub conclusion represents a failed security run."""
    return (conclusion or "").lower() in FAILURES


def is_security_name(*names: str | None) -> bool:
    """Return whether workflow or job names look security-relevant."""
    text = " ".join(name or "" for name in names).lower()
    return any(term in text for term in SECURITY_TERMS)


def parse_run_url(url: str) -> tuple[str, int]:
    """Extract a bounded run id from an exact public GitHub Actions URL."""
    match = re.fullmatch(
        rf"https://github\.com/"
        rf"([A-Za-z0-9_.-]{{1,100}}/[A-Za-z0-9_.-]{{1,100}})"
        rf"/actions/runs/([0-9]{{1,{MAX_GITHUB_RUN_ID_DIGITS}}})"
        rf"(?:/job/[0-9]{{1,{MAX_GITHUB_RUN_ID_DIGITS}}})?"
        r"(?:#step:[0-9]{1,10}:[0-9]{1,10})?/?",
        url,
    )
    if not match:
        raise ValueError("Unsupported or oversized GitHub Actions run URL")
    return match.group(1), int(match.group(2))


def sanitize_label_value(value: str) -> str:
    """Convert arbitrary repository text into a compact GitHub label suffix."""
    value = re.sub(r"[^A-Za-z0-9._:-]+", "-", value.strip()).strip("-")
    return value[:45] or "unknown"


def canonical_workflow_name(name: str) -> str:
    """Return a stable workflow identity without a generated PR/head suffix."""
    normalized = str(name or "").strip()
    normalized = WORKFLOW_DISPATCH_SUFFIX_RE.sub("", normalized).strip()
    return normalized or "unknown workflow"


def redact(log: str) -> str:
    """Remove ANSI noise, timestamps, and obvious secrets from a job log."""
    text = ANSI_RE.sub(
        "", log.replace("\r\n", "\n").translate(_LINE_SEPARATOR_TRANSLATION)
    )
    if text.endswith("\n"):
        text = text[:-1]
    text = TS_RE.sub("", text)
    for regex in SECRET_RE:
        text = regex.sub(
            lambda match: (
                f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]"
            ),
            text,
        )
    return text


def log_ranges(
    lines: list[str], patterns: list[re.Pattern[str]]
) -> list[tuple[int, int]]:
    """Return compact context windows around lines matching failure patterns."""
    return [
        (max(0, index - 2), min(len(lines), index + 9))
        for index, line in enumerate(lines)
        if any(pattern.search(line) for pattern in patterns)
    ]


def compress_log(
    log: str,
    max_lines: int = DEFAULT_MAX_LOG_LINES,
    max_chars: int = DEFAULT_MAX_LOG_CHARS,
) -> str:
    """Compress a full job log to the most useful failure evidence."""
    lines = redact(log).splitlines()
    if not lines:
        return "(no job log returned)"
    ranges = log_ranges(lines, PRIMARY_LOG_RE) or log_ranges(lines, FALLBACK_LOG_RE)
    if not ranges:
        selected = lines[-max_lines:]
    else:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        chosen: list[tuple[int, int]] = []
        count = 0
        for start, end in reversed(merged):
            chosen.append((start, end))
            count += end - start + (1 if len(chosen) > 1 else 0)
            if count >= max_lines:
                break
        selected = []
        for start, end in sorted(chosen):
            if selected:
                selected.append("...")
            selected.extend(lines[start:end])
            if len(selected) >= max_lines:
                break
        selected = selected[:max_lines]
    snippet = "\n".join(selected)
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars].rstrip() + "\n...[truncated]"
    if len(lines) > len(selected):
        snippet += "\n...[compressed]"
    return snippet


def seen_key(finding: dict[str, Any]) -> str:
    """Return a stable run/job key used to deduplicate IssueOps updates."""
    return f"{finding['run_id']}:{finding['job_id']}"


def marker(repo: str, workflow: str, seen: set[str]) -> str:
    """Build the hidden issue marker that stores repository and seen-job state."""
    payload = {
        "repo": repo,
        "workflow": canonical_workflow_name(workflow),
        "seen": sorted(seen),
    }
    return f"{MARKER_PREFIX} {json.dumps(payload, sort_keys=True)} {MARKER_SUFFIX}"


def parse_marker(body: str | None) -> dict[str, Any]:
    """Parse a hidden issue marker, returning an empty seen list when absent."""
    body = body or ""
    start = body.find(MARKER_PREFIX)
    end = body.find(MARKER_SUFFIX, start + len(MARKER_PREFIX))
    if start == -1 or end == -1:
        return {"seen": []}
    try:
        return json.loads(body[start + len(MARKER_PREFIX) : end].strip())
    except json.JSONDecodeError:
        return {"seen": []}


def replace_marker(body: str | None, repo: str, workflow: str, seen: set[str]) -> str:
    """Insert or replace the hidden IssueOps marker in an issue body."""
    body = body or ""
    new_marker = marker(repo, workflow, seen)
    start = body.find(MARKER_PREFIX)
    end = body.find(MARKER_SUFFIX, start + len(MARKER_PREFIX))
    if start == -1 or end == -1:
        return f"{new_marker}\n\n{body}".strip()
    return f"{body[:start]}{new_marker}{body[end + len(MARKER_SUFFIX) :]}".strip()


def title(finding: dict[str, Any]) -> str:
    """Build the canonical issue title for one repository workflow failure."""
    workflow = canonical_workflow_name(finding.get("workflow", ""))
    return f"[security-failure] {finding['repo']}: {workflow}"


def summary(finding: dict[str, Any]) -> str:
    """Render the key run, job, branch, and PR facts for an issue body."""
    prs = ", ".join(f"#{number}" for number in finding["pr_numbers"]) or "n/a"
    rows = [
        ("Repository", f"`{finding['repo']}`"),
        ("Workflow", f"`{finding['workflow']}`"),
        ("Job", f"`{finding['job_name']}`"),
        ("Conclusion", f"`{finding['conclusion']}`"),
        ("Branch", f"`{finding['branch']}`"),
        ("Head SHA", f"`{finding['head_sha']}`"),
        ("Event", f"`{finding['event']}`"),
        ("PRs", prs),
        ("Run", finding["run_url"]),
        ("Job", finding["job_url"]),
    ]
    return "\n".join(f"- {key}: {value}" for key, value in rows)


def diagnosis(finding: dict[str, Any]) -> str:
    """Render safe, actionable diagnosis and remediation from trusted metadata."""
    names = f"{finding.get('workflow', '')} {finding.get('job_name', '')}".lower()
    conclusion = str(finding.get("conclusion") or "unknown").lower()

    if "strix" in names:
        likely_cause = (
            "The Strix security gate did not complete successfully. This metadata alone "
            "does not prove that a vulnerability was found; scanner setup, execution, "
            "result mapping, and policy enforcement failures must be distinguished in "
            "the source job."
        )
        actions = [
            "Open the authorized source job and inspect the first failed step shown above.",
            "If setup or execution failed, correct credentials, runner capacity, or scanner configuration, then rerun the same commit.",
            "If findings caused the failure, review the Strix artifact in the source repository, fix each confirmed finding, and rerun the scan.",
            "Do not merge while confirmed critical/high findings remain unresolved.",
        ]
    elif "opencode" in names:
        likely_cause = (
            "The automated OpenCode review gate failed. Common classes are dispatch or "
            "permission configuration, reviewer execution, and review-result publishing; "
            "the failed step in the authorized source job identifies which class applies."
        )
        actions = [
            "Open the authorized source job and inspect the first failed step shown above.",
            "For dispatch or permission failures, verify the GitHub App installation, repository allowlist, and least-privilege token permissions.",
            "For reviewer execution failures, correct model/service configuration or transient rate limits and rerun the same commit.",
            "For a reported code problem, apply the review recommendation, add regression coverage, and rerun the required review.",
        ]
    else:
        likely_cause = (
            "A security-related workflow gate did not complete successfully. The trusted "
            "metadata identifies the affected run but is insufficient to distinguish an "
            "infrastructure failure from a confirmed security finding."
        )
        actions = [
            "Open the authorized source job and inspect the first failed step shown above.",
            "Separate runner, permission, dependency, and timeout failures from scanner-reported findings.",
            "Fix the identified root cause and rerun the exact head commit before merging.",
        ]

    if conclusion == "cancelled":
        actions.insert(
            1,
            "Determine who or what cancelled the run, then rerun the exact head commit to obtain a conclusive result.",
        )
    elif conclusion == "timed_out":
        actions.insert(
            1,
            "Check runner capacity and configured timeouts; optimize or safely extend the limit before rerunning.",
        )
    elif conclusion == "action_required":
        actions.insert(
            1,
            "Have an authorized maintainer approve the protected action only after reviewing the triggering changes.",
        )

    checklist = "\n".join(
        f"{index}. {action}" for index, action in enumerate(actions, 1)
    )
    return f"### AppGuardrail diagnosis\n\n{likely_cause}\n\n### Recommended resolution\n\n{checklist}"


def issue_body(finding: dict[str, Any], seen: set[str]) -> str:
    """Render the first issue body for a collected security workflow failure."""
    owner = finding["repo"].split("/", 1)[0]
    return "\n\n".join(
        [
            marker(finding["repo"], finding["workflow"], seen),
            f"Automated collection of security workflow failures across {owner}.",
            summary(finding),
            f"```text\n{finding['snippet']}\n```",
            diagnosis(finding),
        ]
    )


def issue_comment(finding: dict[str, Any]) -> str:
    """Render a follow-up comment for a newly observed failure on an issue."""
    return "\n\n".join(
        [
            "New security workflow failure detected.",
            summary(finding),
            f"```text\n{finding['snippet']}\n```",
            diagnosis(finding),
        ]
    )
