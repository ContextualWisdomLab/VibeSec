"""Render AppGuardrail findings as SARIF 2.1.0.

SARIF is the OASIS-standard interchange format for static-analysis results.
Emitting it lets `appguardrail scan --sarif out.sarif` feed GitHub code
scanning (github/codeql-action/upload-sarif), the VS Code SARIF viewer, Azure
DevOps, and any other SARIF consumer — turning findings into native PR
annotations and Security-tab entries without a bespoke integration.

Maps the normalized `appguardrail.findings.v1` model straight to SARIF, so it
stays in lockstep with findings.py.
"""

from __future__ import annotations

from typing import Any, Iterable

from .findings import is_deploy_blocking, normalize_findings

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF result levels + GitHub's security-severity score (0-10) so the Security
# tab ranks findings the way AppGuardrail's deploy gate does.
_LEVEL = {"CRITICAL": "error", "HIGH": "error", "WARNING": "warning", "INFO": "note"}
_SECURITY_SEVERITY = {"CRITICAL": "9.0", "HIGH": "7.0", "WARNING": "4.0", "INFO": "2.0"}


def _tags(finding: dict[str, Any]) -> list[str]:
    tags = ["security", str(finding.get("category") or "misconfig")]
    tags.extend(str(t) for t in finding.get("cwe") or ())
    tags.extend(str(t) for t in finding.get("owasp") or ())
    return tags


def findings_to_sarif(
    findings: Iterable[dict[str, Any]], *, tool_version: str = "0.0.0"
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from AppGuardrail findings."""
    normalized = normalize_findings(findings)

    rules: dict[str, dict[str, Any]] = {}
    rule_indices: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for f in normalized:
        rule_id = f["rule_id"]
        severity = f["severity"]
        refs = f.get("references") or ()
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": f["message"].strip().splitlines()[0][:200]
                },
                "fullDescription": {"text": f["message"].strip()},
                "helpUri": (
                    refs[0]
                    if refs
                    else "https://github.com/ContextualWisdomLab/appguardrail"
                ),
                "defaultConfiguration": {"level": _LEVEL.get(severity, "note")},
                "properties": {
                    "tags": _tags(f),
                    "security-severity": _SECURITY_SEVERITY.get(severity, "2.0"),
                },
            }
            rules[rule_id] = rule
            rule_indices[rule_id] = len(rule_indices)

        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": _LEVEL.get(severity, "note"),
                "message": {"text": f["message"].strip()},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {"startLine": max(1, int(f["line"] or 1))},
                        }
                    }
                ],
                # Stable across runs so code scanning can track/dedupe alerts.
                "partialFingerprints": {
                    "appguardrail/v1": f"{rule_id}:{f['file']}:{f['line']}"
                },
                "properties": {
                    "severity": severity,
                    "context": f.get("context") or "app-code",
                    "deployBlocking": is_deploy_blocking(f),
                    "remediation": f.get("remediation") or "",
                },
            }
        )

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AppGuardrail",
                        "informationUri": "https://github.com/ContextualWisdomLab/appguardrail",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


if __name__ == "__main__":  # pragma: no cover - self-check
    log = findings_to_sarif(
        [
            {
                "severity": "CRITICAL",
                "rule_id": "hardcoded-stripe-secret-key",
                "message": "Hardcoded Stripe key",
                "file": "src/pay.ts",
                "line": 12,
                "cwe": ["CWE-798"],
                "context": "app-code",
            },
            {
                "severity": "INFO",
                "rule_id": "note",
                "message": "fyi",
                "file": "README.md",
                "line": 1,
                "context": "doc",
            },
        ],
        tool_version="1.2.3",
    )
    run = log["runs"][0]
    assert log["version"] == "2.1.0"
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["properties"]["deployBlocking"] is True
    assert run["results"][1]["level"] == "note"
    assert run["results"][1]["properties"]["deployBlocking"] is False
    # rules deduped, security-severity present for GitHub ranking
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.0"
    print("sarif self-check OK")
