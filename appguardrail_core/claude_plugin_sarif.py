"""Bind Claude plugin receipt findings to a deterministic SARIF 2.1.0 document.

This adapter reuses ``findings_to_sarif``. It does not invent a second SARIF
dialect. Receipt ``sarif_sha256`` is the SHA-256 of that document. Secret
literals and raw bidi never appear in SARIF text.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

from .sarif import SARIF_VERSION, findings_to_sarif


def finding_summary_to_sarif(
    finding_summary: Sequence[str] | Iterable[str],
    *,
    tool_version: str = "0.0.0",
) -> dict[str, Any]:
    """Return a deterministic SARIF 2.1.0 log covering receipt finding rule_ids.

    Args:
        finding_summary: Unique rule_ids recorded on the scan receipt.
        tool_version: Scanner version recorded on the SARIF driver.

    Returns:
        SARIF 2.1.0 document with one result per rule_id, in sorted order.
        Snippets are empty so secret literals and raw bidi cannot appear.
    """
    findings = [
        {
            "rule_id": rule_id,
            "severity": "HIGH",
            "message": rule_id,
            "file": "n/a",
            "line": 1,
            "category": "supply-chain",
            "context": "app-code",
            "snippet": "",
        }
        for rule_id in sorted(finding_summary)
    ]
    return findings_to_sarif(findings, tool_version=tool_version)


def sarif_document_sha256(sarif: Mapping[str, Any]) -> str:
    """Return the SHA-256 digest of canonical SARIF JSON.

    Args:
        sarif: SARIF 2.1.0 log.

    Returns:
        Hex digest of compact, key-sorted JSON bytes.
    """
    payload = json.dumps(sarif, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def receipt_sarif_is_consistent(
    finding_summary: Sequence[str] | Iterable[str],
    sarif: object,
) -> bool:
    """Return whether receipt rule_ids and SARIF result ruleIds match.

    Every receipt finding rule_id appears in SARIF results, every SARIF
    result ruleId appears in the receipt summary, and the counts match.

    Args:
        finding_summary: Receipt ``finding_summary`` rule_ids.
        sarif: Candidate SARIF 2.1.0 log.

    Returns:
        True only when rule_ids and counts match. Malformed logs fail closed.
    """
    if type(sarif) is not dict:
        return False
    if sarif.get("version") != SARIF_VERSION:
        return False
    runs = sarif.get("runs")
    if type(runs) is not list or not runs or type(runs[0]) is not dict:
        return False
    results = runs[0].get("results")
    if type(results) is not list:
        return False
    result_ids: list[str] = []
    for item in results:
        if type(item) is not dict:
            return False
        rule_id = item.get("ruleId")
        if type(rule_id) is not str or not rule_id:
            return False
        result_ids.append(rule_id)
    summary_ids = [str(rule_id) for rule_id in finding_summary]
    if len(result_ids) != len(summary_ids):
        return False
    return sorted(result_ids) == sorted(summary_ids)
