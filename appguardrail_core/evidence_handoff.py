"""Build deterministic, redacted remediation evidence for agent handoff."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from appguardrail_core.findings import normalize_finding
from appguardrail_core.issueops import redact

HANDOFF_SCHEMA = "appguardrail.remediation-handoff.v1"
HANDOFF_VERSION = 1
MAX_HANDOFF_BYTES = 2 * 1024 * 1024
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_OUTCOMES = frozenset(
    {"clean", "findings_present", "incomplete", "failed", "untrusted"}
)
_TEXT_FIELDS = ("message", "remediation", "verification", "snippet")
_IDENTIFIER_FIELDS = (
    "repository",
    "revision",
    "commit",
    "artifact_ref",
    "artifact_sha256",
    "evidence_digest",
    "generated_at",
    "scanner_version",
)


def _safe_text(value: Any, *, limit: int = 2_000) -> str:
    """Return bounded text with obvious secrets and terminal controls removed."""
    return redact(str(value or ""))[:limit]


def _safe_identifier(value: Any, *, digest: bool = False) -> str | None:
    """Return one bounded provenance identifier or omit malformed input."""
    if not isinstance(value, str) or not value or not value.isprintable():
        return None
    value = redact(value.strip())
    if digest and not _DIGEST_RE.fullmatch(value):
        return None
    return value[:512]


def _safe_provenance(value: Any) -> dict[str, str]:
    """Select and redact stable source identifiers without copying source text."""
    if not isinstance(value, Mapping):
        return {}
    nested = value.get("source_identity")
    sources = (nested, value) if isinstance(nested, Mapping) else (value,)
    result: dict[str, str] = {}
    for field in _IDENTIFIER_FIELDS:
        for source in sources:
            identifier = _safe_identifier(
                source.get(field),
                digest=field.endswith("sha256") or field == "evidence_digest",
            )
            if identifier is not None:
                result[field] = identifier
                break
    for key in ("revision", "commit"):
        candidate = result.get(key)
        if candidate is not None and not _COMMIT_RE.fullmatch(candidate):
            result.pop(key, None)
    return dict(sorted(result.items()))


def _safe_assurance(value: Any) -> dict[str, Any] | None:
    """Copy only the non-secret assurance fields useful to an agent."""
    if not isinstance(value, Mapping):
        return None
    result: dict[str, Any] = {}
    schema = value.get("schema")
    outcome = value.get("scan_outcome_code")
    if isinstance(schema, str):
        result["schema"] = _safe_text(schema, limit=120)
    if isinstance(outcome, str) and outcome in _OUTCOMES:
        result["scan_outcome_code"] = outcome
    reasons = value.get("reasons")
    if isinstance(reasons, list):
        result["reasons"] = [_safe_text(reason, limit=200) for reason in reasons if isinstance(reason, str)]
    for field in ("repository", "commit", "generated_at", "scanner_version"):
        identifier = _safe_identifier(value.get(field))
        if identifier is not None:
            result[field] = identifier
    provenance = _safe_provenance(value.get("provenance"))
    if provenance:
        result["provenance"] = provenance
    return result or None


def _safe_finding(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Select report-safe remediation fields and source identifiers."""
    normalized = normalize_finding(dict(finding))
    safe: dict[str, Any] = {}
    for field in (
        "rule_id",
        "severity",
        "file",
        "line",
        "category",
        "context",
    ):
        value = normalized.get(field)
        safe[field] = value if isinstance(value, (str, int)) and not isinstance(value, bool) else str(value)
    for field in _TEXT_FIELDS:
        safe[field] = _safe_text(normalized.get(field))
    for field in ("references", "owasp", "cwe"):
        safe[field] = [_safe_text(item, limit=300) for item in normalized.get(field, ())]
    provenance = _safe_provenance(finding.get("source_evidence") or finding.get("provenance"))
    if provenance:
        safe["provenance"] = provenance
    return safe


def _without_digest(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a shallow payload copy without its derived bundle digest."""
    return {key: value for key, value in payload.items() if key != "bundle_sha256"}


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Serialize a handoff payload deterministically for hashing or transport."""
    return (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def build_evidence_handoff(
    findings: Iterable[Mapping[str, Any]],
    *,
    provenance: Mapping[str, Any] | None = None,
    assurance: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic, redacted remediation handoff envelope."""
    payload: dict[str, Any] = {
        "schema": HANDOFF_SCHEMA,
        "version": HANDOFF_VERSION,
        "findings": [_safe_finding(finding) for finding in findings],
        "provenance": _safe_provenance(provenance),
    }
    safe_assurance = _safe_assurance(assurance)
    if safe_assurance is not None:
        payload["assurance"] = safe_assurance
    payload["bundle_sha256"] = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    if len(_canonical_bytes(payload)) > MAX_HANDOFF_BYTES:
        raise ValueError(f"Handoff payload exceeds {MAX_HANDOFF_BYTES} bytes.")
    return payload


def serialize_evidence_handoff(
    findings: Iterable[Mapping[str, Any]],
    *,
    provenance: Mapping[str, Any] | None = None,
    assurance: Mapping[str, Any] | None = None,
) -> bytes:
    """Serialize one handoff envelope for clipboard or agent transport."""
    return _canonical_bytes(
        build_evidence_handoff(
            findings, provenance=provenance, assurance=assurance
        )
    )


def verify_evidence_handoff(data: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    """Validate schema, size, and digest before an agent consumes a handoff."""
    if isinstance(data, Mapping):
        payload = dict(data)
    else:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if not isinstance(raw, bytes) or len(raw) > MAX_HANDOFF_BYTES:
            raise TypeError("Handoff payload must be bounded bytes or text.")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Handoff payload is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict):
        raise TypeError("Handoff payload must be a JSON object.")
    try:
        canonical_payload = _canonical_bytes(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise TypeError("Handoff payload must be JSON-serializable.") from exc
    if len(canonical_payload) > MAX_HANDOFF_BYTES:
        raise TypeError("Handoff payload must be bounded bytes or text.")
    if payload.get("schema") != HANDOFF_SCHEMA or payload.get("version") != HANDOFF_VERSION:
        raise ValueError("Handoff schema or version is invalid.")
    if not isinstance(payload.get("findings"), list) or not isinstance(payload.get("provenance"), dict):
        raise TypeError("Handoff findings or provenance shape is invalid.")
    digest = payload.get("bundle_sha256")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ValueError("Handoff digest is invalid.")
    actual = hashlib.sha256(_canonical_bytes(_without_digest(payload))).hexdigest()
    if actual != digest:
        raise ValueError("Handoff digest does not match its payload.")
    return payload
