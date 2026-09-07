"""Qualify AppGuardrail scan results with explicit evidence before claiming clean.

This module is intentionally independent from the main scanner CLI so control-plane,
MSA, and automation consumers can adopt the assurance contract without importing
command orchestration. It verifies the findings artifact digest, exact repository and
commit binding, detector completion, requested external-engine completion, evidence
freshness, scan scope, and gate accounting. Ambiguous evidence fails closed and never
becomes a clean result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

FINDINGS_SCHEMA = "appguardrail.findings.v1"
EVIDENCE_SCHEMA = "appguardrail.scan-evidence.v1"
ASSURANCE_SCHEMA = "appguardrail.scan-assurance.v1"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
_ALLOWED_EXECUTION_STATES = frozenset({"completed", "failed", "incomplete"})
_ALLOWED_ENGINE_STATES = frozenset({"completed", "unavailable", "failed", "not_requested"})
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _parse_json_object(data: bytes, *, artifact_name: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse a bounded UTF-8 JSON object and return a fail-closed reason on error."""
    if not isinstance(data, bytes):
        return None, f"{artifact_name}_bytes_invalid"
    if len(data) > MAX_ARTIFACT_BYTES:
        return None, "artifact_too_large"
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return None, f"{artifact_name}_json_invalid"
    if not isinstance(value, dict):
        return None, f"{artifact_name}_json_invalid"
    return value, None


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an RFC 3339-like UTC timestamp into an aware UTC datetime."""
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _is_unique_string_list(value: Any, *, allow_empty: bool = True) -> bool:
    """Return whether a value is a duplicate-free list of non-empty strings."""
    if not isinstance(value, list) or (not allow_empty and not value):
        return False
    if any(not isinstance(item, str) or not item for item in value):
        return False
    return len(value) == len(set(value))


def _valid_scope(value: Any) -> bool:
    """Validate the bounded scan-scope evidence shape."""
    if not isinstance(value, dict):
        return False
    files_scanned = value.get("files_scanned")
    return (
        isinstance(files_scanned, int)
        and not isinstance(files_scanned, bool)
        and files_scanned >= 0
        and _is_unique_string_list(value.get("paths"), allow_empty=False)
        and _is_unique_string_list(value.get("languages"))
        and _is_unique_string_list(value.get("exclusions"))
    )


def _valid_gate(value: Any) -> bool:
    """Validate gate threshold and count evidence without reinterpreting policy."""
    if not isinstance(value, dict):
        return False
    blocking = value.get("blocking_count")
    non_blocking = value.get("non_blocking_count")
    return (
        _is_unique_string_list(value.get("threshold"), allow_empty=False)
        and isinstance(blocking, int)
        and not isinstance(blocking, bool)
        and blocking >= 0
        and isinstance(non_blocking, int)
        and not isinstance(non_blocking, bool)
        and non_blocking >= 0
    )


def _valid_external_engines(value: Any) -> bool:
    """Validate external-engine state evidence."""
    if not isinstance(value, dict):
        return False
    return all(
        isinstance(name, str)
        and bool(name)
        and isinstance(state, str)
        and state in _ALLOWED_ENGINE_STATES
        for name, state in value.items()
    )


def _validate_expected_identity(
    expected_repository: str,
    expected_commit: str,
    now: datetime,
    max_age_seconds: int,
) -> None:
    """Reject invalid caller trust anchors and freshness bounds."""
    if not isinstance(expected_repository, str) or not _REPOSITORY_RE.fullmatch(expected_repository):
        raise ValueError("expected_repository must be OWNER/REPOSITORY")
    if not isinstance(expected_commit, str) or not _COMMIT_RE.fullmatch(expected_commit):
        raise ValueError("expected_commit must be a 40-character Git commit SHA")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    if not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be a positive integer")


def _base_result(expected_repository: str, expected_commit: str) -> dict[str, Any]:
    """Return the deterministic fail-closed result skeleton."""
    return {
        "schema": ASSURANCE_SCHEMA,
        "scan_outcome_code": "untrusted",
        "repository": expected_repository,
        "commit": expected_commit.lower(),
        "generated_at": None,
        "scanner_version": None,
        "finding_count": 0,
        "configured_detectors": [],
        "completed_detectors": [],
        "requested_external_engines": [],
        "external_engines": {},
        "scope": {
            "files_scanned": 0,
            "paths": [],
            "languages": [],
            "exclusions": [],
        },
        "gate": {
            "threshold": [],
            "blocking_count": 0,
            "non_blocking_count": 0,
        },
        "provenance": {
            "findings_sha256": None,
            "expected_findings_sha256": None,
            "findings_digest_verified": False,
        },
        "freshness": {
            "age_seconds": None,
            "max_age_seconds": None,
            "stale": True,
        },
        "reasons": [],
    }


def _untrusted_result(
    expected_repository: str,
    expected_commit: str,
    *,
    reason: str,
    max_age_seconds: int,
) -> dict[str, Any]:
    """Return a deterministic untrusted result for malformed source evidence."""
    result = _base_result(expected_repository, expected_commit)
    result["freshness"]["max_age_seconds"] = max_age_seconds
    result["reasons"] = [reason]
    return result


def _evidence_shape_reason(evidence: dict[str, Any]) -> str | None:
    """Return the first structural evidence defect, preserving deterministic precedence."""
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        return "evidence_schema_invalid"
    if not isinstance(evidence.get("repository"), str) or not _REPOSITORY_RE.fullmatch(
        evidence["repository"]
    ):
        return "repository_invalid"
    if not isinstance(evidence.get("commit"), str) or not _COMMIT_RE.fullmatch(evidence["commit"]):
        return "commit_invalid"
    if not isinstance(evidence.get("scanner_version"), str) or not evidence["scanner_version"]:
        return "scanner_version_invalid"
    if evidence.get("execution") not in _ALLOWED_EXECUTION_STATES:
        return "execution_state_invalid"
    if not _is_unique_string_list(evidence.get("configured_detectors"), allow_empty=False):
        return "configured_detectors_invalid"
    if not _is_unique_string_list(evidence.get("completed_detectors")):
        return "completed_detectors_invalid"
    if not set(evidence["completed_detectors"]).issubset(evidence["configured_detectors"]):
        return "completed_detectors_invalid"
    if not _is_unique_string_list(evidence.get("requested_external_engines")):
        return "requested_external_engines_invalid"
    if not _valid_external_engines(evidence.get("external_engines")):
        return "external_engines_invalid"
    if not _valid_scope(evidence.get("scope")):
        return "scope_invalid"
    if not _valid_gate(evidence.get("gate")):
        return "gate_invalid"
    if _parse_timestamp(evidence.get("generated_at")) is None:
        return "generated_at_invalid"
    digest = evidence.get("findings_sha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        return "findings_digest_invalid"
    return None


def assess_scan_artifacts(
    findings_bytes: bytes,
    evidence_bytes: bytes,
    *,
    expected_repository: str,
    expected_commit: str,
    now: datetime,
    max_age_seconds: int = 3600,
) -> dict[str, Any]:
    """Assess findings plus scanner evidence and return a fail-closed assurance envelope.

    A clean outcome is possible only when the findings artifact is schema-valid and
    empty, its SHA-256 digest matches evidence, repository and commit identity match
    caller-supplied trust anchors, every configured built-in detector completed, every
    requested external engine completed, the execution completed, gate counts account
    for every finding, and the evidence remains within the freshness bound.

    Args:
        findings_bytes: Raw ``appguardrail.findings.v1`` JSON bytes.
        evidence_bytes: Raw ``appguardrail.scan-evidence.v1`` JSON bytes.
        expected_repository: Trusted ``OWNER/REPOSITORY`` identity from the caller.
        expected_commit: Trusted exact 40-character Git commit SHA from the caller.
        now: Timezone-aware evaluation timestamp.
        max_age_seconds: Maximum accepted evidence age before the result is incomplete.

    Returns:
        A deterministic ``appguardrail.scan-assurance.v1`` dictionary.

    Raises:
        ValueError: If caller-supplied trust anchors or freshness bounds are invalid.
    """
    _validate_expected_identity(expected_repository, expected_commit, now, max_age_seconds)
    now_utc = now.astimezone(timezone.utc)

    findings_payload, findings_error = _parse_json_object(
        findings_bytes, artifact_name="findings"
    )
    if findings_error:
        return _untrusted_result(
            expected_repository,
            expected_commit,
            reason=findings_error,
            max_age_seconds=max_age_seconds,
        )
    if findings_payload.get("schema") != FINDINGS_SCHEMA:
        return _untrusted_result(
            expected_repository,
            expected_commit,
            reason="findings_schema_invalid",
            max_age_seconds=max_age_seconds,
        )
    findings = findings_payload.get("findings")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        return _untrusted_result(
            expected_repository,
            expected_commit,
            reason="findings_shape_invalid",
            max_age_seconds=max_age_seconds,
        )

    evidence, evidence_error = _parse_json_object(evidence_bytes, artifact_name="evidence")
    if evidence_error:
        return _untrusted_result(
            expected_repository,
            expected_commit,
            reason=evidence_error,
            max_age_seconds=max_age_seconds,
        )
    shape_reason = _evidence_shape_reason(evidence)
    if shape_reason:
        return _untrusted_result(
            expected_repository,
            expected_commit,
            reason=shape_reason,
            max_age_seconds=max_age_seconds,
        )

    generated_at = _parse_timestamp(evidence["generated_at"])
    assert generated_at is not None
    computed_digest = hashlib.sha256(findings_bytes).hexdigest()
    expected_digest = evidence["findings_sha256"]
    age_seconds = (now_utc - generated_at).total_seconds()

    result = _base_result(expected_repository, expected_commit)
    result.update(
        {
            "repository": evidence["repository"],
            "commit": evidence["commit"].lower(),
            "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
            "scanner_version": evidence["scanner_version"],
            "finding_count": len(findings),
            "configured_detectors": list(evidence["configured_detectors"]),
            "completed_detectors": list(evidence["completed_detectors"]),
            "requested_external_engines": list(evidence["requested_external_engines"]),
            "external_engines": dict(sorted(evidence["external_engines"].items())),
            "scope": dict(evidence["scope"]),
            "gate": dict(evidence["gate"]),
            "provenance": {
                "findings_sha256": computed_digest,
                "expected_findings_sha256": expected_digest,
                "findings_digest_verified": computed_digest == expected_digest,
            },
            "freshness": {
                "age_seconds": age_seconds,
                "max_age_seconds": max_age_seconds,
                "stale": age_seconds > max_age_seconds,
            },
        }
    )

    untrusted_reasons: list[str] = []
    if evidence["repository"] != expected_repository:
        untrusted_reasons.append("repository_mismatch")
    if evidence["commit"].lower() != expected_commit.lower():
        untrusted_reasons.append("commit_mismatch")
    if computed_digest != expected_digest:
        untrusted_reasons.append("findings_digest_mismatch")
    if age_seconds < 0:
        untrusted_reasons.append("generated_at_in_future")
    if evidence["gate"]["blocking_count"] + evidence["gate"]["non_blocking_count"] != len(findings):
        untrusted_reasons.append("finding_count_mismatch")
    if untrusted_reasons:
        result["scan_outcome_code"] = "untrusted"
        result["reasons"] = untrusted_reasons
        return result

    failed_reasons: list[str] = []
    if evidence["execution"] == "failed":
        failed_reasons.append("scan_execution_failed")
    requested_states = [
        evidence["external_engines"].get(name) for name in evidence["requested_external_engines"]
    ]
    if "failed" in requested_states:
        failed_reasons.append("external_engine_failed")
    if failed_reasons:
        result["scan_outcome_code"] = "failed"
        result["reasons"] = failed_reasons
        return result

    incomplete_reasons: list[str] = []
    if evidence["execution"] != "completed":
        incomplete_reasons.append("scan_execution_incomplete")
    if set(evidence["completed_detectors"]) != set(evidence["configured_detectors"]):
        incomplete_reasons.append("detectors_incomplete")
    if any(state in {None, "unavailable", "not_requested"} for state in requested_states):
        incomplete_reasons.append("external_engine_unavailable")
    if age_seconds > max_age_seconds:
        incomplete_reasons.append("evidence_stale")
    if incomplete_reasons:
        result["scan_outcome_code"] = "incomplete"
        result["reasons"] = incomplete_reasons
        return result

    result["scan_outcome_code"] = "findings_present" if findings else "clean"
    result["reasons"] = []
    return result


def _read_bounded(path: Path) -> bytes:
    """Read at most one byte beyond the artifact limit to bound memory use."""
    with path.open("rb") as handle:
        return handle.read(MAX_ARTIFACT_BYTES + 1)


def _write_result(path: Path, result: dict[str, Any]) -> None:
    """Write deterministic assurance JSON, replacing any stale prior result."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    """Build the standalone scan-assurance command parser."""
    parser = argparse.ArgumentParser(
        prog="python -m appguardrail_core.scan_assurance",
        description="Qualify AppGuardrail scan evidence before claiming a clean result.",
    )
    parser.add_argument("--findings", required=True, help="Path to appguardrail.findings.v1 JSON")
    parser.add_argument("--evidence", required=True, help="Path to appguardrail.scan-evidence.v1 JSON")
    parser.add_argument("--out", required=True, help="Path for appguardrail.scan-assurance.v1 JSON")
    parser.add_argument("--repository", required=True, help="Trusted OWNER/REPOSITORY identity")
    parser.add_argument("--commit", required=True, help="Trusted exact 40-character Git SHA")
    parser.add_argument("--now", help="Evaluation time in RFC 3339 format; defaults to current UTC")
    parser.add_argument(
        "--max-age-seconds",
        type=int,
        default=3600,
        help="Maximum accepted evidence age in seconds (default: 3600)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the standalone assurance evaluator and return a fail-closed exit code.

    Exit code ``0`` means clean, ``1`` means trusted findings are present, and ``2``
    means evidence is failed, incomplete, untrusted, unavailable, or invalid.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    output_path = Path(args.out)
    try:
        output_path.unlink(missing_ok=True)
        findings_bytes = _read_bounded(Path(args.findings))
        evidence_bytes = _read_bounded(Path(args.evidence))
        now = _parse_timestamp(args.now) if args.now else datetime.now(timezone.utc)
        if now is None:
            raise ValueError("--now must be a timezone-aware ISO 8601 timestamp")
        result = assess_scan_artifacts(
            findings_bytes,
            evidence_bytes,
            expected_repository=args.repository,
            expected_commit=args.commit,
            now=now,
            max_age_seconds=args.max_age_seconds,
        )
        _write_result(output_path, result)
    except (OSError, ValueError) as exc:
        print(f"appguardrail scan assurance failed closed: {exc}", file=sys.stderr)
        return 2

    outcome = result["scan_outcome_code"]
    if outcome == "clean":
        return 0
    if outcome == "findings_present":
        return 1
    return 2


if __name__ == "__main__":  # pragma: no cover - exercised by packaging/runtime, not unit import
    raise SystemExit(main())
