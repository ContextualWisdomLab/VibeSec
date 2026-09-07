"""Regression tests for evidence-qualified scan assurance outcomes."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from appguardrail_core import scan_assurance
from appguardrail_core.scan_assurance import (
    ASSURANCE_SCHEMA,
    EVIDENCE_SCHEMA,
    FINDINGS_SCHEMA,
    assess_scan_artifacts,
    main,
)


NOW = datetime(2026, 8, 16, 0, 0, tzinfo=timezone.utc)
REPOSITORY = "ContextualWisdomLab/appguardrail"
COMMIT = "a" * 40


def _findings_bytes(findings: list[dict] | None = None) -> bytes:
    """Return deterministic AppGuardrail findings JSON bytes."""
    payload = {"schema": FINDINGS_SCHEMA, "findings": findings or []}
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _evidence_bytes(
    findings_bytes: bytes,
    *,
    repository: str = REPOSITORY,
    commit: str = COMMIT,
    generated_at: str = "2026-08-15T23:55:00Z",
    execution: str = "completed",
    configured_detectors: list[str] | None = None,
    completed_detectors: list[str] | None = None,
    requested_external_engines: list[str] | None = None,
    external_engines: dict[str, str] | None = None,
    findings_sha256: str | None = None,
) -> bytes:
    """Return deterministic scanner evidence bytes with safe defaults."""
    configured = configured_detectors or ["builtin"]
    completed = completed_detectors if completed_detectors is not None else list(configured)
    requested = requested_external_engines or []
    engines = external_engines or {}
    payload = {
        "schema": EVIDENCE_SCHEMA,
        "repository": repository,
        "commit": commit,
        "generated_at": generated_at,
        "scanner_version": "0.1.1",
        "execution": execution,
        "configured_detectors": configured,
        "completed_detectors": completed,
        "requested_external_engines": requested,
        "external_engines": engines,
        "scope": {
            "files_scanned": 7,
            "paths": ["."],
            "languages": ["python"],
            "exclusions": [],
        },
        "gate": {
            "threshold": ["CRITICAL", "HIGH"],
            "blocking_count": 0,
            "non_blocking_count": 0,
        },
        "findings_sha256": findings_sha256 or hashlib.sha256(findings_bytes).hexdigest(),
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _assess(
    findings_bytes: bytes,
    evidence_bytes: bytes,
    *,
    expected_repository: str = REPOSITORY,
    expected_commit: str = COMMIT,
    now: datetime = NOW,
    max_age_seconds: int = 3600,
) -> dict:
    """Assess one fixture through the public assurance API."""
    return assess_scan_artifacts(
        findings_bytes,
        evidence_bytes,
        expected_repository=expected_repository,
        expected_commit=expected_commit,
        now=now,
        max_age_seconds=max_age_seconds,
    )


def test_clean_requires_complete_fresh_verified_evidence() -> None:
    """A zero-finding scan is clean only with complete trusted evidence."""
    findings = _findings_bytes()
    result = _assess(findings, _evidence_bytes(findings))

    assert result["schema"] == ASSURANCE_SCHEMA
    assert result["scan_outcome_code"] == "clean"
    assert result["repository"] == REPOSITORY
    assert result["commit"] == COMMIT
    assert result["provenance"]["findings_digest_verified"] is True
    assert result["freshness"]["stale"] is False
    assert result["configured_detectors"] == ["builtin"]
    assert result["completed_detectors"] == ["builtin"]
    assert result["scope"]["files_scanned"] == 7
    assert result["gate"]["blocking_count"] == 0
    assert result["gate"]["non_blocking_count"] == 0
    assert result["reasons"] == []


def test_findings_present_is_not_clean() -> None:
    """Trusted complete scans with findings expose findings_present."""
    findings = _findings_bytes([{"rule_id": "demo", "severity": "HIGH"}])
    evidence = json.loads(_evidence_bytes(findings))
    evidence["gate"]["blocking_count"] = 1
    result = _assess(
        findings,
        (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )

    assert result["scan_outcome_code"] == "findings_present"
    assert result["finding_count"] == 1
    assert result["gate"]["blocking_count"] == 1


@pytest.mark.parametrize(
    ("patch", "reason"),
    [
        ({"completed_detectors": []}, "detectors_incomplete"),
        (
            {
                "requested_external_engines": ["semgrep"],
                "external_engines": {"semgrep": "unavailable"},
            },
            "external_engine_unavailable",
        ),
    ],
)
def test_incomplete_evidence_never_becomes_clean(patch: dict, reason: str) -> None:
    """Detector or requested-engine incompleteness yields incomplete."""
    findings = _findings_bytes()
    evidence = json.loads(_evidence_bytes(findings))
    evidence.update(patch)
    result = _assess(
        findings,
        (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )

    assert result["scan_outcome_code"] == "incomplete"
    assert reason in result["reasons"]


def test_failed_execution_and_external_failure_are_failed() -> None:
    """Execution failures outrank ordinary incompleteness."""
    findings = _findings_bytes()
    execution = json.loads(_evidence_bytes(findings))
    execution["execution"] = "failed"
    failed_execution = _assess(
        findings,
        (json.dumps(execution, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )

    engine = json.loads(_evidence_bytes(findings))
    engine["requested_external_engines"] = ["semgrep"]
    engine["external_engines"] = {"semgrep": "failed"}
    failed_engine = _assess(
        findings,
        (json.dumps(engine, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )

    assert failed_execution["scan_outcome_code"] == "failed"
    assert "scan_execution_failed" in failed_execution["reasons"]
    assert failed_engine["scan_outcome_code"] == "failed"
    assert "external_engine_failed" in failed_engine["reasons"]


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (lambda evidence: evidence.__setitem__("repository", "other/repo"), "repository_mismatch"),
        (lambda evidence: evidence.__setitem__("commit", "b" * 40), "commit_mismatch"),
        (lambda evidence: evidence.__setitem__("findings_sha256", "0" * 64), "findings_digest_mismatch"),
        (lambda evidence: evidence.__setitem__("schema", "unknown"), "evidence_schema_invalid"),
    ],
)
def test_identity_digest_and_schema_fail_closed_as_untrusted(mutator, reason: str) -> None:
    """Identity, digest, and schema ambiguity are untrusted."""
    findings = _findings_bytes()
    evidence = json.loads(_evidence_bytes(findings))
    mutator(evidence)
    result = _assess(
        findings,
        (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )

    assert result["scan_outcome_code"] == "untrusted"
    assert reason in result["reasons"]


def test_stale_and_future_evidence_are_not_clean() -> None:
    """Stale evidence is incomplete while future time evidence is untrusted."""
    findings = _findings_bytes()

    stale = _assess(
        findings,
        _evidence_bytes(findings, generated_at="2026-08-15T20:00:00Z"),
    )
    future = _assess(
        findings,
        _evidence_bytes(findings, generated_at="2026-08-16T00:05:01Z"),
    )

    assert stale["scan_outcome_code"] == "incomplete"
    assert stale["freshness"]["stale"] is True
    assert "evidence_stale" in stale["reasons"]
    assert future["scan_outcome_code"] == "untrusted"
    assert "generated_at_in_future" in future["reasons"]


@pytest.mark.parametrize(
    "findings_bytes,evidence_bytes",
    [
        (b"not-json", b"{}"),
        (b"{}", b"not-json"),
        (b'{"schema":"wrong","findings":[]}', b"{}"),
        (b'{"schema":"appguardrail.findings.v1","findings":{}}', b"{}"),
    ],
)
def test_malformed_artifacts_fail_closed(findings_bytes: bytes, evidence_bytes: bytes) -> None:
    """Malformed artifacts produce a deterministic untrusted result."""
    result = _assess(findings_bytes, evidence_bytes)

    assert result["scan_outcome_code"] == "untrusted"
    assert result["reasons"]


def test_invalid_evidence_shapes_fail_closed() -> None:
    """Invalid detector, engine, scope, gate, and timestamp shapes are untrusted."""
    findings = _findings_bytes()
    variants = [
        ("configured_detectors", ["builtin", "builtin"]),
        ("completed_detectors", ["unknown"]),
        ("requested_external_engines", ["semgrep", "semgrep"]),
        ("external_engines", {"semgrep": "mystery"}),
        ("scope", {"files_scanned": -1, "paths": ["."], "languages": [], "exclusions": []}),
        ("gate", {"threshold": [], "blocking_count": 0, "non_blocking_count": 0}),
        ("generated_at", "not-a-time"),
        ("scanner_version", ""),
    ]

    for key, value in variants:
        evidence = json.loads(_evidence_bytes(findings))
        evidence[key] = value
        result = _assess(
            findings,
            (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )
        assert result["scan_outcome_code"] == "untrusted", key


def test_gate_counts_must_match_finding_count() -> None:
    """Evidence counts that cannot account for findings are untrusted."""
    findings = _findings_bytes([{"rule_id": "demo", "severity": "INFO"}])
    evidence = _evidence_bytes(findings)
    result = _assess(findings, evidence)

    assert result["scan_outcome_code"] == "untrusted"
    assert "finding_count_mismatch" in result["reasons"]


def test_size_and_configuration_arguments_are_bounded() -> None:
    """Oversized input and invalid evaluation bounds fail deterministically."""
    findings = _findings_bytes()
    evidence = _evidence_bytes(findings)

    oversized = assess_scan_artifacts(
        b"x" * (2 * 1024 * 1024 + 1),
        evidence,
        expected_repository=REPOSITORY,
        expected_commit=COMMIT,
        now=NOW,
        max_age_seconds=3600,
    )
    assert oversized["scan_outcome_code"] == "untrusted"
    assert "artifact_too_large" in oversized["reasons"]

    with pytest.raises(ValueError):
        _assess(findings, evidence, max_age_seconds=0)

    with pytest.raises(ValueError):
        assess_scan_artifacts(
            findings,
            evidence,
            expected_repository="bad",
            expected_commit=COMMIT,
            now=NOW,
            max_age_seconds=3600,
        )


def test_cli_writes_deterministic_json_and_uses_fail_closed_exit_codes(
    tmp_path: Path,
) -> None:
    """The module CLI emits canonical JSON and differentiates trusted outcomes."""
    findings_path = tmp_path / "findings.json"
    evidence_path = tmp_path / "evidence.json"
    output_path = tmp_path / "assurance.json"
    findings = _findings_bytes()
    findings_path.write_bytes(findings)
    evidence_path.write_bytes(_evidence_bytes(findings))

    clean_exit = main(
        [
            "--findings",
            str(findings_path),
            "--evidence",
            str(evidence_path),
            "--out",
            str(output_path),
            "--repository",
            REPOSITORY,
            "--commit",
            COMMIT,
            "--now",
            "2026-08-16T00:00:00Z",
            "--max-age-seconds",
            "3600",
        ]
    )
    first = output_path.read_text(encoding="utf-8")
    clean_result = json.loads(first)

    assert clean_exit == 0
    assert clean_result["scan_outcome_code"] == "clean"
    assert first == json.dumps(clean_result, indent=2, sort_keys=True) + "\n"

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["execution"] = "failed"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    failed_exit = main(
        [
            "--findings",
            str(findings_path),
            "--evidence",
            str(evidence_path),
            "--out",
            str(output_path),
            "--repository",
            REPOSITORY,
            "--commit",
            COMMIT,
            "--now",
            "2026-08-16T00:00:00Z",
        ]
    )

    assert failed_exit == 2
    assert json.loads(output_path.read_text(encoding="utf-8"))["scan_outcome_code"] == "failed"


def test_cli_findings_present_exit_code_and_missing_input(tmp_path: Path) -> None:
    """The CLI distinguishes findings from unavailable input without claiming clean."""
    findings_path = tmp_path / "findings.json"
    evidence_path = tmp_path / "evidence.json"
    output_path = tmp_path / "assurance.json"
    findings = _findings_bytes([{"rule_id": "demo"}])
    evidence = json.loads(_evidence_bytes(findings))
    evidence["gate"]["non_blocking_count"] = 1
    findings_path.write_bytes(findings)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    findings_exit = main(
        [
            "--findings",
            str(findings_path),
            "--evidence",
            str(evidence_path),
            "--out",
            str(output_path),
            "--repository",
            REPOSITORY,
            "--commit",
            COMMIT,
            "--now",
            "2026-08-16T00:00:00Z",
        ]
    )
    missing_exit = main(
        [
            "--findings",
            str(tmp_path / "missing.json"),
            "--evidence",
            str(evidence_path),
            "--out",
            str(output_path),
            "--repository",
            REPOSITORY,
            "--commit",
            COMMIT,
            "--now",
            "2026-08-16T00:00:00Z",
        ]
    )

    assert findings_exit == 1
    assert missing_exit == 2
    assert not output_path.exists() or json.loads(output_path.read_text())["scan_outcome_code"] != "clean"


def test_all_production_functions_are_documented() -> None:
    """Every function in the owned production module carries a readable docstring."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(scan_assurance))
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    assert functions
    assert all(ast.get_docstring(node) for node in functions)


def test_low_level_malformed_edges_are_fail_closed() -> None:
    """Malformed byte types and non-object JSON cannot bypass assurance checks."""
    findings = _findings_bytes()
    evidence = _evidence_bytes(findings)

    wrong_bytes = assess_scan_artifacts(
        "not-bytes",  # type: ignore[arg-type]
        evidence,
        expected_repository=REPOSITORY,
        expected_commit=COMMIT,
        now=NOW,
    )
    evidence_array = _assess(findings, b"[]")

    assert wrong_bytes["scan_outcome_code"] == "untrusted"
    assert "findings_bytes_invalid" in wrong_bytes["reasons"]
    assert evidence_array["scan_outcome_code"] == "untrusted"
    assert "evidence_json_invalid" in evidence_array["reasons"]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("repository", ""),
        ("commit", "short"),
        ("execution", "mystery"),
        ("completed_detectors", "builtin"),
        ("configured_detectors", [""]),
        ("external_engines", []),
        ("scope", []),
        ("gate", []),
        ("findings_sha256", "ABC"),
        ("generated_at", ""),
    ],
)
def test_structural_evidence_defects_are_untrusted(key: str, value) -> None:
    """Every malformed evidence field fails closed before outcome qualification."""
    findings = _findings_bytes()
    evidence = json.loads(_evidence_bytes(findings))
    evidence[key] = value
    result = _assess(
        findings,
        (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )

    assert result["scan_outcome_code"] == "untrusted"
    assert result["reasons"]


def test_naive_time_and_invalid_expected_commit_are_rejected() -> None:
    """Caller trust anchors require an exact SHA and timezone-aware evaluation time."""
    findings = _findings_bytes()
    evidence = _evidence_bytes(findings)

    with pytest.raises(ValueError):
        assess_scan_artifacts(
            findings,
            evidence,
            expected_repository=REPOSITORY,
            expected_commit="short",
            now=NOW,
        )

    with pytest.raises(ValueError):
        assess_scan_artifacts(
            findings,
            evidence,
            expected_repository=REPOSITORY,
            expected_commit=COMMIT,
            now=datetime(2026, 8, 16),
        )


def test_naive_generated_time_and_incomplete_execution_never_clean() -> None:
    """Naive timestamps are untrusted and explicit incomplete execution stays incomplete."""
    findings = _findings_bytes()

    naive = _assess(
        findings,
        _evidence_bytes(findings, generated_at="2026-08-15T23:55:00"),
    )
    incomplete = _assess(
        findings,
        _evidence_bytes(findings, execution="incomplete"),
    )

    assert naive["scan_outcome_code"] == "untrusted"
    assert "generated_at_invalid" in naive["reasons"]
    assert incomplete["scan_outcome_code"] == "incomplete"
    assert "scan_execution_incomplete" in incomplete["reasons"]


def test_cli_invalid_now_fails_closed_without_output(tmp_path: Path) -> None:
    """Invalid CLI evaluation time returns non-passing status and no stale output."""
    findings_path = tmp_path / "findings.json"
    evidence_path = tmp_path / "evidence.json"
    output_path = tmp_path / "assurance.json"
    findings = _findings_bytes()
    findings_path.write_bytes(findings)
    evidence_path.write_bytes(_evidence_bytes(findings))
    output_path.write_text('{"scan_outcome_code":"clean"}', encoding="utf-8")

    exit_code = main(
        [
            "--findings",
            str(findings_path),
            "--evidence",
            str(evidence_path),
            "--out",
            str(output_path),
            "--repository",
            REPOSITORY,
            "--commit",
            COMMIT,
            "--now",
            "not-a-time",
        ]
    )

    assert exit_code == 2
    assert not output_path.exists()
