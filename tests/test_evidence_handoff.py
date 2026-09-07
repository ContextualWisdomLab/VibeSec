"""Tests for the deterministic remediation evidence handoff contract."""

from __future__ import annotations

import hashlib
import json

import pytest

from appguardrail_core.evidence_handoff import (
    HANDOFF_SCHEMA,
    HANDOFF_VERSION,
    MAX_HANDOFF_BYTES,
    build_evidence_handoff,
    serialize_evidence_handoff,
    verify_evidence_handoff,
)


def _finding() -> dict:
    """Return a hostile but report-shaped finding fixture."""
    return {
        "rule_id": "demo-rule",
        "severity": "HIGH",
        "file": "src/app.py",
        "line": 8,
        "category": "authz",
        "context": "app-code",
        "message": "api" + "_key='secret-value' <script> `${hostile}`",
        "remediation": "Rotate token='secret-value' and fix <b>ownership</b>.",
        "verification": "Rerun with `--assurance`; \x1b[31mcheck\x1b[0m.",
        "snippet": "token='secret-value'\n```\n${not-code}",
        "references": ["CWE-862"],
        "source_evidence": {
            "source_identity": {
                "repository": "ContextualWisdomLab/appguardrail",
                "revision": "a" * 40,
                "artifact_ref": "github-actions://repo/runs/1/jobs/2",
                "artifact_sha256": "b" * 64,
            },
            "evidence_digest": "c" * 64,
        },
    }


def test_handoff_is_redacted_deterministic_and_verifiable() -> None:
    """The bundle preserves inert text while excluding obvious secret values."""
    provenance = {
        "repository": "ContextualWisdomLab/appguardrail",
        "commit": "d" * 40,
        "artifact_sha256": "e" * 64,
        "api_key": "do-not-copy",
    }
    assurance = {
        "schema": "appguardrail.scan-assurance.v1",
        "scan_outcome_code": "incomplete",
        "reasons": ["detectors_incomplete"],
        "repository": "ContextualWisdomLab/appguardrail",
        "commit": "f" * 40,
        "provenance": {"evidence_digest": "1" * 64},
    }
    first = serialize_evidence_handoff(
        [_finding()], provenance=provenance, assurance=assurance
    )
    second = serialize_evidence_handoff(
        [_finding()], provenance=dict(reversed(list(provenance.items()))), assurance=assurance
    )

    assert first == second
    assert b"secret-value" not in first
    assert b"do-not-copy" not in first
    assert b"${not-code}" in first
    payload = verify_evidence_handoff(first)
    assert payload["schema"] == HANDOFF_SCHEMA
    assert payload["version"] == HANDOFF_VERSION
    assert payload["findings"][0]["provenance"]["artifact_sha256"] == "b" * 64
    assert payload["findings"][0]["provenance"]["evidence_digest"] == "c" * 64
    assert payload["assurance"]["scan_outcome_code"] == "incomplete"


def test_builder_omits_malformed_optional_provenance() -> None:
    """Malformed optional identifiers never become agent-facing claims."""
    payload = build_evidence_handoff(
        [{"rule_id": "r", "severity": "INFO", "message": "ok"}],
        provenance={
            "revision": "a" * 40,
            "commit": "not-a-sha",
            "artifact_sha256": "not-a-digest",
        },
        assurance={"scan_outcome_code": "unknown", "reasons": "bad"},
    )

    assert payload["provenance"] == {"revision": "a" * 40}
    assert "assurance" not in payload


@pytest.mark.parametrize(
    "mutator",
    [
        lambda payload: payload.__setitem__("schema", "other"),
        lambda payload: payload.__setitem__("version", 2),
        lambda payload: payload.__setitem__("findings", {}),
        lambda payload: payload.__setitem__("provenance", []),
        lambda payload: payload.__setitem__("bundle_sha256", "bad"),
        lambda payload: payload["findings"].append({"tampered": True}),
    ],
)
def test_verify_rejects_tampered_or_malformed_payloads(mutator) -> None:
    """Agents must not consume a handoff after schema or digest tampering."""
    payload = build_evidence_handoff([])
    mutator(payload)

    with pytest.raises((TypeError, ValueError)):
        verify_evidence_handoff(payload)


@pytest.mark.parametrize("raw", [b"not-json", b"\xff", b"[]"])
def test_verify_rejects_invalid_wire_payloads(raw: bytes) -> None:
    """Wire input is bounded JSON and fails closed on malformed bytes."""
    with pytest.raises((TypeError, ValueError)):
        verify_evidence_handoff(raw)


def test_verify_rejects_oversized_and_invalid_mapping_inputs() -> None:
    """Large wire payloads and unsupported in-memory inputs are rejected."""
    with pytest.raises((TypeError, ValueError)):
        verify_evidence_handoff(b"x" * (MAX_HANDOFF_BYTES + 1))
    oversized = build_evidence_handoff([])
    oversized["unknown"] = "x" * MAX_HANDOFF_BYTES
    unsigned = {key: value for key, value in oversized.items() if key != "bundle_sha256"}
    oversized["bundle_sha256"] = hashlib.sha256(
        (json.dumps(unsigned, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    ).hexdigest()
    with pytest.raises(TypeError, match="bounded"):
        verify_evidence_handoff(oversized)
    unserializable = build_evidence_handoff([])
    unserializable["unknown"] = object()
    with pytest.raises(TypeError, match="JSON-serializable"):
        verify_evidence_handoff(unserializable)
    with pytest.raises((TypeError, ValueError)):
        verify_evidence_handoff(1)  # type: ignore[arg-type]

    payload = build_evidence_handoff([])
    assert verify_evidence_handoff(json.loads(serialize_evidence_handoff([]))) == payload


def test_builder_rejects_oversized_output() -> None:
    """The producer never emits a wire artifact the verifier must reject."""
    with pytest.raises(ValueError, match="exceeds"):
        serialize_evidence_handoff([{"rule_id": "r", "message": "x"}] * 10_000)
