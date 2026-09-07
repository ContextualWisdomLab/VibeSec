"""Contract tests for AppGuardrail's canonical product and detector documentation."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCUMENTS = (
    "DOCUMENTATION.md",
    "docs/PRD.md",
    "docs/TRD.md",
    "ARCHITECTURE.md",
    "docs/UML.md",
    "docs/ERD.md",
    "docs/THREAT_MODEL.md",
    "docs/TEST_STRATEGY.md",
    "docs/OPERABILITY.md",
    "docs/TRACEABILITY.md",
    "docs/adr/README.md",
    "SECURITY.md",
    "docs/release-automation.md",
    "docs/product/2026-07-02-2b-krw-sale-readiness-plan.md",
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CHANGELOG.md",
)
GOVERNING_ADRS = (
    "0001-executable-detector-truth.md",
    "0002-prevention-versus-detection.md",
    "0003-external-engine-provenance.md",
    "0004-tenant-network-boundaries.md",
    "0005-remediation-authority.md",
    "0006-automation-authority.md",
    "0007-cwl-security-issue-detector-families.md",
)


def _read(relative_path: str) -> str:
    """Return one repository document as UTF-8 text."""

    return (ROOT / relative_path).read_text(encoding="utf-8")


def _single_line_with(text: str, *markers: str) -> str:
    """Return the one documentation line containing every requested marker."""

    matches = [
        line.strip()
        for line in text.splitlines()
        if all(marker in line for marker in markers)
    ]
    assert len(matches) == 1, (
        f"expected one line containing {markers!r}, found {len(matches)}"
    )
    return matches[0]


def test_canonical_detection_documents_exist() -> None:
    """Keep product, technical, detection, and operating memory discoverable."""

    missing = [path for path in REQUIRED_DOCUMENTS if not (ROOT / path).is_file()]
    assert not missing, f"missing canonical documentation: {missing}"


def test_documentation_map_links_cross_cutting_contracts() -> None:
    """Require the documentation map to link every canonical mapped record."""

    documentation = _read("DOCUMENTATION.md")
    for path in REQUIRED_DOCUMENTS[1:]:
        assert f"]({path})" in documentation, (
            f"documentation map does not contain an actual Markdown link to {path}"
        )


def test_integrated_ssrf_controls_are_promoted_but_distinct() -> None:
    """Promote merged SSRF controls without conflating prevention and detection."""

    architecture = _read("ARCHITECTURE.md")
    prd = _read("docs/PRD.md")
    traceability = _read("docs/TRACEABILITY.md")

    prevention_claim = _single_line_with(prd, "PR #924", "implemented-main")
    assert "prevention" in prevention_claim and "webhook write boundary" in prevention_claim

    detector_claim = _single_line_with(prd, "PR #910", "implemented-main")
    assert "scanner detection" in detector_claim
    assert "python-stored-ssrf-webhook-url" in detector_claim

    active_issue_claim = _single_line_with(prd, "PR #911", "active-PR")
    assert "no-exclusions registry" in active_issue_claim

    detector_trace = _single_line_with(
        traceability,
        "automatic scanner detection of unsafe stored-webhook SSRF pattern",
        "PR #910",
    )
    assert "python-stored-ssrf-webhook-url" in detector_trace
    assert "implemented-main" in detector_trace and "bounded scope" in detector_trace

    issue_trace = _single_line_with(
        traceability,
        "every retained issue claim mapped to executable detector obligation",
        "PR #911 active-PR",
    )
    assert "issue-detection audit" in issue_trace
    assert "separate controls" in architecture


def test_structural_rule_fixture_is_not_claimed_as_lightweight_execution() -> None:
    """Prevent Semgrep-style fixtures from becoming false built-in capability claims."""

    prd = _read("docs/PRD.md")
    architecture = _read("ARCHITECTURE.md")
    assert "structural `pattern:`" in prd
    assert "not automatically executable in full" in architecture


def test_issue_claim_identity_is_repository_scoped_and_stable() -> None:
    """Keep future issue obligations collision-safe across GitHub repositories."""

    erd = _read("docs/ERD.md")
    assert "(repository_full_name, issue_number, claim_identifier)" in erd
    assert "canonical_claim_key" in erd
    assert "generated deterministically" in erd
    assert "same issue number/key must produce a different composite identity" in erd
    assert "stable regeneration" in erd


def test_evidence_provenance_is_not_hidden_in_free_form_metadata() -> None:
    """Require explicit producer, digest, version, and authentication fields."""

    erd = _read("docs/ERD.md")
    for field in (
        "engine_version",
        "source_kind_code",
        "producer_capability_code",
        "producer_identity",
        "signed_payload_digest",
        "signature_status_code",
        "signature_algorithm_code",
        "signature_value",
        "attestation_type_code",
        "attestation_issuer",
        "attestation_reference",
    ):
        assert field in erd, f"missing explicit evidence provenance field {field}"
    assert "bounded_metadata_json` is supplementary metadata" in erd
    assert "evidence_untrusted" in erd


def test_evidence_digest_serialization_is_deterministic_and_linked() -> None:
    """Bind producer and verifier digests to one byte-level evidence contract."""

    erd = _read("docs/ERD.md")
    lowered = erd.lower()
    for phrase in (
        "RFC 8785",
        "UTF-8",
        "Unicode NFC",
        "omitted and explicit `null` are distinct",
        "non-finite numbers are rejected",
        "bounded_metadata_json",
        "SHA-256",
        "signed_payload_digest excludes",
        "evidence_digest",
        "finding_digest",
        "producer and verifier",
    ):
        assert phrase.lower() in lowered


def test_webhook_retry_semantics_match_current_one_shot_implementation() -> None:
    """Prevent docs from inventing unsafe retry behavior without idempotency."""

    erd = _read("docs/ERD.md")
    operability = _read("docs/OPERABILITY.md")
    uml = _read("docs/UML.md")
    for document in (erd, operability, uml):
        assert "at-most-once" in document
    assert "does not automatically retry" in operability
    assert "stable `delivery_id`" in operability
    assert "receiver-side deduplication" in operability
    assert "no automatic retry" in uml
    erd_lowered = erd.lower()
    operability_lowered = operability.lower()
    for phrase in (
        "every send attempt and redirect hop",
        "connection-time address pinning",
        "private, loopback, link-local, metadata, unspecified, multicast, or reserved",
        "connected peer address",
    ):
        assert phrase.lower() in erd_lowered
        assert phrase.lower() in operability_lowered


def test_detector_maturity_requires_verified_tests() -> None:
    """Keep a failing RED test from being represented as an executable detector."""

    uml = _read("docs/UML.md")
    assert "detector_obligation --> tests_verified" in uml
    assert "tests_verified --> executable_detector" in uml
    assert "detector_obligation --> tests_failed" in uml
    assert "tests_red --> executable_detector" not in uml
    assert "tests_failed --> executable_detector" not in uml


def test_adr_index_contains_governing_detector_decisions() -> None:
    """Keep the detector/security architecture decisions present and indexed."""

    index = _read("docs/adr/README.md")
    for adr in GOVERNING_ADRS:
        adr_path = ROOT / "docs" / "adr" / adr
        assert adr_path.is_file(), f"ADR file is missing: {adr}"
        assert f"]({adr})" in index, f"ADR index does not link {adr}"


def test_adr_0007_stays_proposed_until_protected_merge() -> None:
    """Family-mapping ADR must not be Accepted on this successor branch."""

    adr = _read("docs/adr/0007-cwl-security-issue-detector-families.md")
    index_row = _single_line_with(
        _read("docs/adr/README.md"),
        "0007-cwl-security-issue-detector-families.md",
        "Proposed",
    )
    assert "**Status:** Proposed" in adr
    assert "**Status:** Accepted" not in adr
    assert "Proposed" in index_row
    assert "Accepted" not in index_row
