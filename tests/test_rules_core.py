from appguardrail_core.rules import (build_rule_metadata,
                                     extract_public_references,
                                     validate_rule_metadata)


def test_extract_public_references_from_rule_message():
    message = (
        "Disable TLS verify false. [CWE-295 - Improper Certificate Validation] "
        "This also maps to [OWASP A05:2021 - Security Misconfiguration]."
    )

    assert extract_public_references(message) == (
        "CWE-295 - Improper Certificate Validation",
        "OWASP A05:2021 - Security Misconfiguration",
    )


def test_extract_public_references_deduplicates_in_first_seen_order():
    message = (
        "[CWE-295 - Improper Certificate Validation] appears first. "
        "[OWASP A05:2021 - Security Misconfiguration] appears second. "
        "[CWE-295 - Improper Certificate Validation] appears again."
    )

    assert extract_public_references(message) == (
        "CWE-295 - Improper Certificate Validation",
        "OWASP A05:2021 - Security Misconfiguration",
    )


def test_build_rule_metadata_adds_defaults_for_category():
    metadata = build_rule_metadata(
        "hardcoded-api-credential",
        "CRITICAL",
        "Hardcoded API credential detected.",
        category="secrets",
    )

    assert metadata.owasp == (
        "OWASP A07:2021 - Identification and Authentication Failures",
    )
    assert metadata.cwe == ("CWE-798 - Use of Hard-coded Credentials",)
    assert metadata.samm_practice == "Operations / Environment Management"
    assert "rotate" in metadata.remediation.lower()
    assert validate_rule_metadata(metadata) == []


def test_build_rule_metadata_deduplicates_message_and_default_references():
    metadata = build_rule_metadata(
        "explicit-secret",
        "HIGH",
        (
            "Hardcoded credential. "
            "[OWASP A07:2021 - Identification and Authentication Failures]"
        ),
        category="secrets",
    )

    assert metadata.references == (
        "OWASP A07:2021 - Identification and Authentication Failures",
        "CWE-798 - Use of Hard-coded Credentials",
    )
    assert metadata.owasp == (
        "OWASP A07:2021 - Identification and Authentication Failures",
    )


def test_validate_rule_metadata_reports_missing_public_reference():
    errors = validate_rule_metadata(
        {
            "rule_id": "demo",
            "severity": "HIGH",
            "category": "demo",
            "references": [],
            "remediation": "Fix it.",
        }
    )

    assert "missing references" in errors
    assert "missing public taxonomy reference" in errors
