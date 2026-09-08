import appguardrail_core.rules as rules_module


def test_extract_public_references_from_rule_message():
    message = (
        "Disable TLS verify false. [CWE-295 - Improper Certificate Validation] "
        "This also maps to [OWASP A05:2021 - Security Misconfiguration]."
    )

    assert rules_module.extract_public_references(message) == (
        "CWE-295 - Improper Certificate Validation",
        "OWASP A05:2021 - Security Misconfiguration",
    )


def test_extract_public_references_deduplicates_in_first_seen_order():
    message = (
        "[CWE-295 - Improper Certificate Validation] appears first. "
        "[OWASP A05:2021 - Security Misconfiguration] appears second. "
        "[CWE-295 - Improper Certificate Validation] appears again."
    )

    assert rules_module.extract_public_references(message) == (
        "CWE-295 - Improper Certificate Validation",
        "OWASP A05:2021 - Security Misconfiguration",
    )


def test_extract_public_references_skips_regex_without_opening_bracket(monkeypatch):
    class RejectRegex:
        def finditer(self, _message):
            raise AssertionError("regex engine must not run on the no-bracket fast path")

    monkeypatch.setattr(rules_module, "REFERENCE_RE", RejectRegex())

    assert rules_module.extract_public_references("CWE-918 mentioned without bracket syntax") == ()


def test_build_rule_metadata_adds_defaults_for_category():
    metadata = rules_module.build_rule_metadata(
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
    assert rules_module.validate_rule_metadata(metadata) == []


def test_build_rule_metadata_deduplicates_message_and_default_references():
    metadata = rules_module.build_rule_metadata(
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
    errors = rules_module.validate_rule_metadata(
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
