"""Regression contracts for reference extraction and ordered deduplication."""

from appguardrail_core.rules import _merge_references, extract_public_references


def test_extract_public_references_preserves_first_seen_order_and_normalizes_space() -> None:
    """Repeated public references keep first-seen order after whitespace normalization."""
    message = (
        "Finding [CWE-918   - Server-Side Request Forgery] then "
        "[OWASP A10:2021 - Server-Side Request Forgery], then "
        "[CWE-918   - Server-Side Request Forgery] again."
    )

    assert extract_public_references(message) == (
        "CWE-918 - Server-Side Request Forgery",
        "OWASP A10:2021 - Server-Side Request Forgery",
    )


def test_extract_public_references_handles_empty_and_unmatched_messages() -> None:
    """Messages without supported taxonomy references return an empty tuple."""
    assert extract_public_references("") == ()
    assert extract_public_references("plain finding without a public reference") == ()


def test_merge_references_preserves_order_while_dropping_empty_and_duplicate_values() -> None:
    """Merging groups keeps the first occurrence and omits empty references."""
    assert _merge_references(
        ("CWE-918 - Server-Side Request Forgery", "", "CWE-74 - Injection"),
        ("CWE-918 - Server-Side Request Forgery", "OWASP A03:2021 - Injection"),
        (),
    ) == (
        "CWE-918 - Server-Side Request Forgery",
        "CWE-74 - Injection",
        "OWASP A03:2021 - Injection",
    )
