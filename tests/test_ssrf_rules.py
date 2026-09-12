"""Regression tests for stored SSRF detection in the packaged rule engine."""

from unittest.mock import patch

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-stored-ssrf-webhook-url"


def _rule():
    """Return the single packaged stored-SSRF rule under test."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _vulnerable_source():
    """Build the original direct request-to-persistence vulnerability."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            f'    {sink}(conn, org, (body or {{}}).get("url"))',
            "",
        ]
    )


def _unvalidated_variable_source(variable="webhook_url"):
    """Build an unvalidated local-variable flow into webhook persistence."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            f'    {variable} = (body or {{}}).get("url")',
            f"    {sink}(conn, org, {variable})",
            "",
        ]
    )


def _ignored_validation_result_source():
    """Build a flow that calls the validator but discards its result."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    target = (body or {}).get("url")',
            "    _is_safe_url(target)",
            f"    {sink}(conn, org, target)",
            "",
        ]
    )


def _non_enforcing_guard_source():
    """Build a guard that logs invalid input without blocking persistence."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    target = (body or {}).get("url")',
            "    if not _is_safe_url(target):",
            '        log.warning("unsafe webhook url")',
            f"    {sink}(conn, org, target)",
            "",
        ]
    )


def _non_enforcing_guard_with_unrelated_return_source():
    """Build a non-enforcing guard followed by an unrelated early return."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body, disabled):",
            '    target = (body or {}).get("url")',
            "    if not _is_safe_url(target):",
            '        log.warning("unsafe webhook url")',
            "    if disabled:",
            "        return",
            f"    {sink}(conn, org, target)",
            "",
        ]
    )


def _conditional_rejection_guard_source():
    """Build a guard that rejects only when an unrelated flag is true."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body, disabled):",
            '    target = (body or {}).get("url")',
            "    if disabled and not _is_safe_url(target):",
            "        return",
            f"    {sink}(conn, org, target)",
            "",
        ]
    )


def _positive_guard_source():
    """Build a safe flow whose persistence sink is inside a positive guard."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    target = (body or {}).get("url")',
            "    if _is_safe_url(target):",
            f"        {sink}(conn, org, target)",
            "",
        ]
    )


def _positive_guard_then_unprotected_sink_source():
    """Build a safe guarded sink followed by an unsafe unguarded sink."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    target = (body or {}).get("url")',
            "    if _is_safe_url(target):",
            f"        {sink}(conn, org, target)",
            f"    {sink}(conn, org, target)",
            "",
        ]
    )


def _safe_source():
    """Build a safe flow that raises before persisting invalid input."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    webhook_url = (body or {}).get("url")',
            "    if webhook_url and not _is_safe_url(webhook_url):",
            "        raise ValueError(\"unsafe webhook url\")",
            f"    {sink}(conn, org, webhook_url)",
            "",
        ]
    )


def _production_guard_source():
    """Build the multiline fail-closed guard used by the control plane."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    webhook_url = body.get("url")',
            '    if webhook_url not in (None, "") and (',
            "        not isinstance(webhook_url, str)",
            "        or not _is_safe_url(webhook_url)",
            "    ):",
            '        return {"error": "unsafe webhook url"}',
            f"    {sink}(conn, org, webhook_url)",
            "",
        ]
    )


def _none_aware_guard_source():
    """Build the compact fail-closed guard used by the control plane."""
    sink = "set_" + "webhook"
    return "\n".join(
        [
            "def update_webhook(conn, org, body):",
            '    webhook_url = body.get("url")',
            "    if webhook_url is not None and not _is_safe_url(webhook_url):",
            '        return {"error": "unsafe webhook url"}',
            f"    {sink}(conn, org, webhook_url)",
            "",
        ]
    )


def _scan_rule_findings(tmp_path, source):
    """Run the real file scanner and return only stored-SSRF findings."""
    source_file = tmp_path / "webhook.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_packaged_rule_matches_direct_request_url_persistence():
    """Detect direct request URL persistence with HIGH severity."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_vulnerable_source())


def test_packaged_rule_declares_sink_prefilter():
    """Skip the expensive flow regex unless the persistence sink is present."""
    assert _rule()["required_substrings"] == ("set_webhook",)


def test_scan_file_skips_regex_when_sink_prefilter_is_absent(tmp_path):
    """Do not invoke an expensive regex for files without its required sink."""
    source_file = tmp_path / "benign.py"
    source_file.write_text('target = body.get("url")\n' * 1000, encoding="utf-8")

    class ExplodingPattern:
        """Prove that prefilter rejection happens before regex evaluation."""

        def finditer(self, _content):
            raise AssertionError("regex must not run without the sink literal")

    rule = {
        "id": _RULE_ID,
        "pattern": ExplodingPattern(),
        "severity": "HIGH",
        "message": "stored SSRF [CWE-918 - Server-Side Request Forgery]",
        "extensions": [".py"],
        "required_substrings": ("set_webhook",),
    }
    with patch("scanner.cli.appguardrail.SCAN_RULES", [rule]):
        assert not _scan_file(source_file, tmp_path)


def test_packaged_rule_matches_unvalidated_variable_persistence():
    """Detect source-to-sink persistence through a local variable."""
    assert _rule()["pattern"].search(_unvalidated_variable_source())


def test_packaged_rule_does_not_depend_on_url_variable_name():
    """Detect the flow even when the variable name omits the word URL."""
    assert _rule()["pattern"].search(_unvalidated_variable_source("target"))


def test_packaged_rule_does_not_treat_ignored_validator_result_as_safe():
    """Detect a validator call whose boolean result is discarded."""
    assert _rule()["pattern"].search(_ignored_validation_result_source())


def test_packaged_rule_matches_non_enforcing_validation_guard():
    """Detect a validation branch that logs but does not terminate."""
    assert _rule()["pattern"].search(_non_enforcing_guard_source())


def test_packaged_rule_matches_non_enforcing_guard_with_unrelated_return():
    """Ignore unrelated returns when deciding whether validation enforces."""
    assert _rule()["pattern"].search(
        _non_enforcing_guard_with_unrelated_return_source()
    )


def test_packaged_rule_matches_conditional_rejection_guard():
    """Do not treat an unrelated conditional rejection as fail-closed."""
    assert _rule()["pattern"].search(_conditional_rejection_guard_source())


def test_packaged_rule_ignores_positive_guarded_persistence():
    """Do not flag a sink that is reachable only after positive validation."""
    assert not _rule()["pattern"].search(_positive_guard_source())


def test_packaged_rule_matches_unprotected_sink_after_positive_guard():
    """A guarded sink must not hide a later unprotected persistence sink."""
    assert _rule()["pattern"].search(
        _positive_guard_then_unprotected_sink_source()
    )


def test_packaged_rule_ignores_fail_closed_guarded_persistence():
    """Do not flag a flow that raises on invalid input before persistence."""
    assert not _rule()["pattern"].search(_safe_source())


def test_packaged_rule_ignores_production_fail_closed_guard():
    """Do not self-flag the control plane's multiline rejection guard."""
    assert not _rule()["pattern"].search(_production_guard_source())


def test_packaged_rule_ignores_none_aware_fail_closed_guard():
    """Do not self-flag a None-aware fail-closed rejection guard."""
    assert not _rule()["pattern"].search(_none_aware_guard_source())


def test_scan_file_emits_stored_ssrf_finding(tmp_path):
    """Emit a normalized SSRF finding through the production file scanner."""
    matches = _scan_rule_findings(tmp_path, _vulnerable_source())

    assert len(matches) == 1
    finding = matches[0]
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["file"] == "webhook.py"
    assert finding["line"] == 2
    assert finding["category"] == "ssrf"
    assert finding["cwe"] == ("CWE-918 - Server-Side Request Forgery",)
    assert finding["owasp"] == ("OWASP A10:2021 - Server-Side Request Forgery",)
    assert "destination" in finding["remediation"].lower()


def test_scan_file_emits_stored_ssrf_finding_for_variable_flow(tmp_path):
    """Emit a finding for an unvalidated local-variable persistence flow."""
    matches = _scan_rule_findings(tmp_path, _unvalidated_variable_source())

    assert len(matches) == 1
    assert matches[0]["line"] == 2


def test_scan_file_emits_finding_when_validator_result_is_ignored(tmp_path):
    """Emit a finding when code ignores the validator's return value."""
    matches = _scan_rule_findings(tmp_path, _ignored_validation_result_source())

    assert len(matches) == 1
    assert matches[0]["line"] == 2


def test_scan_file_emits_finding_for_non_enforcing_guard(tmp_path):
    """Emit a finding when an invalid branch fails to stop persistence."""
    matches = _scan_rule_findings(tmp_path, _non_enforcing_guard_source())

    assert len(matches) == 1
    assert matches[0]["line"] == 2


def test_scan_file_does_not_flag_validated_path(tmp_path):
    """Suppress the finding for a verified fail-closed persistence path."""
    assert not _scan_rule_findings(tmp_path, _safe_source())
