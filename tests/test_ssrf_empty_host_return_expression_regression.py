"""Regression tests for empty-host guards with non-terminal return expressions."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-ssrf-empty-host-fail-open"


def _scan_source(tmp_path, return_expression: str):
    """Scan a validator whose empty-host branch can still return success."""
    source_file = tmp_path / "validator.py"
    source_file.write_text(
        f"""\
def is_safe_url(url, reject):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    if not host:
        return {return_expression}
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return True
""",
        encoding="utf-8",
    )
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_packaged_empty_host_rule_is_loaded():
    """Keep this regression bound to the production packaged rule."""
    assert sum(rule["id"] == _RULE_ID for rule in SCAN_RULES) == 1


def test_conditional_or_compound_falsy_returns_do_not_suppress_finding(tmp_path):
    """Falsy literals only reject when the return expression ends at that literal."""
    for return_expression in (
        "None if reject else True",
        "False if reject else True",
        "None or True",
        "False or True",
    ):
        assert len(_scan_source(tmp_path, return_expression)) == 1


def test_parenthesized_standalone_falsy_returns_are_fail_closed(tmp_path):
    """Simple parentheses do not change a standalone falsy rejection."""
    for return_expression in ("(None)", "(False)", "( None )", "( False )"):
        assert not _scan_source(tmp_path, return_expression)
