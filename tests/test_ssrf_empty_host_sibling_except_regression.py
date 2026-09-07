"""Regression for path-sensitive sibling exception handling in empty-host SSRF."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-ssrf-empty-host-fail-open"


def _scan(tmp_path, source: str):
    source_file = tmp_path / "validator.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_rule_is_packaged_once_after_rule_isolation():
    assert sum(rule["id"] == _RULE_ID for rule in SCAN_RULES) == 1


def test_sibling_value_error_return_does_not_sanitize_gaierror_path(tmp_path):
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    raw = host.split("%", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
    except ValueError:
        return False
    return True
"""
    assert len(_scan(tmp_path, source)) == 1


def test_return_inside_gaierror_handler_still_terminates_that_path(tmp_path):
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    raw = host.split("%", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
        return False
    except ValueError:
        return False
    return True
"""
    assert not _scan(tmp_path, source)
