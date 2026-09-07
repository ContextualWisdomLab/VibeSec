"""Regression tests for empty-host SSRF fail-open validator detection."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-ssrf-empty-host-fail-open"
_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "security_corpus"


def _rule():
    """Return the single packaged empty-host SSRF rule under test."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _fixture(name: str) -> str:
    """Load one immutable security-corpus fixture."""
    return (_FIXTURE_DIR / name).read_text(encoding="utf-8")


def _scan_source(tmp_path, source: str):
    """Run the production file scanner and isolate this detector's findings."""
    source_file = tmp_path / "validator.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def _same_line_guard_source(condition: str) -> str:
    """Build a validator whose empty-host guard shares one condition line."""
    return f"""\
def is_safe_url(url, enforce):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    if {condition}:
        return False
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
    return True
"""


def test_packaged_rule_declares_bounded_ssrf_contract():
    """Expose stable severity and cheap source prefilters for the detector."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["required_substrings"] == ("hostname", "getaddrinfo", "gaierror")


def test_historical_vulnerable_fixture_is_detected_through_production_scan(tmp_path):
    """Preserve the reviewed historical fail-open flow as a positive oracle."""
    findings = _scan_source(
        tmp_path,
        _fixture("appguardrail_empty_host_ssrf_vulnerable.py"),
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "ssrf"
    assert "CWE-918 - Server-Side Request Forgery" in finding["cwe"]


def test_reviewed_empty_host_guard_fixture_is_not_flagged(tmp_path):
    """Do not flag the reviewed unconditional empty-host rejection."""
    assert not _scan_source(
        tmp_path,
        _fixture("appguardrail_empty_host_ssrf_fixed.py"),
    )


def test_nonempty_hostname_fallbacks_are_not_flagged(tmp_path):
    """A nonempty fallback cannot enter the empty-host failure path."""
    for fallback in ('"localhost"', '"example.com"'):
        source = f"""\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or {fallback}).lower()
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
    return True
"""
        assert not _scan_source(tmp_path, source)


def test_direct_hostname_assignment_is_detected(tmp_path):
    """A missing parsed hostname must not pass through DNS failure to success."""
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return True
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_direct_hostname_none_guard_is_not_flagged(tmp_path):
    """A direct hostname assignment is safe when missing None is rejected."""
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if host is None:
        return False
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return True
"""
    assert not _scan_source(tmp_path, source)


def test_empty_fallback_with_inline_comment_is_detected(tmp_path):
    """A trailing comment must not hide an explicitly empty fallback."""
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""  # Missing hosts remain empty.
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return True
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_conditional_empty_host_guard_does_not_hide_fail_open_path(tmp_path):
    """A nested guard is not a dominating rejection when its parent can be false."""
    source = """\
def is_safe_url(url, enforce):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    if enforce:
        if not host:
            return False
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
    return True
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_same_line_and_guards_do_not_hide_fail_open_path(tmp_path):
    """An empty-host check joined by AND is conditional, not dominating."""
    for condition in ("not host and enforce", 'host == "" and enforce'):
        assert len(_scan_source(tmp_path, _same_line_guard_source(condition))) == 1


def test_same_line_or_guards_are_unconditional_for_empty_hosts(tmp_path):
    """An empty-host check joined by OR still rejects every empty host."""
    for condition in ("not host or enforce", 'host == "" or enforce'):
        assert not _scan_source(tmp_path, _same_line_guard_source(condition))


def test_parenthesized_empty_host_guards_are_not_flagged(tmp_path):
    """Parentheses do not make an unconditional empty-host rejection unsafe."""
    for condition in ("(not host)", '(host == "")', "(not host or enforce)"):
        assert not _scan_source(tmp_path, _same_line_guard_source(condition))


def test_none_only_guards_do_not_hide_fail_open_path(tmp_path):
    """None-only checks cannot reject a hostname already normalized to a string."""
    for condition in ("host is None", "host == None", "host in (None,)"):
        assert len(_scan_source(tmp_path, _same_line_guard_source(condition))) == 1


def test_empty_host_guard_may_log_or_space_before_rejecting(tmp_path):
    """Harmless same-scope statements and spacing do not defeat domination."""
    sources = (
        """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    if not host:
        logger.warning("empty hostname")
        return False
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
    return True
""",
        """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    if host == \"\":
        # Preserve a diagnostic breadcrumb without weakening the rejection.

        return False
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
    return True
""",
    )
    for source in sources:
        assert not _scan_source(tmp_path, source)


def test_fail_closed_dns_error_is_not_flagged(tmp_path):
    """A resolver failure that rejects the URL cannot create this fail-open path."""
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        return False
    return True
"""
    assert not _scan_source(tmp_path, source)


def test_dns_error_pass_then_fail_closed_is_not_flagged(tmp_path):
    """A diagnostic no-op before an unconditional handler rejection stays safe."""
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
        return False
    return True
"""
    assert not _scan_source(tmp_path, source)


def test_nonterminating_dns_error_handlers_are_detected(tmp_path):
    """Equivalent ignored resolver errors must remain deploy-blocking positives."""
    for handler in (
        'logger.warning("dns resolution failed")',
        'diagnostic = "dns resolution failed"',
        "...",
    ):
        source = f"""\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        {handler}
    return True
"""
        assert len(_scan_source(tmp_path, source)) == 1


def test_dns_error_diagnostics_then_raise_is_not_flagged(tmp_path):
    """A diagnostic statement followed by an unconditional raise is fail closed."""
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        logger.warning("dns resolution failed")
        raise
    return True
"""
    assert not _scan_source(tmp_path, source)


def test_dns_error_handler_direct_success_is_detected(tmp_path):
    """Returning success directly from resolver failure is an explicit fail-open path."""
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        return True
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_equivalent_late_empty_host_guard_before_success_is_not_flagged(tmp_path):
    """Accept an equivalent unconditional rejection anywhere before success."""
    source = """\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    raw = host.split(\"%\", 1)[0]
    try:
        socket.getaddrinfo(raw, None)
    except socket.gaierror:
        pass
    if host == \"\":
        return False
    return True
"""
    assert not _scan_source(tmp_path, source)


def test_rule_does_not_cross_function_boundaries(tmp_path):
    """Do not combine hostname parsing and DNS behavior from sibling functions."""
    source = """\
def parse_host(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or \"\").lower()
    return host


def dns_probe(host):
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return True
"""
    assert not _scan_source(tmp_path, source)


def test_unrelated_dns_probe_is_not_flagged(tmp_path):
    """Generic DNS error handling without parsed-host validation is out of scope."""
    source = """\
def dns_probe(hostname):
    try:
        socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        pass
    return True
"""
    assert not _scan_source(tmp_path, source)
