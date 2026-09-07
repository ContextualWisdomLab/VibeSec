"""Current-review regressions for empty-host SSRF detector return semantics."""

from scanner.cli.appguardrail import _scan_file


_RULE_ID = "python-ssrf-empty-host-fail-open"


def _findings(tmp_path, source: str):
    """Run the production scanner and return this detector family's findings."""
    target = tmp_path / "validator.py"
    target.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(target, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def _guard_return_source(expression: str) -> str:
    """Build a validator with an unconditional empty-host guard return."""
    return f'''\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return {expression}
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return True
'''


def test_statically_falsy_empty_host_guard_returns_are_safe(tmp_path):
    """Common statically falsy literals terminate the empty-host path safely."""
    for expression in (
        "0",
        "0.0",
        "0j",
        '""',
        "''",
        "()",
        "[]",
        "{}",
        "(0)",
    ):
        assert not _findings(tmp_path, _guard_return_source(expression)), expression


def test_compound_falsy_prefix_returns_remain_detectable(tmp_path):
    """A falsy literal does not sanitize an expression that can still be truthy."""
    for expression in ("0 or True", '"" or True', "0 if reject else True"):
        assert len(_findings(tmp_path, _guard_return_source(expression))) == 1


def test_parenthesized_true_return_from_dns_failure_is_detected(tmp_path):
    """Parenthesizing a successful return must not evade the fail-open detector."""
    source = '''\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        return (True)
'''
    assert len(_findings(tmp_path, source)) == 1


def test_static_truthy_numeric_return_from_dns_failure_is_detected(tmp_path):
    """A statically truthy numeric success has the same fail-open semantics."""
    source = '''\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        return 1
'''
    assert len(_findings(tmp_path, source)) == 1


def test_gaierror_in_exception_tuple_is_detected(tmp_path):
    """Tuple handlers that include gaierror preserve the same resolver-failure path."""
    for handler in ("(socket.gaierror, OSError)", "(OSError, socket.gaierror)"):
        source = f'''\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except {handler}:
        pass
    return True
'''
        assert len(_findings(tmp_path, source)) == 1


def test_tuple_handler_that_fails_closed_remains_negative(tmp_path):
    """Exception-tuple support must not erase a same-handler rejection."""
    source = '''\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    return True
'''
    assert not _findings(tmp_path, source)
