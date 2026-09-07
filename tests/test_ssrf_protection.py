import socket
import urllib.error
import urllib.request

import pytest

from appguardrail_core.controlplane import SafeRedirectHandler, _is_safe_url
from scanner.cli.appguardrail import _is_safe_url as _cli_is_safe_url


def test_is_safe_url_public_domains():
    assert _is_safe_url("http://google.com/")
    assert _is_safe_url("https://github.com/")


@pytest.mark.parametrize(
    "validator",
    [_is_safe_url, _cli_is_safe_url],
    ids=["controlplane", "cli"],
)
@pytest.mark.parametrize(
    "value",
    [123, True, None, [], {}],
    ids=["integer", "boolean", "none", "list", "mapping"],
)
def test_is_safe_url_invalid_types(validator, value):
    assert not validator(value)


def test_is_safe_url_ipv4_localhost():
    assert not _is_safe_url("http://127.0.0.1/")
    assert not _is_safe_url("http://127.0.0.1:8080/")


def test_is_safe_url_ipv6_localhost():
    assert not _is_safe_url("http://[::1]/")
    assert not _is_safe_url("http://[::1]:8080/")
    assert not _is_safe_url("http://[0000:0000:0000:0000:0000:0000:0000:0001]/")


def test_is_safe_url_localhost_domain():
    assert not _is_safe_url("http://localhost/")
    assert not _is_safe_url("http://localhost:8080/")


def test_is_safe_url_private_ips():
    assert not _is_safe_url("http://10.0.0.1/")
    assert not _is_safe_url("http://192.168.1.1/")
    assert not _is_safe_url("http://172.16.0.1/")


def test_is_safe_url_unspecified_ips():
    assert not _is_safe_url("http://0.0.0.0/")
    assert not _is_safe_url("http://[::]/")


def test_is_safe_url_multicast_ips():
    assert not _is_safe_url("http://224.0.0.1/")
    assert not _is_safe_url("http://[ff00::1]/")
    assert not _is_safe_url("http://[ff02::1]/")


def test_is_safe_url_unsupported_schemes():
    assert not _is_safe_url("file:///etc/passwd")
    assert not _is_safe_url("ftp://example.com")
    assert not _is_safe_url("gopher://example.com")


def test_is_safe_url_unresolvable_domain_fails_closed(monkeypatch):
    def _fail_resolution(*_args, **_kwargs):
        raise socket.gaierror("synthetic unresolved host")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolution)

    assert not _is_safe_url("https://unresolved.example/hook")


def test_is_safe_url_mapped_ips():
    assert not _is_safe_url("http://[::ffff:127.0.0.1]/")
    assert not _is_safe_url("http://[::ffff:192.168.1.1]/")


def test_is_safe_url_reserved_and_not_global_ips():
    assert not _is_safe_url("http://255.255.255.255/")
    assert not _is_safe_url("http://0.0.0.0/")


def test_push_findings_unsafe_url_handled_properly(monkeypatch, capsys):
    from scanner.cli.appguardrail import _push_findings

    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "dummy")

    _push_findings("http://127.0.0.1/", [])
    captured = capsys.readouterr()
    assert "URL must be a public HTTPS URL" in captured.err


def test_safe_redirect_handler_rejects_internal_target():
    handler = SafeRedirectHandler()
    with pytest.raises(urllib.error.URLError) as exc:
        handler.redirect_request(None, None, 302, "Found", None, "http://127.0.0.1/")
    assert "Unsafe redirect target" in str(exc.value)


def test_safe_redirect_handler_rejects_metadata_target():
    handler = SafeRedirectHandler()
    with pytest.raises(urllib.error.URLError) as exc:
        handler.redirect_request(
            None, None, 302, "Found", None, "http://169.254.169.254/latest/meta-data"
        )
    assert "Unsafe redirect target" in str(exc.value)


def test_safe_redirect_handler_allows_public_https(monkeypatch):
    handler = SafeRedirectHandler()
    sentinel = object()

    def _fake_super_redirect(self, req, fp, code, msg, headers, newurl):
        return sentinel

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        ],
    )
    monkeypatch.setattr(
        urllib.request.HTTPRedirectHandler,
        "redirect_request",
        _fake_super_redirect,
    )
    result = handler.redirect_request(
        None, None, 302, "Found", None, "https://hooks.example.com/alert"
    )
    assert result is sentinel


def test_is_safe_url_empty_hostname():
    assert not _is_safe_url("http://")
    assert not _is_safe_url("http://user@")
    assert not _cli_is_safe_url("http://")
    assert not _cli_is_safe_url("http://user@")
