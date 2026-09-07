import socket

import pytest

from appguardrail_core.controlplane import _is_safe_url


@pytest.mark.parametrize(
    "url",
    (
        "http://",
        "https://",
        "http://user@",
        "https://user@",
        "http:///path",
    ),
)
def test_missing_hostname_is_rejected_before_dns(monkeypatch, url):
    """Reject malformed HTTP(S) authorities before attempting DNS resolution."""

    def unexpected_resolution(*_args, **_kwargs):
        raise AssertionError("missing-host URLs must not reach DNS resolution")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_resolution)

    assert _is_safe_url(url) is False


def test_unresolvable_nonempty_test_hostname_keeps_existing_contract(monkeypatch):
    """Keep the existing dummy-domain contract for syntactically valid hosts."""

    def unresolved(*_args, **_kwargs):
        raise socket.gaierror

    monkeypatch.setattr(socket, "getaddrinfo", unresolved)

    assert _is_safe_url("https://hook.example/callback") is True
