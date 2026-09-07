"""Admission contracts for missing-host URL validation across AppGuardrail consumers."""

import socket

import pytest

from appguardrail_core.controlplane import _is_safe_url as controlplane_is_safe_url
from scanner.cli.appguardrail import _is_safe_url as cli_is_safe_url


@pytest.mark.parametrize("validator", (controlplane_is_safe_url, cli_is_safe_url))
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
def test_missing_hostname_is_rejected_before_dns(monkeypatch, validator, url) -> None:
    """Reject malformed HTTP(S) authorities without attempting DNS resolution."""

    def unexpected_resolution(*_args, **_kwargs):
        raise AssertionError("missing-host URLs must not reach DNS resolution")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_resolution)

    assert validator(url) is False
