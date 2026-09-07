"""Regression tests for the CLI URL validator's DNS failure boundary."""

import socket

from scanner.cli.appguardrail import _is_safe_url


def test_cli_is_safe_url_rejects_unresolved_hostname(monkeypatch) -> None:
    """A destination is not safe when the CLI cannot establish its resolved IPs."""

    def fail_resolution(*_args, **_kwargs):
        raise socket.gaierror("synthetic unresolved host")

    monkeypatch.setattr(socket, "getaddrinfo", fail_resolution)

    assert not _is_safe_url("https://unresolved.example.invalid/webhook")
