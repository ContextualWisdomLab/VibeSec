"""Regression contracts for hostless HTTP(S) URL admission."""

import pytest

from appguardrail_core.controlplane import _is_safe_url as controlplane_is_safe_url
from scanner.cli.appguardrail import _is_safe_url as cli_is_safe_url


@pytest.mark.parametrize(
    "validator",
    [controlplane_is_safe_url, cli_is_safe_url],
    ids=["controlplane", "cli"],
)
@pytest.mark.parametrize(
    "url",
    ["http://", "https://", "http://user@", "https://user@"],
)
def test_hostless_http_authority_fails_closed(validator, url):
    """A supported scheme is insufficient when the authority has no hostname."""
    assert validator(url) is False
