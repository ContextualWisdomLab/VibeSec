"""Regression contract for external-reference link accessibility markup."""

import re

from scanner.cli.appguardrail import dashboard_index_path


def test_external_reference_link_preserves_visible_name_and_new_tab_notice():
    """Reference links keep the visible URL in the accessible name and announce tab context."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    refs = re.search(
        r"const refs = .*?\.map\(r=>(?P<markup>`<a .*?</a>`)\)\.join",
        html,
    )
    assert refs is not None
    markup = refs.group("markup")
    assert 'target="_blank"' in markup
    assert 'rel="noopener"' in markup
    assert 'aria-label="${esc(r)} (opens in a new tab)"' in markup
    assert '>${esc(r)}</a>' in markup
