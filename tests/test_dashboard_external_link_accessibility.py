"""Regression contract for external-reference link naming in the dashboard."""

from scanner.cli.appguardrail import dashboard_index_path


def _dashboard_html() -> str:
    """Return the shipped dashboard source as UTF-8 text."""
    return dashboard_index_path().read_text(encoding="utf-8")


def test_external_reference_warning_extends_visible_link_name() -> None:
    """The new-tab warning must augment, not replace, the visible URL name."""
    html = _dashboard_html()

    assert 'aria-label="${esc(r)} (opens in a new tab)"' not in html
    assert (
        'target="_blank" rel="noopener">${esc(r)} <span class="sr-only">(opens in a new tab)</span></a>'
    ) in html
