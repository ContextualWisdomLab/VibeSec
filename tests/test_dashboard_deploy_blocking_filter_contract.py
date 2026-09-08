"""Regression contract for the deploy-blocking dashboard filter."""

from scanner.cli.appguardrail import dashboard_index_path


def test_deploy_blocking_filter_preserves_keyboard_focus_target():
    """Rerendered toggle must retain a stable target for keyboard focus."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert 'id="deploy-blocking-filter"' in html
    assert 'aria-pressed="${filterBlocking}"' in html
    assert ".filter(({f})=> (!filterBlocking || isDeployBlocking(f)))" in html
    assert "filterBlocking=false" in html
