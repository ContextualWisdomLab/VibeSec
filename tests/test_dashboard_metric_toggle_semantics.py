"""Accessibility contract for the deploy-blocking metric toggle."""

from scanner.cli.appguardrail import dashboard_index_path


def test_deploy_blocking_filter_uses_native_toggle_button():
    """The new filter uses native button semantics instead of emulating a button on a div."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert (
        '<button type="button" class="card" '
        'aria-label="Filter by Deploy-blocking: ${blocking}" '
        'aria-pressed="${filterBlocking}"' in html
    )
    assert 'filterBlocking = !filterBlocking; render();' in html
    assert 'Deploy-blocking</div><div class="n">${blocking}</div></button>' in html
    assert (
        '<div class="card" role="button" tabindex="0" '
        'aria-label="Filter by Deploy-blocking: ${blocking}"' not in html
    )
