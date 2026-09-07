"""Accessibility contract for dashboard metric toggle controls."""

from scanner.cli.appguardrail import dashboard_index_path


def test_metric_filter_cards_use_native_toggle_buttons():
    """Metric toggles rely on native button keyboard semantics, not ARIA emulation."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert '<button type="button" class="card"' in html
    assert 'aria-label="Filter by ${s}: ${counts[s]}"' in html
    assert 'aria-label="Filter by Deploy-blocking: ${blocking}"' in html
    assert 'aria-pressed="${isSelected}"' in html
    assert 'aria-pressed="${filterBlocking}"' in html
    assert '<div class="card" role="button"' not in html
    assert "onkeydown=\"if(event.key==='Enter'||event.key===' ')" not in html
    assert ".card{appearance:none;font:inherit;color:inherit;text-align:left;cursor:pointer;" in html
