"""Security contracts for untrusted JSON rendered by the control-plane console."""

from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


def test_console_untrusted_json_stays_data_at_innerhtml_boundaries() -> None:
    """Untrusted scan counts and identifiers must not become HTML markup."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert '["Latest deploy-blocking",Number(latest.deploy_blocking)||0]' in html
    assert '["New since last scan",Number(latest.new_blocking)||0]' in html
    assert '["Critical",Number(c.CRITICAL)||0]' in html
    assert '<tr class="scan" data-id="${esc(s.id)}"' in html
    assert '<td>${Number(s.total)||0}</td>' in html
    assert 'pill(Number(s.deploy_blocking)||0,"var(--crit)")' in html
    assert 'pill(Number(s.new_blocking)||0,"var(--high)")' in html

    assert '["Latest deploy-blocking",latest.deploy_blocking||0]' not in html
    assert '<tr class="scan" data-id="${s.id}"' not in html
