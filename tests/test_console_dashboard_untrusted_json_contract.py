"""Security contracts for untrusted JSON rendered by the control-plane console."""

from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


def test_console_untrusted_json_stays_data_at_innerhtml_boundaries() -> None:
    """Untrusted scan fields must not become markup or inherited palette authority."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert '["Latest deploy-blocking",Number(latest.deploy_blocking)||0]' in html
    assert '["New since last scan",Number(latest.new_blocking)||0]' in html
    assert '<tr class="scan" data-id="${esc(s.id)}"' in html
    assert "Object.hasOwn(SEV,severityKey)" in html
    assert "SEV[String(f.severity).toUpperCase()]" not in html
