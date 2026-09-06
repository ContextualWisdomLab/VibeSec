"""Security contracts for the standalone control-plane console."""

from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


def test_console_xss_scan_id_survives_roundtrip(page) -> None:
    """A realistic DOM regression using an attacker-controlled scan id that attempts to break out of data-id."""

    # Mock the API responses
    # Use a malicious scan ID with quotes, angle brackets, and unicode
    malicious_id = '123"><img src=x onerror=alert(1)>🐉'

    # Mock window.fetch manually as page.route has issues with file:// fetch interception
    payload = f'{{"scans": [{{"id": {repr(malicious_id)}, "created_at": "2024-01-01", "deploy_blocking": 0, "new_blocking": 0, "total": 0}}]}}'
    mock_fetch = f"""
    window.fetch = async (url) => {{
        return {{
            ok: true,
            status: 200,
            json: async () => ({payload})
        }};
    }};
    """

    # Listen for alerts to ensure XSS doesn't trigger
    alert_triggered = []
    page.on("dialog", lambda dialog: alert_triggered.append(dialog.message))

    # Initialize the dashboard
    page.goto(f"file://{CONSOLE_PATH}")
    page.add_init_script(mock_fetch)
    page.evaluate(mock_fetch)
    page.evaluate('sessionStorage.setItem("ag_key", "test-key");')
    page.evaluate('load()')
    page.wait_for_selector("tr.scan")

    # The scan row should be rendered. Verify `dataset.id` securely survived the roundtrip
    scan_row = page.locator("tr.scan")
    dataset_id = scan_row.evaluate("el => el.dataset.id")

    assert dataset_id == malicious_id
    assert page.locator("img").count() == 0
    assert len(alert_triggered) == 0


def test_trend_accessibility_attributes_escape_blocking_count() -> None:
    """Untrusted scan counts must not escape innerHTML attribute values."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    trend_template = html.split('$("trend").innerHTML=', 1)[1].split(
        '$("history tbody").innerHTML=', 1
    )[0]

    assert "${s.deploy_blocking||0}" not in trend_template
    assert trend_template.count("${esc(String(s.deploy_blocking||0))}") >= 2


def test_detail_panel_close_invalidates_async_work_and_restores_focus() -> None:
    """Close controls must prevent stale detail responses from stealing focus."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert "function closeDetail()" in html
    assert "currentDetailRequest+=1;" in html
    assert "lastDetailFocus instanceof HTMLElement && lastDetailFocus.isConnected" in html
    assert 'e.key==="Escape"' in html
    assert html.count('class="close-btn" aria-label="Close details"') == 2
    assert html.count('d.querySelector(".close-btn").addEventListener("click",closeDetail);') == 2
    assert html.count("d.focus({preventScroll:true});") == 2
    assert 'aria-label="${esc(s.created_at)}: ${esc(String(s.deploy_blocking||0))} blocking"' in html
