"""Security contracts for the standalone control-plane console."""

import os
from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


def _capture_browser_evidence(page, scene: str) -> None:
    """Persist exact hostile-rendering scenes only when CI requests evidence."""
    evidence_dir = os.environ.get("APPGUARDRAIL_UI_EVIDENCE_DIR", "").strip()
    if not evidence_dir:
        return

    target = Path(evidence_dir)
    target.mkdir(parents=True, exist_ok=True)
    original_viewport = page.viewport_size
    try:
        for label, width, height in (
            ("desktop", 1280, 800),
            ("mobile", 390, 844),
        ):
            page.set_viewport_size({"width": width, "height": height})
            layout = page.evaluate(
                """() => ({
                  viewport: window.innerWidth,
                  document: document.documentElement.scrollWidth,
                })"""
            )
            assert layout["document"] <= layout["viewport"], (
                f"{scene} horizontally overflows {label}: "
                f"document={layout['document']} viewport={layout['viewport']}"
            )
            page.screenshot(
                path=str(target / f"dashboard-hostile-{scene}-{label}.png"),
                full_page=True,
            )
    finally:
        if original_viewport is not None:
            page.set_viewport_size(original_viewport)


def test_untrusted_dashboard_payloads_render_as_data(page) -> None:
    """Hostile list/detail fields stay data and inherited severity keys use INFO."""
    markup = '<img src=x onerror=alert("xss")>'
    scan_id = '123">' + markup
    scans = {
        "scans": [
            {
                "id": scan_id,
                "created_at": markup,
                "repo": markup,
                "commit": markup,
                "deploy_blocking": "1e309",
                "new_blocking": -1,
                "total": "12px",
                "severity_counts": {"CRITICAL": 1.5},
            }
        ]
    }
    detail = {
        "id": scan_id,
        "created_at": markup,
        "repo": markup,
        "findings": [
            {
                "severity": "constructor",
                "rule_id": markup,
                "message": markup,
                "file": markup,
                "line": markup,
            }
        ],
    }
    dialogs = []

    def record_dialog(dialog) -> None:
        dialogs.append(dialog.message)
        dialog.dismiss()

    page.on("dialog", record_dialog)
    page.goto(f"file://{CONSOLE_PATH}")
    page.evaluate(
        """([listPayload, detailPayload]) => {
          window.fetch = async (url) => ({
            ok: true,
            status: 200,
            json: async () => String(url).endsWith("/api/v1/scans")
              ? listPayload
              : detailPayload,
          });
        }""",
        [scans, detail],
    )
    page.evaluate('sessionStorage.setItem("ag_key", "test-key")')
    page.evaluate("load()")

    scan_row = page.locator("tr.scan")
    scan_row.wait_for()
    assert scan_row.evaluate("element => element.dataset.id") == scan_id
    assert page.locator("img").count() == 0
    assert page.locator("#stats .n").all_text_contents() == ["0", "0", "0", "1"]
    assert scan_row.locator("td").all_text_contents()[-3:] == ["0", "0", "0"]
    _capture_browser_evidence(page, "list")

    scan_row.click()
    detail_panel = page.locator("#detail:not(.hidden)")
    detail_panel.wait_for()
    assert detail_panel.locator("img").count() == 0
    assert markup in detail_panel.text_content()
    assert detail_panel.locator(".pill").evaluate(
        "element => element.style.background"
    ) == "var(--info)"
    assert dialogs == []
    _capture_browser_evidence(page, "detail")

    detail_panel.locator(".close-btn").click()
    assert detail_panel.is_hidden()
    assert scan_row.evaluate("element => element === document.activeElement")

    scan_row.press("Enter")
    detail_panel.wait_for()
    page.keyboard.press("Escape")
    assert detail_panel.is_hidden()
    assert scan_row.evaluate("element => element === document.activeElement")


def test_trend_accessibility_attributes_escape_blocking_count() -> None:
    """Untrusted scan counts must not escape innerHTML attribute values."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    trend_template = html.split('$("#trend").innerHTML=', 1)[1].split(
        '$("#history tbody").innerHTML=', 1
    )[0]

    assert "${s.deploy_blocking||0}" not in trend_template
    assert trend_template.count("${db} blocking") >= 2


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
    assert 'aria-label="${esc(s.created_at)}: ${db} blocking"' in html


def test_untrusted_scan_fields_use_typed_and_owned_rendering_boundaries() -> None:
    """Counts, row identities, and severity keys must stay data at innerHTML sinks."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert "function count(n){const v=Number(n);return Number.isSafeInteger(v)&&v>=0?v:0;}" in html
    assert "parseInt(n,10)" not in html
    assert '["Latest deploy-blocking",count(latest.deploy_blocking)]' in html
    assert '["New since last scan",count(latest.new_blocking)]' in html
    assert '["Critical",count(c.CRITICAL)]' in html
    assert '<tr class="scan" data-id="${esc(s.id)}"' in html
    assert '<td>${count(s.total)}</td>' in html
    assert 'pill(count(s.deploy_blocking),"var(--crit)")' in html
    assert 'pill(count(s.new_blocking),"var(--high)")' in html
    assert "const severityKey=String(f.severity).toUpperCase()" in html
    assert "Object.hasOwn(SEV,severityKey)?SEV[severityKey]:'var(--info)'" in html

    assert '["Latest deploy-blocking",latest.deploy_blocking||0]' not in html
    assert '<tr class="scan" data-id="${s.id}"' not in html
    assert "SEV[String(f.severity).toUpperCase()]" not in html
