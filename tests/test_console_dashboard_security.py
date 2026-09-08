"""Security contracts for the standalone control-plane console."""

from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


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
                "deploy_blocking": markup,
                "new_blocking": markup,
                "total": markup,
                "severity_counts": {"CRITICAL": markup},
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

    scan_row.click()
    detail_panel = page.locator("#detail:not(.hidden)")
    detail_panel.wait_for()
    assert detail_panel.locator("img").count() == 0
    assert markup in detail_panel.text_content()
    assert detail_panel.locator(".pill").get_attribute("style") == (
        "background:var(--info)"
    )
    assert dialogs == []


def test_trend_accessibility_attributes_escape_blocking_count() -> None:
    """Untrusted scan counts must not escape innerHTML attribute values."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    trend_template = html.split('$("#trend").innerHTML=', 1)[1].split(
        '$("#history tbody").innerHTML=', 1
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


def test_untrusted_scan_fields_use_typed_and_owned_rendering_boundaries() -> None:
    """Counts, row identities, and severity keys must stay data at innerHTML sinks."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert '["Latest deploy-blocking",Number(latest.deploy_blocking)||0]' in html
    assert '["New since last scan",Number(latest.new_blocking)||0]' in html
    assert '["Critical",Number(c.CRITICAL)||0]' in html
    assert '<tr class="scan" data-id="${esc(s.id)}"' in html
    assert '<td>${Number(s.total)||0}</td>' in html
    assert 'pill(Number(s.deploy_blocking)||0,"var(--crit)")' in html
    assert 'pill(Number(s.new_blocking)||0,"var(--high)")' in html
    assert "const severityKey=String(f.severity).toUpperCase()" in html
    assert "Object.hasOwn(SEV,severityKey)?SEV[severityKey]:'var(--info)'" in html

    assert '["Latest deploy-blocking",latest.deploy_blocking||0]' not in html
    assert '<tr class="scan" data-id="${s.id}"' not in html
    assert "SEV[String(f.severity).toUpperCase()]" not in html
