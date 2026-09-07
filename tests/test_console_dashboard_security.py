"""Security contracts for the standalone control-plane console."""

from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


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


def test_detail_severity_uses_own_key_palette_and_escaped_text() -> None:
    """Untrusted severities must not reach inherited object keys or raw HTML."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    detail_template = html.split("const rows=(s.findings||[]).map", 1)[1].split(
        "d.innerHTML=", 1
    )[0]

    assert "Object.create(null)" in html
    assert 'const severity=String(f.severity??"INFO").toUpperCase();' in detail_template
    assert 'const color=SEV[severity]||"var(--info)";' in detail_template
    assert 'style="background:${color}"' in detail_template
    assert "${esc(severity)}" in detail_template
    assert "${f.severity}" not in detail_template
