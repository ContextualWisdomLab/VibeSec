"""Regression tests for asynchronous console detail rendering."""

from scanner.cli.appguardrail import dashboard_index_path


def _console_html() -> str:
    """Return the standalone console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def test_console_ignores_out_of_order_detail_results_and_errors():
    """Only the most recently selected scan may update the shared detail panel."""
    html = _console_html()

    assert "let currentDetailRequest=0;" in html
    assert "const requestId=++currentDetailRequest;" in html
    assert html.count("if(requestId!==currentDetailRequest)return;") == 2
    assert "tr.dataset.detailRequest=String(requestId);" in html
    assert "tr.dataset.detailRequest===String(requestId)" in html


def test_console_exposes_loading_busy_and_error_states():
    """Loading and failure states must remain perceivable to assistive technology."""
    html = _console_html()

    assert 'tr.setAttribute("aria-busy","true");' in html
    assert 'aria-live="polite" class="muted">Loading scan details...' in html
    assert 'role="alert" class="err">Error loading details:' in html
    assert 'tr.removeAttribute("aria-busy");' in html


def test_console_detail_scrolling_respects_reduced_motion():
    """Successful and failed detail requests must honor reduced-motion preferences."""
    html = _console_html()

    assert 'window.matchMedia("(prefers-reduced-motion: reduce)").matches' in html
    assert "element.scrollIntoView();" in html
    assert 'element.scrollIntoView({behavior:"smooth"});' in html
    assert html.count("scrollDetailIntoView(d);") == 2


def test_console_table_rows_block_interaction_while_busy():
    """Busy row buttons must expose disabled semantics and reject activation."""
    html = _console_html()

    assert 'tr.scan[aria-disabled="true"]{pointer-events:none' in html
    assert 'opacity:0.6' in html
    assert 'tr.setAttribute("aria-disabled","true");' in html
    assert (
        'tr.onclick=()=>{ if(tr.getAttribute("aria-disabled")==="true")return; '
        'detail(tr.dataset.id,tr); };'
    ) in html
    assert (
        "tr.addEventListener('keydown', e => { if(e.key === 'Enter' || e.key === ' ') "
        '{ e.preventDefault(); if(tr.getAttribute("aria-disabled")==="true")return; '
        'detail(tr.dataset.id,tr); } });'
    ) in html
    assert 'lastDetailFocus.removeAttribute("aria-disabled");' in html
    assert 'tr.removeAttribute("aria-disabled");' in html
