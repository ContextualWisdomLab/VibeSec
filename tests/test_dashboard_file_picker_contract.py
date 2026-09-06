"""Contracts for the dashboard findings-file picker."""

from scanner.cli.appguardrail import dashboard_index_path


def _dashboard_html() -> str:
    return dashboard_index_path().read_text(encoding="utf-8")


def test_header_file_picker_uses_visible_native_button_proxy() -> None:
    """The header picker stays keyboard-native while the file input remains hidden."""
    html = _dashboard_html()

    assert '<input type="file" id="file" accept="application/json,.json" hidden>' in html
    assert (
        '<button type="button" id="upload-proxy" class="primary-action" '
        'style="margin-left:12px">Upload findings file</button>'
    ) in html
    assert (
        "document.getElementById('upload-proxy')?.addEventListener('click', "
        "() => fileInput.click());"
    ) in html


def test_file_picker_preserves_same_file_reselection_contract() -> None:
    """Capture the File before clearing the input so the same path can be chosen again."""
    html = _dashboard_html()

    listener = "fileInput.addEventListener('change', () => {"
    capture = "const selectedFile = fileInput.files?.[0];"
    clear = "fileInput.value = '';"
    consume = "selectedFile.text().then"

    listener_pos = html.index(listener)
    capture_pos = html.index(capture, listener_pos)
    clear_pos = html.index(clear, capture_pos)
    consume_pos = html.index(consume, clear_pos)

    assert listener_pos < capture_pos < clear_pos < consume_pos


def test_existing_empty_state_browse_actions_share_the_same_picker() -> None:
    """Unloaded and clean-report states continue to use the canonical file input."""
    html = _dashboard_html()

    assert html.count('id="browse-findings"') >= 2
    assert html.count("browseFindings.addEventListener('click', () => fileInput.click());") >= 2
