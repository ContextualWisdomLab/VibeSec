"""Regression contract for the dashboard header findings-file picker proxy."""

from scanner.cli.appguardrail import dashboard_index_path


def test_header_upload_proxy_preserves_native_file_input_contract():
    """Visible button activation delegates to the hidden native picker boundary."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert '<input type="file" id="file" accept="application/json,.json" hidden>' in html
    assert (
        '<button type="button" id="header-browse-findings" class="primary-action" '
        'style="margin-left:12px">Upload findings file</button>' in html
    )
    assert "const headerBrowseFindings = document.getElementById('header-browse-findings');" in html
    assert "const fileInput = document.getElementById('file');" in html
    assert "headerBrowseFindings.addEventListener('click', () => fileInput.click());" in html
    assert "const selectedFile = fileInput.files?.[0];" in html
    assert "fileInput.value = '';" in html
    assert "if(!selectedFile) return;" in html
