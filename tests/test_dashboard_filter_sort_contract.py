"""Regression contracts for dashboard filtering and severity ordering."""

import re

from scanner.cli.appguardrail import dashboard_index_path


def test_missing_severity_keeps_legacy_filter_and_sort_behavior():
    """A performance refactor must not silently normalize missing severity values."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    filter_body = re.search(
        r"const filtered = \[\];(?P<body>.*?)filtered\.sort",
        html,
        flags=re.DOTALL,
    )
    assert filter_body is not None
    assert "const sev = String(f.severity).toUpperCase();" in filter_body.group("body")

    comparator = re.search(
        r"filtered\.sort\(\(a, b\) => \{(?P<body>.*?)\n  \}\);",
        html,
        flags=re.DOTALL,
    )
    assert comparator is not None
    assert comparator.group("body").count("String(a.f.severity).toUpperCase()") == 1
    assert comparator.group("body").count("String(b.f.severity).toUpperCase()") == 1
