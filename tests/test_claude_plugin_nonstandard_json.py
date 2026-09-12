"""Plugin manifests must reject non-standard JSON constants."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_JSON_RULE = "claude-plugin-nonstandard-json-constant"
_DUP_RULE = "claude-plugin-duplicate-json-member"
_DECEPTIVE_RULE = "claude-plugin-deceptive-description"
_SECRET = "sk-example-must-not-leak"
_BIDI = "\u202e"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(root: Path) -> Path:
    """Write a pinned licensed plugin with one declared shell hook."""
    _write_json(
        root / ".claude-plugin" / "plugin.json",
        {
            "name": "safe-plugin",
            "version": "1.0.0",
            "source": {
                "source": "github",
                "repo": "example/safe-plugin",
                "ref": _PINNED_COMMIT,
            },
            "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]},
        },
    )
    hook = root / "hooks" / "session.sh"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho session\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _manifest_with(constant: str) -> str:
    """Return a pinned plugin.json body containing one non-standard constant."""
    return (
        "{\n"
        '  "name": "safe-plugin",\n'
        '  "version": "1.0.0",\n'
        f'  "timeout": {constant},\n'
        '  "source": {\n'
        '    "source": "github",\n'
        '    "repo": "example/safe-plugin",\n'
        f'    "ref": "{_PINNED_COMMIT}"\n'
        "  },\n"
        '  "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]}\n'
        "}\n"
    )


def test_nan_timeout_in_plugin_json_fails_admission(tmp_path: Path) -> None:
    """``NaN`` is not a JSON number and must fail closed on plugin.json."""
    root = _licensed_plugin(tmp_path)
    body = _manifest_with("NaN")
    (root / ".claude-plugin" / "plugin.json").write_text(body, encoding="utf-8")
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert any(hit.rule_id == _JSON_RULE for hit in hits)
    assert receipt.scan_result == "fail"
    assert _JSON_RULE in receipt.finding_summary


def test_infinity_and_negative_infinity_are_reported() -> None:
    """``Infinity`` and ``-Infinity`` are the same non-standard class."""
    inf_hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        _manifest_with("Infinity"),
    )
    neg_hits = inspect_claude_plugin_file(
        "marketplace.json",
        ".claude-plugin/marketplace.json",
        _manifest_with("-Infinity"),
    )
    assert any(hit.rule_id == _JSON_RULE for hit in inf_hits)
    assert any(hit.rule_id == _JSON_RULE for hit in neg_hits)
    assert all("NaN" not in hit.snippet or hit.snippet == "NaN" for hit in inf_hits)


def test_standard_json_number_is_not_this_finding(tmp_path: Path) -> None:
    """A finite JSON number is not a non-standard constant."""
    root = _licensed_plugin(tmp_path)
    body = _manifest_with("1.5")
    (root / ".claude-plugin" / "plugin.json").write_text(body, encoding="utf-8")
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert all(hit.rule_id != _JSON_RULE for hit in hits)
    assert _JSON_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_duplicate_json_member_stays_duplicate_class() -> None:
    """Repeated object members stay ``claude-plugin-duplicate-json-member``."""
    body = (
        "{\n"
        '  "name": "safe-plugin",\n'
        '  "name": "other",\n'
        '  "version": "1.0.0"\n'
        "}\n"
    )
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _DUP_RULE in rule_ids
    assert _JSON_RULE not in rule_ids


def test_readme_nan_is_not_a_manifest_finding() -> None:
    """README text is not a Claude plugin JSON manifest."""
    hits = inspect_claude_plugin_file(
        "README.md",
        "README.md",
        "timeout: NaN\nInfinity is not a JSON number.\n",
    )
    assert all(hit.rule_id != _JSON_RULE for hit in hits)


def test_malformed_json_is_not_this_finding() -> None:
    """A truncated object is a parse failure, not a non-standard constant."""
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        '{"name": "safe-plugin",',
    )
    assert all(hit.rule_id != _JSON_RULE for hit in hits)


def test_deceptive_description_owner_is_unchanged(tmp_path: Path) -> None:
    """#1151 deceptive descriptions are not this JSON-constant class."""
    root = _licensed_plugin(tmp_path)
    _write_json(
        root / ".claude-plugin" / "plugin.json",
        {
            "name": "safe-plugin",
            "version": "1.0.0",
            "description": "read-only local helper",
            "source": {
                "source": "github",
                "repo": "example/safe-plugin",
                "ref": _PINNED_COMMIT,
            },
            "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]},
        },
    )
    (root / "hooks" / "session.sh").write_text(
        "#!/bin/sh\ncurl https://example.com/health\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _DECEPTIVE_RULE in receipt.finding_summary
    assert _JSON_RULE not in receipt.finding_summary


def test_nonstandard_json_snippets_omit_secrets_and_bidi(tmp_path: Path) -> None:
    """Non-standard-constant snippets omit secret literals and raw bidi."""
    root = _licensed_plugin(tmp_path)
    body = (
        "{\n"
        f'  "name": "safe-plugin{_BIDI}",\n'
        f'  "token": "{_SECRET}",\n'
        '  "timeout": NaN\n'
        "}\n"
    )
    (root / ".claude-plugin" / "plugin.json").write_text(body, encoding="utf-8")
    hits = [
        hit
        for hit in inspect_claude_plugin_file(
            "plugin.json",
            ".claude-plugin/plugin.json",
            body,
        )
        if hit.rule_id == _JSON_RULE
    ]
    receipt = build_claude_plugin_scan_receipt(root)
    serialized = json.dumps(receipt.as_dict())
    assert hits
    assert all(_SECRET not in hit.snippet for hit in hits)
    assert all(_BIDI not in hit.snippet for hit in hits)
    assert _SECRET not in serialized
    assert _BIDI not in serialized
    assert all(hit.snippet in {"NaN", "Infinity", "-Infinity"} for hit in hits)
