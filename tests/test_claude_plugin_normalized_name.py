"""Plugin identity names must match their NFC form."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_NFC_RULE = "claude-plugin-inconsistent-normalized-name"
_UTF8_RULE = "claude-plugin-malformed-utf8"
_JSON_RULE = "claude-plugin-nonstandard-json-constant"
_CONCEAL_RULE = "claude-plugin-concealed-identity"
_NFC_NAME = "caf\u00e9"
_NFD_NAME = "cafe\u0301"
_SECRET = "sk-example-must-not-leak"
_BIDI = "\u202e"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path`` using NFC-preserving UTF-8."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _licensed_plugin(root: Path, *, name: str = "safe-plugin") -> Path:
    """Write a pinned licensed plugin with one declared shell hook."""
    _write_json(
        root / ".claude-plugin" / "plugin.json",
        {
            "name": name,
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


def test_nfd_plugin_name_fails_admission(tmp_path: Path) -> None:
    """A combining-mark plugin name is not NFC and must fail closed."""
    root = _licensed_plugin(tmp_path, name=_NFD_NAME)
    body = (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert any(hit.rule_id == _NFC_RULE for hit in hits)
    assert receipt.scan_result == "fail"
    assert _NFC_RULE in receipt.finding_summary


def test_nfc_plugin_name_is_not_this_finding(tmp_path: Path) -> None:
    """A precomposed accented name is already NFC."""
    root = _licensed_plugin(tmp_path, name=_NFC_NAME)
    body = (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert all(hit.rule_id != _NFC_RULE for hit in hits)
    assert _NFC_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_hangul_composed_name_is_not_this_finding(tmp_path: Path) -> None:
    """Korean Hangul syllables are NFC and stay admitted."""
    root = _licensed_plugin(tmp_path, name="가드")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _NFC_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_marketplace_nfd_plugin_entry_is_reported() -> None:
    """Marketplace plugin entries use the same NFC identity contract."""
    body = json.dumps(
        {
            "plugins": [
                {
                    "name": _NFD_NAME,
                    "source": {"ref": _PINNED_COMMIT},
                }
            ]
        },
        ensure_ascii=False,
    )
    hits = inspect_claude_plugin_file(
        "marketplace.json",
        ".claude-plugin/marketplace.json",
        body,
    )
    assert any(hit.rule_id == _NFC_RULE for hit in hits)


def test_ascii_name_is_not_this_finding() -> None:
    """ASCII plugin names are already NFC."""
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        json.dumps({"name": "safe-plugin", "version": "1.0.0"}),
    )
    assert all(hit.rule_id != _NFC_RULE for hit in hits)


def test_malformed_utf8_owner_is_unchanged() -> None:
    """#1154 invalid UTF-8 stays that class, not this NFC class."""
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        "{\n  \"name\": \"\udcff\"\n}\n",
    )
    # The inspect path takes str; truncated UTF-8 is a bytes-only #1154 case.
    # A replacement-character name is NFC and is not this finding.
    assert all(hit.rule_id != _NFC_RULE for hit in hits)


def test_infinity_stays_nonstandard_json_class() -> None:
    """#1153 Infinity stays the JSON-constant class."""
    body = (
        "{\n"
        '  "name": "safe-plugin",\n'
        '  "timeout": Infinity\n'
        "}\n"
    )
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _JSON_RULE in rule_ids
    assert _NFC_RULE not in rule_ids


def test_bidi_stays_concealment_class() -> None:
    """Bidi marks stay `claude-plugin-concealed-identity`."""
    body = json.dumps({"name": f"safe{_BIDI}plugin"}, ensure_ascii=False)
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _CONCEAL_RULE in rule_ids
    assert _NFC_RULE not in rule_ids


def test_readme_nfd_is_not_a_manifest_finding() -> None:
    """README text is not a plugin identity surface."""
    hits = inspect_claude_plugin_file(
        "README.md",
        "README.md",
        f"name: {_NFD_NAME}\n",
    )
    assert all(hit.rule_id != _NFC_RULE for hit in hits)


def test_normalized_name_snippets_omit_secrets_and_bidi(tmp_path: Path) -> None:
    """NFC-mismatch snippets omit secret literals, bidi, and raw combining marks."""
    root = _licensed_plugin(tmp_path, name=_NFD_NAME)
    payload = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    payload["token"] = _SECRET
    _write_json(root / ".claude-plugin" / "plugin.json", payload)
    body = (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    hits = [
        hit
        for hit in inspect_claude_plugin_file(
            "plugin.json",
            ".claude-plugin/plugin.json",
            body,
        )
        if hit.rule_id == _NFC_RULE
    ]
    receipt = build_claude_plugin_scan_receipt(root)
    serialized = json.dumps(receipt.as_dict())
    assert hits
    assert all(_SECRET not in hit.snippet for hit in hits)
    assert all(_BIDI not in hit.snippet for hit in hits)
    assert all("\u0301" not in hit.snippet for hit in hits)
    assert all(hit.snippet == "name" for hit in hits)
    assert _SECRET not in serialized
    assert _NFC_RULE in receipt.finding_summary
