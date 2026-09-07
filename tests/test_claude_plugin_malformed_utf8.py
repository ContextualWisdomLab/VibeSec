"""Plugin manifests must reject malformed UTF-8 and invalid Unicode bytes."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    _collect_plugin_hits,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_UTF8_RULE = "claude-plugin-malformed-utf8"
_BIDI_RULE = "claude-plugin-concealed-identity"
_JSON_RULE = "claude-plugin-nonstandard-json-constant"
_SECRET = "sk-example-must-not-leak"
_BIDI = "\u202e"
_TRUNCATED_UTF8 = b"\xe2\x82"
_INVALID_CONTINUATION = b"\xc3\x28"
_LONE_SURROGATE = b"\xed\xa0\x80"
_INVALID_START = b"\x80"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


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


def _manifest_prefix() -> bytes:
    """Return the ASCII prefix of a pinned plugin.json object."""
    return (
        b"{\n"
        b'  "name": "safe-plugin",\n'
        b'  "version": "1.0.0",\n'
        b'  "source": {\n'
        b'    "source": "github",\n'
        b'    "repo": "example/safe-plugin",\n'
        + f'    "ref": "{_PINNED_COMMIT}"\n'.encode()
        + b"  },\n"
    )


def _truncated_plugin_json() -> bytes:
    """Return plugin.json bytes ending on a truncated UTF-8 sequence."""
    return (
        _manifest_prefix()
        + f'  "token": "{_SECRET}",\n'.encode()
        + b'  "description": "'
        + _TRUNCATED_UTF8
        + b'"\n}\n'
    )


def test_truncated_utf8_plugin_json_fails_admission(tmp_path: Path) -> None:
    """A truncated multibyte sequence in plugin.json must fail closed."""
    root = _licensed_plugin(tmp_path)
    payload = _truncated_plugin_json()
    (root / ".claude-plugin" / "plugin.json").write_bytes(payload)
    hits = [
        hit
        for hit in _collect_plugin_hits(root)
        if hit.rule_id == _UTF8_RULE
    ]
    receipt = build_claude_plugin_scan_receipt(root)
    assert hits
    assert receipt.scan_result == "fail"
    assert _UTF8_RULE in receipt.finding_summary
    assert all(hit.snippet == "truncated-utf8" for hit in hits)


def test_valid_korean_and_japanese_description_is_not_this_finding(
    tmp_path: Path,
) -> None:
    """Valid CJK UTF-8 is not malformed UTF-8."""
    root = _licensed_plugin(tmp_path)
    _write_json(
        root / ".claude-plugin" / "plugin.json",
        {
            "name": "safe-plugin",
            "version": "1.0.0",
            "description": "안전한 플러그인 安全なプラグイン",
            "source": {
                "source": "github",
                "repo": "example/safe-plugin",
                "ref": _PINNED_COMMIT,
            },
            "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]},
        },
    )
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"),
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert all(hit.rule_id != _UTF8_RULE for hit in hits)
    assert _UTF8_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_bidi_concealment_stays_concealment_class(tmp_path: Path) -> None:
    """Bidi overrides stay ``claude-plugin-concealed-identity``."""
    root = _licensed_plugin(tmp_path)
    body = (
        "{\n"
        f'  "name": "safe-plugin{_BIDI}",\n'
        '  "version": "1.0.0",\n'
        '  "source": {\n'
        '    "source": "github",\n'
        '    "repo": "example/safe-plugin",\n'
        f'    "ref": "{_PINNED_COMMIT}"\n'
        "  },\n"
        '  "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]}\n'
        "}\n"
    )
    (root / ".claude-plugin" / "plugin.json").write_text(body, encoding="utf-8")
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    receipt = build_claude_plugin_scan_receipt(root)
    rule_ids = {hit.rule_id for hit in hits}
    assert _BIDI_RULE in rule_ids
    assert _UTF8_RULE not in rule_ids
    assert _BIDI_RULE in receipt.finding_summary
    assert _UTF8_RULE not in receipt.finding_summary
    assert all(_BIDI not in hit.snippet for hit in hits)


def test_infinity_constant_stays_nonstandard_json_class() -> None:
    """#1153 Infinity constants stay ``claude-plugin-nonstandard-json-constant``."""
    body = (
        "{\n"
        '  "name": "safe-plugin",\n'
        '  "version": "1.0.0",\n'
        '  "timeout": Infinity,\n'
        '  "source": {\n'
        '    "source": "github",\n'
        '    "repo": "example/safe-plugin",\n'
        f'    "ref": "{_PINNED_COMMIT}"\n'
        "  }\n"
        "}\n"
    )
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _JSON_RULE in rule_ids
    assert _UTF8_RULE not in rule_ids
    assert all(hit.snippet == "Infinity" for hit in hits if hit.rule_id == _JSON_RULE)


def test_valid_utf8_invalid_json_is_not_this_finding() -> None:
    """A truncated JSON object that is valid UTF-8 is not this class."""
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        '{"name": "safe-plugin",',
    )
    assert all(hit.rule_id != _UTF8_RULE for hit in hits)


def test_invalid_utf8_start_byte_fails_admission(tmp_path: Path) -> None:
    """An illegal UTF-8 start byte in plugin.json is the same fail-closed class."""
    root = _licensed_plugin(tmp_path)
    (root / ".claude-plugin" / "plugin.json").write_bytes(
        b'{"name": "' + _INVALID_START + b'"}\n'
    )
    hits = [
        hit
        for hit in _collect_plugin_hits(root)
        if hit.rule_id == _UTF8_RULE
    ]
    receipt = build_claude_plugin_scan_receipt(root)
    assert hits
    assert all(hit.snippet == "invalid-utf8" for hit in hits)
    assert _UTF8_RULE in receipt.finding_summary
    assert receipt.scan_result == "fail"


def test_marketplace_and_mcp_invalid_utf8_fail_closed(tmp_path: Path) -> None:
    """Marketplace and MCP JSON bytes use the same malformed-UTF-8 class."""
    root = _licensed_plugin(tmp_path)
    (root / ".claude-plugin" / "marketplace.json").write_bytes(
        b'{"name": "listed", "description": "' + _INVALID_CONTINUATION + b'"}\n'
    )
    (root / ".mcp.json").write_bytes(
        b'{"mcpServers": {"demo": "' + _LONE_SURROGATE + b'"}}\n'
    )
    hits = _collect_plugin_hits(root)
    utf8_hits = [hit for hit in hits if hit.rule_id == _UTF8_RULE]
    snippets = {hit.snippet for hit in utf8_hits}
    receipt = build_claude_plugin_scan_receipt(root)
    assert len(utf8_hits) >= 2
    assert "invalid-continuation" in snippets
    assert "lone-surrogate" in snippets
    assert _UTF8_RULE in receipt.finding_summary
    assert receipt.scan_result == "fail"


def test_readme_and_hook_invalid_bytes_are_not_this_finding(tmp_path: Path) -> None:
    """README text and hook binaries are not marketplace/plugin/MCP JSON."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_bytes(b"notes " + _TRUNCATED_UTF8 + b"\n")
    (root / "hooks" / "session.sh").write_bytes(
        b"#!/bin/sh\necho " + _INVALID_START + b"\n"
    )
    hits = _collect_plugin_hits(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert all(hit.rule_id != _UTF8_RULE for hit in hits)
    assert _UTF8_RULE not in receipt.finding_summary


def test_malformed_utf8_snippets_omit_secrets_and_raw_bytes(tmp_path: Path) -> None:
    """Malformed-UTF-8 snippets are short labels and omit secrets and raw bytes."""
    root = _licensed_plugin(tmp_path)
    payload = _truncated_plugin_json()
    (root / ".claude-plugin" / "plugin.json").write_bytes(payload)
    hits = [
        hit
        for hit in _collect_plugin_hits(root)
        if hit.rule_id == _UTF8_RULE
    ]
    receipt = build_claude_plugin_scan_receipt(root)
    serialized = json.dumps(receipt.as_dict())
    assert hits
    assert all(hit.snippet == "truncated-utf8" for hit in hits)
    assert all(_SECRET not in hit.snippet for hit in hits)
    assert all(_TRUNCATED_UTF8 not in hit.snippet.encode("utf-8") for hit in hits)
    assert _SECRET not in serialized
    assert _TRUNCATED_UTF8 not in serialized.encode("utf-8")
    assert _INVALID_CONTINUATION not in serialized.encode("utf-8")
    assert _LONE_SURROGATE not in serialized.encode("utf-8")
