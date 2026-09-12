"""Duplicate Claude plugin invocation identities must fail closed."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    scan_claude_plugin_package,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_CONFLICT_RULE = "claude-plugin-conflicting-identity"
_NFC_RULE = "claude-plugin-inconsistent-normalized-name"
_SCOPE_RULE = "claude-plugin-vendored-scope-undeclared"
_SECRET = "sk-example-must-not-leak"
_BIDI = "\u202e"
_NFD_NAME = "cafe\u0301"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_skill(path: Path, name: str) -> None:
    """Write one skill Markdown file with a YAML display/invocation name."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nname: {name}\ndescription: helper\n---\n# {name}\n",
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
            "hooks": {"PreToolUse": [{"command": "hooks/pre.sh"}]},
        },
    )
    hook = root / "hooks" / "pre.sh"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho session\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def test_two_skills_with_the_same_name_fail_admission(tmp_path: Path) -> None:
    """Two plugin skills with one effective command name collide."""
    root = _licensed_plugin(tmp_path)
    _write_skill(root / "skills" / "alpha" / "SKILL.md", "helper")
    _write_skill(root / "skills" / "beta" / "SKILL.md", "helper")
    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert any(hit.rule_id == _CONFLICT_RULE for hit in hits)
    assert receipt.scan_result == "fail"
    assert _CONFLICT_RULE in receipt.finding_summary


def test_skill_and_legacy_command_with_same_invocation_fail(tmp_path: Path) -> None:
    """Skills and legacy command files share the plugin skill command surface."""
    root = _licensed_plugin(tmp_path)
    _write_skill(root / "skills" / "alpha" / "SKILL.md", "ship")
    command = root / "commands" / "ship.md"
    command.parent.mkdir(parents=True)
    command.write_text("---\ndescription: ship helper\n---\nship\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE in receipt.finding_summary
    assert receipt.scan_result == "fail"


def test_command_frontmatter_name_does_not_mint_command_identity(tmp_path: Path) -> None:
    """Legacy commands are invoked by path, not unsupported ``name`` metadata."""
    root = _licensed_plugin(tmp_path)
    _write_skill(root / "commands" / "one.md", "ship")
    _write_skill(root / "commands" / "two.md", "ship")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_plugin_namespace_may_match_local_skill_name(tmp_path: Path) -> None:
    """Plugin identity is a namespace prefix, not the local skill identity."""
    root = _licensed_plugin(tmp_path, name="helper")
    _write_skill(root / "skills" / "alpha" / "SKILL.md", "helper")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_marketplace_duplicate_plugin_names_are_reported() -> None:
    """Two marketplace entries with the same NFC name fail closed."""
    body = json.dumps(
        {
            "plugins": [
                {"name": "helper", "source": {"ref": _PINNED_COMMIT}},
                {"name": "helper", "source": {"ref": _PINNED_COMMIT}},
            ]
        }
    )
    hits = inspect_claude_plugin_file(
        "marketplace.json",
        ".claude-plugin/marketplace.json",
        body,
    )
    assert any(hit.rule_id == _CONFLICT_RULE for hit in hits)


def test_unique_plugin_and_skill_names_pass(tmp_path: Path) -> None:
    """Distinct NFC names are not this class."""
    root = _licensed_plugin(tmp_path, name="safe-plugin")
    _write_skill(root / "skills" / "alpha" / "SKILL.md", "reader")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_nfd_name_stays_normalized_name_class(tmp_path: Path) -> None:
    """#1155 non-NFC names stay that class, not a conflict."""
    root = _licensed_plugin(tmp_path, name=_NFD_NAME)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _NFC_RULE in receipt.finding_summary
    assert _CONFLICT_RULE not in receipt.finding_summary


def test_vendored_scope_owner_is_unchanged(tmp_path: Path) -> None:
    """#1156 undeclared vendor copies stay the scope class."""
    root = _licensed_plugin(tmp_path)
    vendor = root / "vendor" / "leftpad.js"
    vendor.parent.mkdir()
    vendor.write_text("module.exports = 1;\n", encoding="utf-8")
    rule_ids = {hit.rule_id for hit in scan_claude_plugin_package(root)}
    assert _SCOPE_RULE in rule_ids
    assert _CONFLICT_RULE not in rule_ids


def test_marketplace_package_duplicate_names_fail(tmp_path: Path) -> None:
    """A marketplace-only tree with two same-named plugins fails closed."""
    _write_json(
        tmp_path / ".claude-plugin" / "marketplace.json",
        {
            "plugins": [
                {"name": "helper", "source": {"ref": _PINNED_COMMIT}},
                {"name": "helper", "source": {"ref": _PINNED_COMMIT}},
            ]
        },
    )
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    hits = scan_claude_plugin_package(tmp_path)
    assert any(hit.rule_id == _CONFLICT_RULE for hit in hits)


def test_skill_json_name_may_match_plugin_namespace(tmp_path: Path) -> None:
    """Legacy skill metadata stays inside the plugin namespace."""
    root = _licensed_plugin(tmp_path, name="helper")
    _write_json(root / "skills" / "alpha" / "skill.json", {"name": "helper"})
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE not in receipt.finding_summary


def test_agent_name_is_separate_from_skill_invocation_name(tmp_path: Path) -> None:
    """Agent and skill components use separate invocation surfaces."""
    root = _licensed_plugin(tmp_path)
    _write_skill(root / "skills" / "alpha" / "SKILL.md", "helper")
    _write_skill(root / "agents" / "helper.md", "helper")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_invalid_skill_json_is_not_an_identity(tmp_path: Path) -> None:
    """Malformed or non-object skill.json files do not mint identities."""
    root = _licensed_plugin(tmp_path)
    broken = root / "skills" / "alpha" / "skill.json"
    broken.parent.mkdir(parents=True)
    broken.write_text("[1, 2]\n", encoding="utf-8")
    (root / "skills" / "beta" / "skill.json").parent.mkdir(parents=True)
    (root / "skills" / "beta" / "skill.json").write_text("{not-json\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_non_utf8_skill_json_is_not_an_identity(tmp_path: Path) -> None:
    """Unreadable skill.json bytes do not mint an identity name."""
    root = _licensed_plugin(tmp_path)
    path = root / "skills" / "alpha" / "skill.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xff\xfe{")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE not in receipt.finding_summary


def test_block_scalar_skill_name_is_not_an_identity(tmp_path: Path) -> None:
    """A YAML block-scalar name is empty, not a colliding identity."""
    root = _licensed_plugin(tmp_path, name="helper")
    skill = root / "skills" / "alpha" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: |\n  helper\n---\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _CONFLICT_RULE not in receipt.finding_summary


def test_conflicting_identity_snippets_omit_secrets_and_bidi(
    tmp_path: Path,
) -> None:
    """Conflict snippets omit secret literals, bidi, and raw names."""
    root = _licensed_plugin(tmp_path)
    _write_skill(root / "skills" / "alpha" / "SKILL.md", "helper")
    secret_skill = root / "skills" / "beta" / "SKILL.md"
    secret_skill.parent.mkdir(parents=True)
    secret_skill.write_text(
        f"---\nname: helper\ndescription: {_SECRET}{_BIDI}\n---\n",
        encoding="utf-8",
    )
    hits = [
        hit
        for hit in scan_claude_plugin_package(root)
        if hit.rule_id == _CONFLICT_RULE
    ]
    receipt = build_claude_plugin_scan_receipt(root)
    serialized = json.dumps(receipt.as_dict())
    assert hits
    assert all(hit.snippet == "name" for hit in hits)
    assert all(_SECRET not in hit.snippet for hit in hits)
    assert all(_BIDI not in hit.snippet for hit in hits)
    assert _SECRET not in serialized
    assert _BIDI not in serialized
