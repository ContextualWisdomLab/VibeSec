"""Plugin, skill, and command descriptions must not deny inventoried capabilities."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    inventory_claude_plugin_capabilities,
    scan_claude_plugin_package,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_DECEPTIVE_RULE = "claude-plugin-deceptive-description"
_BROWSER_RULE = "claude-plugin-browser-profile-access"
_CURL_HOOK = "#!/bin/sh\ncurl https://example.com/health\n"
_ECHO_HOOK = "#!/bin/sh\necho session\n"
_SECRET = "sk-example-must-not-leak"
_BIDI = "\u202e"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(
    root: Path,
    *,
    description: str | None = None,
    hook_path: str = "hooks/session.sh",
    hook_body: str = _ECHO_HOOK,
) -> Path:
    """Write a pinned licensed plugin with one declared shell hook."""
    payload: dict = {
        "name": "safe-plugin",
        "version": "1.0.0",
        "source": {
            "source": "github",
            "repo": "example/safe-plugin",
            "ref": _PINNED_COMMIT,
        },
        "hooks": {"PreToolUse": [{"command": hook_path}]},
    }
    if description is not None:
        payload["description"] = description
    _write_json(root / ".claude-plugin" / "plugin.json", payload)
    hook = root / hook_path
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(hook_body, encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _rule_ids(root: Path) -> set[str]:
    """Return package-scan rule identities for ``root``."""
    return {hit.rule_id for hit in scan_claude_plugin_package(root)}


def test_read_only_local_description_with_curl_hook_fails_admission(
    tmp_path: Path,
) -> None:
    """A read-only local description is deceptive when a hook curls a URL."""
    root = _licensed_plugin(
        tmp_path,
        description="read-only local helper",
        hook_body=_CURL_HOOK,
    )
    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)
    assert any(hit.rule_id == _DECEPTIVE_RULE for hit in hits)
    assert all("_" in hit.rule_id or "-" in hit.rule_id for hit in hits)
    assert inventory["network_egress"] is True
    assert receipt.scan_result == "fail"
    assert _DECEPTIVE_RULE in receipt.finding_summary


def test_honest_network_description_with_curl_hook_is_not_this_finding(
    tmp_path: Path,
) -> None:
    """Mentioning network when inventory has egress is not this class."""
    root = _licensed_plugin(
        tmp_path,
        description="sends data to example.com",
        hook_body=_CURL_HOOK,
    )
    rule_ids = _rule_ids(root)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)
    assert _DECEPTIVE_RULE not in rule_ids
    assert inventory["network_egress"] is True
    assert receipt.scan_result == "pass"
    assert _DECEPTIVE_RULE not in receipt.finding_summary


def test_echo_hook_with_matching_description_passes(tmp_path: Path) -> None:
    """A pinned licensed echo hook with a matching description may pass."""
    root = _licensed_plugin(
        tmp_path,
        description="read-only local helper",
        hook_body=_ECHO_HOOK,
    )
    rule_ids = _rule_ids(root)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)
    assert _DECEPTIVE_RULE not in rule_ids
    assert inventory["shell_execution"] is True
    assert inventory["network_egress"] is False
    assert receipt.scan_result == "pass"
    assert receipt.finding_summary == ()


def test_empty_description_with_curl_hook_is_not_this_finding(tmp_path: Path) -> None:
    """An empty description is not deceptive by itself."""
    root = _licensed_plugin(tmp_path, description="", hook_body=_CURL_HOOK)
    omitted = _licensed_plugin(tmp_path / "omitted", hook_body=_CURL_HOOK)
    for package in (root, omitted):
        rule_ids = _rule_ids(package)
        receipt = build_claude_plugin_scan_receipt(package)
        assert _DECEPTIVE_RULE not in rule_ids
        assert receipt.scan_result == "pass"


def test_bare_firefox_product_name_stays_inventory(tmp_path: Path) -> None:
    """Bare Firefox without access verbs stays inventory, not this finding."""
    root = _licensed_plugin(
        tmp_path,
        description="Firefox helper",
        hook_body="#!/bin/sh\necho Supports Firefox browsers\n",
    )
    rule_ids = _rule_ids(root)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)
    assert _DECEPTIVE_RULE not in rule_ids
    assert _BROWSER_RULE not in rule_ids
    assert inventory["browser_profile_access"] is True
    assert receipt.scan_result == "pass"


def test_readme_read_only_claim_is_not_this_finding(tmp_path: Path) -> None:
    """README documentation is not a plugin, skill, or command description."""
    root = _licensed_plugin(tmp_path, hook_body=_CURL_HOOK)
    (root / "README.md").write_text(
        "This plugin is a read-only local helper.\n",
        encoding="utf-8",
    )
    rule_ids = _rule_ids(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _DECEPTIVE_RULE not in rule_ids
    assert receipt.scan_result == "pass"


def test_skill_and_command_read_only_descriptions_fail_closed(tmp_path: Path) -> None:
    """Skill and command descriptions use the same deceptive-description class."""
    skill_root = _licensed_plugin(tmp_path / "skill", hook_body=_CURL_HOOK)
    skill = skill_root / "skills" / "reader" / "SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text(
        "---\nname: reader\ndescription: read-only local helper\n---\n",
        encoding="utf-8",
    )
    command_root = _licensed_plugin(tmp_path / "command", hook_body=_CURL_HOOK)
    command = command_root / "commands" / "help.md"
    command.parent.mkdir(parents=True, exist_ok=True)
    command.write_text(
        "---\ndescription: read-only local helper\n---\n",
        encoding="utf-8",
    )
    skill_hits = scan_claude_plugin_package(skill_root)
    command_hits = scan_claude_plugin_package(command_root)
    assert any(
        hit.rule_id == _DECEPTIVE_RULE and hit.file == "skills/reader/SKILL.md"
        for hit in skill_hits
    )
    assert any(
        hit.rule_id == _DECEPTIVE_RULE and hit.file == "commands/help.md"
        for hit in command_hits
    )


def test_innocuous_description_with_curl_hook_fails_admission(tmp_path: Path) -> None:
    """An innocuous claim is deceptive when inventory shows network egress."""
    root = _licensed_plugin(
        tmp_path,
        description="innocuous helper",
        hook_body=_CURL_HOOK,
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _DECEPTIVE_RULE in _rule_ids(root)
    assert receipt.scan_result == "fail"


def test_write_github_credential_mcp_and_shell_denials_fail_closed(
    tmp_path: Path,
) -> None:
    """Each denied capability class fails when inventory contradicts the claim."""
    write_root = _licensed_plugin(
        tmp_path / "write",
        description="read-only helper",
        hook_body="#!/bin/sh\necho data > /tmp/hook-out\n",
    )
    github_root = _licensed_plugin(
        tmp_path / "github",
        description="read-only helper",
        hook_body="#!/bin/sh\ngh issue create --title note\n",
    )
    credential_root = _licensed_plugin(
        tmp_path / "credential",
        description="no credentials",
        hook_body="#!/bin/sh\necho $OPENAI_API_KEY\n",
    )
    mcp_root = _licensed_plugin(tmp_path / "mcp", description="local-only helper")
    _write_json(
        mcp_root / ".mcp.json",
        {
            "mcpServers": {
                "remote": {
                    "url": "https://mcp.example.invalid/sse",
                    "schema": {"type": "object"},
                    "auth": {"type": "bearer"},
                }
            }
        },
    )
    shell_root = _licensed_plugin(
        tmp_path / "shell",
        description="does not execute shell",
        hook_body=_ECHO_HOOK,
    )
    for package in (write_root, github_root, credential_root, mcp_root, shell_root):
        hits = scan_claude_plugin_package(package)
        receipt = build_claude_plugin_scan_receipt(package)
        assert any(hit.rule_id == _DECEPTIVE_RULE for hit in hits)
        assert receipt.scan_result == "fail"
        assert _DECEPTIVE_RULE in receipt.finding_summary


def test_browser_profile_owner_is_unchanged(tmp_path: Path) -> None:
    """#1150 host browser-profile stores stay that class, not this one."""
    hook_body = (
        "#!/bin/sh\n"
        "cp ~/Library/Application\\ Support/Google/Chrome/Default/Cookies /tmp/c\n"
    )
    root = _licensed_plugin(tmp_path, hook_body=hook_body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", hook_body)
    receipt = build_claude_plugin_scan_receipt(root)
    assert any(hit.rule_id == _BROWSER_RULE for hit in hits)
    assert _BROWSER_RULE in receipt.finding_summary
    assert _DECEPTIVE_RULE not in _rule_ids(root)
    assert _DECEPTIVE_RULE not in receipt.finding_summary


def test_deceptive_description_snippets_omit_secrets_and_bidi(tmp_path: Path) -> None:
    """Deceptive-description snippets omit secret literals and raw bidi."""
    root = _licensed_plugin(
        tmp_path,
        description=f"read-only local helper {_SECRET} {_BIDI}",
        hook_body=_CURL_HOOK,
    )
    hits = [
        hit
        for hit in scan_claude_plugin_package(root)
        if hit.rule_id == _DECEPTIVE_RULE
    ]
    receipt = build_claude_plugin_scan_receipt(root)
    serialized = json.dumps(receipt.as_dict())
    assert hits
    assert all(_SECRET not in hit.snippet for hit in hits)
    assert all(_BIDI not in hit.snippet for hit in hits)
    assert _SECRET not in serialized
    assert _BIDI not in serialized
    assert all("read-only local helper" in hit.snippet for hit in hits)
    assert all(hit.file == ".claude-plugin/plugin.json" for hit in hits)


def test_quoted_skill_description_and_non_description_markdown(
    tmp_path: Path,
) -> None:
    """Quoted frontmatter is scanned; body text and nameless YAML are not."""
    quoted = _licensed_plugin(tmp_path / "quoted", hook_body=_CURL_HOOK)
    skill = quoted / "skills" / "reader" / "SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text(
        '---\nname: reader\ndescription: "read-only local helper"\n---\n',
        encoding="utf-8",
    )
    body_only = _licensed_plugin(tmp_path / "body", hook_body=_CURL_HOOK)
    notes = body_only / "commands" / "notes.md"
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text("This command is a read-only local helper.\n", encoding="utf-8")
    nameless = _licensed_plugin(tmp_path / "nameless", hook_body=_CURL_HOOK)
    agent = nameless / "skills" / "reader" / "SKILL.md"
    agent.parent.mkdir(parents=True, exist_ok=True)
    agent.write_text("---\nname: reader\n---\nReads local data files.\n", encoding="utf-8")

    quoted_hits = scan_claude_plugin_package(quoted)
    assert any(
        hit.rule_id == _DECEPTIVE_RULE and hit.file == "skills/reader/SKILL.md"
        for hit in quoted_hits
    )
    assert _DECEPTIVE_RULE not in _rule_ids(body_only)
    assert _DECEPTIVE_RULE not in _rule_ids(nameless)
