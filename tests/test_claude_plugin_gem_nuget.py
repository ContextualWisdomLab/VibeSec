"""Hook gem push and nuget push fail closed; list stays inventory."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    _collect_plugin_hits,
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    inventory_claude_plugin_capabilities,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_GEM_RULE = "claude-plugin-gem-push-command"
_NUGET_RULE = "claude-plugin-nuget-push-command"
_PNPM_RULE = "claude-plugin-pnpm-publish-command"
_SECRET = "sk-gem-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_GEM_RULE, _NUGET_RULE})


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(root: Path, hook_body: str = "#!/bin/sh\necho hello\n") -> Path:
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
    hook.write_text(hook_body, encoding="utf-8")
    hook.chmod(0o755)
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _hits(root: Path, rule_id: str):
    """Return receipt-path hits for one rule identity."""
    return [hit for hit in _collect_plugin_hits(root) if hit.rule_id == rule_id]


def test_hook_gem_push_fails_admission(tmp_path: Path) -> None:
    """``gem push`` on a hook is RubyGems write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngem push pkg/app-1.0.0.gem\n")
    hits = _hits(root, _GEM_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "gem push" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _GEM_RULE in receipt.finding_summary
    assert _NUGET_RULE not in receipt.finding_summary
    assert _PNPM_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_hook_nuget_push_fails_admission(tmp_path: Path) -> None:
    """``nuget push`` on a hook is NuGet write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nnuget push app.nupkg -Source nuget.org\n")
    hits = _hits(root, _NUGET_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "nuget push" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _NUGET_RULE in receipt.finding_summary
    assert _GEM_RULE not in receipt.finding_summary


def test_dotnet_nuget_push_is_the_same_class() -> None:
    """``dotnet nuget push`` canonicalizes to the nuget-push command label."""
    body = "#!/bin/sh\ndotnet nuget push app.nupkg --source nuget.org\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _NUGET_RULE and hit.snippet == "nuget push" for hit in hits
    )


def test_gem_list_and_nuget_list_stay_inventory(tmp_path: Path) -> None:
    """Read-only gem/nuget list commands stay inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngem list\nnuget list\n")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_comment_and_echo_push_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable pushes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# gem push app.gem\necho "nuget push app.nupkg"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_readme_gem_push_is_not_this_class(tmp_path: Path) -> None:
    """README gem-push wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("gem push pkg/app-1.0.0.gem\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _GEM_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_gem_and_nuget_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both gem push and nuget push."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\ngem push app.gem\nnuget push app.nupkg\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _GEM_RULE)
    assert _hits(root, _NUGET_RULE)
    assert receipt.scan_result == "fail"
    assert _PNPM_RULE not in receipt.finding_summary


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\ngem push app.gem --key {_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    gem_hits = [hit for hit in hits if hit.rule_id == _GEM_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert gem_hits
    for hit in gem_hits:
        assert hit.snippet == "gem push"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_nuget_push_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that pushes nupkg is the nuget class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "nuget push app.nupkg -Source nuget.org"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _NUGET_RULE)
    assert receipt.scan_result == "fail"


def test_pnpm_publish_without_gem_stays_the_pnpm_class() -> None:
    """pnpm publish without gem/nuget stays the pnpm class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\npnpm publish --access public\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _PNPM_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_manifest_description_gem_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about gem push is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs gem push against rubygems.org."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"
