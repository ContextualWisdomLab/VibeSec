"""Hook gradle publish and luarocks upload fail closed; tasks/list stay inventory."""

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
_GRADLE_RULE = "claude-plugin-gradle-publish-command"
_LUAROCKS_RULE = "claude-plugin-luarocks-upload-command"
_CABAL_RULE = "claude-plugin-cabal-upload-command"
_SECRET = "sk-gradle-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_GRADLE_RULE, _LUAROCKS_RULE})


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


def test_hook_gradle_publish_fails_admission(tmp_path: Path) -> None:
    """``gradle publish`` on a hook is Maven-repository write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngradle publish\n")
    hits = _hits(root, _GRADLE_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "gradle publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _GRADLE_RULE in receipt.finding_summary
    assert _LUAROCKS_RULE not in receipt.finding_summary
    assert _CABAL_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_gradlew_publish_is_the_same_class() -> None:
    """``gradlew publish`` is the wrapper spelling of the Gradle publish class."""
    body = "#!/bin/sh\n./gradlew publish\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _GRADLE_RULE and hit.snippet == "gradlew publish" for hit in hits
    )


def test_hook_luarocks_upload_fails_admission(tmp_path: Path) -> None:
    """``luarocks upload`` on a hook is LuaRocks write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nluarocks upload dist/app-1.0.0-1.rockspec\n")
    hits = _hits(root, _LUAROCKS_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "luarocks upload" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _LUAROCKS_RULE in receipt.finding_summary
    assert _GRADLE_RULE not in receipt.finding_summary


def test_gradle_tasks_and_luarocks_list_stay_inventory(tmp_path: Path) -> None:
    """Read-only gradle tasks and luarocks list stay inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngradle tasks\nluarocks list\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _GRADLE_RULE) == []
    assert _hits(root, _LUAROCKS_RULE) == []
    assert receipt.scan_result == "pass"


def test_gradle_publish_to_maven_local_is_not_this_class(tmp_path: Path) -> None:
    """``gradle publishToMavenLocal`` stays a local task, not a remote publish."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngradle publishToMavenLocal\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _GRADLE_RULE) == []
    assert receipt.scan_result == "pass"


def test_cabal_and_gradle_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both cabal upload and gradle publish."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\ncabal upload dist/app-1.0.0.tar.gz\ngradle publish\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _CABAL_RULE)
    assert _hits(root, _GRADLE_RULE)
    assert receipt.scan_result == "fail"
    assert _LUAROCKS_RULE not in receipt.finding_summary


def test_cabal_upload_stays_the_cabal_class() -> None:
    """``cabal upload`` remains the Hackage class, not Gradle."""
    body = "#!/bin/sh\ncabal upload dist/app-1.0.0.tar.gz\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _CABAL_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_comment_and_echo_gradle_luarocks_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# gradle publish\necho "luarocks upload dist/app-1.0.0-1.rockspec"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _GRADLE_RULE) == []
    assert _hits(root, _LUAROCKS_RULE) == []
    assert receipt.scan_result == "pass"


def test_assignment_values_are_not_this_class() -> None:
    """An unquoted assignment value cannot turn its following word into the CLI."""
    bodies = (
        "#!/bin/sh\nmessage=gradle publish\n",
        "#!/bin/sh\ncommand=luarocks upload dist/app-1.0.0-1.rockspec\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_environment_assignment_before_real_command_still_fails() -> None:
    """Environment assignments do not hide a later executable registry write."""
    bodies = (
        "#!/bin/sh\nGRADLE_USER_HOME=/tmp gradle publish\n",
        "#!/bin/sh\nLUAROCKS_CONFIG=/tmp/config.lua luarocks upload dist/app-1.0.0-1.rockspec\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)


def test_readme_gradle_luarocks_is_not_this_class(tmp_path: Path) -> None:
    """README gradle/luarocks wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text(
        "gradle publish\nluarocks upload dist/app-1.0.0-1.rockspec\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _GRADLE_RULE) == []
    assert _hits(root, _LUAROCKS_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_echo_then_real_gradle_publish_still_fails() -> None:
    """``echo done && gradle publish`` still runs the registry write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && gradle publish\n',
    )
    assert any(
        hit.rule_id == _GRADLE_RULE and hit.snippet == "gradle publish" for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\ngradle publish -Psigning.key={_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    gradle_hits = [hit for hit in hits if hit.rule_id == _GRADLE_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert gradle_hits
    for hit in gradle_hits:
        assert hit.snippet == "gradle publish"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_luarocks_upload_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that uploads to LuaRocks is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "luarocks upload dist/app-1.0.0-1.rockspec"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _LUAROCKS_RULE)
    assert receipt.scan_result == "fail"


def test_manifest_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about gradle publish is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs gradle publish or luarocks upload."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _GRADLE_RULE) == []
    assert _hits(root, _LUAROCKS_RULE) == []
    assert receipt.scan_result == "pass"
