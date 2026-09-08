"""Hook dart/flutter pub publish fail closed; pub get stays inventory."""

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
_PUB_RULE = "claude-plugin-pub-publish-command"
_GEM_RULE = "claude-plugin-gem-push-command"
_PNPM_RULE = "claude-plugin-pnpm-publish-command"
_SECRET = "sk-pub-must-not-leak"
_BIDI = "\u202e"


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


def test_hook_dart_pub_publish_fails_admission(tmp_path: Path) -> None:
    """``dart pub publish`` on a hook is pub.dev write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ndart pub publish --force\n")
    hits = _hits(root, _PUB_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "dart pub publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _PUB_RULE in receipt.finding_summary
    assert _GEM_RULE not in receipt.finding_summary
    assert _PNPM_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_hook_flutter_pub_publish_fails_admission() -> None:
    """``flutter pub publish`` is the same pub.dev class."""
    body = "#!/bin/sh\nflutter pub publish\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _PUB_RULE and hit.snippet == "flutter pub publish" for hit in hits
    )


def test_legacy_pub_publish_fails_admission() -> None:
    """Bare ``pub publish`` is the Dart SDK spelling of the same class."""
    body = "#!/bin/sh\npub publish --force\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _PUB_RULE and hit.snippet == "pub publish" for hit in hits)


def test_pub_get_stays_inventory(tmp_path: Path) -> None:
    """``dart pub get`` stays inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ndart pub get\nflutter pub get\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _PUB_RULE) == []
    assert receipt.scan_result == "pass"


def test_pnpm_publish_stays_the_pnpm_class() -> None:
    """``pnpm publish`` remains the pnpm class, not pub.dev."""
    body = "#!/bin/sh\npnpm publish --access public\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _PNPM_RULE in rule_ids
    assert _PUB_RULE not in rule_ids


def test_comment_and_echo_pub_publish_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# dart pub publish\necho "flutter pub publish"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _PUB_RULE) == []
    assert receipt.scan_result == "pass"


def test_readme_pub_publish_is_not_this_class(tmp_path: Path) -> None:
    """README pub wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("dart pub publish --force\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _PUB_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_echo_then_real_pub_publish_still_fails() -> None:
    """``echo done && dart pub publish`` still runs the registry write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && dart pub publish\n',
    )
    assert any(
        hit.rule_id == _PUB_RULE and hit.snippet == "dart pub publish" for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\ndart pub publish --token {_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    pub_hits = [hit for hit in hits if hit.rule_id == _PUB_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert pub_hits
    for hit in pub_hits:
        assert hit.snippet == "dart pub publish"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_flutter_pub_publish_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that publishes to pub.dev is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "flutter pub publish"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _PUB_RULE)
    assert receipt.scan_result == "fail"


def test_manifest_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about pub publish is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs dart pub publish against pub.dev."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _PUB_RULE) == []
    assert receipt.scan_result == "pass"
