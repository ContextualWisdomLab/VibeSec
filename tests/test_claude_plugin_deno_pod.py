"""Hook deno publish and pod trunk push fail closed; info/install stay inventory."""

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
_DENO_RULE = "claude-plugin-deno-publish-command"
_POD_RULE = "claude-plugin-pod-trunk-push-command"
_SBT_RULE = "claude-plugin-sbt-publish-command"
_SECRET = "sk-deno-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_DENO_RULE, _POD_RULE})


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


def test_hook_deno_publish_fails_admission(tmp_path: Path) -> None:
    """``deno publish`` on a hook is JSR write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ndeno publish --allow-slow-types\n")
    hits = _hits(root, _DENO_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "deno publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _DENO_RULE in receipt.finding_summary
    assert _POD_RULE not in receipt.finding_summary
    assert _SBT_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_hook_pod_trunk_push_fails_admission(tmp_path: Path) -> None:
    """``pod trunk push`` on a hook is CocoaPods trunk write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\npod trunk push App.podspec\n")
    hits = _hits(root, _POD_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "pod trunk push" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _POD_RULE in receipt.finding_summary
    assert _DENO_RULE not in receipt.finding_summary


def test_deno_info_and_pod_install_stay_inventory(tmp_path: Path) -> None:
    """Read-only deno info and local pod install stay inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ndeno info\npod install\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"


def test_pod_lib_lint_is_not_this_class(tmp_path: Path) -> None:
    """``pod lib lint`` stays local validation, not trunk write."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\npod lib lint\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"


def test_sbt_and_deno_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both sbt publish and deno publish."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nsbt publish && deno publish\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _SBT_RULE)
    assert _hits(root, _DENO_RULE)
    assert receipt.scan_result == "fail"
    assert _POD_RULE not in receipt.finding_summary


def test_sbt_publish_stays_the_sbt_class() -> None:
    """``sbt publish`` remains the sbt class, not JSR."""
    body = "#!/bin/sh\nsbt publish\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _SBT_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_comment_and_echo_deno_pod_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# deno publish\necho "pod trunk push App.podspec"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"


def test_assignment_values_are_not_this_class() -> None:
    """An unquoted assignment value cannot turn its following word into the CLI."""
    bodies = (
        "#!/bin/sh\nmessage=deno publish --allow-slow-types\n",
        "#!/bin/sh\ncommand=pod trunk push App.podspec\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_environment_assignment_before_real_command_still_fails() -> None:
    """Environment assignments do not hide a later executable registry write."""
    bodies = (
        "#!/bin/sh\nDENO_DIR=/tmp deno publish --allow-slow-types\n",
        "#!/bin/sh\nCOCOAPODS_TRUNK_TOKEN=x pod trunk push App.podspec\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)


def test_readme_deno_pod_is_not_this_class(tmp_path: Path) -> None:
    """README deno/pod wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text(
        "deno publish --allow-slow-types\npod trunk push App.podspec\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_echo_then_real_deno_publish_still_fails() -> None:
    """``echo done && deno publish`` still runs the registry write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && deno publish --allow-slow-types\n',
    )
    assert any(
        hit.rule_id == _DENO_RULE and hit.snippet == "deno publish" for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\ndeno publish --token {_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    deno_hits = [hit for hit in hits if hit.rule_id == _DENO_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert deno_hits
    for hit in deno_hits:
        assert hit.snippet == "deno publish"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_pod_trunk_push_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that pushes to CocoaPods trunk is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "pod trunk push App.podspec"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _POD_RULE)
    assert receipt.scan_result == "fail"


def test_manifest_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about deno publish is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs deno publish or pod trunk push."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"
