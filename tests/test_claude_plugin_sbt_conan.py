"""Hook sbt publish and conan upload fail closed; compile/list stay inventory."""

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
_SBT_RULE = "claude-plugin-sbt-publish-command"
_CONAN_RULE = "claude-plugin-conan-upload-command"
_GRADLE_RULE = "claude-plugin-gradle-publish-command"
_SECRET = "sk-sbt-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_SBT_RULE, _CONAN_RULE})


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


def test_hook_sbt_publish_fails_admission(tmp_path: Path) -> None:
    """``sbt publish`` on a hook is Maven-repository write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nsbt publish\n")
    hits = _hits(root, _SBT_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "sbt publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _SBT_RULE in receipt.finding_summary
    assert _CONAN_RULE not in receipt.finding_summary
    assert _GRADLE_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_sbt_publish_signed_is_the_same_class() -> None:
    """``sbt publishSigned`` is the signed spelling of the sbt publish class."""
    body = "#!/bin/sh\nsbt publishSigned\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _SBT_RULE and hit.snippet == "sbt publishSigned" for hit in hits
    )


def test_hook_conan_upload_fails_admission(tmp_path: Path) -> None:
    """``conan upload`` on a hook is Conan Center write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nconan upload pkg/1.0.0@user/stable\n")
    hits = _hits(root, _CONAN_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "conan upload" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _CONAN_RULE in receipt.finding_summary
    assert _SBT_RULE not in receipt.finding_summary


def test_sbt_compile_and_conan_list_stay_inventory(tmp_path: Path) -> None:
    """Read-only sbt compile and conan list stay inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nsbt compile\nconan list\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _SBT_RULE) == []
    assert _hits(root, _CONAN_RULE) == []
    assert receipt.scan_result == "pass"


def test_sbt_publish_local_is_not_this_class(tmp_path: Path) -> None:
    """Quoted or unquoted publishLocal stays local, not a remote publish."""
    bodies = ("#!/bin/sh\nsbt publishLocal\n", '#!/bin/sh\nsbt "publishLocal"\n')
    for body in bodies:
        root = _licensed_plugin(tmp_path, body)
        receipt = build_claude_plugin_scan_receipt(root)
        assert _hits(root, _SBT_RULE) == []
        assert receipt.scan_result == "pass"


def test_gradle_and_sbt_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both gradle publish and sbt publish."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\ngradle publish\nsbt publish\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _GRADLE_RULE)
    assert _hits(root, _SBT_RULE)
    assert receipt.scan_result == "fail"
    assert _CONAN_RULE not in receipt.finding_summary


def test_gradle_publish_stays_the_gradle_class() -> None:
    """``gradle publish`` remains the Gradle class, not sbt."""
    body = "#!/bin/sh\ngradle publish\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _GRADLE_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_comment_and_echo_sbt_conan_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# sbt publish\necho "conan upload pkg/1.0.0@user/stable"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _SBT_RULE) == []
    assert _hits(root, _CONAN_RULE) == []
    assert receipt.scan_result == "pass"


def test_assignment_values_are_not_this_class() -> None:
    """An unquoted assignment value cannot turn its following word into the CLI."""
    bodies = (
        "#!/bin/sh\nmessage=sbt publish\n",
        "#!/bin/sh\ncommand=conan upload pkg/1.0.0@user/stable\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_environment_assignment_before_real_command_still_fails() -> None:
    """Environment assignments do not hide a later executable registry write."""
    bodies = (
        "#!/bin/sh\nSBT_OPTS=-Xmx1g sbt publish\n",
        "#!/bin/sh\nCONAN_USER_HOME=/tmp conan upload pkg/1.0.0@user/stable\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)


def test_readme_sbt_conan_is_not_this_class(tmp_path: Path) -> None:
    """README sbt/conan wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text(
        "sbt publish\nconan upload pkg/1.0.0@user/stable\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _SBT_RULE) == []
    assert _hits(root, _CONAN_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_echo_then_real_sbt_publish_still_fails() -> None:
    """``echo done && sbt publish`` still runs the registry write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && sbt publish\n',
    )
    assert any(
        hit.rule_id == _SBT_RULE and hit.snippet == "sbt publish" for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\nsbt publish -Dsbt.sonatype.password={_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    sbt_hits = [hit for hit in hits if hit.rule_id == _SBT_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert sbt_hits
    for hit in sbt_hits:
        assert hit.snippet == "sbt publish"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_conan_upload_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that uploads to Conan Center is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "conan upload pkg/1.0.0@user/stable"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _CONAN_RULE)
    assert receipt.scan_result == "fail"


def test_manifest_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about sbt publish is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs sbt publish or conan upload."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _SBT_RULE) == []
    assert _hits(root, _CONAN_RULE) == []
    assert receipt.scan_result == "pass"


def test_quoted_sbt_publish_tasks_fail_admission() -> None:
    """Quoted exact sbt publish tasks remain executable registry writes."""
    bodies = (
        '#!/bin/sh\nsbt "publish"\n',
        "#!/bin/sh\nsbt 'publishSigned'\n",
    )
    expected = ("sbt publish", "sbt publishSigned")
    for body, snippet in zip(bodies, expected, strict=True):
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(
            hit.rule_id == _SBT_RULE and hit.snippet == snippet for hit in hits
        )

