"""Hook cabal upload and mvn deploy fail closed; list/package stay inventory."""

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
_CABAL_RULE = "claude-plugin-cabal-upload-command"
_MVN_RULE = "claude-plugin-mvn-deploy-command"
_HEX_RULE = "claude-plugin-hex-publish-command"
_SECRET = "sk-cabal-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_CABAL_RULE, _MVN_RULE})


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


def test_hook_cabal_upload_fails_admission(tmp_path: Path) -> None:
    """``cabal upload`` on a hook is Hackage write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ncabal upload dist/app-1.0.0.tar.gz\n")
    hits = _hits(root, _CABAL_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "cabal upload" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _CABAL_RULE in receipt.finding_summary
    assert _MVN_RULE not in receipt.finding_summary
    assert _HEX_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_cabal_v2_upload_is_the_same_class() -> None:
    """``cabal v2-upload`` is the Cabal 3 spelling of the Hackage class."""
    body = "#!/bin/sh\ncabal v2-upload dist/app-1.0.0.tar.gz\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _CABAL_RULE and hit.snippet == "cabal v2-upload" for hit in hits
    )


def test_hook_mvn_deploy_fails_admission(tmp_path: Path) -> None:
    """``mvn deploy`` on a hook is Maven repository write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nmvn deploy -DskipTests\n")
    hits = _hits(root, _MVN_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "mvn deploy" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _MVN_RULE in receipt.finding_summary
    assert _CABAL_RULE not in receipt.finding_summary


def test_mvn_deploy_file_is_the_same_class() -> None:
    """``mvn deploy:deploy-file`` is the same Maven write class."""
    body = "#!/bin/sh\nmvn deploy:deploy-file -Dfile=app.jar\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _MVN_RULE and hit.snippet == "mvn deploy" for hit in hits
    )


def test_cabal_list_and_mvn_package_stay_inventory(tmp_path: Path) -> None:
    """Read-only cabal list and local mvn package stay inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ncabal list\nmvn package\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _CABAL_RULE) == []
    assert _hits(root, _MVN_RULE) == []
    assert receipt.scan_result == "pass"


def test_hex_and_cabal_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both hex publish and cabal upload."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nhex publish --yes\ncabal upload dist/app-1.0.0.tar.gz\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _HEX_RULE)
    assert _hits(root, _CABAL_RULE)
    assert receipt.scan_result == "fail"
    assert _MVN_RULE not in receipt.finding_summary


def test_hex_publish_stays_the_hex_class() -> None:
    """``hex publish`` remains the Hex.pm class, not Hackage."""
    body = "#!/bin/sh\nhex publish --yes\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _HEX_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_comment_and_echo_cabal_mvn_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# cabal upload\necho "mvn deploy -DskipTests"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _CABAL_RULE) == []
    assert _hits(root, _MVN_RULE) == []
    assert receipt.scan_result == "pass"


def test_assignment_values_are_not_this_class() -> None:
    """An unquoted assignment value cannot turn its following word into the CLI."""
    bodies = (
        "#!/bin/sh\nmessage=cabal upload dist/app-1.0.0.tar.gz\n",
        "#!/bin/sh\ncommand=mvn deploy -DskipTests\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_environment_assignment_before_real_command_still_fails() -> None:
    """Environment assignments do not hide a later executable registry write."""
    bodies = (
        "#!/bin/sh\nCABAL_DIR=/tmp cabal upload dist/app-1.0.0.tar.gz\n",
        "#!/bin/sh\nMAVEN_OPTS=-Xmx1g mvn deploy -DskipTests\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)


def test_readme_cabal_mvn_is_not_this_class(tmp_path: Path) -> None:
    """README cabal/mvn wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text(
        "cabal upload dist/app-1.0.0.tar.gz\nmvn deploy -DskipTests\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _CABAL_RULE) == []
    assert _hits(root, _MVN_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_echo_then_real_cabal_upload_still_fails() -> None:
    """``echo done && cabal upload`` still runs the registry write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && cabal upload dist/app-1.0.0.tar.gz\n',
    )
    assert any(
        hit.rule_id == _CABAL_RULE and hit.snippet == "cabal upload" for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\ncabal upload --token {_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    cabal_hits = [hit for hit in hits if hit.rule_id == _CABAL_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert cabal_hits
    for hit in cabal_hits:
        assert hit.snippet == "cabal upload"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_mvn_deploy_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that deploys to Maven is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "mvn deploy -DskipTests"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _MVN_RULE)
    assert receipt.scan_result == "fail"


def test_manifest_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about cabal upload is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs cabal upload or mvn deploy."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _CABAL_RULE) == []
    assert _hits(root, _MVN_RULE) == []
    assert receipt.scan_result == "pass"
