"""Hook hex publish and conda upload fail closed; list stays inventory."""

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
_HEX_RULE = "claude-plugin-hex-publish-command"
_CONDA_RULE = "claude-plugin-conda-upload-command"
_PUB_RULE = "claude-plugin-pub-publish-command"
_SECRET = "sk-hex-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_HEX_RULE, _CONDA_RULE})


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


def test_hook_hex_publish_fails_admission(tmp_path: Path) -> None:
    """``hex publish`` on a hook is Hex.pm write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nhex publish --yes\n")
    hits = _hits(root, _HEX_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "hex publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _HEX_RULE in receipt.finding_summary
    assert _CONDA_RULE not in receipt.finding_summary
    assert _PUB_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_mix_hex_publish_is_the_same_class() -> None:
    """``mix hex.publish`` is the Mix spelling of the Hex.pm class."""
    body = "#!/bin/sh\nmix hex.publish --yes\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _HEX_RULE and hit.snippet == "mix hex.publish" for hit in hits
    )


def test_hook_conda_upload_fails_admission(tmp_path: Path) -> None:
    """``conda upload`` on a hook is Anaconda.org write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nconda upload dist/app-1.0.0.tar.bz2\n")
    hits = _hits(root, _CONDA_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "conda upload" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _CONDA_RULE in receipt.finding_summary
    assert _HEX_RULE not in receipt.finding_summary


def test_anaconda_upload_is_the_same_class() -> None:
    """``anaconda upload`` canonicalizes to the conda-upload command class."""
    body = "#!/bin/sh\nanaconda upload dist/app-1.0.0.tar.bz2\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _CONDA_RULE and hit.snippet == "anaconda upload" for hit in hits
    )


def test_hex_info_and_conda_list_stay_inventory(tmp_path: Path) -> None:
    """Read-only hex/conda listing stays inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nhex info phoenix\nconda list\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _HEX_RULE) == []
    assert _hits(root, _CONDA_RULE) == []
    assert receipt.scan_result == "pass"


def test_hex_and_conda_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both hex publish and conda upload."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nhex publish --yes\nconda upload dist/app-1.0.0.tar.bz2\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _HEX_RULE)
    assert _hits(root, _CONDA_RULE)
    assert receipt.scan_result == "fail"
    assert _PUB_RULE not in receipt.finding_summary


def test_pub_publish_stays_the_pub_class() -> None:
    """``dart pub publish`` remains the pub.dev class, not Hex.pm."""
    body = "#!/bin/sh\ndart pub publish --force\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _PUB_RULE in rule_ids
    assert _HEX_RULE not in rule_ids
    assert _CONDA_RULE not in rule_ids


def test_comment_and_echo_hex_conda_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# hex publish\necho "conda upload dist/app.tar.bz2"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _HEX_RULE) == []
    assert _hits(root, _CONDA_RULE) == []
    assert receipt.scan_result == "pass"


def test_readme_hex_conda_is_not_this_class(tmp_path: Path) -> None:
    """README hex/conda wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("hex publish --yes\nconda upload app.tar.bz2\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _HEX_RULE) == []
    assert _hits(root, _CONDA_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_echo_then_real_hex_publish_still_fails() -> None:
    """``echo done && hex publish`` still runs the registry write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && hex publish --yes\n',
    )
    assert any(
        hit.rule_id == _HEX_RULE and hit.snippet == "hex publish" for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\nhex publish --key {_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    hex_hits = [hit for hit in hits if hit.rule_id == _HEX_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert hex_hits
    for hit in hex_hits:
        assert hit.snippet == "hex publish"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_conda_upload_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that uploads to Anaconda.org is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "conda upload dist/app-1.0.0.tar.bz2"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _CONDA_RULE)
    assert receipt.scan_result == "fail"


def test_manifest_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about hex publish is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs hex publish or conda upload."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _HEX_RULE) == []
    assert _hits(root, _CONDA_RULE) == []
    assert receipt.scan_result == "pass"
