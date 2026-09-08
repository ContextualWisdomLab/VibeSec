"""Hook npm publish, twine upload, and cargo publish fail closed."""

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
_NPM_RULE = "claude-plugin-npm-publish-command"
_PYPI_RULE = "claude-plugin-pypi-upload-command"
_CARGO_RULE = "claude-plugin-cargo-publish-command"
_S3_RULE = "claude-plugin-aws-s3-write-command"
_SECRET = "sk-publish-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_NPM_RULE, _PYPI_RULE, _CARGO_RULE})


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


def test_hook_npm_publish_fails_admission(tmp_path: Path) -> None:
    """``npm publish`` on a hook is registry write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nnpm publish --access public\n")
    hits = _hits(root, _NPM_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "npm publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _NPM_RULE in receipt.finding_summary
    assert _PYPI_RULE not in receipt.finding_summary
    assert _S3_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_hook_twine_upload_fails_admission(tmp_path: Path) -> None:
    """``twine upload`` on a hook is PyPI write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ntwine upload dist/*\n")
    hits = _hits(root, _PYPI_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "twine upload" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _PYPI_RULE in receipt.finding_summary
    assert _NPM_RULE not in receipt.finding_summary


def test_hook_cargo_publish_fails_admission(tmp_path: Path) -> None:
    """``cargo publish`` on a hook is crates.io write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ncargo publish --allow-dirty\n")
    hits = _hits(root, _CARGO_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "cargo publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _CARGO_RULE in receipt.finding_summary


def test_npm_pack_and_cargo_check_stay_inventory(tmp_path: Path) -> None:
    """Read-only pack and check commands stay inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nnpm pack\ncargo check\npip install .\n")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_comment_and_echo_publish_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# npm publish\necho "cargo publish"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_readme_npm_publish_is_not_this_class(tmp_path: Path) -> None:
    """README publish wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("npm publish --access public\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _NPM_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_three_registries_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on npm, PyPI, and cargo publish."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nnpm publish\ntwine upload dist/*\ncargo publish\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _NPM_RULE)
    assert _hits(root, _PYPI_RULE)
    assert _hits(root, _CARGO_RULE)
    assert receipt.scan_result == "fail"
    assert _S3_RULE not in receipt.finding_summary


def test_python_module_twine_upload_is_the_same_class() -> None:
    """``python -m twine upload`` is the same PyPI class."""
    body = "#!/bin/sh\npython -m twine upload dist/*\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _PYPI_RULE and hit.snippet == "twine upload" for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\nnpm publish --otp {_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    npm_hits = [hit for hit in hits if hit.rule_id == _NPM_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert npm_hits
    for hit in npm_hits:
        assert hit.snippet == "npm publish"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_cargo_publish_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that publishes crates is the cargo class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "cargo publish --allow-dirty"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _CARGO_RULE)
    assert receipt.scan_result == "fail"


def test_s3_write_without_publish_stays_the_s3_class() -> None:
    """Object-store writes without registry publish stay the s3 class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\naws s3 sync ./dist s3://bucket/app\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _S3_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_manifest_description_publish_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about npm publish is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs npm publish against the public registry."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"
