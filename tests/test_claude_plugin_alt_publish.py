"""Hook pnpm, uv, and poetry publish fail closed; yarn npm stays npm."""

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
_PNPM_RULE = "claude-plugin-pnpm-publish-command"
_UV_RULE = "claude-plugin-uv-publish-command"
_POETRY_RULE = "claude-plugin-poetry-publish-command"
_NPM_RULE = "claude-plugin-npm-publish-command"
_PYPI_RULE = "claude-plugin-pypi-upload-command"
_SECRET = "sk-alt-publish-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_PNPM_RULE, _UV_RULE, _POETRY_RULE})


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


def test_hook_pnpm_publish_fails_admission(tmp_path: Path) -> None:
    """``pnpm publish`` on a hook is registry write authority, not npm."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\npnpm publish --access public\n")
    hits = _hits(root, _PNPM_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "pnpm publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _PNPM_RULE in receipt.finding_summary
    assert _NPM_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_hook_uv_publish_fails_admission() -> None:
    """``uv publish`` is a PyPI write, not twine upload."""
    body = "#!/bin/sh\nuv publish --token dummy\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _UV_RULE and hit.snippet == "uv publish" for hit in hits)
    assert all(hit.rule_id != _PYPI_RULE for hit in hits)


def test_hook_poetry_publish_fails_admission(tmp_path: Path) -> None:
    """``poetry publish`` on a hook is registry write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\npoetry publish --build\n")
    hits = _hits(root, _POETRY_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "poetry publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _POETRY_RULE in receipt.finding_summary
    assert _PYPI_RULE not in receipt.finding_summary


def test_yarn_npm_publish_stays_the_npm_class() -> None:
    """``yarn npm publish`` remains the npm-publish class, not pnpm."""
    body = "#!/bin/sh\nyarn npm publish\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _NPM_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_pnpm_list_stays_inventory(tmp_path: Path) -> None:
    """``pnpm list`` stays inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\npnpm list\nuv pip list\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_comment_and_echo_alt_publish_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# pnpm publish\necho "poetry publish"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_readme_pnpm_publish_is_not_this_class(tmp_path: Path) -> None:
    """README publish wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("pnpm publish --access public\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _PNPM_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_echo_then_real_uv_publish_still_fails() -> None:
    """``echo done && uv publish`` still runs the registry write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && uv publish\n',
    )
    assert any(hit.rule_id == _UV_RULE and hit.snippet == "uv publish" for hit in hits)


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\npnpm publish --otp {_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    pnpm_hits = [hit for hit in hits if hit.rule_id == _PNPM_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert pnpm_hits
    for hit in pnpm_hits:
        assert hit.snippet == "pnpm publish"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_poetry_publish_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that publishes with poetry is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "poetry publish --build"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _POETRY_RULE)
    assert receipt.scan_result == "fail"


def test_manifest_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about pnpm publish is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs pnpm publish against the public registry."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_npm_publish_stays_the_npm_class() -> None:
    """Bare ``npm publish`` stays the npm class, not pnpm."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\nnpm publish --access public\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _NPM_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)
