"""Hidden undeclared plugin executables and configs must fail closed."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    scan_claude_plugin_package,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_HIDDEN_RULE = "claude-plugin-hidden-undeclared-executable"
_UNDECLARED_RULE = "claude-plugin-undeclared-executable"
_EVAL_RULE = "claude-plugin-dynamic-eval"
_SECRET = "sk-example-must-not-leak"
_BIDI = "\u202e"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(
    root: Path,
    *,
    hook_path: str = "hooks/pre.sh",
    hook_body: str = "#!/bin/sh\necho session\n",
) -> Path:
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
            "hooks": {"PreToolUse": [{"command": hook_path}]},
        },
    )
    hook = root / hook_path
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(hook_body, encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _rule_ids(root: Path) -> set[str]:
    """Return package-scan rule identities for ``root``."""
    return {hit.rule_id for hit in scan_claude_plugin_package(root)}


def test_hidden_bin_run_sh_fails_admission(tmp_path: Path) -> None:
    """``.bin/run.sh`` is a hidden undeclared executable surface."""
    root = _licensed_plugin(tmp_path)
    hidden = root / ".bin" / "run.sh"
    hidden.parent.mkdir()
    hidden.write_text("#!/bin/sh\necho stealth\n", encoding="utf-8")

    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert any(hit.rule_id == _HIDDEN_RULE and hit.file == ".bin/run.sh" for hit in hits)
    assert _HIDDEN_RULE in {hit.rule_id for hit in hits}
    assert all("_" in hit.rule_id or "-" in hit.rule_id for hit in hits)
    assert receipt.scan_result == "fail"
    assert _HIDDEN_RULE in receipt.finding_summary


def test_hidden_hooks_secret_py_is_reported(tmp_path: Path) -> None:
    """``.hooks/secret.py`` is not the documented ``hooks/`` undeclared class."""
    root = _licensed_plugin(tmp_path)
    secret = root / ".hooks" / "secret.py"
    secret.parent.mkdir()
    secret.write_text("print('secret')\n", encoding="utf-8")

    hits = scan_claude_plugin_package(root)
    rule_ids = {hit.rule_id for hit in hits}
    assert _HIDDEN_RULE in rule_ids
    assert _UNDECLARED_RULE not in rule_ids
    assert any(hit.file == ".hooks/secret.py" for hit in hits if hit.rule_id == _HIDDEN_RULE)


def test_declared_hooks_pre_sh_is_not_hidden_finding(tmp_path: Path) -> None:
    """A declared ``hooks/pre.sh`` stays inventory, not this hidden class."""
    root = _licensed_plugin(tmp_path, hook_path="hooks/pre.sh")
    rule_ids = _rule_ids(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _HIDDEN_RULE not in rule_ids
    assert _UNDECLARED_RULE not in rule_ids
    assert receipt.scan_result == "pass"


def test_gitignore_only_is_not_hidden_executable(tmp_path: Path) -> None:
    """``.gitignore`` is not a plugin executable or config surface."""
    root = _licensed_plugin(tmp_path)
    (root / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    rule_ids = _rule_ids(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _HIDDEN_RULE not in rule_ids
    assert receipt.scan_result == "pass"


def test_git_internals_are_not_plugin_executable_surfaces(tmp_path: Path) -> None:
    """``.git/`` metadata is not a Claude plugin executable surface."""
    root = _licensed_plugin(tmp_path)
    git_hook = root / ".git" / "hooks" / "pre-commit"
    git_hook.parent.mkdir(parents=True)
    git_hook.write_text("#!/bin/sh\necho git\n", encoding="utf-8")
    rule_ids = _rule_ids(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _HIDDEN_RULE not in rule_ids
    assert receipt.scan_result == "pass"


def test_mcp_json_is_not_hidden_undeclared_executable(tmp_path: Path) -> None:
    """``.mcp.json`` stays the MCP class; do not double-count it here."""
    root = _licensed_plugin(tmp_path)
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {
                        "command": "python",
                        "schema": {"type": "object"},
                        "source": {"sha": _PINNED_COMMIT},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    rule_ids = _rule_ids(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _HIDDEN_RULE not in rule_ids
    assert "claude-plugin-unbounded-mcp" not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_non_hidden_extra_script_is_not_this_finding(tmp_path: Path) -> None:
    """``scripts/hidden.py`` remains ``claude-plugin-undeclared-executable``."""
    root = _licensed_plugin(tmp_path)
    extra = root / "scripts" / "hidden.py"
    extra.parent.mkdir()
    extra.write_text("print('hidden')\n", encoding="utf-8")
    rule_ids = _rule_ids(root)
    assert _UNDECLARED_RULE in rule_ids
    assert _HIDDEN_RULE not in rule_ids


def test_hidden_snippets_omit_secrets_and_bidi(tmp_path: Path) -> None:
    """Hidden-surface snippets omit secret literals and raw bidi characters."""
    root = _licensed_plugin(tmp_path)
    hidden = root / ".bin" / "run.sh"
    hidden.parent.mkdir()
    hidden.write_text(
        f"#!/bin/sh\nOPENAI_API_KEY={_SECRET}\necho {_BIDI}hidden\n",
        encoding="utf-8",
    )
    hits = [hit for hit in scan_claude_plugin_package(root) if hit.rule_id == _HIDDEN_RULE]
    receipt = build_claude_plugin_scan_receipt(root)
    serialized = json.dumps(receipt.as_dict())
    assert hits
    assert all(_SECRET not in hit.snippet for hit in hits)
    assert all(_BIDI not in hit.snippet for hit in hits)
    assert _SECRET not in serialized
    assert _BIDI not in serialized


def test_hidden_config_and_extensionless_tool_are_reported(tmp_path: Path) -> None:
    """Hidden config files and extensionless ``.bin/tool`` fail closed."""
    root = _licensed_plugin(tmp_path)
    config = root / ".config.json"
    config.write_text('{"command": "stealth"}\n', encoding="utf-8")
    tool = root / ".bin" / "tool"
    tool.parent.mkdir()
    tool.write_text("#!/bin/sh\necho tool\n", encoding="utf-8")
    hits = scan_claude_plugin_package(root)
    files = {hit.file for hit in hits if hit.rule_id == _HIDDEN_RULE}
    assert ".config.json" in files
    assert ".bin/tool" in files


def test_declared_hidden_path_is_not_this_finding(tmp_path: Path) -> None:
    """A manifest-declared hidden hook is classified, not this undeclared class."""
    root = _licensed_plugin(tmp_path, hook_path=".bin/run.sh")
    rule_ids = _rule_ids(root)
    assert _HIDDEN_RULE not in rule_ids


def test_nested_manifest_and_gitlink_are_not_hidden_findings(tmp_path: Path) -> None:
    """Nested plugin.json and gitlink ``.git`` files are not this class."""
    root = _licensed_plugin(tmp_path)
    nested = root / "vendor" / "nested"
    _write_json(
        nested / ".claude-plugin" / "plugin.json",
        {
            "name": "nested",
            "version": "1.0.0",
            "source": {"ref": _PINNED_COMMIT},
        },
    )
    (nested / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (nested / ".git").write_text("gitdir: ../../.git/modules/vendor/nested\n", encoding="utf-8")
    rule_ids = _rule_ids(root)
    assert _HIDDEN_RULE not in rule_ids


def test_dynamic_eval_on_declared_hook_is_unchanged(tmp_path: Path) -> None:
    """#1145 eval/exec on a declared hook is not this hidden-path class."""
    root = _licensed_plugin(
        tmp_path,
        hook_path="hooks/pre.sh",
        hook_body='#!/bin/sh\neval "$PAYLOAD"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert receipt.scan_result == "fail"
    assert _EVAL_RULE in receipt.finding_summary
    assert _HIDDEN_RULE not in receipt.finding_summary
