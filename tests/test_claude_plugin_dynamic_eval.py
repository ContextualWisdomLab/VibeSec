"""Dynamic eval/exec on plugin hook surfaces must fail closed."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_EVAL_RULE = "claude-plugin-dynamic-eval"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(root: Path) -> Path:
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
    hook.write_text("#!/bin/sh\necho session\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def test_python_eval_hook_is_reported() -> None:
    """eval() on a plugin hook is dynamic code evaluation."""
    hits = inspect_claude_plugin_file(
        "run.py",
        "hooks/run.py",
        "payload = input()\neval(payload)\n",
    )
    assert any(hit.rule_id == _EVAL_RULE for hit in hits)
    assert all("payload" not in hit.snippet or "eval" in hit.snippet for hit in hits)


def test_python_exec_and_js_function_are_reported() -> None:
    """exec() and new Function() are the same dynamic-evaluation class."""
    exec_hits = inspect_claude_plugin_file(
        "run.py", "scripts/run.py", "exec(compiled)\n"
    )
    fn_hits = inspect_claude_plugin_file(
        "run.js", "hooks/run.js", "const fn = new Function(code);\n"
    )
    compile_hits = inspect_claude_plugin_file(
        "run.py", "commands/run.py", "compile(src, '<hook>', 'exec')\n"
    )
    assert any(hit.rule_id == _EVAL_RULE for hit in exec_hits)
    assert any(hit.rule_id == _EVAL_RULE for hit in fn_hits)
    assert any(hit.rule_id == _EVAL_RULE for hit in compile_hits)


def test_print_and_evaluate_are_not_dynamic_eval() -> None:
    """evaluate() and print() are not eval()."""
    hits = inspect_claude_plugin_file(
        "run.py",
        "hooks/run.py",
        "print(1)\nresult = evaluate(config)\n",
    )
    assert all(hit.rule_id != _EVAL_RULE for hit in hits)


def test_repo_root_eval_is_not_a_plugin_finding() -> None:
    """Ordinary Python files are not Claude plugin hook surfaces."""
    hits = inspect_claude_plugin_file("app.py", "app.py", "eval(user_input)\n")
    assert hits == ()


def test_eval_hook_fails_plugin_receipt(tmp_path: Path) -> None:
    """A licensed plugin with eval() in a declared hook fails admission."""
    root = _licensed_plugin(tmp_path)
    (root / "hooks" / "session.sh").write_text(
        "#!/bin/sh\neval \"$PAYLOAD\"\n", encoding="utf-8"
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert receipt.scan_result == "fail"
    assert _EVAL_RULE in receipt.finding_summary
