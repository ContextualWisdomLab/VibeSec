"""Plugin executables must not ship setuid, setgid, or world-writable modes."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_SETUID_RULE = "claude-plugin-setuid-executable"
_WORLD_RULE = "claude-plugin-world-writable-executable"
_VENDORED_RULE = "claude-plugin-vendored-scope-undeclared"


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
    hook.write_text("#!/bin/sh\necho hello\n", encoding="utf-8")
    hook.chmod(0o755)
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def test_setuid_hook_fails_admission(tmp_path: Path) -> None:
    """A declared hook with the setuid bit fails closed."""
    root = _licensed_plugin(tmp_path)
    hook = root / "hooks" / "session.sh"
    hook.chmod(0o4755)
    receipt = build_claude_plugin_scan_receipt(root)

    assert receipt.scan_result == "fail"
    assert _SETUID_RULE in receipt.finding_summary
    assert _WORLD_RULE not in receipt.finding_summary


def test_setgid_script_fails_admission(tmp_path: Path) -> None:
    """A ``scripts/`` helper with the setgid bit is the setuid class."""
    root = _licensed_plugin(tmp_path)
    helper = root / "scripts" / "run.sh"
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text("#!/bin/sh\necho helper\n", encoding="utf-8")
    helper.chmod(0o2755)
    receipt = build_claude_plugin_scan_receipt(root)

    assert receipt.scan_result == "fail"
    assert _SETUID_RULE in receipt.finding_summary


def test_world_writable_hook_fails_admission(tmp_path: Path) -> None:
    """A world-writable declared hook can be swapped after install."""
    root = _licensed_plugin(tmp_path)
    hook = root / "hooks" / "session.sh"
    hook.chmod(0o777)
    receipt = build_claude_plugin_scan_receipt(root)

    assert receipt.scan_result == "fail"
    assert _WORLD_RULE in receipt.finding_summary
    assert _SETUID_RULE not in receipt.finding_summary


def test_world_writable_unsuffixed_binary_fails_admission(tmp_path: Path) -> None:
    """A world-writable unsuffixed helper under ``scripts/`` is this class."""
    root = _licensed_plugin(tmp_path)
    binary = root / "scripts" / "run"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"\x7fELF")
    binary.chmod(0o666)
    receipt = build_claude_plugin_scan_receipt(root)

    assert receipt.scan_result == "fail"
    assert _WORLD_RULE in receipt.finding_summary


def test_owner_executable_hook_stays_receipt_pass(tmp_path: Path) -> None:
    """``0755`` on a declared hook is not setuid or world-writable."""
    root = _licensed_plugin(tmp_path)
    receipt = build_claude_plugin_scan_receipt(root)

    assert receipt.scan_result == "pass"
    assert _SETUID_RULE not in receipt.finding_summary
    assert _WORLD_RULE not in receipt.finding_summary


def test_world_writable_license_is_not_this_class(tmp_path: Path) -> None:
    """World-writable LICENSE is not an executable host-fs surface."""
    root = _licensed_plugin(tmp_path)
    license_path = root / "LICENSE"
    license_path.chmod(0o666)
    receipt = build_claude_plugin_scan_receipt(root)

    assert _WORLD_RULE not in receipt.finding_summary
    assert _SETUID_RULE not in receipt.finding_summary


def test_vendored_world_writable_stays_vendored_scope(tmp_path: Path) -> None:
    """World-writable files under vendor/ stay the vendored-scope class."""
    root = _licensed_plugin(tmp_path)
    vendored = root / "vendor" / "hooks" / "evil.sh"
    vendored.parent.mkdir(parents=True, exist_ok=True)
    vendored.write_text("#!/bin/sh\necho evil\n", encoding="utf-8")
    vendored.chmod(0o777)
    receipt = build_claude_plugin_scan_receipt(root)

    assert _WORLD_RULE not in receipt.finding_summary
    assert _SETUID_RULE not in receipt.finding_summary
    assert _VENDORED_RULE in receipt.finding_summary


def test_symlink_hook_is_not_a_mode_finding(tmp_path: Path) -> None:
    """Symlink hooks stay the symlink-escape class, not a mode finding."""
    root = _licensed_plugin(tmp_path)
    extra = root / "hooks" / "extra.sh"
    extra.symlink_to(root / "hooks" / "session.sh")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _SETUID_RULE not in receipt.finding_summary
    assert _WORLD_RULE not in receipt.finding_summary


def test_setuid_python_outside_hook_dirs_fails_admission(tmp_path: Path) -> None:
    """A setuid ``.py`` at the package root is still this class."""
    root = _licensed_plugin(tmp_path)
    script = root / "install.py"
    script.write_text("print('install')\n", encoding="utf-8")
    script.chmod(0o4755)
    receipt = build_claude_plugin_scan_receipt(root)

    assert receipt.scan_result == "fail"
    assert _SETUID_RULE in receipt.finding_summary


def test_git_hook_setuid_is_not_plugin_mode_finding(tmp_path: Path) -> None:
    """``.git/hooks`` stays Git metadata, not a plugin setuid finding."""
    root = _licensed_plugin(tmp_path)
    git_hook = root / ".git" / "hooks" / "pre-commit.sh"
    git_hook.parent.mkdir(parents=True, exist_ok=True)
    git_hook.write_text("#!/bin/sh\necho git\n", encoding="utf-8")
    git_hook.chmod(0o4755)
    receipt = build_claude_plugin_scan_receipt(root)

    assert _SETUID_RULE not in receipt.finding_summary
    assert _WORLD_RULE not in receipt.finding_summary


def test_mcp_json_under_hooks_is_not_a_mode_finding(tmp_path: Path) -> None:
    """``.mcp.json`` stays the MCP class even under ``hooks/``."""
    root = _licensed_plugin(tmp_path)
    mcp = root / "hooks" / ".mcp.json"
    mcp.write_text("{}\n", encoding="utf-8")
    mcp.chmod(0o666)
    receipt = build_claude_plugin_scan_receipt(root)

    assert _WORLD_RULE not in receipt.finding_summary
    assert _SETUID_RULE not in receipt.finding_summary


def test_mode_stat_errors_are_skipped(tmp_path: Path, monkeypatch) -> None:
    """Unreadable mode bits are skipped rather than failing open as pass."""
    import os

    from appguardrail_core import claude_plugin_detector as detector

    root = _licensed_plugin(tmp_path)
    hook = root / "hooks" / "session.sh"
    original_lstat = os.lstat

    def fake_lstat(target, *args, **kwargs):
        if os.fspath(target) == os.fspath(hook):
            raise OSError("unreadable")
        return original_lstat(target, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    hits = detector._insecure_file_mode_hits(root)
    assert hits == ()
