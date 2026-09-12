"""LICENSE/NOTICE evidence must fail closed on SPDX mismatch, not legal approval."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    scan_claude_plugin_package,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_MISMATCH_RULE = "claude-plugin-license-mismatch"
_MISSING_RULE = "claude-plugin-license-missing"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _plugin(root: Path, *, license_field: str | None = "MIT") -> Path:
    """Write a pinned plugin with an optional declared license expression."""
    manifest: dict[str, object] = {
        "name": "safe-plugin",
        "version": "1.0.0",
        "source": {
            "source": "github",
            "repo": "example/safe-plugin",
            "ref": _PINNED_COMMIT,
        },
    }
    if license_field is not None:
        manifest["license"] = license_field
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    _write_json(root / ".claude-plugin" / "marketplace.json", manifest)
    return root


def test_matching_declared_mit_and_license_file_is_not_a_finding(tmp_path: Path) -> None:
    """Matching MIT evidence is recorded, not a mismatch finding."""
    root = _plugin(tmp_path)
    (root / "LICENSE").write_text("MIT License\nPermission is hereby granted.\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert receipt.scan_result == "pass"
    assert _MISMATCH_RULE not in receipt.finding_summary
    assert _MISSING_RULE not in receipt.finding_summary
    assert "LICENSE" in receipt.license_evidence_summary


def test_declared_apache_with_mit_license_file_is_mismatch(tmp_path: Path) -> None:
    """A declared Apache-2.0 expression cannot sit on an MIT license file."""
    root = _plugin(tmp_path, license_field="Apache-2.0")
    (root / "LICENSE").write_text("MIT License\nPermission is hereby granted.\n", encoding="utf-8")
    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert any(hit.rule_id == _MISMATCH_RULE for hit in hits)
    assert receipt.scan_result == "fail"
    assert _MISMATCH_RULE in receipt.finding_summary
    assert _MISSING_RULE not in receipt.finding_summary


def test_mit_license_and_apache_notice_is_mismatch(tmp_path: Path) -> None:
    """LICENSE and NOTICE SPDX tokens must not contradict each other."""
    root = _plugin(tmp_path, license_field=None)
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (root / "NOTICE").write_text("Apache-2.0\nCopyright 2026 Example\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert receipt.scan_result == "fail"
    assert _MISMATCH_RULE in receipt.finding_summary


def test_notice_only_is_not_license_missing(tmp_path: Path) -> None:
    """A NOTICE file is license evidence and is not treated as absence."""
    root = _plugin(tmp_path, license_field="MIT")
    (root / "NOTICE").write_text("MIT\nCopyright 2026 Example\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _MISSING_RULE not in receipt.finding_summary
    assert "NOTICE" in receipt.license_evidence_summary
    assert receipt.scan_result == "pass"


def test_copyright_only_notice_does_not_invent_spdx(tmp_path: Path) -> None:
    """A NOTICE without an SPDX token is not a mismatch against MIT."""
    root = _plugin(tmp_path)
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (root / "NOTICE").write_text("Copyright 2026 Example Inc.\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert receipt.scan_result == "pass"
    assert _MISMATCH_RULE not in receipt.finding_summary


def test_non_object_manifest_still_compares_license_files(tmp_path: Path) -> None:
    """File SPDX tokens still conflict when the manifest is not an object."""
    root = tmp_path
    plugin_dir = root / ".claude-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.json").write_text("[]\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (root / "NOTICE").write_text("Apache-2.0\n", encoding="utf-8")
    hits = scan_claude_plugin_package(root)
    assert any(hit.rule_id == _MISMATCH_RULE for hit in hits)


def test_non_string_license_field_is_ignored(tmp_path: Path) -> None:
    """Object license fields are not SPDX evidence."""
    root = _plugin(tmp_path, license_field=None)
    manifest = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    manifest["license"] = {"type": "MIT"}
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps(manifest) + "\n", encoding="utf-8"
    )
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _MISMATCH_RULE not in receipt.finding_summary


def test_unreadable_license_file_is_skipped(tmp_path: Path) -> None:
    """Invalid LICENSE bytes do not crash mismatch collection."""
    from appguardrail_core import claude_plugin_detector as detector

    root = _plugin(tmp_path, license_field="Apache-2.0")
    (root / "LICENSE").write_bytes(b"\xff\xfe")
    hits = detector._license_mismatch_hits(root, {"license": "Apache-2.0"})
    assert all(hit.rule_id == _MISMATCH_RULE for hit in hits) or hits == ()
