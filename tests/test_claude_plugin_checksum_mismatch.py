"""First-party plugin checksum files must fail closed when digests disagree."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from appguardrail_core import claude_plugin_detector as detector
from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    scan_claude_plugin_package,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_CHECKSUM_RULE = "claude-plugin-checksum-mismatch"
_SECRET = "sk-checksum-must-not-leak"
_BIDI = "\u202e"
_WRONG_DIGEST = "0" * 64


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(root: Path) -> Path:
    """Write a pinned licensed plugin that satisfies current admission policy."""
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
        },
    )
    _write_json(
        root / ".claude-plugin" / "marketplace.json",
        {
            "name": "safe-plugin",
            "version": "1.0.0",
            "source": {
                "source": "github",
                "repo": "example/safe-plugin",
                "ref": _PINNED_COMMIT,
            },
        },
    )
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _sha256(path: Path) -> str:
    """Return the hex SHA-256 digest of a regular file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _plugin_json(root: Path) -> Path:
    """Return the materialized plugin.json path."""
    return root / ".claude-plugin" / "plugin.json"


def _checksum_hits(root: Path):
    """Return checksum-mismatch hits from the package scan."""
    return [hit for hit in scan_claude_plugin_package(root) if hit.rule_id == _CHECKSUM_RULE]


def test_sha256sums_wrong_plugin_json_digest_fails_admission(tmp_path: Path) -> None:
    """SHA256SUMS listing ``plugin.json`` with a wrong digest fails closed."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text(f"{_WRONG_DIGEST}  plugin.json\n", encoding="utf-8")
    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    assert any(hit.rule_id == _CHECKSUM_RULE for hit in hits)
    assert all("_" in hit.rule_id or "-" in hit.rule_id for hit in hits if hit.rule_id == _CHECKSUM_RULE)
    assert receipt.scan_result == "fail"
    assert _CHECKSUM_RULE in receipt.finding_summary


def test_sha256sums_matching_plugin_json_is_not_a_finding(tmp_path: Path) -> None:
    """SHA256SUMS that matches the bytes of plugin.json is not this class."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _checksum_hits(root) == []
    assert _CHECKSUM_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_no_checksum_file_is_not_a_finding(tmp_path: Path) -> None:
    """Absence of a checksum or signature file is not this class."""
    root = _licensed_plugin(tmp_path)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _checksum_hits(root) == []
    assert _CHECKSUM_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"
    assert not (root / "SHA256SUMS").exists()
    assert not list(root.rglob("*.sig"))


def test_sha256sums_comment_lines_are_ignored(tmp_path: Path) -> None:
    """``#`` comments in SHA256SUMS are not enumerated checksum rows."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(
        f"# {_SECRET} {_BIDI} ignore this row\n{digest}  plugin.json\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _checksum_hits(root) == []
    assert _CHECKSUM_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_sbom_sha256_still_binds_and_verifies_with_checksum_file(
    tmp_path: Path,
) -> None:
    """#1168 ``sbom_sha256`` remains present and still verifies on this slice."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    payload = receipt.as_dict()
    verification = detector.verify_plugin_scan_receipt(receipt, root)

    assert isinstance(payload["sbom_sha256"], str)
    assert len(payload["sbom_sha256"]) == 64
    assert payload["sbom_sha256"] == receipt.sbom_sha256
    assert payload["sbom_sha256"] != receipt.scanner_policy_sha256
    assert verification.matches is True
    assert "sbom_sha256" not in verification.mismatches
    assert verification.admitted is False


def test_checksum_snippets_are_path_labels_not_hashes_or_secrets(
    tmp_path: Path,
) -> None:
    """Snippets name the listed path and omit digests, secrets, and bidi."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(_plugin_json(root).read_text(encoding="utf-8"))
    manifest["note"] = _SECRET
    _write_json(_plugin_json(root), manifest)
    (root / "SHA256SUMS").write_text(
        f"{_WRONG_DIGEST}  plugin.json\n",
        encoding="utf-8",
    )
    hits = _checksum_hits(root)
    receipt = build_claude_plugin_scan_receipt(root)
    payload = json.dumps(receipt.as_dict())
    assert hits
    for hit in hits:
        assert "plugin.json" in hit.snippet
        assert _WRONG_DIGEST not in hit.snippet
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_sha256sums_txt_wrong_digest_fails_admission(tmp_path: Path) -> None:
    """``SHA256SUMS.txt`` is a first-party checksum file."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS.txt").write_text(
        f"{_WRONG_DIGEST}  plugin.json\n",
        encoding="utf-8",
    )
    assert _checksum_hits(root)
    assert build_claude_plugin_scan_receipt(root).scan_result == "fail"


def test_checksums_sha256_wrong_digest_fails_admission(tmp_path: Path) -> None:
    """``checksums.sha256`` is a first-party checksum file."""
    root = _licensed_plugin(tmp_path)
    (root / "checksums.sha256").write_text(
        f"{_WRONG_DIGEST}  plugin.json\n",
        encoding="utf-8",
    )
    assert _checksum_hits(root)
    assert build_claude_plugin_scan_receipt(root).scan_result == "fail"


def test_plugin_json_sha256_sibling_mismatch_fails_admission(tmp_path: Path) -> None:
    """A ``*.sha256`` file next to plugin.json binds that artifact."""
    root = _licensed_plugin(tmp_path)
    (_plugin_json(root).parent / "plugin.json.sha256").write_text(
        f"{_WRONG_DIGEST}\n",
        encoding="utf-8",
    )
    hits = _checksum_hits(root)
    assert hits
    assert "plugin.json" in hits[0].snippet
    assert build_claude_plugin_scan_receipt(root).scan_result == "fail"


def test_plugin_json_sha256_sibling_match_is_not_a_finding(tmp_path: Path) -> None:
    """A matching ``plugin.json.sha256`` sibling is not this class."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (_plugin_json(root).parent / "plugin.json.sha256").write_text(
        f"{digest}\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _checksum_hits(root) == []
    assert receipt.scan_result == "pass"


def test_binary_mode_star_prefix_matching_digest_is_not_a_finding(
    tmp_path: Path,
) -> None:
    """GNU binary-mode `` *`` separators still compare file bytes."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest} *plugin.json\n", encoding="utf-8")
    assert _checksum_hits(root) == []
    assert build_claude_plugin_scan_receipt(root).scan_result == "pass"


def test_comments_only_checksum_file_is_not_a_finding(tmp_path: Path) -> None:
    """A checksum file with only comments enumerates no artifacts."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text("# nothing listed\n\n", encoding="utf-8")
    assert _checksum_hits(root) == []
    assert build_claude_plugin_scan_receipt(root).scan_result == "pass"


def test_missing_listed_file_fails_closed(tmp_path: Path) -> None:
    """A listed path with no regular file on disk disagrees with the claim."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text(f"{_WRONG_DIGEST}  missing.bin\n", encoding="utf-8")
    hits = _checksum_hits(root)
    assert hits
    assert "missing.bin" in hits[0].snippet
    assert build_claude_plugin_scan_receipt(root).scan_result == "fail"


def test_escaped_listed_path_fails_closed(tmp_path: Path) -> None:
    """Checksum rows must not follow ``../`` or absolute paths."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text(
        f"{_WRONG_DIGEST}  ../outside.bin\n",
        encoding="utf-8",
    )
    hits = _checksum_hits(root)
    assert hits
    assert "outside.bin" in hits[0].snippet or ".." in hits[0].snippet
    assert _WRONG_DIGEST not in hits[0].snippet


def test_unreadable_checksum_file_fails_closed(tmp_path: Path) -> None:
    """Invalid checksum bytes fail closed instead of skipping verification."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_bytes(b"\xff\xfe")
    hits = detector._checksum_mismatch_hits(root)
    assert hits
    assert all(hit.rule_id == _CHECKSUM_RULE for hit in hits)


def test_symlink_checksum_file_is_not_this_class(tmp_path: Path) -> None:
    """Symlink checksum files are not first-party checksum evidence."""
    root = _licensed_plugin(tmp_path)
    target = root / "LICENSE"
    checksum = root / "SHA256SUMS"
    checksum.symlink_to(target)
    assert _checksum_hits(root) == []


def test_malformed_checksum_line_is_ignored(tmp_path: Path) -> None:
    """Non-SHA-256 rows are not treated as artifact bindings."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text("not-a-digest  plugin.json\n", encoding="utf-8")
    assert _checksum_hits(root) == []
    assert build_claude_plugin_scan_receipt(root).scan_result == "pass"
