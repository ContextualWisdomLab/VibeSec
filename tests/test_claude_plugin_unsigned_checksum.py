"""First-party checksum files with digest rows need a sibling signature file."""

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
_UNSIGNED_RULE = "claude-plugin-unsigned-checksum"
_MISMATCH_RULE = "claude-plugin-checksum-mismatch"
_SECRET = "sk-sig-must-not-leak"
_BIDI = "\u202e"


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
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _sha256(path: Path) -> str:
    """Return the hex SHA-256 digest of a regular file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _plugin_json(root: Path) -> Path:
    """Return the materialized plugin.json path."""
    return root / ".claude-plugin" / "plugin.json"


def _unsigned_hits(root: Path):
    """Return unsigned-checksum hits from the package scan."""
    return [hit for hit in scan_claude_plugin_package(root) if hit.rule_id == _UNSIGNED_RULE]


def test_matching_checksum_without_signature_fails_admission(tmp_path: Path) -> None:
    """A matching SHA256SUMS with no sibling signature is unsigned."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    hits = _unsigned_hits(root)

    assert hits
    assert all(hit.snippet == "SHA256SUMS" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _UNSIGNED_RULE in receipt.finding_summary
    assert _MISMATCH_RULE not in receipt.finding_summary


def test_matching_checksum_with_sig_is_not_this_class(tmp_path: Path) -> None:
    """A non-empty ``SHA256SUMS.sig`` sibling is not the unsigned class."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    (root / "SHA256SUMS.sig").write_text("untrusted-detached-signature\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _unsigned_hits(root) == []
    assert _UNSIGNED_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_cosign_bundle_sibling_is_not_this_class(tmp_path: Path) -> None:
    """A non-empty ``cosign.bundle`` next to the checksum is a signature file."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    (root / "cosign.bundle").write_text('{"payload":"offline"}\n', encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _unsigned_hits(root) == []
    assert receipt.scan_result == "pass"


def test_empty_sig_file_still_fails_admission(tmp_path: Path) -> None:
    """A zero-byte ``.sig`` is not a signature."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    (root / "SHA256SUMS.sig").write_bytes(b"")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _unsigned_hits(root)
    assert receipt.scan_result == "fail"
    assert _UNSIGNED_RULE in receipt.finding_summary


def test_no_checksum_file_is_not_this_class(tmp_path: Path) -> None:
    """Absence of a checksum file is not the unsigned class."""
    root = _licensed_plugin(tmp_path)
    receipt = build_claude_plugin_scan_receipt(root)

    assert _unsigned_hits(root) == []
    assert receipt.scan_result == "pass"
    assert _UNSIGNED_RULE not in receipt.finding_summary


def test_comments_only_checksum_is_not_this_class(tmp_path: Path) -> None:
    """Comment-only SHA256SUMS enumerates no digests, so it is not unsigned."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text("# nothing listed\n\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _unsigned_hits(root) == []
    assert receipt.scan_result == "pass"


def test_mismatch_without_signature_is_both_classes(tmp_path: Path) -> None:
    """Wrong digest and missing signature are independent findings."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text(f"{'0' * 64}  plugin.json\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    hits = scan_claude_plugin_package(root)
    rule_ids = {hit.rule_id for hit in hits}

    assert _MISMATCH_RULE in rule_ids
    assert _UNSIGNED_RULE in rule_ids
    assert receipt.scan_result == "fail"


def test_gpg_asc_sibling_is_not_this_class(tmp_path: Path) -> None:
    """A non-empty ``SHA256SUMS.asc`` sibling is a GPG signature file."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    (root / "SHA256SUMS.asc").write_text("-----BEGIN PGP SIGNATURE-----\n", encoding="utf-8")
    assert _unsigned_hits(root) == []
    assert build_claude_plugin_scan_receipt(root).scan_result == "pass"


def test_snippets_are_checksum_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the checksum file and omit secrets, bidi, and digests."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(
        f"# {_SECRET}{_BIDI}\n{digest}  plugin.json\n",
        encoding="utf-8",
    )
    hits = _unsigned_hits(root)
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert hits
    for hit in hits:
        assert hit.snippet == "SHA256SUMS"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert digest not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_json_sha256_without_sig_fails_admission(tmp_path: Path) -> None:
    """A matching ``plugin.json.sha256`` sibling still needs a signature file."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (_plugin_json(root).parent / "plugin.json.sha256").write_text(
        f"{digest}\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    hits = _unsigned_hits(root)

    assert hits
    assert all(hit.snippet == "plugin.json.sha256" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _UNSIGNED_RULE in receipt.finding_summary
    assert _MISMATCH_RULE not in receipt.finding_summary


def test_unreadable_checksum_is_not_the_unsigned_class(tmp_path: Path) -> None:
    """Undecodable checksum bytes stay the mismatch class, not unsigned."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_bytes(b"\xff\xfe")
    assert _unsigned_hits(root) == []
    assert _UNSIGNED_RULE not in {
        hit.rule_id for hit in scan_claude_plugin_package(root)
    }


def test_symlink_sig_is_not_a_signature(tmp_path: Path) -> None:
    """A symlink ``.sig`` is not a regular signature file."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    target = tmp_path / "outside.sig"
    target.write_text("detached\n", encoding="utf-8")
    (root / "SHA256SUMS.sig").symlink_to(target)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _unsigned_hits(root)
    assert receipt.scan_result == "fail"


def test_signature_stat_oserror_is_unsigned(tmp_path: Path, monkeypatch) -> None:
    """An unreadable sibling signature file does not count as signed."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    checksum = root / "SHA256SUMS"
    checksum.write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    (root / "SHA256SUMS.sig").write_text("detached\n", encoding="utf-8")
    original_stat = Path.stat

    def boom_stat(self: Path, *args, **kwargs):
        """Raise when the sibling signature is stat'd."""
        if self.name.endswith(".sig"):
            raise OSError("stat")
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", boom_stat)
    assert detector._checksum_has_signature_file(checksum) is False
