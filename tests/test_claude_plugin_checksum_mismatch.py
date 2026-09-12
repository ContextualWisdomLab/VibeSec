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


def test_tab_separator_matching_digest_is_not_a_finding(tmp_path: Path) -> None:
    """A tab between digest and name still binds the listed file."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(f"{digest}\tplugin.json\n", encoding="utf-8")
    assert _checksum_hits(root) == []
    assert build_claude_plugin_scan_receipt(root).scan_result == "pass"


def test_absolute_and_windows_listed_paths_fail_closed(tmp_path: Path) -> None:
    """Absolute, UNC, and Windows-drive checksum paths fail closed."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text(
        f"{_WRONG_DIGEST}  /tmp/outside.bin\n"
        f"{_WRONG_DIGEST}  C:\\Windows\\plugin.json\n"
        f"{_WRONG_DIGEST}  //host/share/plugin.json\n",
        encoding="utf-8",
    )
    hits = _checksum_hits(root)
    assert len(hits) >= 3
    assert all(_WRONG_DIGEST not in hit.snippet for hit in hits)


def test_bidi_listed_name_fails_closed_without_raw_bidi(tmp_path: Path) -> None:
    """Concealed characters in a listed name fail closed with a sanitized snippet."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text(
        f"{_WRONG_DIGEST}  {_BIDI}plugin.json\n",
        encoding="utf-8",
    )
    hits = _checksum_hits(root)
    assert hits
    assert _BIDI not in hits[0].snippet


def test_quoted_empty_name_and_non_hex_digest_are_ignored(tmp_path: Path) -> None:
    """Empty quoted names and 64-character non-hex rows are not bindings."""
    root = _licensed_plugin(tmp_path)
    (root / "SHA256SUMS").write_text(
        f"{_WRONG_DIGEST}  \n"
        f"{'g' * 64}  plugin.json\n"
        f"{_WRONG_DIGEST}|plugin.json\n",
        encoding="utf-8",
    )
    assert _checksum_hits(root) == []


def test_dot_sha256_hex_file_without_sibling_name_is_ignored(tmp_path: Path) -> None:
    """A ``.sha256`` hex file next to plugin.json has no sibling artifact name."""
    root = _licensed_plugin(tmp_path)
    mystery = _plugin_json(root).parent / ".sha256"
    mystery.write_text(f"{_WRONG_DIGEST}\n", encoding="utf-8")
    assert detector._parse_checksum_entries(_WRONG_DIGEST + "\n", mystery) == ()
    assert _checksum_hits(root) == []


def test_sha256_file_without_plugin_json_sibling_is_not_first_party(
    tmp_path: Path,
) -> None:
    """Root ``*.sha256`` files are not next to plugin.json."""
    root = _licensed_plugin(tmp_path)
    (root / "README.sha256").write_text(f"{_WRONG_DIGEST}\n", encoding="utf-8")
    assert detector._is_first_party_checksum_file(root / "README.sha256") is False
    assert _checksum_hits(root) == []


def test_symlink_listed_payload_fails_closed(tmp_path: Path) -> None:
    """A listed symlink is not compared as the regular plugin artifact."""
    root = _licensed_plugin(tmp_path)
    payload = root / "payload.bin"
    payload.symlink_to(root / "LICENSE")
    (root / "SHA256SUMS").write_text(
        f"{_sha256(root / 'LICENSE')}  payload.bin\n",
        encoding="utf-8",
    )
    hits = _checksum_hits(root)
    assert hits
    assert "payload.bin" in hits[0].snippet


def test_checksum_helper_oserror_branches_fail_closed(
    tmp_path: Path, monkeypatch
) -> None:
    """Unreadable checksum paths fail closed instead of skipping verification."""
    root = _licensed_plugin(tmp_path)
    checksum = root / "SHA256SUMS"
    digest = _sha256(_plugin_json(root))
    checksum.write_text(f"{digest}  plugin.json\n", encoding="utf-8")
    sibling = _plugin_json(root).parent / "extra.sha256"
    sibling.write_text(f"{digest}\n", encoding="utf-8")

    original_is_file = Path.is_file

    def boom_is_file(self: Path) -> bool:
        if self.name == "plugin.json" and self.parent == sibling.parent:
            raise OSError("stat")
        return original_is_file(self)

    monkeypatch.setattr(Path, "is_file", boom_is_file)
    assert detector._is_first_party_checksum_file(sibling) is False
    monkeypatch.setattr(Path, "is_file", original_is_file)

    original_resolve = Path.resolve

    def boom_resolve(self: Path, *args, **kwargs):
        if self == root:
            raise OSError("resolve")
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", boom_resolve)
    assert detector._resolve_checksum_target(root, checksum, "plugin.json") is None
    monkeypatch.setattr(Path, "resolve", original_resolve)

    def boom_candidate_stat(self: Path) -> bool:
        if self == checksum.parent / "plugin.json":
            raise OSError("candidate")
        return original_is_file(self)

    monkeypatch.setattr(Path, "is_file", boom_candidate_stat)
    target = detector._resolve_checksum_target(root, checksum, "plugin.json")
    monkeypatch.setattr(Path, "is_file", original_is_file)
    assert target == _plugin_json(root) or target is None


def test_resolve_rejects_paths_outside_the_plugin_root(
    tmp_path: Path, monkeypatch
) -> None:
    """Resolved checksum targets must stay inside the plugin root."""
    root = _licensed_plugin(tmp_path)
    checksum = root / "SHA256SUMS"
    checksum.write_text(f"{_WRONG_DIGEST}  plugin.json\n", encoding="utf-8")
    original_relative_to = Path.is_relative_to

    def outside(self: Path, other: Path) -> bool:
        if self == _plugin_json(root).resolve():
            return False
        return original_relative_to(self, other)

    monkeypatch.setattr(Path, "is_relative_to", outside)
    assert detector._resolve_checksum_target(root, checksum, "plugin.json") is None


def test_parse_helpers_cover_empty_and_quoted_names() -> None:
    """Parser helpers reject empty names and accept quoted GNU rows."""
    empty = detector._parse_gnu_checksum_line(f"{_WRONG_DIGEST}  ")
    quoted = detector._parse_gnu_checksum_line(f'{_WRONG_DIGEST}  "plugin.json"')
    escaped = detector._checksum_listed_name_escapes("")
    nul = detector._checksum_listed_name_escapes("plugin.json\x00")
    drive = detector._checksum_listed_name_escapes("C:plugin.json")
    unc = detector._checksum_listed_name_escapes("\\\\host\\share")
    assert empty is None
    assert quoted == (_WRONG_DIGEST, "plugin.json")
    assert escaped is True
    assert nul is True
    assert drive is True
    assert unc is True


def test_missing_nested_plugin_json_does_not_fall_back_to_root_basename(
    tmp_path: Path,
) -> None:
    """A missing nested checksum target must not bind the root plugin manifest."""
    root = _licensed_plugin(tmp_path)
    digest = _sha256(_plugin_json(root))
    (root / "SHA256SUMS").write_text(
        f"{digest}  nested/plugin.json\n",
        encoding="utf-8",
    )
    hits = _checksum_hits(root)
    assert hits
    assert "nested/plugin.json" in hits[0].snippet


def test_matching_dot_prefixed_regular_filename_is_not_traversal(
    tmp_path: Path,
) -> None:
    """A regular filename beginning with two dots is not a parent segment."""
    root = _licensed_plugin(tmp_path)
    payload = root / "..safe.bin"
    payload.write_bytes(b"safe payload")
    (root / "SHA256SUMS").write_text(
        f"{_sha256(payload)}  ..safe.bin\n",
        encoding="utf-8",
    )
    assert _checksum_hits(root) == []
