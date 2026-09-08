"""Plugin trees and archives must fail closed on excessive path depth."""

from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile
import zipfile

from appguardrail_core import claude_plugin_detector as detector
from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_archive,
    scan_claude_plugin_package,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_DEPTH_RULE = "claude-plugin-excessive-path-depth"
_BOMB_RULE = "claude-plugin-decompression-bomb"
_TRAVERSAL_RULE = "claude-plugin-archive-path-traversal"
_OVERSIZED_RULE = "claude-plugin-oversized-package"
_MAX_DEPTH = 32
_SECRET = "sk-depth-must-not-leak"
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


def _nested_file(root: Path, components: int, name: str = "leaf.txt") -> Path:
    """Write a regular file whose relative path has ``components`` parts."""
    dirs = ["d"] * max(components - 1, 0)
    path = root.joinpath(*dirs, name) if dirs else root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("ok\n", encoding="utf-8")
    return path


def _depth_hits(root: Path):
    """Return excessive-path-depth hits from the package scan."""
    return [
        hit for hit in scan_claude_plugin_package(root) if hit.rule_id == _DEPTH_RULE
    ]


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    """Return zip bytes for ``members`` without writing a tree."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buf.getvalue()


def _write_zip(path: Path, members: dict[str, bytes]) -> Path:
    """Write a purpose-built zip archive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_zip_bytes(members))
    return path


def _write_tar(path: Path, members: dict[str, bytes]) -> Path:
    """Write a purpose-built tar archive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return path


def test_tree_path_deeper_than_bound_fails_admission(tmp_path: Path) -> None:
    """A materialized file nested past the bound is directory recursion."""
    root = _licensed_plugin(tmp_path)
    _nested_file(root, _MAX_DEPTH + 1)
    receipt = build_claude_plugin_scan_receipt(root)
    hits = _depth_hits(root)

    assert hits
    assert receipt.scan_result == "fail"
    assert _DEPTH_RULE in receipt.finding_summary
    assert _BOMB_RULE not in receipt.finding_summary
    assert _TRAVERSAL_RULE not in receipt.finding_summary


def test_tree_path_at_bound_is_not_this_class(tmp_path: Path) -> None:
    """A file at the exact component bound is not excessive depth."""
    root = _licensed_plugin(tmp_path)
    _nested_file(root, _MAX_DEPTH)
    receipt = build_claude_plugin_scan_receipt(root)

    assert _depth_hits(root) == []
    assert _DEPTH_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_zip_member_deeper_than_bound_fails_without_extract(tmp_path: Path) -> None:
    """A zip member with too many components fails closed and is not written."""
    root = _licensed_plugin(tmp_path)
    member = "/".join(["d"] * _MAX_DEPTH + ["leaf.txt"])
    archive = _write_zip(root / "payload.zip", {member: b"x\n"})
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    hits = inspect_claude_plugin_archive(archive, extract_root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == _DEPTH_RULE for hit in hits)
    assert _DEPTH_RULE in receipt.finding_summary
    assert not any(extract_root.rglob("leaf.txt"))


def test_tar_member_deeper_than_bound_fails_admission(tmp_path: Path) -> None:
    """A tar member nested past the bound is the same class."""
    root = _licensed_plugin(tmp_path)
    member = "/".join(["d"] * _MAX_DEPTH + ["leaf.txt"])
    _write_tar(root / "payload.tar", {member: b"x\n"})
    receipt = build_claude_plugin_scan_receipt(root)

    assert _depth_hits(root)
    assert receipt.scan_result == "fail"
    assert _DEPTH_RULE in receipt.finding_summary


def test_zip_slip_stays_traversal_not_this_class(tmp_path: Path) -> None:
    """``../`` archive members stay path-traversal, not depth."""
    root = _licensed_plugin(tmp_path)
    archive = _write_zip(root / "escape.zip", {"../outside.bin": b"x\n"})
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    hits = inspect_claude_plugin_archive(archive, extract_root)
    rule_ids = {hit.rule_id for hit in hits}

    assert _TRAVERSAL_RULE in rule_ids
    assert _DEPTH_RULE not in rule_ids


def test_nested_archive_is_not_this_class(tmp_path: Path) -> None:
    """A zip containing another zip is not excessive path depth."""
    inner = _zip_bytes({"inner.txt": b"x\n"})
    root = _licensed_plugin(tmp_path)
    archive = _write_zip(root / "outer.zip", {"nested.zip": inner})
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    hits = inspect_claude_plugin_archive(archive, extract_root)
    rule_ids = {hit.rule_id for hit in hits}

    assert _DEPTH_RULE not in rule_ids


def test_multiple_deep_files_emit_one_tree_finding(tmp_path: Path) -> None:
    """A deep tree emits one depth finding, not one per nested file."""
    root = _licensed_plugin(tmp_path)
    _nested_file(root, _MAX_DEPTH + 1, "one.txt")
    _nested_file(root, _MAX_DEPTH + 2, "two.txt")
    hits = _depth_hits(root)
    assert len(hits) == 1


def test_snippets_are_path_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets omit secrets and bidi even when a deep name contains them."""
    root = _licensed_plugin(tmp_path)
    _nested_file(root, _MAX_DEPTH + 1, f"{_SECRET}{_BIDI}.txt")
    hits = _depth_hits(root)
    receipt = build_claude_plugin_scan_receipt(root)
    payload = json.dumps(receipt.as_dict())

    assert hits
    for hit in hits:
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_path_component_helpers_cover_empty_dot_and_slash_edges() -> None:
    """Component counting ignores empty, ``.``, and mixed-separator noise."""
    assert detector._path_component_count("") == 0
    assert detector._path_component_count("/") == 0
    assert detector._path_component_count("././") == 0
    assert detector._path_component_count("a\\\\b/c") == 3
    assert detector._path_component_count("/d/" * _MAX_DEPTH + "leaf.txt") == _MAX_DEPTH + 1
    assert detector._path_exceeds_max_depth("leaf.txt") is False
    assert detector._path_exceeds_max_depth("/".join(["d"] * _MAX_DEPTH + ["x"])) is True


def test_path_depth_helpers_fail_closed_on_oserror(
    tmp_path: Path, monkeypatch
) -> None:
    """Unreadable tree entries and archives do not skip the depth bound."""
    root = _licensed_plugin(tmp_path)
    archive = _write_zip(root / "payload.zip", {"ok.txt": b"x\n"})
    original_relative_to = Path.relative_to

    def boom_relative(self: Path, other: Path):
        if self == archive:
            raise OSError("relative")
        return original_relative_to(self, other)

    monkeypatch.setattr(Path, "relative_to", boom_relative)
    assert detector._excessive_path_depth_hits(root) == ()
    monkeypatch.setattr(Path, "relative_to", original_relative_to)

    original_is_file = Path.is_file

    def boom_is_file(self: Path) -> bool:
        if self == archive:
            raise OSError("stat")
        return original_is_file(self)

    monkeypatch.setattr(Path, "is_file", boom_is_file)
    hits = detector._excessive_path_depth_hits(root)
    monkeypatch.setattr(Path, "is_file", original_is_file)
    assert all(hit.rule_id == _DEPTH_RULE for hit in hits)

    assert detector._archive_member_path_depth_hits(root / "missing.zip", root) == ()
    symlink = root / "link.zip"
    symlink.symlink_to(archive)
    assert detector._archive_member_names(symlink) == ((), False)
