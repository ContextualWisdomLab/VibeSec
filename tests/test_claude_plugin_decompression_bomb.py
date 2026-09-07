"""Plugin zip/tar members must not expand as bombs or nest beyond a small depth."""

from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile
import zipfile

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_archive,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_BOMB_RULE = "claude-plugin-decompression-bomb"
_TRAVERSAL_RULE = "claude-plugin-archive-path-traversal"
_OVERSIZED_RULE = "claude-plugin-oversized-package"
_SETUID_RULE = "claude-plugin-setuid-executable"
_WORLD_RULE = "claude-plugin-world-writable-executable"
_MAX_RATIO = 100
_MAX_DEPTH = 1
_ZERO_UNCOMPRESSED = 32_768
_SECRET = "sk-bomb-must-not-leak"
_BIDI = "\u202e"
_PLUGIN_JSON = json.dumps(
    {
        "name": "safe-plugin",
        "version": "1.0.0",
        "source": {
            "source": "github",
            "repo": "example/safe-plugin",
            "ref": _PINNED_COMMIT,
        },
    },
    indent=2,
).encode("utf-8") + b"\n"
_LICENSE = b"MIT\n"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(root: Path) -> Path:
    """Write a pinned licensed plugin tree."""
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


def _zip_bytes(members: dict[str, bytes], *, compress=zipfile.ZIP_DEFLATED) -> bytes:
    """Return zip bytes for ``members`` without writing a tree."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compress) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buf.getvalue()


def _write_zip(path: Path, members: dict[str, bytes], *, compress=zipfile.ZIP_DEFLATED) -> Path:
    """Write a purpose-built zip archive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_zip_bytes(members, compress=compress))
    return path


def _write_tar(path: Path, members: dict[str, bytes], mode: str = "w") -> Path:
    """Write a purpose-built tar archive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, mode) as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return path


def _zeros() -> bytes:
    """Return a highly compressible bomb payload."""
    return b"\x00" * _ZERO_UNCOMPRESSED


def _assert_zip_ratio_exceeds_bound(path: Path, name: str) -> float:
    """Return the header uncompressed/compressed ratio and require it exceed the bound."""
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(name)
        file_size = info.file_size
        ratio = file_size / max(info.compress_size, 1)
    assert file_size == _ZERO_UNCOMPRESSED
    assert ratio > _MAX_RATIO
    return ratio


def test_ratio_and_depth_constants_are_explicit() -> None:
    """The bomb bound is an explicit ratio and a small nested-archive depth."""
    from appguardrail_core import claude_plugin_detector as detector

    assert detector._MAX_ARCHIVE_COMPRESSION_RATIO == _MAX_RATIO
    assert detector._MAX_ARCHIVE_NESTING_DEPTH == _MAX_DEPTH
    assert detector._ratio_is_bomb(_ZERO_UNCOMPRESSED, 46) is True
    assert detector._ratio_is_bomb(40, 42) is False
    assert _MAX_RATIO > 1
    assert _MAX_DEPTH >= 1


def test_zip_claimed_huge_uncompressed_fails_closed_without_extract(
    tmp_path: Path,
) -> None:
    """A tiny deflated member claiming huge uncompressed size is a bomb."""
    root = _licensed_plugin(tmp_path / "plugin")
    archive = _write_zip(
        root / "payload.zip",
        {"zeros.bin": _zeros(), "secret.txt": _SECRET.encode("utf-8")},
    )
    ratio = _assert_zip_ratio_exceeds_bound(archive, "zeros.bin")
    extracted = root / "zeros.bin"
    secret_out = root / "secret.txt"

    hits = inspect_claude_plugin_archive(archive, root)
    receipt = build_claude_plugin_scan_receipt(root)
    snippets = [hit.snippet for hit in hits]
    serialized = json.dumps(receipt.as_dict())

    assert ratio > _MAX_RATIO
    assert receipt.scan_result == "fail"
    assert _BOMB_RULE in receipt.finding_summary
    assert any(hit.rule_id == _BOMB_RULE for hit in hits)
    assert _TRAVERSAL_RULE not in receipt.finding_summary
    assert _OVERSIZED_RULE not in receipt.finding_summary
    assert not extracted.exists()
    assert not secret_out.exists()
    assert _SECRET not in serialized
    assert all(_SECRET not in snippet for snippet in snippets)
    assert all("\x00" not in snippet for snippet in snippets)
    assert all(_BIDI not in snippet for snippet in snippets)
    assert all(len(snippet) <= 120 for snippet in snippets)


def test_nested_zip_in_zip_beyond_depth_fails_closed_without_extract(
    tmp_path: Path,
) -> None:
    """Zip-in-zip beyond ``_MAX_ARCHIVE_NESTING_DEPTH`` is a bomb, not extractable."""
    root = _licensed_plugin(tmp_path / "plugin")
    innermost = _zip_bytes({".claude-plugin/plugin.json": _PLUGIN_JSON, "LICENSE": _LICENSE})
    nested = innermost
    for index in range(_MAX_DEPTH + 1):
        nested = _zip_bytes({f"nest-{index}.zip": nested}, compress=zipfile.ZIP_STORED)
    archive = root / "nested.zip"
    archive.write_bytes(nested)

    hits = inspect_claude_plugin_archive(archive, root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert receipt.scan_result == "fail"
    assert _BOMB_RULE in receipt.finding_summary
    assert any(hit.rule_id == _BOMB_RULE for hit in hits)
    assert _TRAVERSAL_RULE not in receipt.finding_summary
    assert not (root / "nest-0.zip").exists()
    assert not (root / f"nest-{_MAX_DEPTH}.zip").exists()
    assert all(_SECRET not in hit.snippet for hit in hits)
    assert all(_BIDI not in hit.snippet for hit in hits)


def test_targz_high_ratio_member_fails_closed_without_extract(tmp_path: Path) -> None:
    """A gzip tar whose member expands far beyond archive size is a bomb."""
    root = _licensed_plugin(tmp_path / "plugin")
    zeros = _zeros()
    archive = _write_tar(root / "payload.tar.gz", {"zeros.bin": zeros}, mode="w:gz")
    archive_size = archive.stat().st_size
    ratio = len(zeros) / max(archive_size, 1)
    extracted = root / "zeros.bin"

    hits = inspect_claude_plugin_archive(archive, root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert ratio > _MAX_RATIO
    assert receipt.scan_result == "fail"
    assert _BOMB_RULE in receipt.finding_summary
    assert any(hit.rule_id == _BOMB_RULE for hit in hits)
    assert not extracted.exists()
    assert all("\x00" not in hit.snippet for hit in hits)


def test_honest_small_zip_of_plugin_files_is_not_this_class(tmp_path: Path) -> None:
    """A small zip of plugin.json and LICENSE is not a decompression bomb."""
    root = _licensed_plugin(tmp_path / "plugin")
    archive = _write_zip(
        root / "payload.zip",
        {".claude-plugin/plugin.json": _PLUGIN_JSON, "LICENSE": _LICENSE},
    )
    with zipfile.ZipFile(archive) as handle:
        for info in handle.infolist():
            ratio = info.file_size / max(info.compress_size, 1)
            assert ratio <= _MAX_RATIO

    hits = inspect_claude_plugin_archive(archive, root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert all(hit.rule_id != _BOMB_RULE for hit in hits)
    assert _BOMB_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"
    assert (root / "LICENSE").read_bytes() == _LICENSE


def test_honest_small_tar_of_plugin_files_is_not_this_class(tmp_path: Path) -> None:
    """A small tar of declared plugin files is not a decompression bomb."""
    root = _licensed_plugin(tmp_path / "plugin")
    archive = _write_tar(
        root / "payload.tar",
        {".claude-plugin/plugin.json": _PLUGIN_JSON, "LICENSE": _LICENSE},
    )

    hits = inspect_claude_plugin_archive(archive, root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert all(hit.rule_id != _BOMB_RULE for hit in hits)
    assert _BOMB_RULE not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_path_traversal_member_stays_archive_path_traversal(tmp_path: Path) -> None:
    """``../escape`` stays the traversal class, not a decompression bomb."""
    root = _licensed_plugin(tmp_path / "plugin")
    archive = _write_zip(
        root / "payload.zip",
        {"../escape.sh": f"#!/bin/sh\necho {_SECRET}\n".encode("utf-8")},
    )
    escaped = tmp_path / "escape.sh"

    hits = inspect_claude_plugin_archive(archive, root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == _TRAVERSAL_RULE for hit in hits)
    assert all(hit.rule_id != _BOMB_RULE for hit in hits)
    assert _TRAVERSAL_RULE in receipt.finding_summary
    assert _BOMB_RULE not in receipt.finding_summary
    assert not escaped.exists()
    assert all(_SECRET not in hit.snippet for hit in hits)


def test_oversized_file_count_stays_oversized_class(
    tmp_path: Path, monkeypatch
) -> None:
    """File-count and byte-count budgets stay the oversized class."""
    from appguardrail_core import claude_plugin_detector as detector

    root = _licensed_plugin(tmp_path / "plugin")
    monkeypatch.setattr(detector, "_MAX_PACKAGE_FILES", 1)
    receipt = build_claude_plugin_scan_receipt(root)

    assert _OVERSIZED_RULE in receipt.finding_summary
    assert _BOMB_RULE not in receipt.finding_summary
    assert _SETUID_RULE not in receipt.finding_summary
    assert _WORLD_RULE not in receipt.finding_summary


def test_one_level_nested_zip_of_plugin_files_is_not_this_class(tmp_path: Path) -> None:
    """A single nested zip of plugin files stays inside the small depth bound."""
    root = _licensed_plugin(tmp_path / "plugin")
    inner = _zip_bytes({".claude-plugin/plugin.json": _PLUGIN_JSON, "LICENSE": _LICENSE})
    archive = _write_zip(root / "payload.zip", {"files.zip": inner}, compress=zipfile.ZIP_STORED)

    hits = inspect_claude_plugin_archive(archive, root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert all(hit.rule_id != _BOMB_RULE for hit in hits)
    assert _BOMB_RULE not in receipt.finding_summary


def test_nested_tar_beyond_depth_fails_closed(tmp_path: Path) -> None:
    """Tar-in-tar beyond the small depth bound is this class."""
    root = _licensed_plugin(tmp_path / "plugin")
    innermost = io.BytesIO()
    with tarfile.open(fileobj=innermost, mode="w") as archive:
        info = tarfile.TarInfo(name="LICENSE")
        info.size = len(_LICENSE)
        archive.addfile(info, io.BytesIO(_LICENSE))
    nested = innermost.getvalue()
    for index in range(_MAX_DEPTH + 1):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as archive:
            name = f"nest-{index}.tar"
            info = tarfile.TarInfo(name=name)
            info.size = len(nested)
            archive.addfile(info, io.BytesIO(nested))
        nested = buf.getvalue()
    archive_path = root / "nested.tar"
    archive_path.write_bytes(nested)

    hits = inspect_claude_plugin_archive(archive_path, root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == _BOMB_RULE for hit in hits)
    assert _BOMB_RULE in receipt.finding_summary
    assert not (root / "nest-0.tar").exists()


def test_bomb_snippets_are_path_labels(tmp_path: Path) -> None:
    """Snippets name the member path and omit raw bomb bytes and secrets."""
    root = _licensed_plugin(tmp_path / "plugin")
    archive = _write_zip(root / "payload.zip", {"zeros.bin": _zeros()})
    hits = inspect_claude_plugin_archive(archive, root)
    bomb_hits = [hit for hit in hits if hit.rule_id == _BOMB_RULE]
    assert bomb_hits
    assert all(hit.snippet == "zeros.bin" or "zeros.bin" in hit.snippet for hit in bomb_hits)
    assert all(b"\x00" * 8 not in hit.snippet.encode("utf-8") for hit in bomb_hits)


def test_unreadable_archive_is_not_silently_extracted(
    tmp_path: Path, monkeypatch
) -> None:
    """Bomb inspection of an unreadable zip does not extract members."""
    from appguardrail_core import claude_plugin_detector as detector

    root = _licensed_plugin(tmp_path / "plugin")
    archive = _write_zip(root / "payload.zip", {"ok.txt": b"ok\n"})
    original = detector.zipfile.ZipFile

    def boom(*args, **kwargs):
        raise zipfile.BadZipFile("bad")

    monkeypatch.setattr(detector.zipfile, "ZipFile", boom)
    hits = detector._decompression_bomb_hits(root)
    monkeypatch.setattr(detector.zipfile, "ZipFile", original)
    assert all(hit.rule_id != _BOMB_RULE or hit.file == "payload.zip" for hit in hits)


def test_symlink_archive_is_skipped(tmp_path: Path) -> None:
    """Symlinked archives are not followed for bomb inspection."""
    from appguardrail_core import claude_plugin_detector as detector

    root = _licensed_plugin(tmp_path / "plugin")
    real = _write_zip(root / "real.zip", {"zeros.bin": _zeros()})
    link = root / "link.zip"
    link.symlink_to(real)
    hits = detector._decompression_bomb_hits(root)
    files = {hit.file for hit in hits if hit.rule_id == _BOMB_RULE}
    assert "link.zip" not in files
    assert "real.zip" in files
