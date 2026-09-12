"""Archive admission must bound aggregate bytes before materialization."""

from __future__ import annotations

import io
from pathlib import Path
import tarfile
import zipfile

from appguardrail_core import claude_plugin_detector as detector


_BOMB_RULE = "claude-plugin-decompression-bomb"


def _write_zip(path: Path, members: dict[str, bytes]) -> Path:
    """Write stored members so each member stays below the ratio threshold."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return path


def _write_tar(path: Path, members: dict[str, bytes]) -> Path:
    """Write regular tar members without per-member compression amplification."""
    with tarfile.open(path, "w") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return path


def _assert_aggregate_budget_fails_closed(
    archive: Path, extract_root: Path
) -> None:
    """Require aggregate admission to reject before writing any member."""
    hits = detector.inspect_claude_plugin_archive(archive, extract_root)

    assert any(hit.rule_id == _BOMB_RULE for hit in hits)
    assert list(extract_root.iterdir()) == []


def test_zip_aggregate_uncompressed_bytes_are_bounded_before_extract(
    tmp_path: Path, monkeypatch
) -> None:
    """Many individually safe zip members cannot exceed the package byte budget."""
    archive = _write_zip(
        tmp_path / "payload.zip",
        {"one.bin": b"a" * 40, "two.bin": b"b" * 40},
    )
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 64)

    _assert_aggregate_budget_fails_closed(archive, extract_root)


def test_tar_aggregate_uncompressed_bytes_are_bounded_before_extract(
    tmp_path: Path, monkeypatch
) -> None:
    """Many individually safe tar members cannot exceed the package byte budget."""
    archive = _write_tar(
        tmp_path / "payload.tar",
        {"one.bin": b"a" * 40, "two.bin": b"b" * 40},
    )
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 64)

    _assert_aggregate_budget_fails_closed(archive, extract_root)


def test_honest_small_zip_still_extracts_under_budget(tmp_path: Path) -> None:
    """A zip whose members sum below the package budget is still extracted."""
    archive = _write_zip(tmp_path / "payload.zip", {"LICENSE": b"MIT\n"})
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    hits = detector.inspect_claude_plugin_archive(archive, extract_root)

    assert all(hit.rule_id != _BOMB_RULE for hit in hits)
    assert (extract_root / "LICENSE").read_bytes() == b"MIT\n"


def test_zip_directory_members_are_omitted_from_the_budget(
    tmp_path: Path, monkeypatch
) -> None:
    """Directory entries do not count toward the uncompressed byte budget."""
    archive = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as handle:
        handle.writestr("docs/", b"")
        handle.writestr("docs/one.bin", b"a" * 40)
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 64)
    hits = detector.inspect_claude_plugin_archive(archive, extract_root)

    assert all(hit.rule_id != _BOMB_RULE for hit in hits)
    assert (extract_root / "docs" / "one.bin").read_bytes() == b"a" * 40


def test_escaping_members_are_omitted_from_the_budget(
    tmp_path: Path, monkeypatch
) -> None:
    """Traversal members keep the traversal class and are not extracted."""
    archive = _write_zip(
        tmp_path / "payload.zip",
        {"../escape.bin": b"a" * 80, "LICENSE": b"MIT\n"},
    )
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 64)
    hits = detector.inspect_claude_plugin_archive(archive, extract_root)

    assert any(hit.rule_id == "claude-plugin-archive-path-traversal" for hit in hits)
    assert all(hit.rule_id != _BOMB_RULE for hit in hits)
    assert list(extract_root.iterdir()) == [extract_root / "LICENSE"]


def test_unreadable_archive_metadata_yields_no_budget_hit(tmp_path: Path) -> None:
    """Broken zip metadata is not a silent extract and is not a fake budget hit."""
    archive = tmp_path / "payload.zip"
    archive.write_bytes(b"not-a-zip")
    extract_root = tmp_path / "extract"
    extract_root.mkdir()
    hits = detector._archive_aggregate_budget_hits(archive, extract_root)
    assert hits == ()


def test_non_archive_name_has_zero_aggregate_bytes(tmp_path: Path) -> None:
    """A non-archive filename is not treated as zip/tar metadata."""
    path = tmp_path / "notes.txt"
    path.write_text("hello\n", encoding="utf-8")
    assert detector._archive_regular_in_root_bytes(path, tmp_path) == 0
