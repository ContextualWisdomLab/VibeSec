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
