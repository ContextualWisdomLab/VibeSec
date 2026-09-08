"""Official ``metadata.pluginRoot`` marketplace source contracts."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import build_claude_plugin_scan_receipt


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_CATALOG_REPOSITORY = "anthropics/claude-plugins-official"
_PLUGIN_REPOSITORY = "https://github.com/example/safe-plugin.git"


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _plugin(root: Path) -> Path:
    identity = {
        "name": "safe-plugin",
        "version": "1.0.0",
        "source": {
            "source": "github",
            "repo": _PLUGIN_REPOSITORY,
            "ref": _PINNED_COMMIT,
        },
    }
    _write_json(root / ".claude-plugin" / "plugin.json", identity)
    _write_json(root / ".claude-plugin" / "marketplace.json", identity)
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _catalog(*, plugin_root: str | None, source: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "repository": _CATALOG_REPOSITORY,
        "commit": _PINNED_COMMIT,
        "plugins": [
            {
                "name": "safe-plugin",
                "version": "1.0.0",
                "source": source,
            }
        ],
    }
    if plugin_root is not None:
        payload["metadata"] = {"pluginRoot": plugin_root}
    return payload


def _receipt(root: Path, catalog: dict[str, object]):
    return build_claude_plugin_scan_receipt(
        root,
        catalog_payload=catalog,
        catalog_bytes=(json.dumps(catalog, indent=2) + "\n").encode(),
    )


def test_receipt_accepts_bare_source_under_safe_plugin_root(tmp_path: Path) -> None:
    """Claude Code v2.1.239+ bare names resolve below ``metadata.pluginRoot``."""
    receipt = _receipt(
        _plugin(tmp_path / "plugin"),
        _catalog(plugin_root="./plugins", source="safe-plugin"),
    )

    assert receipt.scan_result == "pass"
    assert "claude-plugin-source-mismatch" not in receipt.finding_summary


def test_receipt_rejects_bare_source_without_plugin_root(tmp_path: Path) -> None:
    """A bare source has no relative-path authority without ``pluginRoot``."""
    receipt = _receipt(
        _plugin(tmp_path / "plugin"),
        _catalog(plugin_root=None, source="safe-plugin"),
    )

    assert receipt.scan_result == "fail"
    assert "claude-plugin-source-mismatch" in receipt.finding_summary


def test_receipt_rejects_plugin_root_parent_traversal(tmp_path: Path) -> None:
    """The marketplace root cannot be escaped through ``pluginRoot``."""
    receipt = _receipt(
        _plugin(tmp_path / "plugin"),
        _catalog(plugin_root="../plugins", source="safe-plugin"),
    )

    assert receipt.scan_result == "fail"
    assert "claude-plugin-source-mismatch" in receipt.finding_summary


def test_receipt_rejects_non_bare_source_under_plugin_root(tmp_path: Path) -> None:
    """A slash-containing source still requires the explicit ``./`` form."""
    receipt = _receipt(
        _plugin(tmp_path / "plugin"),
        _catalog(plugin_root="./plugins", source="team/safe-plugin"),
    )

    assert receipt.scan_result == "fail"
    assert "claude-plugin-source-mismatch" in receipt.finding_summary
