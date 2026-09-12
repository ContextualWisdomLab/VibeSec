"""Official relative-path marketplace source contracts for Claude plugin receipts."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import build_claude_plugin_scan_receipt


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_CATALOG_REPOSITORY = "anthropics/claude-plugins-official"
_PLUGIN_REPOSITORY = "https://github.com/example/safe-plugin.git"


def _write_json(path: Path, payload: object) -> None:
    """Write deterministic JSON fixture bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _plugin(root: Path) -> Path:
    """Write one pinned local plugin identity that satisfies package policy."""
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


def _catalog(source: str) -> dict[str, object]:
    """Return one catalog entry using Claude Code's documented string source form."""
    return {
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


def _catalog_bytes(payload: object) -> bytes:
    """Return exact deterministic bytes supplied to receipt hashing."""
    return (json.dumps(payload, indent=2) + "\n").encode()


def test_receipt_api_accepts_documented_relative_marketplace_source(
    tmp_path: Path,
) -> None:
    """A documented ``./...`` source remains valid after selector centralization."""
    root = _plugin(tmp_path / "plugin")
    catalog = _catalog("./plugins/safe-plugin")

    receipt = build_claude_plugin_scan_receipt(
        root,
        catalog_payload=catalog,
        catalog_bytes=_catalog_bytes(catalog),
    )

    assert receipt.scan_result == "pass"
    assert receipt.plugin_name == "safe-plugin"
    assert receipt.catalog_repository == _CATALOG_REPOSITORY
    assert receipt.catalog_commit_sha == _PINNED_COMMIT
    assert "claude-plugin-source-mismatch" not in receipt.finding_summary


def test_receipt_api_rejects_relative_marketplace_source_escape(tmp_path: Path) -> None:
    """String sources cannot escape the marketplace root through parent traversal."""
    root = _plugin(tmp_path / "plugin")
    catalog = _catalog("../outside/safe-plugin")

    receipt = build_claude_plugin_scan_receipt(
        root,
        catalog_payload=catalog,
        catalog_bytes=_catalog_bytes(catalog),
    )

    assert receipt.scan_result == "fail"
    assert "claude-plugin-source-mismatch" in receipt.finding_summary
