"""Scan a materialized Claude plugin artifact and emit the existing receipt.

This is a CLI adapter over ``build_claude_plugin_scan_receipt`` and
``verify_plugin_scan_receipt``. It does not fork the receipt schema, does not
reimplement package detectors, and does not treat ``scan_result=pass`` as
Noema admission.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from appguardrail_core.claude_plugin_detector import (
    build_claude_plugin_scan_receipt,
    verify_plugin_scan_receipt,
)

MAX_MARKETPLACE_BYTES = 1_000_000
_ERROR_PLUGIN_ROOT = "plugin root is missing or not a directory"
_ERROR_MARKETPLACE = "marketplace entry is missing or not a file"
_ERROR_MARKETPLACE_SIZE = "marketplace entry exceeds the bounded size"
_ERROR_MARKETPLACE_JSON = "marketplace entry is not valid JSON"
_ERROR_MARKETPLACE_IDENTITY = "marketplace catalog does not contain one matching plugin entry"
_ERROR_RECEIPT_WRITE = "cannot write receipt"
_ERROR_RECEIPT_STALE = "receipt does not match the scanned artifact"


def cmd_scan_plugin(args: object) -> int:
    """Scan one materialized plugin from the AppGuardrail argparse namespace.

    Args:
        args: Namespace with ``plugin_root`` and optional ``marketplace_entry``
            and ``receipt_json`` paths.

    Returns:
        0 when ``scan_result`` is pass; nonzero otherwise. Secret literals
        are never printed.
    """
    marketplace = getattr(args, "marketplace_entry", None)
    receipt_json = getattr(args, "receipt_json", None)
    return scan_plugin_artifact(
        Path(getattr(args, "plugin_root", "") or ""),
        marketplace_entry=Path(marketplace) if marketplace else None,
        receipt_json=Path(receipt_json) if receipt_json else None,
    )


def scan_plugin_artifact(
    plugin_root: Path,
    marketplace_entry: Path | None = None,
    receipt_json: Path | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Scan a materialized plugin tree and emit a deterministic receipt.

    Args:
        plugin_root: Local materialized plugin directory.
        marketplace_entry: Optional marketplace catalog JSON path.
        receipt_json: Optional bounded file for the receipt JSON.
        stdout: Receipt stream when ``receipt_json`` is omitted.
        stderr: Fail-closed diagnostic stream.

    Returns:
        0 when the exact artifact satisfies the exact AppGuardrail policy.
        Nonzero on missing inputs, stale verification, or ``scan_result``
        other than pass. Secret literals, raw bidi, and unbounded plugin
        text are never written. ``scan_result=pass`` is not admission.
    """
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    if not str(plugin_root) or plugin_root.is_symlink() or not plugin_root.is_dir():
        print(_ERROR_PLUGIN_ROOT, file=err)
        return 1
    catalog_payload: object | None = None
    catalog_bytes: bytes | None = None
    if marketplace_entry is not None:
        status, catalog_payload, catalog_bytes = _load_marketplace_catalog(
            marketplace_entry, err
        )
        if status != 0:
            return status
        status, catalog_payload = _select_marketplace_entry(
            catalog_payload, plugin_root, err
        )
        if status != 0:
            return status
    receipt = build_claude_plugin_scan_receipt(
        plugin_root,
        catalog_payload=catalog_payload,
        catalog_bytes=catalog_bytes,
    )
    verification = verify_plugin_scan_receipt(
        receipt,
        plugin_root,
        catalog_payload=catalog_payload,
        catalog_bytes=catalog_bytes,
    )
    if not verification.matches:
        print(_ERROR_RECEIPT_STALE, file=err)
        return 1
    payload = json.dumps(receipt.as_dict(), sort_keys=True, separators=(",", ":"))
    if receipt_json is not None:
        if _write_receipt(receipt_json, payload, err) != 0:
            return 1
    else:
        print(payload, file=out)
    return 0 if receipt.scan_result == "pass" else 1


def _load_marketplace_catalog(
    path: Path, err: TextIO
) -> tuple[int, object | None, bytes | None]:
    """Return parsed catalog bytes or a fail-closed status."""
    if path.is_symlink() or not path.is_file():
        print(_ERROR_MARKETPLACE, file=err)
        return 1, None, None
    try:
        data = path.read_bytes()
    except OSError:
        print(_ERROR_MARKETPLACE, file=err)
        return 1, None, None
    if len(data) > MAX_MARKETPLACE_BYTES:
        print(_ERROR_MARKETPLACE_SIZE, file=err)
        return 1, None, None
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print(_ERROR_MARKETPLACE_JSON, file=err)
        return 1, None, None
    if not isinstance(payload, dict):
        print(_ERROR_MARKETPLACE_JSON, file=err)
        return 1, None, None
    return 0, payload, data


def _materialized_plugin_name(root: Path) -> str:
    """Return the local plugin name used to select one catalog entry."""
    path = root / ".claude-plugin" / "plugin.json"
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    name = payload.get("name")
    return name if isinstance(name, str) else ""


def _normalize_marketplace_entry(entry: dict[str, object]) -> dict[str, object]:
    """Normalize current URL/SHA catalog sources for the shared identity parser."""
    normalized = dict(entry)
    source = entry.get("source")
    if isinstance(source, str):
        normalized["source"] = {"path": source}
        return normalized
    if not isinstance(source, dict):
        return normalized
    source_identity = dict(source)
    url = source.get("url")
    if "repo" not in source_identity and isinstance(url, str):
        source_identity["repo"] = url
    sha = source.get("sha")
    if isinstance(sha, str):
        source_identity["ref"] = sha
    normalized["source"] = source_identity
    return normalized


def _select_marketplace_entry(
    payload: object | None,
    plugin_root: Path,
    err: TextIO,
) -> tuple[int, object | None]:
    """Select exactly one canonical catalog entry for the materialized plugin."""
    if not isinstance(payload, dict):
        print(_ERROR_MARKETPLACE_JSON, file=err)
        return 1, None
    plugins = payload.get("plugins")
    if plugins is None:
        return 0, payload
    if not isinstance(plugins, list):
        print(_ERROR_MARKETPLACE_JSON, file=err)
        return 1, None
    plugin_name = _materialized_plugin_name(plugin_root)
    matches = [
        item
        for item in plugins
        if isinstance(item, dict) and item.get("name") == plugin_name
    ]
    if not plugin_name or len(matches) != 1:
        print(_ERROR_MARKETPLACE_IDENTITY, file=err)
        return 1, None
    selected = dict(payload)
    selected["plugins"] = [_normalize_marketplace_entry(matches[0])]
    return 0, selected


def _write_receipt(path: Path, payload: str, err: TextIO) -> int:
    """Write receipt JSON to a bounded regular file without following symlinks."""
    if path.is_symlink() or path.is_dir():
        print(_ERROR_RECEIPT_WRITE, file=err)
        return 1
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload + "\n", encoding="utf-8")
    except OSError:
        print(_ERROR_RECEIPT_WRITE, file=err)
        return 1
    return 0
