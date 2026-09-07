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
    if marketplace_entry is not None:
        status = _validate_marketplace_entry(marketplace_entry, err)
        if status != 0:
            return status
    receipt = build_claude_plugin_scan_receipt(plugin_root)
    verification = verify_plugin_scan_receipt(receipt, plugin_root)
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


def _validate_marketplace_entry(path: Path, err: TextIO) -> int:
    """Fail closed unless ``path`` is a bounded regular JSON catalog file."""
    if path.is_symlink() or not path.is_file():
        print(_ERROR_MARKETPLACE, file=err)
        return 1
    try:
        data = path.read_bytes()
    except OSError:
        print(_ERROR_MARKETPLACE, file=err)
        return 1
    if len(data) > MAX_MARKETPLACE_BYTES:
        print(_ERROR_MARKETPLACE_SIZE, file=err)
        return 1
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print(_ERROR_MARKETPLACE_JSON, file=err)
        return 1
    if not isinstance(payload, (dict, list)):
        print(_ERROR_MARKETPLACE_JSON, file=err)
        return 1
    return 0


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
