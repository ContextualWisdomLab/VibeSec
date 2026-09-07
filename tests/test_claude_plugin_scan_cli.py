"""CLI contracts for scanning a materialized Claude plugin artifact."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scanner.cli.appguardrail import main


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_SECRET = "sk-scan-cli-must-not-leak"
_REQUIRED_RECEIPT_KEYS = (
    "scan_receipt_id",
    "scanner_name",
    "scanner_version",
    "scanner_policy_sha256",
    "catalog_repository",
    "catalog_commit_sha",
    "marketplace_blob_sha",
    "marketplace_entry_sha256",
    "plugin_name",
    "plugin_version",
    "source_repository",
    "source_commit_sha",
    "source_path",
    "artifact_sha256",
    "file_count",
    "scanned_byte_count",
    "capability_inventory_sha256",
    "sarif_sha256",
    "finding_summary",
    "license_evidence_summary",
    "scan_started_at",
    "scan_completed_at",
    "scan_result",
)


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _pass_plugin(root: Path) -> Path:
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


def _undeclared_plugin(root: Path) -> Path:
    """Write a pinned licensed plugin with an undeclared executable hook."""
    _pass_plugin(root)
    hook = root / "hooks" / "hidden.sh"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho hidden\n", encoding="utf-8")
    return root


def _leaky_plugin(root: Path) -> Path:
    """Write a plugin whose manifest contains a provider secret literal."""
    _write_json(
        root / ".claude-plugin" / "plugin.json",
        {
            "name": "leaky",
            "version": "0.0.1",
            "env": {"OPENAI_API_KEY": _SECRET},
            "source": {"ref": "main"},
        },
    )
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _run_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
) -> tuple[int, str, str]:
    """Invoke the public AppGuardrail entrypoint and return exit code plus streams."""
    monkeypatch.setattr(sys, "argv", ["appguardrail", *argv])
    with pytest.raises(SystemExit) as excinfo:
        main()
    captured = capsys.readouterr()
    code = excinfo.value.code
    return (0 if code is None else int(code)), captured.out, captured.err


def test_scan_plugin_pass_exits_zero_and_prints_receipt_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A clean materialized plugin prints the deterministic receipt and exits 0."""
    root = _pass_plugin(tmp_path / "plugin")
    marketplace = root / ".claude-plugin" / "marketplace.json"

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        [
            "scan-plugin",
            "--plugin-root",
            str(root),
            "--marketplace-entry",
            str(marketplace),
        ],
    )

    payload = json.loads(stdout)
    assert code == 0
    assert payload["scan_result"] == "pass"
    assert payload["plugin_name"] == "safe-plugin"
    for key in _REQUIRED_RECEIPT_KEYS:
        assert key in payload
    assert "admitted" not in payload
    assert _SECRET not in stdout
    assert _SECRET not in stderr


def test_scan_plugin_undeclared_executable_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An undeclared hook fails closed and still emits a receipt without secrets."""
    root = _undeclared_plugin(tmp_path / "plugin")

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        ["scan-plugin", "--plugin-root", str(root)],
    )

    payload = json.loads(stdout)
    assert code != 0
    assert payload["scan_result"] == "fail"
    assert "claude-plugin-undeclared-executable" in payload["finding_summary"]
    for key in _REQUIRED_RECEIPT_KEYS:
        assert key in payload
    assert "echo hidden" not in stdout
    assert "echo hidden" not in stderr


def test_scan_plugin_missing_root_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing plugin root must not emit a pass receipt."""
    missing = tmp_path / "absent-plugin"

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        ["scan-plugin", "--plugin-root", str(missing)],
    )

    assert code != 0
    assert "scan_result" not in stdout
    assert "plugin root" in stderr.lower()
    assert _SECRET not in stdout
    assert _SECRET not in stderr
    with pytest.raises(json.JSONDecodeError):
        json.loads(stdout or "")


def test_scan_plugin_receipt_json_omits_secret_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Receipt JSON written to stdout or a file must not echo secret literals."""
    root = _leaky_plugin(tmp_path / "plugin")
    receipt_path = tmp_path / "out" / "receipt.json"

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        [
            "scan-plugin",
            "--plugin-root",
            str(root),
            "--receipt-json",
            str(receipt_path),
        ],
    )

    serialized = receipt_path.read_text(encoding="utf-8")
    payload = json.loads(serialized)
    assert code != 0
    assert payload["scan_result"] == "fail"
    assert _SECRET not in serialized
    assert _SECRET not in stdout
    assert _SECRET not in stderr
    assert "OPENAI_API_KEY" not in serialized
    assert "OPENAI_API_KEY" not in stdout
    assert "OPENAI_API_KEY" not in stderr
    for key in _REQUIRED_RECEIPT_KEYS:
        assert key in payload
