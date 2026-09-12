"""SARIF 2.1.0 documents must stay semantically bound to plugin receipts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from appguardrail_core.claude_plugin_detector import build_claude_plugin_scan_receipt
from appguardrail_core.claude_plugin_sarif import (
    finding_summary_to_sarif,
    receipt_sarif_is_consistent,
    sarif_document_sha256,
)
from scanner.cli.appguardrail import main


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_SECRET = "sk-sarif-receipt-must-not-leak"
_UNDECLARED_RULE = "claude-plugin-undeclared-executable"


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _pass_plugin(root: Path) -> Path:
    """Write a pinned licensed plugin that satisfies current admission policy."""
    manifest = {
        "name": "safe-plugin",
        "version": "1.0.0",
        "source": {
            "source": "github",
            "repo": "example/safe-plugin",
            "ref": _PINNED_COMMIT,
        },
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    _write_json(root / ".claude-plugin" / "marketplace.json", manifest)
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
    """Write a plugin whose manifest contains a provider secret and bidi mark."""
    _write_json(
        root / ".claude-plugin" / "plugin.json",
        {
            "name": "leaky\u202e",
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


def _bound_sarif(receipt: object) -> dict:
    """Rebuild the SARIF document that the receipt sarif_sha256 must hash."""
    return finding_summary_to_sarif(
        receipt.finding_summary,
        tool_version=receipt.scanner_version,
    )


def test_pinned_plugin_sarif_sha256_is_stable_and_consistent(tmp_path: Path) -> None:
    """Two scans of a pinned licensed plugin bind the same empty-or-consistent SARIF."""
    first = build_claude_plugin_scan_receipt(_pass_plugin(tmp_path / "a"))
    second = build_claude_plugin_scan_receipt(_pass_plugin(tmp_path / "b"))
    sarif = _bound_sarif(first)

    assert first.sarif_sha256 == second.sarif_sha256
    assert first.finding_summary == second.finding_summary
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert first.sarif_sha256 == sarif_document_sha256(sarif)
    assert receipt_sarif_is_consistent(first.finding_summary, sarif)
    assert len(sarif["runs"][0]["results"]) == len(first.finding_summary)


def test_undeclared_executable_rule_id_is_in_receipt_and_sarif(tmp_path: Path) -> None:
    """An undeclared hook changes both finding_summary and the bound SARIF digest."""
    clean = build_claude_plugin_scan_receipt(_pass_plugin(tmp_path / "clean"))
    dirty_root = _undeclared_plugin(tmp_path / "dirty")
    dirty = build_claude_plugin_scan_receipt(dirty_root)
    sarif = _bound_sarif(dirty)
    rule_ids = [result["ruleId"] for result in sarif["runs"][0]["results"]]

    assert _UNDECLARED_RULE in dirty.finding_summary
    assert _UNDECLARED_RULE in rule_ids
    assert dirty.finding_summary != clean.finding_summary
    assert dirty.sarif_sha256 != clean.sarif_sha256
    assert dirty.sarif_sha256 == sarif_document_sha256(sarif)
    assert receipt_sarif_is_consistent(dirty.finding_summary, sarif)
    assert len(rule_ids) == len(dirty.finding_summary)
    serialized = json.dumps(sarif)
    assert "echo hidden" not in serialized


def test_swapped_sarif_rule_id_fails_consistency_check(tmp_path: Path) -> None:
    """Swapping one SARIF result ruleId against the receipt summary must fail."""
    receipt = build_claude_plugin_scan_receipt(_undeclared_plugin(tmp_path / "plugin"))
    sarif = _bound_sarif(receipt)
    swapped = json.loads(json.dumps(sarif))
    swapped["runs"][0]["results"][0]["ruleId"] = "not-the-receipt-rule"

    assert receipt_sarif_is_consistent(receipt.finding_summary, sarif)
    assert not receipt_sarif_is_consistent(receipt.finding_summary, swapped)
    extra = json.loads(json.dumps(sarif))
    extra["runs"][0]["results"].append({"ruleId": "extra-rule"})
    missing = json.loads(json.dumps(sarif))
    missing["runs"][0]["results"] = []
    assert not receipt_sarif_is_consistent(receipt.finding_summary, extra)
    assert not receipt_sarif_is_consistent(receipt.finding_summary, missing)


def test_scan_plugin_cli_receipt_includes_bound_sarif_sha256(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """scan-plugin stdout receipt sarif_sha256 hashes the bound SARIF document."""
    root = _pass_plugin(tmp_path / "plugin")

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        ["scan-plugin", "--plugin-root", str(root)],
    )

    payload = json.loads(stdout)
    sarif = finding_summary_to_sarif(
        payload["finding_summary"],
        tool_version=payload["scanner_version"],
    )
    assert code == 0
    assert payload["scan_result"] == "pass"
    assert payload["sarif_sha256"] == sarif_document_sha256(sarif)
    assert receipt_sarif_is_consistent(payload["finding_summary"], sarif)
    assert _SECRET not in stdout
    assert _SECRET not in stderr


def test_sarif_and_receipt_omit_raw_secrets_and_bidi(tmp_path: Path) -> None:
    """Bound SARIF and the receipt must not echo secret literals or raw bidi."""
    receipt = build_claude_plugin_scan_receipt(_leaky_plugin(tmp_path / "leaky"))
    sarif = _bound_sarif(receipt)
    serialized = json.dumps(receipt.as_dict()) + json.dumps(sarif)

    assert "claude-plugin-provider-secret" in receipt.finding_summary
    assert receipt_sarif_is_consistent(receipt.finding_summary, sarif)
    assert _SECRET not in serialized
    assert "OPENAI_API_KEY" not in serialized
    assert "\u202e" not in serialized


def test_receipt_sarif_consistency_rejects_malformed_logs() -> None:
    """Malformed SARIF documents are not semantically consistent with a receipt."""
    summary = (_UNDECLARED_RULE,)
    valid = finding_summary_to_sarif(summary, tool_version="0.1.1")

    assert receipt_sarif_is_consistent(summary, valid)
    assert not receipt_sarif_is_consistent(summary, "not-a-log")
    assert not receipt_sarif_is_consistent(summary, {"version": "2.0.0", "runs": []})
    assert not receipt_sarif_is_consistent(summary, {"version": "2.1.0", "runs": []})
    assert not receipt_sarif_is_consistent(
        summary, {"version": "2.1.0", "runs": ["not-a-run"]}
    )
    assert not receipt_sarif_is_consistent(
        summary, {"version": "2.1.0", "runs": [{"results": "nope"}]}
    )
    assert not receipt_sarif_is_consistent(
        summary, {"version": "2.1.0", "runs": [{"results": ["not-a-result"]}]}
    )
    assert not receipt_sarif_is_consistent(
        summary, {"version": "2.1.0", "runs": [{"results": [{"ruleId": ""}]}]}
    )
    assert not receipt_sarif_is_consistent((), valid)
