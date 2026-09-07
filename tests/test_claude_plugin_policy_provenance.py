"""Plugin receipts must bind the exact AppGuardrail release and scan-policy bytes."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

from appguardrail_core import claude_plugin_detector as detector
from scanner.cli.appguardrail import __version__ as _RELEASE_VERSION


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_SECRET = "sk-provenance-must-not-leak"
_BIDI = "\u202e"
_SOURCE_REPOSITORY = "ContextualWisdomLab/appguardrail"


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


def test_honest_pinned_plugin_receipt_verifies_against_current_policy_and_version(
    tmp_path: Path,
) -> None:
    """An honest pinned plugin still verifies against the running policy and version."""
    root = _licensed_plugin(tmp_path)
    receipt = detector.build_claude_plugin_scan_receipt(root)
    verification = detector.verify_plugin_scan_receipt(receipt, root)

    assert receipt.scan_result == "pass"
    assert receipt.scanner_version == detector._SCANNER_VERSION == _RELEASE_VERSION
    assert receipt.scanner_policy_sha256 == detector._scanner_policy_sha256()
    assert verification.matches is True
    assert verification.mismatches == ()
    assert verification.admitted is False


def test_receipt_binds_policy_provenance_to_release_and_policy_bytes(
    tmp_path: Path,
) -> None:
    """The receipt records bounded provenance for the exact release and policy digest."""
    root = _licensed_plugin(tmp_path)
    receipt = detector.build_claude_plugin_scan_receipt(root)
    payload = receipt.as_dict()
    provenance = payload["policy_provenance"]

    assert isinstance(provenance, dict)
    assert provenance["schema_version"] == "1"
    assert provenance["source_repository"] == _SOURCE_REPOSITORY
    assert provenance["scanner_release_version"] == detector._SCANNER_VERSION
    assert provenance["scanner_policy_sha256"] == receipt.scanner_policy_sha256
    assert "scan_policy_sha256" not in payload
    assert payload["scanner_policy_sha256"] == detector._scanner_policy_sha256()
    assert _SECRET not in json.dumps(payload)
    assert _BIDI not in json.dumps(payload)


def test_mutated_scanner_policy_sha256_fails_verification(tmp_path: Path) -> None:
    """A swapped policy digest fails closed against the running scanner."""
    root = _licensed_plugin(tmp_path)
    receipt = detector.build_claude_plugin_scan_receipt(root)
    swapped = replace(receipt, scanner_policy_sha256="0" * 64)
    verification = detector.verify_plugin_scan_receipt(swapped, root)

    assert verification.matches is False
    assert "scanner_policy_sha256" in verification.mismatches
    assert verification.admitted is False


def test_mutated_scanner_version_fails_verification(tmp_path: Path) -> None:
    """A swapped scanner version fails closed against the running scanner."""
    root = _licensed_plugin(tmp_path)
    receipt = detector.build_claude_plugin_scan_receipt(root)
    swapped = replace(receipt, scanner_version="0.0.0")
    verification = detector.verify_plugin_scan_receipt(swapped, root)

    assert swapped.scanner_version != detector._SCANNER_VERSION
    assert verification.matches is False
    assert "scanner_version" in verification.mismatches
    assert verification.admitted is False


def test_identical_scans_share_policy_digest(tmp_path: Path) -> None:
    """Two identical source trees share the policy digest and provenance object."""
    left = detector.build_claude_plugin_scan_receipt(_licensed_plugin(tmp_path / "a"))
    right = detector.build_claude_plugin_scan_receipt(_licensed_plugin(tmp_path / "b"))

    assert left.scan_receipt_id == right.scan_receipt_id
    assert left.scanner_policy_sha256 == right.scanner_policy_sha256
    assert left.policy_provenance == right.policy_provenance
    assert left.policy_provenance.scanner_policy_sha256 == left.scanner_policy_sha256
    assert detector.verify_plugin_scan_receipt(left, tmp_path / "b").matches is True


def test_mutated_policy_provenance_fails_verification(tmp_path: Path) -> None:
    """A swapped provenance identity fails closed and never echoes secrets."""
    root = _licensed_plugin(tmp_path)
    receipt = detector.build_claude_plugin_scan_receipt(root)
    swapped = replace(
        receipt,
        policy_provenance=replace(
            receipt.policy_provenance,
            source_repository="evil/not-appguardrail",
        ),
    )
    verification = detector.verify_plugin_scan_receipt(swapped, root)
    serialized = json.dumps([swapped.as_dict(), verification.as_dict()])

    assert verification.matches is False
    assert "policy_provenance" in verification.mismatches
    assert _SECRET not in serialized
    assert _BIDI not in serialized
    assert "sk-" not in serialized
