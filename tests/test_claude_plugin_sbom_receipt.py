"""Plugin receipts must bind a deterministic CycloneDX SBOM digest."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

from appguardrail_core import claude_plugin_detector as detector
from appguardrail_core.sbom import build_sbom, collect_components


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_SECRET = "sk-sbom-must-not-leak"
_BIDI = "\u202e"


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


def test_receipt_binds_cyclonedx_sbom_digest(tmp_path: Path) -> None:
    """An honest plugin receipt records SHA-256 of a CycloneDX 1.5 document."""
    root = _licensed_plugin(tmp_path)
    receipt = detector.build_claude_plugin_scan_receipt(root)
    payload = receipt.as_dict()

    assert isinstance(payload["sbom_sha256"], str)
    assert len(payload["sbom_sha256"]) == 64
    assert payload["sbom_sha256"] == receipt.sbom_sha256
    assert payload["sbom_sha256"] != receipt.scanner_policy_sha256
    assert payload["sbom_sha256"] != receipt.policy_provenance.scanner_policy_sha256
    assert _SECRET not in json.dumps(payload)
    assert _BIDI not in json.dumps(payload)


def test_package_json_dependency_changes_sbom_digest(tmp_path: Path) -> None:
    """Adding a declared npm dependency changes the bound SBOM digest."""
    empty = _licensed_plugin(tmp_path / "empty")
    with_dep = _licensed_plugin(tmp_path / "dep")
    _write_json(
        with_dep / "package.json",
        {"name": "safe-plugin", "dependencies": {"left-pad": "1.3.0"}},
    )
    empty_receipt = detector.build_claude_plugin_scan_receipt(empty)
    dep_receipt = detector.build_claude_plugin_scan_receipt(with_dep)

    assert empty_receipt.sbom_sha256 != dep_receipt.sbom_sha256
    assert empty_receipt.scanner_policy_sha256 == dep_receipt.scanner_policy_sha256


def test_identical_trees_emit_identical_sbom_digests(tmp_path: Path) -> None:
    """The same manifests produce the same SBOM digest."""
    first = _licensed_plugin(tmp_path / "a")
    second = _licensed_plugin(tmp_path / "b")
    _write_json(
        first / "package.json",
        {"dependencies": {"left-pad": "1.3.0", "ms": "2.1.3"}},
    )
    _write_json(
        second / "package.json",
        {"dependencies": {"ms": "2.1.3", "left-pad": "1.3.0"}},
    )
    first_receipt = detector.build_claude_plugin_scan_receipt(first)
    second_receipt = detector.build_claude_plugin_scan_receipt(second)

    assert first_receipt.sbom_sha256 == second_receipt.sbom_sha256


def test_verify_fails_closed_when_sbom_digest_is_swapped(tmp_path: Path) -> None:
    """A retained receipt with a mutated sbom_sha256 is not current."""
    root = _licensed_plugin(tmp_path)
    _write_json(root / "package.json", {"dependencies": {"left-pad": "1.3.0"}})
    receipt = detector.build_claude_plugin_scan_receipt(root)
    mutated = replace(receipt, sbom_sha256="0" * 64)
    verification = detector.verify_plugin_scan_receipt(mutated, root)

    assert verification.matches is False
    assert "sbom_sha256" in verification.mismatches
    assert verification.admitted is False


def test_plugin_sbom_reuses_existing_cyclonedx_builder(tmp_path: Path) -> None:
    """The bound digest is SHA-256 of the existing CycloneDX document."""
    root = _licensed_plugin(tmp_path)
    _write_json(root / "package.json", {"dependencies": {"left-pad": "1.3.0"}})
    receipt = detector.build_claude_plugin_scan_receipt(root)
    document = detector._plugin_sbom_document(root)

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert receipt.sbom_sha256 == detector._sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    )
    names = {component["name"] for component in document["components"]}
    assert "left-pad" in names
    collected = collect_components(root)
    rebuilt = build_sbom(
        sorted(
            collected,
            key=lambda item: (
                str(item.get("name") or ""),
                str(item.get("version") or ""),
                str(item.get("purl") or ""),
            ),
        ),
        "safe-plugin",
    )
    assert rebuilt["components"][0]["name"] == document["components"][0]["name"]


def test_malformed_package_json_still_emits_a_bounded_sbom(tmp_path: Path) -> None:
    """Unreadable manifests yield an empty-component SBOM, not a crash."""
    root = _licensed_plugin(tmp_path)
    (root / "package.json").write_text("{", encoding="utf-8")
    receipt = detector.build_claude_plugin_scan_receipt(root)
    document = detector._plugin_sbom_document(root)

    assert receipt.scan_result == "pass"
    assert document["components"] == []
    assert len(receipt.sbom_sha256) == 64
