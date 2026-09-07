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
    "policy_provenance",
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


def _create_symlink(target: Path, link: Path, target_is_directory: bool = False) -> None:
    """Create a symlink or skip when the host cannot."""
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:  # pragma: no cover
        pytest.skip(f"symlinks are not available in this environment: {exc}")


def test_scan_plugin_missing_marketplace_entry_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing marketplace entry path fails closed without a pass receipt."""
    root = _pass_plugin(tmp_path / "plugin")

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        [
            "scan-plugin",
            "--plugin-root",
            str(root),
            "--marketplace-entry",
            str(tmp_path / "absent-market.json"),
        ],
    )

    assert code != 0
    assert "marketplace entry" in stderr.lower()
    assert "scan_result" not in stdout


def test_scan_plugin_rejects_symlink_root_and_non_json_marketplace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Symlink roots and hostile marketplace documents fail closed."""
    from types import SimpleNamespace

    from appguardrail_core.claude_plugin_scan_cli import (
        MAX_MARKETPLACE_BYTES,
        cmd_scan_plugin,
        scan_plugin_artifact,
    )

    root = _pass_plugin(tmp_path / "plugin")
    link = tmp_path / "plugin-link"
    _create_symlink(root, link, target_is_directory=True)
    assert scan_plugin_artifact(link) == 1

    file_root = tmp_path / "not-a-dir"
    file_root.write_text("x\n", encoding="utf-8")
    assert (
        cmd_scan_plugin(
            SimpleNamespace(
                plugin_root=str(file_root),
                marketplace_entry=None,
                receipt_json=None,
            )
        )
        == 1
    )
    assert cmd_scan_plugin(SimpleNamespace()) == 1

    market_link = tmp_path / "market-link.json"
    _create_symlink(root / ".claude-plugin" / "marketplace.json", market_link)
    assert scan_plugin_artifact(root, marketplace_entry=market_link) == 1

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    assert scan_plugin_artifact(root, marketplace_entry=invalid) == 1

    scalar = tmp_path / "scalar.json"
    scalar.write_text("1\n", encoding="utf-8")
    assert scan_plugin_artifact(root, marketplace_entry=scalar) == 1

    binary = tmp_path / "binary.json"
    binary.write_bytes(b"\xff\xfe")
    assert scan_plugin_artifact(root, marketplace_entry=binary) == 1

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"[" + (b" " * (MAX_MARKETPLACE_BYTES + 1)) + b"]")
    assert scan_plugin_artifact(root, marketplace_entry=oversized) == 1

    original_read = Path.read_bytes

    def boom_read(self: Path) -> bytes:
        """Raise on the marketplace file only."""
        if self == binary:
            raise OSError("denied")
        return original_read(self)

    monkeypatch.setattr(Path, "read_bytes", boom_read)
    assert scan_plugin_artifact(root, marketplace_entry=binary) == 1
    captured = capsys.readouterr()
    assert _SECRET not in captured.out
    assert _SECRET not in captured.err


def test_scan_plugin_receipt_write_and_verify_edges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Receipt file destinations and stale verification fail closed."""
    from appguardrail_core import claude_plugin_scan_cli as cli
    from appguardrail_core.claude_plugin_detector import PluginReceiptVerification

    root = _pass_plugin(tmp_path / "plugin")
    as_dir = tmp_path / "receipt-dir"
    as_dir.mkdir()
    assert cli.scan_plugin_artifact(root, receipt_json=as_dir) == 1

    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    linked = tmp_path / "linked-receipt.json"
    _create_symlink(target, linked)
    assert cli.scan_plugin_artifact(root, receipt_json=linked) == 1

    blocked_parent = tmp_path / "blocked"
    blocked_parent.write_text("x\n", encoding="utf-8")
    assert cli.scan_plugin_artifact(root, receipt_json=blocked_parent / "receipt.json") == 1

    monkeypatch.setattr(
        cli,
        "verify_plugin_scan_receipt",
        lambda *_args, **_kwargs: PluginReceiptVerification(
            matches=False,
            mismatches=("artifact_sha256",),
        ),
    )
    assert cli.scan_plugin_artifact(root) == 1
    captured = capsys.readouterr()
    assert "does not match" in captured.err
    assert "scan_result" not in captured.out


_CATALOG_REPOSITORY = "anthropics/claude-plugins-community"


def _catalog_document(
    *,
    repository: str = _CATALOG_REPOSITORY,
    commit: str = _PINNED_COMMIT,
    plugin_name: str = "safe-plugin",
    plugin_repo: str = "example/safe-plugin",
    plugin_ref: str = _PINNED_COMMIT,
) -> dict:
    """Return a bounded external marketplace catalog document."""
    return {
        "repository": repository,
        "commit": commit,
        "plugins": [
            {
                "name": plugin_name,
                "version": "1.0.0",
                "source": {"source": "github", "repo": plugin_repo, "ref": plugin_ref},
            }
        ],
    }


def test_scan_plugin_binds_matching_catalog_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A matching catalog SHA and repository bind onto the receipt."""
    root = _pass_plugin(tmp_path / "plugin")
    catalog = tmp_path / "catalog" / "marketplace.json"
    _write_json(catalog, _catalog_document())
    catalog_digest = __import__("hashlib").sha256(catalog.read_bytes()).hexdigest()

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        [
            "scan-plugin",
            "--plugin-root",
            str(root),
            "--marketplace-entry",
            str(catalog),
        ],
    )

    payload = json.loads(stdout)
    assert code == 0
    assert payload["scan_result"] == "pass"
    assert payload["catalog_repository"] == _CATALOG_REPOSITORY
    assert payload["catalog_commit_sha"] == _PINNED_COMMIT
    assert payload["marketplace_blob_sha"] == catalog_digest
    assert payload["source_repository"] == "example/safe-plugin"
    assert payload["source_commit_sha"] == _PINNED_COMMIT
    assert _SECRET not in stdout
    assert _SECRET not in stderr


def test_scan_plugin_rejects_floating_catalog_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A branch name is not an immutable catalog commit SHA."""
    root = _pass_plugin(tmp_path / "plugin")
    catalog = tmp_path / "catalog" / "marketplace.json"
    _write_json(catalog, _catalog_document(commit="main"))

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        [
            "scan-plugin",
            "--plugin-root",
            str(root),
            "--marketplace-entry",
            str(catalog),
        ],
    )

    payload = json.loads(stdout)
    assert code != 0
    assert payload["scan_result"] == "fail"
    assert "claude-plugin-floating-git-ref" in payload["finding_summary"]
    assert payload["catalog_commit_sha"] == "main"


def test_scan_plugin_rejects_catalog_source_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Catalog plugin identity must match the retrieved artifact."""
    root = _pass_plugin(tmp_path / "plugin")
    catalog = tmp_path / "catalog" / "marketplace.json"
    _write_json(
        catalog,
        _catalog_document(plugin_repo="example/other-plugin"),
    )

    code, stdout, stderr = _run_cli(
        monkeypatch,
        capsys,
        [
            "scan-plugin",
            "--plugin-root",
            str(root),
            "--marketplace-entry",
            str(catalog),
        ],
    )

    payload = json.loads(stdout)
    assert code != 0
    assert payload["scan_result"] == "fail"
    assert "claude-plugin-source-mismatch" in payload["finding_summary"]
    assert payload["catalog_repository"] == _CATALOG_REPOSITORY


def test_catalog_identity_aliases_and_non_object_payloads(tmp_path: Path) -> None:
    """Catalog bind reads alias keys and ignores non-object catalogs."""
    from appguardrail_core.claude_plugin_detector import (
        _catalog_bind_hits,
        _catalog_identity,
        build_claude_plugin_scan_receipt,
    )

    root = _pass_plugin(tmp_path / "plugin")
    aliased = _catalog_identity(
        {
            "catalog_repository": _CATALOG_REPOSITORY,
            "catalog_commit_sha": _PINNED_COMMIT,
            "plugins": [
                {
                    "name": "safe-plugin",
                    "source": {"repo": "example/safe-plugin", "ref": _PINNED_COMMIT},
                }
            ],
        }
    )
    sha_alias = _catalog_identity({"sha": _PINNED_COMMIT})
    empty = _catalog_identity(["not-an-object"])
    missing = _catalog_identity(None)
    name_mismatch = _catalog_bind_hits(
        root,
        {
            "catalog_repository": "",
            "catalog_commit_sha": "",
            "plugin_name": "other-plugin",
            "source_repository": "",
            "source_commit_sha": "",
        },
    )
    sha_mismatch = _catalog_bind_hits(
        root,
        {
            "catalog_repository": "",
            "catalog_commit_sha": "",
            "plugin_name": "",
            "source_repository": "",
            "source_commit_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
    )
    receipt = build_claude_plugin_scan_receipt(
        root,
        catalog_payload=_catalog_document(),
        catalog_bytes=b'{"repository":"anthropics/claude-plugins-community"}',
    )

    assert aliased["catalog_repository"] == _CATALOG_REPOSITORY
    assert aliased["catalog_commit_sha"] == _PINNED_COMMIT
    assert sha_alias["catalog_commit_sha"] == _PINNED_COMMIT
    assert empty["catalog_repository"] == ""
    assert missing["catalog_commit_sha"] == ""
    assert any(hit.rule_id == "claude-plugin-source-mismatch" for hit in name_mismatch)
    assert any(hit.rule_id == "claude-plugin-source-mismatch" for hit in sha_mismatch)
    assert receipt.marketplace_blob_sha == __import__("hashlib").sha256(
        b'{"repository":"anthropics/claude-plugins-community"}'
    ).hexdigest()
