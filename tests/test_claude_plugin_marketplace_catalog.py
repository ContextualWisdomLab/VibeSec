"""Canonical marketplace catalog contracts for the Claude plugin scan CLI."""

from __future__ import annotations

from io import StringIO
import json
from pathlib import Path

from appguardrail_core.claude_plugin_scan_cli import scan_plugin_artifact


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


def _catalog(*plugins: dict[str, object]) -> dict[str, object]:
    """Return catalog provenance plus canonical ``plugins`` entries."""
    return {
        "repository": _CATALOG_REPOSITORY,
        "commit": _PINNED_COMMIT,
        "plugins": list(plugins),
    }


def _canonical_entry(name: str = "safe-plugin") -> dict[str, object]:
    """Return the current upstream URL/SHA source shape."""
    return {
        "name": name,
        "version": "1.0.0",
        "source": {
            "source": "git-subdir",
            "url": _PLUGIN_REPOSITORY,
            "path": "plugins/safe-plugin",
            "ref": "main",
            "sha": _PINNED_COMMIT,
        },
    }


def _scan(root: Path, catalog: Path) -> tuple[int, str, str]:
    """Run the public adapter with captured streams."""
    stdout = StringIO()
    stderr = StringIO()
    code = scan_plugin_artifact(
        root,
        marketplace_entry=catalog,
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_scan_selects_named_plugin_from_canonical_multi_plugin_catalog(
    tmp_path: Path,
) -> None:
    """Catalog order and a human ref must not override the matching pinned SHA."""
    root = _plugin(tmp_path / "plugin")
    catalog = tmp_path / "marketplace.json"
    _write_json(
        catalog,
        _catalog(
            _canonical_entry("unrelated-plugin"),
            _canonical_entry(),
        ),
    )

    code, stdout, stderr = _scan(root, catalog)

    receipt = json.loads(stdout)
    assert code == 0
    assert stderr == ""
    assert receipt["scan_result"] == "pass"
    assert receipt["catalog_repository"] == _CATALOG_REPOSITORY
    assert receipt["catalog_commit_sha"] == _PINNED_COMMIT
    assert receipt["plugin_name"] == "safe-plugin"
    assert receipt["source_repository"] == _PLUGIN_REPOSITORY
    assert receipt["source_commit_sha"] == _PINNED_COMMIT
    assert "claude-plugin-source-mismatch" not in receipt["finding_summary"]
    assert "claude-plugin-floating-git-ref" not in receipt["finding_summary"]


def test_scan_rejects_duplicate_named_catalog_entries(tmp_path: Path) -> None:
    """Two catalog entries cannot both claim the one materialized plugin identity."""
    root = _plugin(tmp_path / "plugin")
    catalog = tmp_path / "marketplace.json"
    _write_json(catalog, _catalog(_canonical_entry(), _canonical_entry()))

    code, stdout, stderr = _scan(root, catalog)

    assert code != 0
    assert stdout == ""
    assert "matching plugin entry" in stderr
