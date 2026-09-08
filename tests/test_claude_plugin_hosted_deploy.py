"""Hook vercel deploy and fly deploy fail closed; status/list stay inventory."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core.claude_plugin_detector import (
    _collect_plugin_hits,
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    inventory_claude_plugin_capabilities,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_VERCEL_RULE = "claude-plugin-vercel-deploy-command"
_FLY_RULE = "claude-plugin-fly-deploy-command"
_TERRAFORM_RULE = "claude-plugin-terraform-apply-command"
_KUBECTL_RULE = "claude-plugin-kubectl-apply-command"
_SECRET = "sk-hosted-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_VERCEL_RULE, _FLY_RULE})


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(root: Path, hook_body: str = "#!/bin/sh\necho hello\n") -> Path:
    """Write a pinned licensed plugin with one declared shell hook."""
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
            "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]},
        },
    )
    hook = root / "hooks" / "session.sh"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(hook_body, encoding="utf-8")
    hook.chmod(0o755)
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _hits(root: Path, rule_id: str):
    """Return receipt-path hits for one rule identity."""
    return [hit for hit in _collect_plugin_hits(root) if hit.rule_id == rule_id]


def test_hook_vercel_deploy_fails_admission(tmp_path: Path) -> None:
    """``vercel deploy`` on a hook is hosted write authority, not inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nvercel deploy --prod\n")
    hits = _hits(root, _VERCEL_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "vercel deploy" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _VERCEL_RULE in receipt.finding_summary
    assert _FLY_RULE not in receipt.finding_summary
    assert _TERRAFORM_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_hook_fly_deploy_fails_admission(tmp_path: Path) -> None:
    """``fly deploy`` on a hook is hosted write authority, not inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nfly deploy\n")
    hits = _hits(root, _FLY_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "fly deploy" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _FLY_RULE in receipt.finding_summary
    assert _VERCEL_RULE not in receipt.finding_summary
    assert _KUBECTL_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_flyctl_deploy_is_the_same_class(tmp_path: Path) -> None:
    """``flyctl deploy`` canonicalizes to the fly-deploy command label."""
    body = "#!/bin/sh\nflyctl deploy --now\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    root = _licensed_plugin(tmp_path, body)
    assert _hits(root, _FLY_RULE)
    assert any(hit.rule_id == _FLY_RULE and hit.snippet == "fly deploy" for hit in hits)


def test_vercel_ls_and_fly_status_stay_inventory(tmp_path: Path) -> None:
    """Read-only hosted CLIs stay inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nvercel ls\nfly status\n")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _VERCEL_RULE) == []
    assert _hits(root, _FLY_RULE) == []
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_readme_vercel_deploy_is_not_this_class(tmp_path: Path) -> None:
    """README hosted-deploy wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("vercel deploy --prod\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _VERCEL_RULE) == []
    assert receipt.scan_result == "pass"
    assert _VERCEL_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_vercel_and_fly_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both vercel deploy and fly deploy."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nvercel deploy --prod\nfly deploy\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _VERCEL_RULE)
    assert _hits(root, _FLY_RULE)
    assert receipt.scan_result == "fail"
    assert _VERCEL_RULE in receipt.finding_summary
    assert _FLY_RULE in receipt.finding_summary
    assert _TERRAFORM_RULE not in receipt.finding_summary


def test_case_insensitive_vercel_deploy_fails_admission(tmp_path: Path) -> None:
    """``VERCEL DEPLOY`` is the same hosted-write class."""
    body = "#!/bin/sh\nVERCEL DEPLOY --prod\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    root = _licensed_plugin(tmp_path, body)
    assert _hits(root, _VERCEL_RULE)
    assert any(
        hit.rule_id == _VERCEL_RULE and hit.snippet == "vercel deploy" for hit in hits
    )


def test_case_insensitive_fly_deploy_fails_admission() -> None:
    """``FLY DEPLOY`` canonicalizes the snippet to ``fly deploy``."""
    body = "#!/bin/sh\nFLY DEPLOY\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _FLY_RULE and hit.snippet == "fly deploy" for hit in hits)


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\nvercel deploy --token '{_SECRET}{_BIDI}'\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    vercel_hits = [hit for hit in hits if hit.rule_id == _VERCEL_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert vercel_hits
    for hit in vercel_hits:
        assert hit.snippet == "vercel deploy"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_fly_deploy_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that deploys to Fly is the fly class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "fly deploy --now"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _FLY_RULE)
    assert receipt.scan_result == "fail"
    assert _FLY_RULE in receipt.finding_summary


def test_empty_hook_is_not_this_class() -> None:
    """Empty hook text is not hosted deploy write authority."""
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", "")
    assert [hit.rule_id for hit in hits if hit.rule_id in _THIS_CLASS] == []


def test_terraform_apply_without_hosted_deploy_stays_the_terraform_class() -> None:
    """Infra apply without vercel/fly stays the terraform class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\nterraform apply -auto-approve\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _TERRAFORM_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)
