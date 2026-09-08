"""Hook aws/gcloud/az deploy writes fail closed; reads stay inventory."""

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
_AWS_RULE = "claude-plugin-aws-deploy-command"
_GCLOUD_RULE = "claude-plugin-gcloud-deploy-command"
_AZ_RULE = "claude-plugin-az-deploy-command"
_VERCEL_RULE = "claude-plugin-vercel-deploy-command"
_SECRET = "sk-cloud-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_AWS_RULE, _GCLOUD_RULE, _AZ_RULE})


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


def test_hook_aws_cloudformation_deploy_fails_admission(tmp_path: Path) -> None:
    """``aws cloudformation deploy`` on a hook is cloud write authority."""
    root = _licensed_plugin(
        tmp_path, "#!/bin/sh\naws cloudformation deploy --stack-name app\n"
    )
    hits = _hits(root, _AWS_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "aws cloudformation deploy" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _AWS_RULE in receipt.finding_summary
    assert _GCLOUD_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_hook_gcloud_run_deploy_fails_admission(tmp_path: Path) -> None:
    """``gcloud run deploy`` on a hook is cloud write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngcloud run deploy app --image img\n")
    hits = _hits(root, _GCLOUD_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "gcloud run deploy" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _GCLOUD_RULE in receipt.finding_summary
    assert _AWS_RULE not in receipt.finding_summary


def test_hook_az_webapp_deploy_fails_admission(tmp_path: Path) -> None:
    """``az webapp deploy`` on a hook is cloud write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\naz webapp deploy --name app\n")
    hits = _hits(root, _AZ_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "az webapp deploy" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _AZ_RULE in receipt.finding_summary


def test_aws_s3_ls_and_gcloud_config_stay_inventory(tmp_path: Path) -> None:
    """Read-only cloud CLIs stay inventory, not this class."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\naws s3 ls\ngcloud config list\naz account show\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_comment_and_echo_cloud_deploy_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable cloud deploys."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# aws cloudformation deploy\necho "gcloud run deploy"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_readme_gcloud_deploy_is_not_this_class(tmp_path: Path) -> None:
    """README cloud-deploy wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("gcloud run deploy app --image img\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _GCLOUD_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["deployment_write"] is True


def test_three_clouds_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on aws, gcloud, and az deploy writes."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\n"
        "aws cloudformation deploy --stack-name app\n"
        "gcloud app deploy\n"
        "az webapp deploy --name app\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _AWS_RULE)
    assert _hits(root, _GCLOUD_RULE)
    assert _hits(root, _AZ_RULE)
    assert receipt.scan_result == "fail"
    assert _VERCEL_RULE not in receipt.finding_summary


def test_aws_deploy_create_deployment_fails_admission() -> None:
    """``aws deploy create-deployment`` is the same aws-deploy class."""
    body = "#!/bin/sh\naws deploy create-deployment --application-name app\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _AWS_RULE and hit.snippet == "aws deploy create-deployment"
        for hit in hits
    )


def test_gcloud_functions_deploy_canonicalizes_snippet() -> None:
    """``gcloud functions deploy`` keeps the service token in the snippet."""
    body = "#!/bin/sh\ngcloud functions deploy fn --runtime python312\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _GCLOUD_RULE and hit.snippet == "gcloud functions deploy"
        for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\naws cloudformation deploy --parameter-overrides t={_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    aws_hits = [hit for hit in hits if hit.rule_id == _AWS_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert aws_hits
    for hit in aws_hits:
        assert hit.snippet == "aws cloudformation deploy"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_az_webapp_deploy_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that deploys to Azure is the az class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "az webapp deploy --name app"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _AZ_RULE)
    assert receipt.scan_result == "fail"


def test_vercel_deploy_without_cloud_stays_the_vercel_class() -> None:
    """Hosted vercel deploy without aws/gcloud/az stays the vercel class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\nvercel deploy --prod\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _VERCEL_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_manifest_cloud_prose_and_reporting_commands_are_not_this_class(
    tmp_path: Path,
) -> None:
    """Manifest prose and reporting-only values are not cloud deploy writes."""
    root = _licensed_plugin(tmp_path)
    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["description"] = "operators may later run gcloud run deploy"
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [
            {"command": 'echo "aws cloudformation deploy"'},
            {"command": "printf '%s\\n' 'az webapp deploy'"},
        ],
    }
    _write_json(manifest_path, manifest)

    receipt = build_claude_plugin_scan_receipt(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_manifest_reporting_command_does_not_hide_later_cloud_deploy(
    tmp_path: Path,
) -> None:
    """A later structural command value still exposes a real cloud deploy."""
    root = _licensed_plugin(tmp_path)
    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [
            {"command": 'echo "gcloud run deploy"'},
            {"command": "aws cloudformation deploy --stack-name app"},
        ],
    }
    _write_json(manifest_path, manifest)

    receipt = build_claude_plugin_scan_receipt(root)

    assert _GCLOUD_RULE not in receipt.finding_summary
    assert _AWS_RULE in receipt.finding_summary
    assert receipt.scan_result == "fail"
