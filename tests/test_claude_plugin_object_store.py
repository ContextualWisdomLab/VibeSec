"""Hook aws s3 writes and az containerapp up fail closed; reads stay inventory."""

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
_S3_RULE = "claude-plugin-aws-s3-write-command"
_CONTAINERAPP_RULE = "claude-plugin-az-containerapp-up-command"
_AWS_DEPLOY_RULE = "claude-plugin-aws-deploy-command"
_AZ_DEPLOY_RULE = "claude-plugin-az-deploy-command"
_SECRET = "sk-object-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_S3_RULE, _CONTAINERAPP_RULE})


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


def test_hook_aws_s3_sync_fails_admission(tmp_path: Path) -> None:
    """``aws s3 sync`` to S3 is object-store write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\naws s3 sync ./dist s3://bucket/app\n")
    hits = _hits(root, _S3_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "aws s3 sync" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _S3_RULE in receipt.finding_summary
    assert _CONTAINERAPP_RULE not in receipt.finding_summary
    assert _AWS_DEPLOY_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_hook_aws_s3_cp_fails_admission() -> None:
    """``aws s3 cp`` to S3 is object-store write authority."""
    body = "#!/bin/sh\naws s3 cp artifact.tgz s3://bucket/app.tgz\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _S3_RULE and hit.snippet == "aws s3 cp" for hit in hits)


def test_hook_aws_s3_cp_download_stays_inventory() -> None:
    """A provable S3-to-local copy is read authority, not this write class."""
    body = "#!/bin/sh\naws s3 cp s3://bucket/app.tgz ./app.tgz\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert not any(hit.rule_id == _S3_RULE for hit in hits)


def test_hook_aws_s3_sync_download_stays_inventory() -> None:
    """A provable S3-to-local sync is read authority, not this write class."""
    body = "#!/bin/sh\naws s3 sync s3://bucket/app ./app\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert not any(hit.rule_id == _S3_RULE for hit in hits)


def test_hook_aws_s3_to_s3_copy_still_fails_admission() -> None:
    """S3-to-S3 copy still writes the destination bucket."""
    body = "#!/bin/sh\naws s3 cp s3://source/app.tgz s3://target/app.tgz\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _S3_RULE for hit in hits)


def test_hook_az_containerapp_up_fails_admission(tmp_path: Path) -> None:
    """``az containerapp up`` on a hook is Azure write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\naz containerapp up --name app\n")
    hits = _hits(root, _CONTAINERAPP_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "az containerapp up" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _CONTAINERAPP_RULE in receipt.finding_summary
    assert _AZ_DEPLOY_RULE not in receipt.finding_summary


def test_aws_s3_ls_stays_inventory(tmp_path: Path) -> None:
    """``aws s3 ls`` stays inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\naws s3 ls\n")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _S3_RULE) == []
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_comment_and_echo_object_store_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable s3 writes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# aws s3 sync ./dist s3://bucket\necho "az containerapp up"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_readme_s3_sync_is_not_this_class(tmp_path: Path) -> None:
    """README object-store wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("aws s3 sync ./dist s3://bucket/app\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _S3_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["deployment_write"] is True


def test_echo_then_real_s3_sync_still_fails() -> None:
    """``echo done && aws s3 sync`` still runs the object-store write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && aws s3 sync ./dist s3://bucket\n',
    )
    assert any(hit.rule_id == _S3_RULE and hit.snippet == "aws s3 sync" for hit in hits)


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\naws s3 cp secret.bin s3://bucket/{_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    s3_hits = [hit for hit in hits if hit.rule_id == _S3_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert s3_hits
    for hit in s3_hits:
        assert hit.snippet == "aws s3 cp"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_containerapp_up_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that runs containerapp up is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "az containerapp up --name app"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _CONTAINERAPP_RULE)
    assert receipt.scan_result == "fail"
    assert _CONTAINERAPP_RULE in receipt.finding_summary


def test_manifest_prose_and_reporting_are_not_this_class(tmp_path: Path) -> None:
    """Manifest prose and reporting-only values are not object-store writes."""
    root = _licensed_plugin(tmp_path)
    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["description"] = "operators may later run aws s3 sync"
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": 'echo "az containerapp up"'}],
    }
    _write_json(manifest_path, manifest)
    receipt = build_claude_plugin_scan_receipt(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_cloudformation_deploy_stays_the_aws_deploy_class() -> None:
    """CloudFormation deploy without s3/containerapp stays the aws-deploy class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\naws cloudformation deploy --stack-name app\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _AWS_DEPLOY_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_download_before_later_upload_still_fails_admission() -> None:
    """A safe first command cannot hide a later S3 destination write."""
    body = (
        "#!/bin/sh\n"
        "aws s3 cp s3://bucket/input.tgz ./input.tgz && "
        "aws s3 cp ./output.tgz s3://bucket/output.tgz\n"
    )
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _S3_RULE for hit in hits)

