"""Hook terraform apply and helm install fail closed; plan/list stay inventory."""

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
_TERRAFORM_RULE = "claude-plugin-terraform-apply-command"
_HELM_RULE = "claude-plugin-helm-install-command"
_KUBECTL_RULE = "claude-plugin-kubectl-apply-command"
_DOCKER_PUSH_RULE = "claude-plugin-docker-push-command"
_SECRET = "sk-tf-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_TERRAFORM_RULE, _HELM_RULE})


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


def test_hook_terraform_apply_fails_admission(tmp_path: Path) -> None:
    """``terraform apply`` on a hook is infra write authority, not inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nterraform apply -auto-approve\n")
    hits = _hits(root, _TERRAFORM_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "terraform apply" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _TERRAFORM_RULE in receipt.finding_summary
    assert _HELM_RULE not in receipt.finding_summary
    assert _KUBECTL_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_hook_helm_install_fails_admission(tmp_path: Path) -> None:
    """``helm install`` on a hook is cluster write authority, not inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nhelm install app chart/\n")
    hits = _hits(root, _HELM_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "helm install" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _HELM_RULE in receipt.finding_summary
    assert _TERRAFORM_RULE not in receipt.finding_summary
    assert _DOCKER_PUSH_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_terraform_plan_and_helm_list_stay_inventory(tmp_path: Path) -> None:
    """``terraform plan`` and ``helm list`` stay inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nterraform plan\nhelm list\n")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _TERRAFORM_RULE) == []
    assert _hits(root, _HELM_RULE) == []
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_vercel_deploy_and_fly_deploy_stay_inventory(tmp_path: Path) -> None:
    """Hosted deploy CLIs stay inventory; this slice does not own them."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nvercel deploy\nfly deploy\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"
    assert inventory["deployment_write"] is True


def test_readme_terraform_apply_is_not_this_class(tmp_path: Path) -> None:
    """README terraform wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("terraform apply -auto-approve\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _TERRAFORM_RULE) == []
    assert receipt.scan_result == "pass"
    assert _TERRAFORM_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_terraform_and_helm_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both terraform apply and helm install."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nterraform apply -auto-approve\nhelm install app chart/\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _TERRAFORM_RULE)
    assert _hits(root, _HELM_RULE)
    assert receipt.scan_result == "fail"
    assert _TERRAFORM_RULE in receipt.finding_summary
    assert _HELM_RULE in receipt.finding_summary
    assert _KUBECTL_RULE not in receipt.finding_summary


def test_case_insensitive_terraform_apply_fails_admission(tmp_path: Path) -> None:
    """``TERRAFORM APPLY`` is the same infra-write class."""
    body = "#!/bin/sh\nTERRAFORM APPLY -auto-approve\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    root = _licensed_plugin(tmp_path, body)
    assert _hits(root, _TERRAFORM_RULE)
    assert any(
        hit.rule_id == _TERRAFORM_RULE and hit.snippet == "terraform apply" for hit in hits
    )


def test_case_insensitive_helm_install_fails_admission() -> None:
    """``HELM INSTALL`` canonicalizes the snippet to ``helm install``."""
    body = "#!/bin/sh\nHELM INSTALL app chart/\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _HELM_RULE and hit.snippet == "helm install" for hit in hits)


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\nterraform apply -var 'token={_SECRET}{_BIDI}'\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    terraform_hits = [hit for hit in hits if hit.rule_id == _TERRAFORM_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert terraform_hits
    for hit in terraform_hits:
        assert hit.snippet == "terraform apply"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_helm_install_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that installs a chart is the helm class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "helm install app chart/"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _HELM_RULE)
    assert receipt.scan_result == "fail"
    assert _HELM_RULE in receipt.finding_summary


def test_manifest_command_args_preserve_executable_argv() -> None:
    """Structured command and args are one executable argv surface."""
    content = json.dumps(
        {
            "mcpServers": {
                "terraform-writer": {
                    "command": "terraform",
                    "args": ["apply", "-auto-approve"],
                },
                "helm-writer": {
                    "command": "helm",
                    "args": ["install", "app", "chart/"],
                },
                "path-writer": {
                    "command": "/usr/bin/terraform",
                    "args": ["apply"],
                },
            }
        }
    )
    hits = inspect_claude_plugin_file(".mcp.json", ".mcp.json", content)
    rule_ids = {hit.rule_id for hit in hits}

    assert _TERRAFORM_RULE in rule_ids
    assert _HELM_RULE in rule_ids


def test_manifest_command_args_preserve_nonwrite_token_boundaries() -> None:
    """Non-write, non-token, and non-array args do not invent write commands."""
    manifests = (
        {"command": "terraform", "args": ["plan"]},
        {"command": "helm", "args": ["list"]},
        {"command": "terraform", "args": ["apply later"]},
        {"command": "terraform", "args": ["applyLocal"]},
        {"command": "terraform", "args": ["apply-now"]},
        {"command": "helm", "args": ["install-chart"]},
        {"command": "wrapper", "args": ["terraform", "apply"]},
        {"command": "echo", "args": ["helm", "install", "app", "chart/"]},
        {"command": "helm", "args": "install"},
        {"command": "terraform", "args": ["apply", 1]},
    )
    for manifest in manifests:
        content = json.dumps({"mcpServers": {"reader": manifest}})
        hits = inspect_claude_plugin_file(".mcp.json", ".mcp.json", content)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_empty_hook_is_not_this_class() -> None:
    """Empty hook text is not terraform or helm write authority."""
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", "")
    assert [hit.rule_id for hit in hits if hit.rule_id in _THIS_CLASS] == []


def test_kubectl_apply_without_terraform_stays_the_kubectl_class() -> None:
    """Cluster apply without terraform/helm stays the kubectl class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\nkubectl apply -f deploy.yml\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _KUBECTL_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_hook_comments_and_reporting_builtins_are_not_commands() -> None:
    """Comments and reporting builtins do not execute terraform or Helm."""
    bodies = (
        "#!/bin/sh\n# terraform apply -auto-approve\n",
        "#!/bin/sh\necho 'helm install app chart/'\n",
        "#!/bin/sh\nprintf 'terraform apply -auto-approve\\n'\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_manifest_prose_and_reporting_commands_are_not_commands() -> None:
    """Only structural executable command values carry deployment authority."""
    content = json.dumps(
        {
            "name": "safe-plugin",
            "description": "Run terraform apply or helm install only after review.",
            "hooks": {
                "PostToolUse": [
                    {"command": "echo 'terraform apply -auto-approve'"},
                    {"command": "printf 'helm install app chart/\\n'"},
                ]
            },
        }
    )
    hits = inspect_claude_plugin_file(
        "plugin.json", ".claude-plugin/plugin.json", content
    )
    assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_later_executable_command_after_reporting_segment_still_fails() -> None:
    """A reporting segment cannot hide a later real terraform or Helm write."""
    bodies = (
        "#!/bin/sh\necho checked && terraform apply -auto-approve\n",
        "#!/bin/sh\nprintf 'checked\\n'; helm install app chart/\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)

def test_quoted_shell_prose_is_not_executable() -> None:
    """Quoted command names and reporting substitutions are inert prose."""
    bodies = (
        '#!/bin/sh\nmessage="terraform apply -auto-approve"\n',
        '#!/bin/sh\nif [ "$mode" = "helm install app chart/" ]; then echo safe; fi\n',
        "#!/bin/sh\nmessage='helm install app chart/'\n",
        '#!/bin/sh\nresult="$(echo \'terraform apply -auto-approve\')"\n',
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_command_substitution_remains_executable() -> None:
    """Direct commands in modern and legacy substitutions remain executable."""
    bodies = (
        '#!/bin/sh\nresult="$(terraform apply -auto-approve)"\n',
        "#!/bin/sh\nresult=`helm install app chart/`\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)



def test_assignment_values_are_not_executable_commands() -> None:
    """An unquoted assignment value cannot turn its following word into the CLI."""
    bodies = (
        "#!/bin/sh\nmessage=terraform apply -auto-approve\n",
        "#!/bin/sh\ncommand=helm install app chart/\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_environment_assignment_before_real_command_still_fails() -> None:
    """Environment assignments do not hide a later executable deployment CLI."""
    bodies = (
        "#!/bin/sh\nTF_IN_AUTOMATION=1 terraform apply -auto-approve\n",
        "#!/bin/sh\nHELM_NAMESPACE=prod helm install app chart/\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)


def test_here_document_payload_is_not_an_executable_command() -> None:
    """Literal here-document payload is data, even when it names deployment CLIs."""
    bodies = (
        "#!/bin/sh\ncat <<'EOF'\nterraform apply -auto-approve\nEOF\n",
        "#!/bin/sh\ncat <<-EOF\n\thelm install app chart/\n\tEOF\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_command_after_here_document_still_fails() -> None:
    """An inert payload cannot hide a later executable deployment command."""
    body = (
        "#!/bin/sh\ncat <<'EOF'\nterraform apply -auto-approve\nEOF\n"
        "helm install app chart/\n"
    )
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _TERRAFORM_RULE not in rule_ids
    assert _HELM_RULE in rule_ids


def test_heredoc_opener_lookalikes_do_not_hide_real_commands() -> None:
    """Quoted or commented opener text cannot suppress a later real command."""
    bodies = (
        '#!/bin/sh\necho "<<EOF"\nterraform apply -auto-approve\n',
        "#!/bin/sh\n# cat <<EOF\nhelm install app chart/\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)



def test_nonexecuting_builtins_do_not_execute_argument_text() -> None:
    """No-op and status builtins do not execute command-like arguments."""
    bodies = (
        "#!/bin/sh\n: terraform apply -auto-approve\n",
        "#!/bin/sh\ntrue helm install app chart/\n",
        "#!/bin/sh\nfalse terraform apply -auto-approve\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


def test_command_after_nonexecuting_builtin_still_fails() -> None:
    """A no-op argument cannot hide a later real deployment command."""
    bodies = (
        "#!/bin/sh\n: terraform apply; helm install app chart/\n",
        "#!/bin/sh\nfalse helm install app chart/ || terraform apply\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)
