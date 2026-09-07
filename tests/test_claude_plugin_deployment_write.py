"""Hook kubectl apply and docker push fail closed; reads stay inventory."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appguardrail_core.claude_plugin_detector import (
    _collect_plugin_hits,
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    inventory_claude_plugin_capabilities,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_KUBECTL_RULE = "claude-plugin-kubectl-apply-command"
_DOCKER_PUSH_RULE = "claude-plugin-docker-push-command"
_MERGE_RULE = "claude-plugin-github-merge-command"
_SOCKET_RULE = "claude-plugin-docker-socket"
_WRITE_TOKEN_RULE = "claude-plugin-github-write-token"
_SECRET = "sk-deploy-must-not-leak"
_BIDI = "\u202e"
_TEST_GITHUB_PAT = "ghp_" + ("A" * 36)
_THIS_CLASS = frozenset({_KUBECTL_RULE, _DOCKER_PUSH_RULE})


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


def test_hook_kubectl_apply_fails_admission(tmp_path: Path) -> None:
    """``kubectl apply`` on a hook is cluster write authority, not inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nkubectl apply -f deploy.yml\n")
    hits = _hits(root, _KUBECTL_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "kubectl apply" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _KUBECTL_RULE in receipt.finding_summary
    assert _DOCKER_PUSH_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_hook_docker_push_fails_admission(tmp_path: Path) -> None:
    """``docker push`` on a hook is registry write authority, not inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ndocker push example/app:1\n")
    hits = _hits(root, _DOCKER_PUSH_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "docker push" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _DOCKER_PUSH_RULE in receipt.finding_summary
    assert _KUBECTL_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_docker_image_push_is_the_same_class(tmp_path: Path) -> None:
    """``docker image push`` canonicalizes to the docker-push command label."""
    body = "#!/bin/sh\ndocker image push example/app:1\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    root = _licensed_plugin(tmp_path, body)
    assert _hits(root, _DOCKER_PUSH_RULE)
    assert any(
        hit.rule_id == _DOCKER_PUSH_RULE and hit.snippet == "docker push" for hit in hits
    )


def test_kubectl_get_and_docker_ps_stay_inventory(tmp_path: Path) -> None:
    """Read-only cluster and daemon commands stay inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nkubectl get pods\ndocker ps\n")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _KUBECTL_RULE) == []
    assert _hits(root, _DOCKER_PUSH_RULE) == []
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"
    assert inventory["deployment_write"] is False


def test_terraform_and_helm_stay_inventory(tmp_path: Path) -> None:
    """Terraform apply and Helm install stay inventory; this slice does not own them."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nterraform apply -auto-approve\nhelm install app chart/\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"
    assert inventory["deployment_write"] is True


def test_readme_kubectl_apply_is_not_this_class(tmp_path: Path) -> None:
    """README deploy wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("kubectl apply -f deploy.yml\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _KUBECTL_RULE) == []
    assert receipt.scan_result == "pass"
    assert _KUBECTL_RULE not in receipt.finding_summary
    assert inventory["deployment_write"] is True


def test_kubectl_and_docker_push_on_one_hook_are_distinct_findings(
    tmp_path: Path,
) -> None:
    """One hook can fail closed on both cluster apply and registry push."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nkubectl apply -f deploy.yml\ndocker push example/app:1\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _KUBECTL_RULE)
    assert _hits(root, _DOCKER_PUSH_RULE)
    assert receipt.scan_result == "fail"
    assert _KUBECTL_RULE in receipt.finding_summary
    assert _DOCKER_PUSH_RULE in receipt.finding_summary
    assert _MERGE_RULE not in receipt.finding_summary


def test_case_insensitive_kubectl_apply_fails_admission(tmp_path: Path) -> None:
    """``KUBECTL APPLY`` is the same cluster-write class."""
    body = "#!/bin/sh\nKUBECTL APPLY -f deploy.yml\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    root = _licensed_plugin(tmp_path, body)
    assert _hits(root, _KUBECTL_RULE)
    assert any(
        hit.rule_id == _KUBECTL_RULE and hit.snippet == "kubectl apply" for hit in hits
    )


def test_case_insensitive_docker_push_fails_admission() -> None:
    """``DOCKER PUSH`` canonicalizes the snippet to ``docker push``."""
    body = "#!/bin/sh\nDOCKER PUSH example/app:1\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _DOCKER_PUSH_RULE and hit.snippet == "docker push" for hit in hits
    )


def test_snippets_are_command_labels_not_tokens_or_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit tokens, secrets, and bidi."""
    body = (
        f"#!/bin/sh\nexport GH_TOKEN={_TEST_GITHUB_PAT}\n"
        f"kubectl apply -f '{_SECRET}{_BIDI}.yml'\n"
    )
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    kubectl_hits = [hit for hit in hits if hit.rule_id == _KUBECTL_RULE]
    receipt = build_claude_plugin_scan_receipt(root)
    payload = json.dumps(receipt.as_dict())

    assert kubectl_hits
    for hit in kubectl_hits:
        assert hit.snippet == "kubectl apply"
        assert _TEST_GITHUB_PAT not in hit.snippet
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload
    assert any(hit.rule_id == _WRITE_TOKEN_RULE for hit in hits)


def test_plugin_manifest_kubectl_apply_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that applies is the same cluster class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "kubectl apply -f deploy.yml"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _KUBECTL_RULE)
    assert receipt.scan_result == "fail"
    assert _KUBECTL_RULE in receipt.finding_summary


def test_empty_hook_is_not_this_class() -> None:
    """Empty hook text is not cluster or registry write authority."""
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", "")
    assert [hit.rule_id for hit in hits if hit.rule_id in _THIS_CLASS] == []


def test_docker_socket_without_push_stays_the_socket_class() -> None:
    """A Docker socket bind without push stays the socket class."""
    hits = inspect_claude_plugin_file(
        "run.sh",
        "hooks/run.sh",
        "docker -H unix:///var/run/docker.sock ps\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _SOCKET_RULE in rule_ids
    assert _DOCKER_PUSH_RULE not in rule_ids


def test_gh_pr_merge_without_deploy_stays_the_merge_class() -> None:
    """Merge CLI without kubectl or docker push stays the merge class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\ngh pr merge 1 --squash\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _MERGE_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


@pytest.mark.parametrize("command", ("kubectl apply", "docker push"))
def test_vendored_hook_is_not_this_class(tmp_path: Path, command: str) -> None:
    """Vendored trees stay the vendored-scope class, not deployment-write."""
    root = _licensed_plugin(tmp_path)
    vendor = root / "vendor" / "hooks" / "session.sh"
    vendor.parent.mkdir(parents=True, exist_ok=True)
    vendor.write_text(f"#!/bin/sh\n{command}\n", encoding="utf-8")
    vendor.chmod(0o755)
    assert _hits(root, _KUBECTL_RULE) == []
    assert _hits(root, _DOCKER_PUSH_RULE) == []
