"""Hook vercel deploy and fly deploy fail closed; status/list stay inventory."""

from __future__ import annotations

import json
from pathlib import Path

from appguardrail_core import claude_plugin_detector as detector
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


def test_hook_comment_vercel_deploy_is_not_this_class(tmp_path: Path) -> None:
    """``# vercel deploy`` is hook documentation, not hosted write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\n# vercel deploy --prod\necho hello\n")
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _VERCEL_RULE) == []
    assert _hits(root, _FLY_RULE) == []
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_hook_echo_fly_deploy_is_not_this_class(tmp_path: Path) -> None:
    """``echo "fly deploy"`` prints a label; it does not run flyctl."""
    root = _licensed_plugin(tmp_path, '#!/bin/sh\necho "fly deploy"\n')
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _FLY_RULE) == []
    assert _hits(root, _VERCEL_RULE) == []
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_hook_printf_vercel_deploy_is_not_this_class() -> None:
    """``printf`` of a deploy label is not an executable vercel command."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\nprintf '%s\\n' \"vercel deploy\"\n",
    )
    assert [hit.rule_id for hit in hits if hit.rule_id in _THIS_CLASS] == []


def test_comment_then_real_vercel_deploy_still_fails(tmp_path: Path) -> None:
    """A comment lookalike does not hide a later executable vercel deploy."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# vercel deploy\necho "fly deploy"\nvercel deploy --prod\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _VERCEL_RULE)
    assert _hits(root, _FLY_RULE) == []
    assert receipt.scan_result == "fail"
    assert _VERCEL_RULE in receipt.finding_summary
    assert _FLY_RULE not in receipt.finding_summary


def test_echo_then_real_fly_deploy_still_fails() -> None:
    """``echo done && fly deploy`` still runs fly on the second segment."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && fly deploy --now\n',
    )
    assert any(hit.rule_id == _FLY_RULE and hit.snippet == "fly deploy" for hit in hits)


def test_inline_comment_after_vercel_deploy_still_fails() -> None:
    """``vercel deploy # note`` remains an executable hosted-write command."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\nvercel deploy --prod # documented\n",
    )
    assert any(
        hit.rule_id == _VERCEL_RULE and hit.snippet == "vercel deploy" for hit in hits
    )


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


def test_print_fly_deploy_lookalike_is_not_this_class() -> None:
    """A Python ``print`` of fly deploy is not hosted write authority."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        'print("fly deploy")\n',
    )
    assert [hit.rule_id for hit in hits if hit.rule_id in _THIS_CLASS] == []


def test_pipeline_and_or_segments_keep_executable_fly_deploy() -> None:
    """Unquoted ``||``, ``;``, ``|``, and ``&`` still run fly deploy."""
    body = "#!/bin/sh\nfalse || fly deploy; true | flyctl deploy & fly deploy\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _FLY_RULE and hit.snippet == "fly deploy" for hit in hits)


def test_quoted_ampersand_echo_is_not_this_class() -> None:
    """Quoted ``&&`` inside echo does not invent a second command segment."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "ready && fly deploy"\n',
    )
    assert [hit.rule_id for hit in hits if hit.rule_id in _THIS_CLASS] == []


def test_hosted_deploy_helpers_cover_comment_quote_and_token_edges() -> None:
    """Comment, escape, splitter, and token helpers keep executable matches only."""
    assert detector._unquoted_hash_index("vercel deploy # note") == len("vercel deploy ")
    assert detector._unquoted_hash_index("echo '# vercel deploy'") is None
    assert detector._unquoted_hash_index('echo "# fly deploy"') is None
    assert detector._unquoted_hash_index("echo \\# not-a-comment") is None
    assert detector._unquoted_hash_index("") is None
    assert detector._first_shell_token("   ") == ""
    assert detector._first_shell_token("/usr/bin/echo hi") == "echo"
    assert detector._first_shell_token("printf.exe hi") == "printf"
    assert detector._first_shell_token("print('x')") == "print"
    quoted = 'echo "a && b"'
    assert detector._iter_unquoted_segment_bounds(quoted) == ((0, len(quoted)),)
    escaped_line = 'echo \\"x\\" && y'
    escaped = detector._iter_unquoted_segment_bounds(escaped_line)
    assert len(escaped) == 2
    assert escaped_line[escaped[1][0] : escaped[1][1]].strip() == "y"
    single = "echo 'a | b' ; c"
    bounds = detector._iter_unquoted_segment_bounds(single)
    assert bounds[-1][1] == len(single)
    assert single[bounds[0][0] : bounds[0][1]].startswith("echo")
    assert detector._executable_command_match("", detector._VERCEL_DEPLOY_COMMAND) is None
    assert detector._executable_command_match("vercel ls", detector._VERCEL_DEPLOY_COMMAND) is None
    match = detector._executable_command_match(
        "vercel deploy",
        detector._VERCEL_DEPLOY_COMMAND,
    )
    assert match is not None
    assert match.group(0).lower() == "vercel deploy"


def test_manifest_reporting_commands_and_description_are_not_this_class(
    tmp_path: Path,
) -> None:
    """Manifest prose and reporting-only command values are not hosted writes."""
    root = _licensed_plugin(tmp_path)
    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["description"] = "operators may later run vercel deploy"
    manifest["hooks"] = {
        "PostToolUse": [
            {"command": 'echo "fly deploy"'},
            {"command": "printf '%s\\n' 'vercel deploy'"},
        ],
    }
    _write_json(manifest_path, manifest)

    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _VERCEL_RULE) == []
    assert _hits(root, _FLY_RULE) == []
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"


def test_manifest_reporting_command_does_not_hide_later_deploy(
    tmp_path: Path,
) -> None:
    """A later structural command value still exposes hosted write authority."""
    root = _licensed_plugin(tmp_path)
    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["hooks"] = {
        "PostToolUse": [
            {"command": 'echo "fly deploy"'},
            {"command": "vercel deploy --prod"},
        ],
    }
    _write_json(manifest_path, manifest)

    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _FLY_RULE) == []
    assert _hits(root, _VERCEL_RULE)
    assert _VERCEL_RULE in receipt.finding_summary
    assert receipt.scan_result == "fail"
