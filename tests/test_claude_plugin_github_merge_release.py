"""Hook merge and release commands fail closed; review and deploy stay inventory."""

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
_MERGE_RULE = "claude-plugin-github-merge-command"
_RELEASE_RULE = "claude-plugin-github-release-command"
_WRITE_TOKEN_RULE = "claude-plugin-github-write-token"
_SECRET = "sk-merge-must-not-leak"
_BIDI = "\u202e"
_TEST_GITHUB_PAT = "ghp_" + ("A" * 36)
_THIS_CLASS = frozenset({_MERGE_RULE, _RELEASE_RULE})


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
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _hits(root: Path, rule_id: str):
    """Return receipt-path hits for one rule identity."""
    return [hit for hit in _collect_plugin_hits(root) if hit.rule_id == rule_id]


def test_hook_gh_pr_merge_fails_admission(tmp_path: Path) -> None:
    """``gh pr merge`` on a hook is merge authority, not inventory-only evidence."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngh pr merge 1 --squash\n")
    hits = _hits(root, _MERGE_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "gh pr merge" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _MERGE_RULE in receipt.finding_summary
    assert _RELEASE_RULE not in receipt.finding_summary
    assert inventory["github_merge"] is True
    assert inventory["github_release"] is False


def test_hook_gh_release_write_verbs_fail_admission(tmp_path: Path, verb: str) -> None:
    """``gh release`` create, upload, delete, and edit fail closed."""
    root = _licensed_plugin(tmp_path, f"#!/bin/sh\ngh release {verb} v1.0.0\n")
    hits = _hits(root, _RELEASE_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == f"gh release {verb}" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _RELEASE_RULE in receipt.finding_summary
    assert _MERGE_RULE not in receipt.finding_summary
    assert inventory["github_release"] is True
    assert inventory["github_merge"] is False


@pytest.fixture(params=("create", "upload", "delete", "edit"))
def verb(request: pytest.FixtureRequest) -> str:
    """Return one GitHub CLI release write verb."""
    return str(request.param)


def test_gh_release_list_stays_inventory(tmp_path: Path) -> None:
    """``gh release list`` is inventory evidence, not this write class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngh release list\n")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _RELEASE_RULE) == []
    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert receipt.scan_result == "pass"
    assert inventory["github_release"] is True


def test_gh_issue_create_and_pr_review_stay_inventory(tmp_path: Path) -> None:
    """Issue create and PR review stay inventory; they are not merge or release."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\ngh issue create --title note\ngh pr review 1 --comment -b ok\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _MERGE_RULE) == []
    assert _hits(root, _RELEASE_RULE) == []
    assert receipt.scan_result == "pass"
    assert receipt.finding_summary == ()
    assert inventory["github_write"] is True
    assert inventory["github_review"] is True
    assert inventory["github_merge"] is False
    assert inventory["github_release"] is False


def test_kubectl_apply_and_docker_push_are_not_merge_or_release(
    tmp_path: Path,
) -> None:
    """Deployment writes are not the merge or release command family."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nkubectl apply -f deploy.yml\ndocker push example/app:1\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert inventory["deployment_write"] is True


def test_readme_merge_command_is_not_this_class(tmp_path: Path) -> None:
    """README merge wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text("run gh pr merge after review\n", encoding="utf-8")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _MERGE_RULE) == []
    assert receipt.scan_result == "pass"
    assert _MERGE_RULE not in receipt.finding_summary
    assert inventory["github_merge"] is True


def test_merge_and_release_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both merge and release without PAT findings."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\ngh pr merge 1\ngh release create v1.0.0\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _MERGE_RULE)
    assert _hits(root, _RELEASE_RULE)
    assert receipt.scan_result == "fail"
    assert _MERGE_RULE in receipt.finding_summary
    assert _RELEASE_RULE in receipt.finding_summary
    assert _WRITE_TOKEN_RULE not in receipt.finding_summary


def test_case_insensitive_merge_command_fails_admission(tmp_path: Path) -> None:
    """``GH PR MERGE`` is the same merge-authority class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\nGH PR MERGE 1\n")
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\nGH PR MERGE 1\n",
    )
    assert _hits(root, _MERGE_RULE)
    assert any(hit.rule_id == _MERGE_RULE and hit.snippet == "gh pr merge" for hit in hits)


def test_case_insensitive_release_create_fails_admission(tmp_path: Path) -> None:
    """``GH RELEASE CREATE`` canonicalizes the snippet verb."""
    body = "#!/bin/sh\nGH RELEASE CREATE v1.0.0\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(
        hit.rule_id == _RELEASE_RULE and hit.snippet == "gh release create" for hit in hits
    )


def test_snippets_are_command_labels_not_tokens_or_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit tokens, secrets, and bidi."""
    body = (
        f"#!/bin/sh\nexport GH_TOKEN={_TEST_GITHUB_PAT}\n"
        f"gh pr merge 1 --body '{_SECRET}{_BIDI}'\n"
    )
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    merge_hits = [hit for hit in hits if hit.rule_id == _MERGE_RULE]
    receipt = build_claude_plugin_scan_receipt(root)
    payload = json.dumps(receipt.as_dict())

    assert merge_hits
    for hit in merge_hits:
        assert hit.snippet == "gh pr merge"
        assert _TEST_GITHUB_PAT not in hit.snippet
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload
    assert any(hit.rule_id == _WRITE_TOKEN_RULE for hit in hits)


def test_plugin_manifest_merge_command_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that merges is the same merge class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "gh pr merge --auto --squash"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _MERGE_RULE)
    assert receipt.scan_result == "fail"
    assert _MERGE_RULE in receipt.finding_summary


def test_empty_hook_is_not_this_class(tmp_path: Path) -> None:
    """Empty hook text is not merge or release authority."""
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", "")
    assert [hit.rule_id for hit in hits if hit.rule_id in _THIS_CLASS] == []


def test_github_write_token_without_merge_stays_the_pat_class(tmp_path: Path) -> None:
    """A hardcoded PAT without merge/release stays the write-token class."""
    body = f"#!/bin/sh\nexport GH_TOKEN={_TEST_GITHUB_PAT}\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    assert any(hit.rule_id == _WRITE_TOKEN_RULE for hit in hits)
    assert all(hit.rule_id != _MERGE_RULE for hit in hits)
    assert all(hit.rule_id != _RELEASE_RULE for hit in hits)
