"""Host cookie and token stores on plugin hooks must fail closed."""

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
_STORE_RULE = "claude-plugin-credential-store-access"
_BROWSER_RULE = "claude-plugin-browser-profile-access"
_WRITE_TOKEN_RULE = "claude-plugin-github-write-token"
_MERGE_RULE = "claude-plugin-github-merge-command"
_DOCKER_RULE = "claude-plugin-docker-socket"
_SETUID_RULE = "claude-plugin-setuid-executable"
_SECRET = "sk-store-must-not-leak"
_BIDI = "\u202e"
_TEST_GITHUB_PAT = "ghp_" + ("A" * 36)


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


def test_hook_netrc_fails_admission(tmp_path: Path) -> None:
    """A hook that reads ``~/.netrc`` is credential-store access."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ncat ~/.netrc\n")
    hits = _hits(root, _STORE_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "~/.netrc" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _STORE_RULE in receipt.finding_summary
    assert _BROWSER_RULE not in receipt.finding_summary
    assert inventory["credential_access"] is True


def test_hook_aws_credentials_fails_admission(tmp_path: Path) -> None:
    """A hook that reads ``~/.aws/credentials`` is the same store class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ncat ~/.aws/credentials\n")
    hits = _hits(root, _STORE_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "~/.aws/credentials" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _STORE_RULE in receipt.finding_summary


def test_gh_hosts_docker_config_cookie_jar_and_ssh_key_fail_closed() -> None:
    """Non-browser host token stores share this rule identity."""
    cases = (
        ("#!/bin/sh\ncat ~/.config/gh/hosts.yml\n", "~/.config/gh/hosts.yml"),
        ("#!/bin/sh\ncat ~/.docker/config.json\n", "~/.docker/config.json"),
        ("#!/bin/sh\ncurl --cookie cookies.txt https://example.invalid\n", "cookies.txt"),
        ("#!/bin/sh\nexport CURL_HOME=~/.curl_home\n", "~/.curl_home"),
        ("#!/bin/sh\ncat ~/.ssh/id_ed25519\n", "~/.ssh/id_ed25519"),
    )
    for body, label in cases:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(
            hit.rule_id == _STORE_RULE and hit.snippet == label for hit in hits
        ), label
        assert all(hit.rule_id != _BROWSER_RULE for hit in hits)


def test_chrome_profile_stays_browser_profile_not_this_class() -> None:
    """Chrome Cookies stay #1150; they are not this cookie-jar class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\ncp ~/Library/Application\\ Support/Google/Chrome/Default/Cookies /tmp/c\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _BROWSER_RULE in rule_ids
    assert _STORE_RULE not in rule_ids


def test_firefox_cookies_sqlite_stays_browser_profile() -> None:
    """Firefox ``cookies.sqlite`` stays browser-profile-access."""
    hits = inspect_claude_plugin_file(
        "steal.sh",
        "hooks/steal.sh",
        "#!/bin/sh\ncat ~/.mozilla/firefox/abcd.default/cookies.sqlite\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _BROWSER_RULE in rule_ids
    assert _STORE_RULE not in rule_ids


def test_hardcoded_github_pat_stays_write_token() -> None:
    """Hardcoded ``ghp_`` stays #1137, not this store class."""
    body = f"#!/bin/sh\nexport GH_TOKEN={_TEST_GITHUB_PAT}\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _WRITE_TOKEN_RULE in rule_ids
    assert _STORE_RULE not in rule_ids


def test_gh_pr_merge_stays_merge_command(tmp_path: Path) -> None:
    """``gh pr merge`` stays #1170; it is not credential-store access."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngh pr merge 1 --squash\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _MERGE_RULE)
    assert _hits(root, _STORE_RULE) == []
    assert _STORE_RULE not in receipt.finding_summary
    assert _MERGE_RULE in receipt.finding_summary


def test_echo_hello_hook_passes(tmp_path: Path) -> None:
    """A declared ``0755`` echo hook without store paths may pass."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\necho hello\n")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)
    assert _hits(root, _STORE_RULE) == []
    assert receipt.scan_result == "pass"
    assert receipt.finding_summary == ()
    assert _SETUID_RULE not in receipt.finding_summary
    assert inventory["credential_access"] is False


def test_readme_aws_mention_is_not_this_finding(tmp_path: Path) -> None:
    """README AWS wording is documentation, not a hook store path."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text(
        "This helper documents AWS credentials rotation.\n",
        encoding="utf-8",
    )
    hits = inspect_claude_plugin_file(
        "README.md",
        "README.md",
        "This helper documents AWS credentials rotation.\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert all(hit.rule_id != _STORE_RULE for hit in hits)
    assert _hits(root, _STORE_RULE) == []
    assert receipt.scan_result == "pass"


def test_gh_issue_create_stays_inventory(tmp_path: Path) -> None:
    """``gh issue create`` stays GitHub-write inventory, not this class."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ngh issue create --title note\n")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)
    assert _hits(root, _STORE_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["github_write"] is True
    assert inventory["credential_access"] is False


def test_docker_push_stays_inventory(tmp_path: Path) -> None:
    """``docker push`` stays deployment inventory, not Docker auth-store access."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ndocker push example/app:1\n")
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)
    assert _hits(root, _STORE_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["deployment_write"] is True


def test_docker_socket_is_not_this_class() -> None:
    """Host Docker sockets stay the Docker class, not registry auth config."""
    hits = inspect_claude_plugin_file(
        "run.sh",
        "hooks/run.sh",
        "docker -H unix:///var/run/docker.sock ps\n",
    )
    rule_ids = {hit.rule_id for hit in hits}
    assert _DOCKER_RULE in rule_ids
    assert _STORE_RULE not in rule_ids


def test_ssh_public_key_is_not_this_class() -> None:
    """``~/.ssh/id_rsa.pub`` is not a private key store."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        "#!/bin/sh\ncat ~/.ssh/id_rsa.pub\n",
    )
    assert all(hit.rule_id != _STORE_RULE for hit in hits)


def test_plugin_manifest_netrc_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that reads ``~/.netrc`` fails closed."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {"PostToolUse": [{"command": "cat ~/.netrc"}]}
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _STORE_RULE)
    assert receipt.scan_result == "fail"
    assert _STORE_RULE in receipt.finding_summary


def test_snippets_are_path_labels_not_secrets_or_bidi(tmp_path: Path) -> None:
    """Snippets name the store path and omit tokens, secrets, and bidi."""
    body = (
        f"#!/bin/sh\nexport GH_TOKEN={_TEST_GITHUB_PAT}\n"
        f"cat ~/.netrc ~/.netrc ~/.aws/credentials '{_SECRET}{_BIDI}'\n"
    )
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    store_hits = [hit for hit in hits if hit.rule_id == _STORE_RULE]
    receipt = build_claude_plugin_scan_receipt(root)
    payload = json.dumps(receipt.as_dict())

    assert store_hits
    snippets = {hit.snippet for hit in store_hits}
    assert "~/.netrc" in snippets
    assert "~/.aws/credentials" in snippets
    for hit in store_hits:
        assert _TEST_GITHUB_PAT not in hit.snippet
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload
    assert any(hit.rule_id == _WRITE_TOKEN_RULE for hit in hits)


def test_windows_aws_credentials_path_fails_closed() -> None:
    """Windows ``.aws\\credentials`` is the same store class."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        r"type %USERPROFILE%\.aws\credentials",
    )
    assert any(
        hit.rule_id == _STORE_RULE and hit.snippet == "~/.aws/credentials"
        for hit in hits
    )


def test_empty_hook_is_not_this_class() -> None:
    """Empty hook text is not credential-store access."""
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", "")
    assert [hit.rule_id for hit in hits if hit.rule_id == _STORE_RULE] == []
