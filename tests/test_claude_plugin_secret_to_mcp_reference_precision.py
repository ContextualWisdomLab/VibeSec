"""MCP secret references must match exact named variables, not prefixes."""

from __future__ import annotations

import json

from appguardrail_core.claude_plugin_detector import inspect_claude_plugin_file


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_MCP_SECRET_RULE = "claude-plugin-secret-to-mcp"


def _bounded_mcp(*, args: list[str] | None = None, command: str = "python") -> dict:
    """Return one bounded stdio MCP declaration for reference-precision tests."""
    server: dict = {
        "command": command,
        "schema": {"type": "object"},
        "source": {"sha": _PINNED_COMMIT},
    }
    if args is not None:
        server["args"] = args
    return {"mcpServers": {"local": server}}


def _rule_ids(payload: dict) -> set[str]:
    """Return rule identities emitted for one MCP manifest payload."""
    body = json.dumps(payload, indent=2)
    return {
        hit.rule_id
        for hit in inspect_claude_plugin_file(".mcp.json", ".mcp.json", body)
    }


def test_mcp_arg_secret_name_prefix_variable_is_not_a_secret_reference() -> None:
    """``$OPENAI_API_KEY_DOCUMENTATION`` must not alias ``OPENAI_API_KEY``."""
    rule_ids = _rule_ids(
        _bounded_mcp(args=["--label", "$OPENAI_API_KEY_DOCUMENTATION"])
    )
    assert _MCP_SECRET_RULE not in rule_ids


def test_mcp_command_braced_secret_name_prefix_is_not_a_secret_reference() -> None:
    """A longer braced variable name must not be truncated to a secret name."""
    rule_ids = _rule_ids(
        _bounded_mcp(command="python ${OPENAI_API_KEY_DOCUMENTATION}")
    )
    assert _MCP_SECRET_RULE not in rule_ids


def test_mcp_exact_braced_default_expansion_remains_a_secret_reference() -> None:
    """Shell default expansion of the exact secret remains fail-closed."""
    rule_ids = _rule_ids(_bounded_mcp(args=["--token", "${OPENAI_API_KEY:-}"]))
    assert _MCP_SECRET_RULE in rule_ids
