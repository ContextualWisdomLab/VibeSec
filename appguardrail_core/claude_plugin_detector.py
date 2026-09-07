"""Static analysis for Claude plugin marketplace entries and package trees.

Findings come from parsed manifests and executable surfaces, not from issue
titles. A floating Git ref, provider secret, pipe-to-shell installer, or
undeclared hook is a policy finding. Inventory is evidence, not permission.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Final, Iterable


CLAUDE_PLUGIN_FLOATING_REF_MESSAGE: Final = (
    "Claude plugin source uses a floating branch or tag instead of an immutable "
    "40-character commit SHA. Pin the exact Git object before admission. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_PROVIDER_SECRET_MESSAGE: Final = (
    "Claude plugin package contains a direct model-provider secret or routing "
    "key. Remove the secret and load credentials from the host secret store. "
    "[CWE-798 - Use of Hard-coded Credentials]"
)
CLAUDE_PLUGIN_PIPE_TO_SHELL_MESSAGE: Final = (
    "Claude plugin hook downloads a mutable script and pipes it to a shell. "
    "Pin and verify installers; do not execute unsigned remote content. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_UNDECLARED_EXECUTABLE_MESSAGE: Final = (
    "Claude plugin package contains an executable surface that is not declared "
    "in the plugin manifest. Unknown hooks fail admission until classified. "
    "[CWE-829 - Inclusion of Functionality from Untrusted Control Sphere]"
)

_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_PROVIDER_SECRET = re.compile(
    r"\b(?:OPENAI_API_KEY|NVIDIA_NIM_API_KEY(?:_SUB)?|BYTEZ_API_KEY|"
    r"OPENROUTER_API_KEY)\b"
)
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n]*\|\s*(?:bash|sh|zsh)\b",
    re.IGNORECASE,
)
_EXECUTABLE_SUFFIXES = frozenset(
    {".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".py"}
)
_HOOK_DIRS = ("hooks", "scripts")


@dataclass(frozen=True, slots=True)
class PluginHit:
    """One source-bound Claude plugin policy finding."""

    rule_id: str
    line: int
    snippet: str
    message: str
    file: str | None = None


def inspect_claude_plugin_file(
    filename: str,
    relative_path: str,
    content: str,
) -> tuple[PluginHit, ...]:
    """Inspect one file for Claude plugin supply-chain findings.

    Args:
        filename: Basename of the file being scanned.
        relative_path: Repository-relative display path.
        content: File text.

    Returns:
        Zero or more hits. Unrelated files return an empty tuple.
    """
    posix = relative_path.replace("\\", "/")
    hits: list[PluginHit] = []
    manifest = _is_manifest(filename, posix)
    hook_surface = _is_hook_surface(filename, posix)
    if not manifest and not hook_surface:
        return ()
    if manifest:
        hits.extend(_inspect_manifest(content))
    if _PIPE_TO_SHELL.search(content) and hook_surface:
        match = _PIPE_TO_SHELL.search(content)
        line = 1
        snippet = content.splitlines()[0][:120] if content else filename
        if match is not None:
            line = content[: match.start()].count("\n") + 1
            snippet = content[match.start() :].splitlines()[0].strip()[:120]
        hits.append(
            PluginHit(
                rule_id="claude-plugin-pipe-to-shell",
                line=line,
                snippet=snippet,
                message=CLAUDE_PLUGIN_PIPE_TO_SHELL_MESSAGE,
            )
        )
    return tuple(hits)


def scan_claude_plugin_package(root: Path) -> tuple[PluginHit, ...]:
    """Return package-level findings for a materialized Claude plugin tree.

    Args:
        root: Scan root that may contain ``.claude-plugin/``.

    Returns:
        Undeclared executable findings. Empty when the tree is not a plugin
        package or every hook is declared.
    """
    plugin_dir = root / ".claude-plugin"
    if not plugin_dir.is_dir():
        return ()
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.is_file():
        manifest_path = plugin_dir / "marketplace.json"
    declared: set[str] = set()
    if manifest_path.is_file():
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        declared = _declared_paths(payload)
    hits: list[PluginHit] = []
    for directory_name in _HOOK_DIRS:
        directory = root / directory_name
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _EXECUTABLE_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            if relative in declared or path.name in declared:
                continue
            snippet = path.name[:120]
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-undeclared-executable",
                    line=1,
                    snippet=snippet,
                    message=CLAUDE_PLUGIN_UNDECLARED_EXECUTABLE_MESSAGE,
                    file=relative,
                )
            )
    return tuple(hits)


def _is_manifest(filename: str, posix: str) -> bool:
    """Return whether the file is a Claude plugin or marketplace manifest."""
    if filename in {"marketplace.json", "plugin.json"}:
        return True
    return posix.endswith("/.claude-plugin/marketplace.json") or posix.endswith(
        "/.claude-plugin/plugin.json"
    )


def _is_hook_surface(filename: str, posix: str) -> bool:
    """Return whether the file is a hook, script, or plugin executable surface."""
    posix_norm = f"/{posix.replace(chr(92), '/')}/"
    in_plugin_tree = (
        "/hooks/" in posix_norm
        or "/scripts/" in posix_norm
        or "/.claude-plugin/" in posix_norm
    )
    if not in_plugin_tree:
        return False
    suffix = Path(filename).suffix.lower()
    return suffix in _EXECUTABLE_SUFFIXES or suffix == ""


def _inspect_manifest(content: str) -> tuple[PluginHit, ...]:
    """Return floating-ref and provider-secret hits from one manifest."""
    hits: list[PluginHit] = []
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return ()
    for entry in _plugin_entries(payload):
        ref = _source_ref(entry)
        if isinstance(ref, str) and not _FULL_SHA.fullmatch(ref):
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-floating-git-ref",
                    line=_line_of(content, ref),
                    snippet=ref[:120],
                    message=CLAUDE_PLUGIN_FLOATING_REF_MESSAGE,
                )
            )
    secret = _PROVIDER_SECRET.search(content)
    if secret is not None:
        hits.append(
            PluginHit(
                rule_id="claude-plugin-provider-secret",
                line=content[: secret.start()].count("\n") + 1,
                snippet=secret.group(0),
                message=CLAUDE_PLUGIN_PROVIDER_SECRET_MESSAGE,
            )
        )
    return tuple(hits)


def _plugin_entries(payload: object) -> Iterable[dict]:
    """Yield plugin objects from a marketplace document or single plugin."""
    if isinstance(payload, dict):
        plugins = payload.get("plugins")
        if isinstance(plugins, list):
            for item in plugins:
                if isinstance(item, dict):
                    yield item
            return
        yield payload


def _source_ref(entry: dict) -> str | None:
    """Return the Git ref declared on a plugin source object."""
    source = entry.get("source")
    if isinstance(source, dict):
        ref = source.get("ref") or source.get("sha")
        return ref if isinstance(ref, str) else None
    ref = entry.get("ref")
    return ref if isinstance(ref, str) else None


def _declared_paths(payload: object) -> set[str]:
    """Return hook and command paths declared by a plugin manifest."""
    declared: set[str] = set()
    entries = list(_plugin_entries(payload))
    for entry in entries:
        hooks = entry.get("hooks") or {}
        if isinstance(hooks, dict):
            for value in hooks.values():
                _collect_declared(value, declared)
        commands = entry.get("commands") or []
        if isinstance(commands, list):
            for value in commands:
                _collect_declared(value, declared)
    return declared


def _collect_declared(value: object, declared: set[str]) -> None:
    """Add string command paths from one manifest value."""
    if isinstance(value, str):
        declared.add(value)
        declared.add(Path(value).name)
        return
    if isinstance(value, dict):
        command = value.get("command") or value.get("path") or value.get("script")
        if isinstance(command, str):
            declared.add(command)
            declared.add(Path(command).name)
        return
    if isinstance(value, list):
        for item in value:
            _collect_declared(item, declared)


def _line_of(content: str, token: str) -> int:
    """Return the 1-based line where ``token`` first appears."""
    index = content.find(token)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1
