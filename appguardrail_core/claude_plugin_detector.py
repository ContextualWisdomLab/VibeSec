"""Static analysis for Claude plugin marketplace entries and package trees.

Findings come from parsed manifests and executable surfaces, not from issue
titles. A floating Git ref, provider secret, pipe-to-shell installer, or
undeclared hook is a policy finding. Inventory is evidence, not permission.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
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
CLAUDE_PLUGIN_SYMLINK_ESCAPE_MESSAGE: Final = (
    "Claude plugin package contains a symbolic link. Symlinks are not followed "
    "and fail admission until the exact regular-file identity is declared. "
    "[CWE-59 - Improper Link Resolution Before File Access]"
)
CLAUDE_PLUGIN_DUPLICATE_JSON_MESSAGE: Final = (
    "Claude plugin manifest contains duplicate JSON object members. Duplicate "
    "keys conceal identity and must fail admission. "
    "[CWE-20 - Improper Input Validation]"
)
CLAUDE_PLUGIN_UNBOUNDED_MCP_MESSAGE: Final = (
    "Claude plugin starts a remote or stdio MCP server without a bounded "
    "schema and source or authentication identity. Inventory is not permission. "
    "[CWE-829 - Inclusion of Functionality from Untrusted Control Sphere]"
)
CLAUDE_PLUGIN_LICENSE_MISSING_MESSAGE: Final = (
    "Claude plugin package has no LICENSE or NOTICE file. Record license "
    "evidence without inventing legal approval. "
    "[CWE-1104 - Use of Unmaintained Third Party Components]"
)
CLAUDE_PLUGIN_CONCEALED_IDENTITY_MESSAGE: Final = (
    "Claude plugin manifest contains concealed control or bidirectional "
    "formatting characters. Decode identity before admission. "
    "[CWE-451 - User Interface (UI) Misrepresentation of Critical Information]"
)
CLAUDE_PLUGIN_OVERSIZED_PACKAGE_MESSAGE: Final = (
    "Claude plugin package exceeds the bounded file count or scanned byte "
    "budget. Hostile oversized trees fail admission. "
    "[CWE-400 - Uncontrolled Resource Consumption]"
)
CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE: Final = (
    "Claude plugin marketplace identity does not match the retrieved artifact "
    "ref, repository, or source path. Bind admission to one exact object. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
_MCP_FILENAMES: Final = frozenset({".mcp.json", "mcp.json"})
_MAX_PACKAGE_FILES: Final = 10_000
_MAX_PACKAGE_BYTES: Final = 10 * 1024 * 1024
_CONCEALED_CHAR = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200d\u202a-\u202e\u2066-\u2069]"
)
_SCANNER_NAME: Final = "appguardrail"
_SCANNER_VERSION: Final = "0.1.1"

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


@dataclass(frozen=True, slots=True)
class PluginScanReceipt:
    """Bounded deterministic receipt for one Claude plugin artifact scan."""

    scan_receipt_id: str
    scanner_name: str
    scanner_version: str
    scanner_policy_sha256: str
    catalog_repository: str
    catalog_commit_sha: str
    marketplace_blob_sha: str
    marketplace_entry_sha256: str
    plugin_name: str
    plugin_version: str
    source_repository: str
    source_commit_sha: str
    source_path: str
    artifact_sha256: str
    file_count: int
    scanned_byte_count: int
    capability_inventory_sha256: str
    sarif_sha256: str
    finding_summary: tuple[str, ...]
    license_evidence_summary: str
    scan_started_at: str
    scan_completed_at: str
    scan_result: str

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe receipt with no secret literals."""
        return {
            "scan_receipt_id": self.scan_receipt_id,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "scanner_policy_sha256": self.scanner_policy_sha256,
            "catalog_repository": self.catalog_repository,
            "catalog_commit_sha": self.catalog_commit_sha,
            "marketplace_blob_sha": self.marketplace_blob_sha,
            "marketplace_entry_sha256": self.marketplace_entry_sha256,
            "plugin_name": self.plugin_name,
            "plugin_version": self.plugin_version,
            "source_repository": self.source_repository,
            "source_commit_sha": self.source_commit_sha,
            "source_path": self.source_path,
            "artifact_sha256": self.artifact_sha256,
            "file_count": self.file_count,
            "scanned_byte_count": self.scanned_byte_count,
            "capability_inventory_sha256": self.capability_inventory_sha256,
            "sarif_sha256": self.sarif_sha256,
            "finding_summary": list(self.finding_summary),
            "license_evidence_summary": self.license_evidence_summary,
            "scan_started_at": self.scan_started_at,
            "scan_completed_at": self.scan_completed_at,
            "scan_result": self.scan_result,
        }


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
        Undeclared executable and symlink findings. Empty when the tree is not
        a plugin package or every hook is a declared regular file.
    """
    plugin_dir = root / ".claude-plugin"
    if not plugin_dir.is_dir() or plugin_dir.is_symlink():
        return ()
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        manifest_path = plugin_dir / "marketplace.json"
    declared: set[str] = set()
    if manifest_path.is_file() and not manifest_path.is_symlink():
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        declared = _declared_paths(payload)
    hits: list[PluginHit] = []
    if _license_summary(root) == "absent":
        hits.append(
            PluginHit(
                rule_id="claude-plugin-license-missing",
                line=1,
                snippet=".claude-plugin",
                message=CLAUDE_PLUGIN_LICENSE_MISSING_MESSAGE,
                file=".claude-plugin",
            )
        )
    _, file_count, scanned_byte_count = _artifact_digest(root)
    if file_count > _MAX_PACKAGE_FILES or scanned_byte_count > _MAX_PACKAGE_BYTES:
        hits.append(
            PluginHit(
                rule_id="claude-plugin-oversized-package",
                line=1,
                snippet=".claude-plugin",
                message=CLAUDE_PLUGIN_OVERSIZED_PACKAGE_MESSAGE,
                file=".claude-plugin",
            )
        )
    hits.extend(_source_mismatch_hits(root))
    for directory_name in _HOOK_DIRS:
        directory = root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            continue
        for path in _walk_entries(directory):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                hits.append(
                    PluginHit(
                        rule_id="claude-plugin-symlink-escape",
                        line=1,
                        snippet=path.name[:120],
                        message=CLAUDE_PLUGIN_SYMLINK_ESCAPE_MESSAGE,
                        file=relative,
                    )
                )
                continue
            if not path.is_file() or path.suffix.lower() not in _EXECUTABLE_SUFFIXES:
                continue
            if relative in declared or path.name in declared:
                continue
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-undeclared-executable",
                    line=1,
                    snippet=path.name[:120],
                    message=CLAUDE_PLUGIN_UNDECLARED_EXECUTABLE_MESSAGE,
                    file=relative,
                )
            )
    return tuple(hits)


def build_claude_plugin_scan_receipt(
    root: Path,
    *,
    scanner_version: str = _SCANNER_VERSION,
    scan_started_at: str = "",
    scan_completed_at: str = "",
) -> PluginScanReceipt:
    """Return a deterministic admission receipt for one plugin artifact.

    Args:
        root: Materialized plugin tree.
        scanner_version: Scanner release identity recorded on the receipt.
        scan_started_at: Optional caller-supplied start timestamp.
        scan_completed_at: Optional caller-supplied completion timestamp.

    Returns:
        Receipt whose identity excludes wall-clock fields. ``scan_result`` is
        ``pass`` only when ``.claude-plugin/`` exists and no policy findings
        remain. Secret literals never appear on the receipt.
    """
    hits = _collect_plugin_hits(root)
    finding_summary = tuple(sorted({hit.rule_id for hit in hits}))
    identity = _plugin_identity(root)
    artifact_sha256, file_count, scanned_byte_count = _artifact_digest(root)
    marketplace_path = root / ".claude-plugin" / "marketplace.json"
    marketplace_bytes = _regular_file_bytes(marketplace_path)
    marketplace_blob_sha = _sha256(marketplace_bytes) if marketplace_bytes else ""
    marketplace_entry_sha256 = _sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    policy_sha256 = _sha256(Path(__file__).read_bytes())
    capability_inventory_sha256 = _sha256(
        json.dumps(finding_summary, separators=(",", ":")).encode()
    )
    sarif_sha256 = _sha256(
        json.dumps(
            [
                {"rule_id": hit.rule_id, "line": hit.line, "file": hit.file or ""}
                for hit in hits
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    is_package = (root / ".claude-plugin").is_dir() and not (
        root / ".claude-plugin"
    ).is_symlink()
    scan_result = "pass" if is_package and not finding_summary else "fail"
    body = {
        "scanner_name": _SCANNER_NAME,
        "scanner_version": scanner_version,
        "scanner_policy_sha256": policy_sha256,
        "catalog_repository": "",
        "catalog_commit_sha": "",
        "marketplace_blob_sha": marketplace_blob_sha,
        "marketplace_entry_sha256": marketplace_entry_sha256,
        "plugin_name": identity["plugin_name"],
        "plugin_version": identity["plugin_version"],
        "source_repository": identity["source_repository"],
        "source_commit_sha": identity["source_commit_sha"],
        "source_path": identity["source_path"],
        "artifact_sha256": artifact_sha256,
        "file_count": file_count,
        "scanned_byte_count": scanned_byte_count,
        "capability_inventory_sha256": capability_inventory_sha256,
        "sarif_sha256": sarif_sha256,
        "finding_summary": list(finding_summary),
        "license_evidence_summary": _license_summary(root),
        "scan_result": scan_result,
    }
    receipt_id = _sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    )
    return PluginScanReceipt(
        scan_receipt_id=receipt_id,
        scan_started_at=scan_started_at,
        scan_completed_at=scan_completed_at,
        finding_summary=finding_summary,
        **{key: value for key, value in body.items() if key != "finding_summary"},
    )


def receipt_matches_artifact(receipt: PluginScanReceipt, root: Path) -> bool:
    """Return whether ``receipt`` still describes the current artifact bytes.

    Args:
        receipt: Previously issued receipt.
        root: Current materialized tree.

    Returns:
        True only when the current artifact digest matches the receipt.
    """
    artifact_sha256, _, _ = _artifact_digest(root)
    return artifact_sha256 == receipt.artifact_sha256 and (
        receipt.scanner_policy_sha256 == _sha256(Path(__file__).read_bytes())
    )


def _is_manifest(filename: str, posix: str) -> bool:
    """Return whether the file is a Claude plugin, marketplace, or MCP manifest."""
    if filename in {"marketplace.json", "plugin.json"} or filename in _MCP_FILENAMES:
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
    """Return floating-ref, duplicate-JSON, MCP, concealment, and secret hits."""
    hits: list[PluginHit] = list(_concealment_hits(content))
    try:
        payload = _load_manifest_json(content)
    except _DuplicateJsonMember as exc:
        return (
            PluginHit(
                rule_id="claude-plugin-duplicate-json-member",
                line=_line_of(content, str(exc)),
                snippet=str(exc)[:120],
                message=CLAUDE_PLUGIN_DUPLICATE_JSON_MESSAGE,
            ),
        )
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
    hits.extend(_mcp_hits(payload, content))
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


def _concealment_hits(content: str) -> tuple[PluginHit, ...]:
    """Return hits for concealed control or bidirectional characters."""
    match = _CONCEALED_CHAR.search(content)
    if match is None:
        return ()
    codepoint = f"U+{ord(match.group(0)):04X}"
    return (
        PluginHit(
            rule_id="claude-plugin-concealed-identity",
            line=_line_of(content, match.group(0)),
            snippet=codepoint,
            message=CLAUDE_PLUGIN_CONCEALED_IDENTITY_MESSAGE,
        ),
    )


class _DuplicateJsonMember(ValueError):
    """Raised when a JSON object repeats a member name."""


def _load_manifest_json(content: str) -> object:
    """Parse JSON while rejecting duplicate object members."""

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Fail closed when a JSON object repeats a member name."""
        seen: set[str] = set()
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in seen:
                raise _DuplicateJsonMember(key)
            seen.add(key)
            result[key] = value
        return result

    return json.loads(content, object_pairs_hook=object_pairs)


def _mcp_is_bounded(server: dict) -> bool:
    """Return whether one MCP server declaration has schema plus identity."""
    schema = server.get("schema") or server.get("inputSchema")
    if not isinstance(schema, dict) or not schema:
        return False
    if isinstance(server.get("url"), str) and server["url"]:
        auth = server.get("auth") or server.get("authentication")
        return isinstance(auth, dict) and bool(auth)
    if isinstance(server.get("command"), str) and server["command"]:
        identity = server.get("source") or server.get("identity") or server.get("sha")
        return bool(identity)
    return False


def _mcp_hits(payload: object, content: str) -> tuple[PluginHit, ...]:
    """Return unbounded MCP server declarations from one manifest."""
    if not isinstance(payload, dict):
        return ()
    servers = payload.get("mcpServers") or payload.get("mcp_servers")
    if not isinstance(servers, dict) or not servers:
        return ()
    hits: list[PluginHit] = []
    for name, server in servers.items():
        if isinstance(server, dict) and _mcp_is_bounded(server):
            continue
        token = name if isinstance(name, str) else "mcp"
        hits.append(
            PluginHit(
                rule_id="claude-plugin-unbounded-mcp",
                line=_line_of(content, token),
                snippet=token[:120],
                message=CLAUDE_PLUGIN_UNBOUNDED_MCP_MESSAGE,
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


def _sha256(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _walk_entries(root: Path) -> tuple[Path, ...]:
    """Yield regular files and symlinks without following linked directories."""
    found: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda path: path.name, reverse=True)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    found.append(entry)
                    continue
                if entry.is_dir():
                    stack.append(entry)
                    continue
                if entry.is_file():
                    found.append(entry)
            except OSError:
                continue
    return tuple(sorted(found, key=lambda path: path.as_posix()))


def _regular_file_bytes(path: Path) -> bytes:
    """Return bytes of a regular file, or empty bytes for missing/symlink paths."""
    try:
        if not path.is_file() or path.is_symlink():
            return b""
        return path.read_bytes()
    except OSError:
        return b""


def _artifact_digest(root: Path) -> tuple[str, int, int]:
    """Return SHA-256, file count, and byte count for regular files under ``root``."""
    hasher = hashlib.sha256()
    file_count = 0
    scanned_byte_count = 0
    for path in _walk_entries(root):
        if path.is_symlink():
            hasher.update(b"symlink:")
            hasher.update(path.relative_to(root).as_posix().encode())
            hasher.update(b"\0")
            continue
        payload = _regular_file_bytes(path)
        relative = path.relative_to(root).as_posix().encode()
        hasher.update(relative)
        hasher.update(b"\0")
        hasher.update(str(len(payload)).encode())
        hasher.update(b"\0")
        hasher.update(payload)
        hasher.update(b"\0")
        file_count += 1
        scanned_byte_count += len(payload)
    return hasher.hexdigest(), file_count, scanned_byte_count


def _license_summary(root: Path) -> str:
    """Return present license path names or ``absent`` without legal approval."""
    names = [
        path.relative_to(root).as_posix()
        for path in _walk_entries(root)
        if not path.is_symlink() and path.name.upper().startswith("LICENSE")
    ]
    return ",".join(names) if names else "absent"


def _empty_identity() -> dict[str, str]:
    """Return blank plugin identity fields."""
    return {
        "plugin_name": "",
        "plugin_version": "",
        "source_repository": "",
        "source_commit_sha": "",
        "source_path": "",
    }


def _identity_from_payload(payload: object) -> dict[str, str]:
    """Return bounded identity from one parsed marketplace or plugin document."""
    identity = _empty_identity()
    entries = list(_plugin_entries(payload))
    if not entries:
        return identity
    entry = entries[0]
    name = entry.get("name")
    if not isinstance(name, str) and isinstance(payload, dict):
        name = payload.get("name")
    identity["plugin_name"] = name if isinstance(name, str) else ""
    version = entry.get("version")
    if not isinstance(version, str) and isinstance(payload, dict):
        version = payload.get("version")
    identity["plugin_version"] = version if isinstance(version, str) else ""
    source = entry.get("source")
    if isinstance(source, dict):
        repo = source.get("repo") or source.get("source")
        identity["source_repository"] = repo if isinstance(repo, str) else ""
        identity["source_commit_sha"] = _source_ref(entry) or ""
        path_value = source.get("path")
        identity["source_path"] = path_value if isinstance(path_value, str) else ""
        return identity
    if isinstance(entry.get("ref"), str):
        identity["source_commit_sha"] = entry["ref"]
    return identity


def _identity_from_file(path: Path) -> dict[str, str]:
    """Return identity from one regular JSON file, or blanks on parse failure."""
    payload_bytes = _regular_file_bytes(path)
    if not payload_bytes:
        return _empty_identity()
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _empty_identity()
    return _identity_from_payload(payload)


def _source_mismatch_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return hits when catalog identity disagrees with the retrieved artifact."""
    plugin = _identity_from_file(root / ".claude-plugin" / "plugin.json")
    market = _identity_from_file(root / ".claude-plugin" / "marketplace.json")
    hits: list[PluginHit] = []
    for field in ("source_commit_sha", "source_repository"):
        left, right = plugin[field], market[field]
        if left and right and left != right:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-source-mismatch",
                    line=1,
                    snippet=field,
                    message=CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE,
                    file=".claude-plugin/plugin.json",
                )
            )
            break
    path_value = plugin["source_path"] or market["source_path"]
    if path_value:
        parts = Path(path_value).parts
        if path_value.startswith("/") or ".." in parts:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-source-mismatch",
                    line=1,
                    snippet="source.path",
                    message=CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE,
                    file=".claude-plugin/plugin.json",
                )
            )
        elif not (root / path_value).exists():
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-source-mismatch",
                    line=1,
                    snippet="source.path",
                    message=CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE,
                    file=".claude-plugin/plugin.json",
                )
            )
    return tuple(hits)


def _plugin_identity(root: Path) -> dict[str, str]:
    """Return bounded plugin identity fields from the local manifest."""
    for name in ("plugin.json", "marketplace.json"):
        identity = _identity_from_file(root / ".claude-plugin" / name)
        if any(identity.values()):
            return identity
    return _empty_identity()


def _collect_plugin_hits(root: Path) -> tuple[PluginHit, ...]:
    """Combine package-level and per-file Claude plugin findings."""
    hits = list(scan_claude_plugin_package(root))
    for mcp_name in _MCP_FILENAMES:
        mcp_path = root / mcp_name
        if mcp_path.is_symlink() or not mcp_path.is_file():
            continue
        try:
            content = mcp_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            content = ""
        hits.extend(inspect_claude_plugin_file(mcp_path.name, mcp_name, content))
    plugin_dir = root / ".claude-plugin"
    if not plugin_dir.is_dir() or plugin_dir.is_symlink():
        return tuple(hits)
    for path in _walk_entries(plugin_dir):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            content = ""
        hits.extend(inspect_claude_plugin_file(path.name, relative, content))
    for directory_name in _HOOK_DIRS:
        directory = root / directory_name
        if not directory.is_dir() or directory.is_symlink():
            continue
        for path in _walk_entries(directory):
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                content = ""
            hits.extend(inspect_claude_plugin_file(path.name, relative, content))
    return tuple(hits)
