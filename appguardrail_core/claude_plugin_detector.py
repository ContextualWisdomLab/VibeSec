"""Static analysis for Claude plugin marketplace entries and package trees.

Findings come from parsed manifests and executable surfaces, not from issue
titles. A floating Git ref, provider secret, pipe-to-shell installer,
unsigned executable download, package.json lifecycle download, unpinned
package URL install, dynamic eval/exec, undeclared hook, hidden undeclared
executable or config surface, archive path
escape, unadmitted nested submodule, hardcoded GitHub write token, Docker
socket bind, host browser-profile store, secret copied into a network
request, or a released
skill-supply-chain finding on a plugin skill/agent surface is a policy
finding. Capability inventory is evidence,
not permission: presence of a capability is not a finding by itself. Skill
homoglyph, injection, exfiltration, and placeholder hits reuse #1036 rule
identities. A lockfile-backed package.json without a lifecycle download
stays inventory.
"""

from __future__ import annotations

from dataclasses import dataclass
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
from typing import Final, Iterable
import zipfile

from .claude_plugin_sarif import finding_summary_to_sarif, sarif_document_sha256

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
    "Claude plugin hook or package lifecycle script downloads a mutable "
    "script and pipes it to a shell. Pin and verify installers; do not "
    "execute unsigned remote content. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_UNDECLARED_EXECUTABLE_MESSAGE: Final = (
    "Claude plugin package contains an executable surface that is not declared "
    "in the plugin manifest. Unknown hooks fail admission until classified. "
    "[CWE-829 - Inclusion of Functionality from Untrusted Control Sphere]"
)
CLAUDE_PLUGIN_HIDDEN_UNDECLARED_EXECUTABLE_MESSAGE: Final = (
    "Claude plugin package contains a hidden executable or configuration "
    "surface that is not declared in the plugin manifest. Dotfile names and "
    "hidden directories fail admission until classified. "
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
CLAUDE_PLUGIN_LICENSE_MISMATCH_MESSAGE: Final = (
    "Claude plugin license evidence names more than one SPDX identifier. "
    "Record the conflict without inventing legal approval. "
    "[CWE-1104 - Use of Unmaintained Third Party Components]"
)
CLAUDE_PLUGIN_DYNAMIC_EVAL_MESSAGE: Final = (
    "Claude plugin hook evaluates a string as code. Dynamic eval, exec, "
    "compile, or Function constructors fail admission. "
    "[CWE-95 - Improper Neutralization of Directives in Dynamically Evaluated Code]"
)
_DYNAMIC_EVAL = re.compile(
    r"\b(?:eval|exec|compile)\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|"
    r"(?:^|[\s;&|])eval\s+[\"'$]",
    re.IGNORECASE | re.MULTILINE,
)
_SPDX_TOKEN = re.compile(
    r"\b(Apache-2\.0|MIT|BSD-2-Clause|BSD-3-Clause|GPL-3\.0-only|"
    r"GPL-3\.0-or-later|LGPL-3\.0-only|AGPL-3\.0-only|MPL-2\.0|ISC|"
    r"Unlicense|CC0-1\.0|0BSD)\b",
    re.IGNORECASE,
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
CLAUDE_PLUGIN_ARCHIVE_PATH_TRAVERSAL_MESSAGE: Final = (
    "Claude plugin archive contains a member that escapes the extract root. "
    "Do not follow ../, absolute, or Windows-prefix paths. "
    "[CWE-22 - Improper Limitation of a Pathname to a Restricted Directory]"
)
CLAUDE_PLUGIN_UNADMITTED_SUBMODULE_MESSAGE: Final = (
    "Claude plugin nested submodule, gitlink, or .gitmodules pointer lacks a "
    "recursively admitted immutable SHA identity. Pin and scan the nested "
    "package before admission. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_GITHUB_WRITE_TOKEN_MESSAGE: Final = (
    "Claude plugin package contains a hardcoded GitHub personal or app token. "
    "That token is write-capable authority. Remove it and use the host secret "
    "store. [CWE-798 - Use of Hard-coded Credentials]"
)
CLAUDE_PLUGIN_DOCKER_SOCKET_MESSAGE: Final = (
    "Claude plugin hook reaches the host Docker socket. Socket access is host "
    "control, not an image push. Remove the socket bind and keep builds "
    "isolated. [CWE-250 - Execution with Unnecessary Privileges]"
)
CLAUDE_PLUGIN_BROWSER_PROFILE_MESSAGE: Final = (
    "Claude plugin hook or manifest reaches a host browser profile store. "
    "Cookie and login databases are credential access, not a supported "
    "browser. Remove the profile path. "
    "[CWE-219 - Sensitive Information in Browser's History/Cache/Cookies]"
)
CLAUDE_PLUGIN_SECRET_TO_NETWORK_MESSAGE: Final = (
    "Claude plugin hook copies a named secret into a network request. Keep "
    "credentials out of curl, wget, and fetch payloads. "
    "[CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor]"
)
CLAUDE_PLUGIN_UNSIGNED_EXECUTABLE_DOWNLOAD_MESSAGE: Final = (
    "Claude plugin hook or package lifecycle script downloads an unsigned "
    "executable and makes it runnable. Pin and verify binaries; do not "
    "fetch mutable runtime payloads. "
    "[CWE-494 - Download of Code Without Integrity Check]"
)
CLAUDE_PLUGIN_UNPINNED_PACKAGE_INSTALL_MESSAGE: Final = (
    "Claude plugin hook or package lifecycle script installs a package "
    "from an unpinned URL. Pin versions and integrity hashes; do not "
    "install mutable remote artifacts. "
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
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_ARCHIVE_SUFFIXES: Final = (".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")
_PROVIDER_SECRET = re.compile(
    r"\b(?:OPENAI_API_KEY|NVIDIA_NIM_API_KEY(?:_SUB)?|BYTEZ_API_KEY|"
    r"OPENROUTER_API_KEY)\b"
)
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n]*\|\s*(?:bash|sh|zsh)\b",
    re.IGNORECASE,
)
_GITHUB_TOKEN = re.compile(
    r"\b(?P<prefix>ghp_|github_pat_|gho_|ghu_|ghs_)[A-Za-z0-9_]{20,}\b"
)
_DOCKER_SOCKET = re.compile(
    r"(?:/var/run/docker\.sock|unix://\S*docker\.sock)",
    re.IGNORECASE,
)
_BROWSER_PROFILE = re.compile(
    r"(?:Google/Chrome|Chromium/User Data|"
    r"%LOCALAPPDATA%\\Google\\Chrome|"
    r"Library/Application Support/(?:Google/Chrome|Chromium)|"
    r"\.mozilla/firefox|cookies\.sqlite|Login Data)",
    re.IGNORECASE,
)
_SECRET_TO_NETWORK = re.compile(
    r"(?:curl|wget|fetch)\b[^\n]*\$(?:\{)?(?P<name>"
    r"OPENAI_API_KEY|NVIDIA_NIM_API_KEY(?:_SUB)?|BYTEZ_API_KEY|"
    r"OPENROUTER_API_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|"
    r"AWS_SECRET_ACCESS_KEY)(?:\})?",
    re.IGNORECASE,
)
_PIPE_TO_INTERPRETER = re.compile(
    r"(?:curl|wget)\b[^\n]*\|\s*(?:python3?|node|nodejs|perl|ruby|pwsh|"
    r"powershell)\b",
    re.IGNORECASE,
)
_DOWNLOAD_TO_FILE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*?(?:\s|^)(?:-o|-O|--output-document|--output)\s+"
    r"(?P<path>[^\s;|&]+)",
    re.IGNORECASE,
)
_CHMOD_PLUS_X = re.compile(
    r"\bchmod\s+(?:\+x|a\+x|u\+x)\s+(?P<path>[^\s;|&]+)",
    re.IGNORECASE,
)
_UNPINNED_PACKAGE_INSTALL = re.compile(
    r"\b(?:pip(?:3)?|python(?:3)?\s+-m\s+pip|npm|pnpm|yarn|uv(?:\s+pip)?|"
    r"cargo)\s+(?:install|add)\s+[^\n]*?(?:https?://|git\+https?://|git://)",
    re.IGNORECASE,
)
_SK_LITERAL = re.compile(r"sk-[A-Za-z0-9_-]+")
_PACKAGE_LOCK_NAMES: Final = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }
)
_LIFECYCLE_SCRIPT_NAMES: Final = ("preinstall", "install", "postinstall")
_EXECUTABLE_SUFFIXES = frozenset(
    {".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".py"}
)
_SHELL_SUFFIXES: Final = frozenset({".sh", ".bash", ".zsh"})
_HOOK_DIRS = ("hooks", "scripts", "commands")
_HIDDEN_CONFIG_SUFFIXES: Final = frozenset(
    {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env"}
)
_GIT_METADATA_NAMES: Final = frozenset(
    {".gitignore", ".gitattributes", ".gitmodules"}
)
_CLAUDE_PLUGIN_MANIFEST_NAMES: Final = frozenset(
    {"plugin.json", "marketplace.json"}
)
_SKILL_SUPPLY_CHAIN_RULE_IDS: Final = frozenset(
    {
        "skill-name-homoglyph-confusable",
        "skill-manifest-prompt-injection-payload",
        "skill-doc-exfiltration-endpoint-directive",
        "skill-placeholder-template-unresolved",
    }
)
_SKILL_SURFACE_NAMES: Final = frozenset({"SKILL.md", "skill.json", "agent.md"})
_INVENTORY_MANIFESTS: Final = frozenset(
    {"plugin.json", "marketplace.json", ".mcp.json", "mcp.json", "hooks.json"}
)
CAPABILITY_INVENTORY_KEYS: Final = (
    "browser_profile_access",
    "credential_access",
    "deployment_write",
    "filesystem_read",
    "filesystem_write",
    "github_merge",
    "github_read",
    "github_release",
    "github_review",
    "github_write",
    "mcp_remote_connect",
    "mcp_server_start",
    "model_provider_access",
    "network_egress",
    "package_install",
    "process_spawn",
    "shell_execution",
)
_TEXT_CAPABILITY_PATTERNS: Final = (
    (
        "browser_profile_access",
        re.compile(
            r"Google/Chrome|Chromium|Firefox|cookies\.sqlite|Login Data",
            re.IGNORECASE,
        ),
    ),
    ("credential_access", _PROVIDER_SECRET),
    (
        "deployment_write",
        re.compile(
            r"\b(?:kubectl\s+apply|terraform\s+apply|helm\s+install|"
            r"vercel\s+deploy|fly\s+deploy|docker\s+push)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "filesystem_read",
        re.compile(r"\b(?:cat|read_text|read_bytes|Get-Content)\b"),
    ),
    (
        "filesystem_write",
        re.compile(
            r"\b(?:write_text|write_bytes|mkdir)\b|(?:^|\s)>\s*\S",
            re.MULTILINE,
        ),
    ),
    ("github_merge", re.compile(r"\bgh\s+pr\s+merge\b", re.IGNORECASE)),
    (
        "github_read",
        re.compile(
            r"\bgh\s+(?:api|issue\s+list|pr\s+view|repo\s+view)\b",
            re.IGNORECASE,
        ),
    ),
    ("github_release", re.compile(r"\bgh\s+release\b", re.IGNORECASE)),
    ("github_review", re.compile(r"\bgh\s+pr\s+review\b", re.IGNORECASE)),
    (
        "github_write",
        re.compile(
            r"\bgh\s+(?:issue\s+create|pr\s+create|repo\s+create)\b|"
            r"\b(?:ghp_|github_pat_|gho_|ghu_|ghs_)[A-Za-z0-9_]{20,}\b",
            re.IGNORECASE,
        ),
    ),
    ("model_provider_access", _PROVIDER_SECRET),
    (
        "network_egress",
        re.compile(r"\b(?:curl|wget|fetch)\b|https?://", re.IGNORECASE),
    ),
    (
        "package_install",
        re.compile(
            r"\b(?:pip|npm|pnpm|yarn|uv|cargo|apt-get)\s+install\b",
            re.IGNORECASE,
        ),
    ),
    (
        "process_spawn",
        re.compile(r"\b(?:subprocess|os\.system|Popen|posix_spawn)\b"),
    ),
    (
        "shell_execution",
        re.compile(
            r"^#![^\n]*(?:ba)?sh\b|\b(?:bash|zsh)\s+-c\b",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
)


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


def inventory_claude_plugin_capabilities(root: Path) -> dict[str, bool]:
    """Return a machine-readable capability inventory for one plugin tree.

    Inventory is evidence, not permission. A true capability is not a policy
    finding by itself and does not authorize admission or activation.

    Args:
        root: Materialized plugin tree.

    Returns:
        Mapping of every inventory key to a boolean, in deterministic key
        order. Secret literals never appear in the mapping.
    """
    inventory = _empty_capability_inventory()
    texts: list[str] = []
    saw_package_json = False
    saw_lockfile = False
    for path in _walk_entries(root):
        if path.is_symlink():
            continue
        if path.name == "package.json":
            saw_package_json = True
        elif path.name in _PACKAGE_LOCK_NAMES:
            saw_lockfile = True
        suffix = path.suffix.lower()
        if suffix in _SHELL_SUFFIXES:
            inventory["shell_execution"] = True
            inventory["process_spawn"] = True
        elif suffix in _EXECUTABLE_SUFFIXES:
            inventory["process_spawn"] = True
        payload = _regular_file_bytes(path)
        if not payload:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        texts.append(text)
        if path.name in _INVENTORY_MANIFESTS:
            _inventory_manifest_capabilities(text, inventory)
    _inventory_text_capabilities("\n".join(texts), inventory)
    if saw_package_json and saw_lockfile:
        inventory["package_install"] = True
    return {key: inventory[key] for key in CAPABILITY_INVENTORY_KEYS}


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
        ``package.json`` is inspected only for npm install lifecycle scripts.
    """
    posix = relative_path.replace("\\", "/")
    hits: list[PluginHit] = []
    manifest = _is_manifest(filename, posix)
    hook_surface = _is_hook_surface(filename, posix)
    lifecycle_surface = _is_package_lifecycle_surface(filename)
    if not manifest and not hook_surface and not lifecycle_surface:
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
    if hook_surface:
        hits.extend(_unsigned_executable_download_hits(content))
        hits.extend(_unpinned_package_install_hits(content))
        hits.extend(_dynamic_eval_hits(content))
    if lifecycle_surface:
        hits.extend(_package_lifecycle_hits(content))
    if manifest or hook_surface:
        hits.extend(_github_write_token_hits(content))
        hits.extend(_docker_socket_hits(content))
        hits.extend(_browser_profile_hits(content))
        hits.extend(_secret_to_network_hits(content))
    return tuple(hits)


def scan_claude_plugin_package(root: Path) -> tuple[PluginHit, ...]:
    """Return package-level findings for a materialized Claude plugin tree.

    Args:
        root: Scan root that may contain ``.claude-plugin/``.

    Returns:
        Undeclared executable, hidden undeclared executable or config,
        license absence or SPDX mismatch, size, symlink, archive traversal,
        and unadmitted-submodule findings. Empty when the tree is not a
        plugin package or every hook is a declared regular file. Inventory
        presence is not a finding. Git metadata is not a plugin executable
        surface. ``.mcp.json`` stays the MCP class.
    """
    plugin_dir = root / ".claude-plugin"
    if not plugin_dir.is_dir() or plugin_dir.is_symlink():
        return ()
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        manifest_path = plugin_dir / "marketplace.json"
    declared: set[str] = set()
    payload: object = {}
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
    elif isinstance(payload, dict):
        hits.extend(_license_mismatch_hits(root, payload))
    else:
        hits.extend(_license_mismatch_hits(root, {}))
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
    hits.extend(_archive_traversal_hits(root))
    hits.extend(_unadmitted_submodule_hits(root))
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
    hits.extend(_hidden_undeclared_executable_hits(root, declared))
    return tuple(hits)


def inspect_claude_plugin_archive(
    archive_path: Path,
    extract_root: Path,
) -> tuple[PluginHit, ...]:
    """Inspect one zip or tar plugin archive without escaping ``extract_root``.

    Members whose names leave the extract root (``../``, absolute POSIX
    paths, Windows drive or UNC prefixes) are findings and are never
    written. Safe members are materialized under ``extract_root``. Snippets
    record a sanitized member-path label only.

    Args:
        archive_path: Regular zip or tar file.
        extract_root: Bounded destination root.

    Returns:
        Path-traversal hits. Empty when every member stays inside the root
        or ``archive_path`` is not a readable archive. Secret literals and
        raw archive bytes never appear in snippets.
    """
    hits, safe_members = _classify_archive_members(archive_path, extract_root)
    for name in safe_members:
        _extract_archive_member(archive_path, name, extract_root)
    return hits


def build_claude_plugin_scan_receipt(
    root: Path,
    *,
    scanner_version: str = _SCANNER_VERSION,
    scan_started_at: str = "",
    scan_completed_at: str = "",
    catalog_payload: object | None = None,
    catalog_bytes: bytes | None = None,
) -> PluginScanReceipt:
    """Return a deterministic admission receipt for one plugin artifact.

    Args:
        root: Materialized plugin tree.
        scanner_version: Scanner release identity recorded on the receipt.
        scan_started_at: Optional caller-supplied start timestamp.
        scan_completed_at: Optional caller-supplied completion timestamp.
        catalog_payload: Optional parsed marketplace catalog document.
        catalog_bytes: Optional exact catalog file bytes.

    Returns:
        Receipt whose identity excludes wall-clock fields. ``scan_result`` is
        ``pass`` only when ``.claude-plugin/`` exists and no policy findings
        remain. Secret literals never appear on the receipt.
    """
    hits = list(_collect_plugin_hits(root))
    catalog = _catalog_identity(catalog_payload)
    hits.extend(_catalog_bind_hits(root, catalog))
    finding_summary = tuple(sorted({hit.rule_id for hit in hits}))
    identity = _plugin_identity(root)
    artifact_sha256, file_count, scanned_byte_count = _artifact_digest(root)
    marketplace_path = root / ".claude-plugin" / "marketplace.json"
    marketplace_bytes = (
        catalog_bytes if catalog_bytes is not None else _regular_file_bytes(marketplace_path)
    )
    marketplace_blob_sha = _sha256(marketplace_bytes) if marketplace_bytes else ""
    marketplace_entry_sha256 = _sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    policy_sha256 = _sha256(Path(__file__).read_bytes())
    inventory = inventory_claude_plugin_capabilities(root)
    capability_inventory_sha256 = _capability_inventory_digest(inventory)
    sarif_sha256 = sarif_document_sha256(
        finding_summary_to_sarif(finding_summary, tool_version=scanner_version)
    )
    is_package = (root / ".claude-plugin").is_dir() and not (
        root / ".claude-plugin"
    ).is_symlink()
    scan_result = "pass" if is_package and not finding_summary else "fail"
    body = {
        "scanner_name": _SCANNER_NAME,
        "scanner_version": scanner_version,
        "scanner_policy_sha256": policy_sha256,
        "catalog_repository": catalog["catalog_repository"],
        "catalog_commit_sha": catalog["catalog_commit_sha"],
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


@dataclass(frozen=True, slots=True)
class PluginReceiptVerification:
    """Fail-closed comparison of a retained receipt against current bytes.

    Matching is not Noema admission. ``scan_result=pass`` on the retained
    receipt never authorizes activation.
    """

    matches: bool
    mismatches: tuple[str, ...]

    @property
    def admitted(self) -> bool:
        """Return False; receipt verification is not product admission."""
        return False

    def as_dict(self) -> dict[str, object]:
        """Return JSON-safe mismatch reasons without secret or bidi values."""
        return {
            "matches": self.matches,
            "mismatches": list(self.mismatches),
            "admitted": False,
        }


def verify_plugin_scan_receipt(
    receipt: PluginScanReceipt,
    root: Path,
    *,
    expected_policy_sha256: str | None = None,
    catalog_payload: object | None = None,
    catalog_bytes: bytes | None = None,
) -> PluginReceiptVerification:
    """Fail closed unless the receipt still binds the current artifact and policy.

    Args:
        receipt: Previously issued scan receipt.
        root: Materialized tree being admitted.
        expected_policy_sha256: Caller-pinned policy digest. When omitted,
            the current scanner policy bytes are required.
        catalog_payload: Catalog document used when the receipt was issued.
        catalog_bytes: Exact catalog bytes used when the receipt was issued.

    Returns:
        Structured mismatch field names. Empty mismatches mean the receipt
        still describes this tree and policy. ``admitted`` is always false:
        ``scan_result=pass`` is not Noema admission. Reasons never include
        secret literals or raw bidi characters.
    """
    live = build_claude_plugin_scan_receipt(
        root,
        catalog_payload=catalog_payload,
        catalog_bytes=catalog_bytes,
    )
    current_policy_sha256 = _sha256(Path(__file__).read_bytes())
    expected = (
        current_policy_sha256
        if expected_policy_sha256 is None
        else expected_policy_sha256
    )
    mismatches: list[str] = []
    if receipt.artifact_sha256 != live.artifact_sha256:
        mismatches.append("artifact_sha256")
    if (
        receipt.scanner_policy_sha256 != current_policy_sha256
        or receipt.scanner_policy_sha256 != expected
    ):
        mismatches.append("scanner_policy_sha256")
    if receipt.catalog_commit_sha != live.catalog_commit_sha:
        mismatches.append("catalog_commit_sha")
    if receipt.source_commit_sha != live.source_commit_sha:
        mismatches.append("source_commit_sha")
    if receipt.marketplace_blob_sha != live.marketplace_blob_sha:
        mismatches.append("marketplace_blob_sha")
    if receipt.scan_receipt_id != live.scan_receipt_id:
        mismatches.append("scan_receipt_id")
    if receipt.scan_result != live.scan_result:
        mismatches.append("scan_result")
    return PluginReceiptVerification(
        matches=not mismatches,
        mismatches=tuple(mismatches),
    )


def _empty_capability_inventory() -> dict[str, bool]:
    """Return every inventory key as false, in deterministic order."""
    return {key: False for key in CAPABILITY_INVENTORY_KEYS}


def _capability_inventory_digest(inventory: dict[str, bool]) -> str:
    """Return SHA-256 of the canonical JSON capability inventory."""
    return _sha256(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    )


def _inventory_manifest_capabilities(
    content: str, inventory: dict[str, bool]
) -> None:
    """Mark MCP and process capabilities declared in one JSON manifest."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return
    if not isinstance(payload, dict):
        return
    servers = payload.get("mcpServers") or payload.get("mcp_servers") or {}
    if isinstance(servers, dict):
        for server in servers.values():
            if not isinstance(server, dict):
                continue
            remote_url = server.get("url")
            if isinstance(remote_url, str) and remote_url:
                inventory["mcp_remote_connect"] = True
                inventory["network_egress"] = True
            command = server.get("command")
            if isinstance(command, str) and command:
                inventory["mcp_server_start"] = True
                inventory["process_spawn"] = True
    if payload.get("hooks"):
        inventory["process_spawn"] = True


def _inventory_text_capabilities(content: str, inventory: dict[str, bool]) -> None:
    """Mark text-derived capabilities without recording secret literals."""
    if not content:
        return
    for key, pattern in _TEXT_CAPABILITY_PATTERNS:
        if pattern.search(content):
            inventory[key] = True


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
        or "/commands/" in posix_norm
        or "/.claude-plugin/" in posix_norm
    )
    if not in_plugin_tree:
        return False
    suffix = Path(filename).suffix.lower()
    return suffix in _EXECUTABLE_SUFFIXES or suffix == ""


def _is_package_lifecycle_surface(filename: str) -> bool:
    """Return whether the file is an npm ``package.json`` lifecycle surface."""
    return filename == "package.json"


def _lifecycle_script_values(content: str) -> tuple[tuple[str, str], ...]:
    """Return ``(name, script)`` pairs for npm install lifecycle scripts."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return ()
    if not isinstance(payload, dict):
        return ()
    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return ()
    found: list[tuple[str, str]] = []
    for name in _LIFECYCLE_SCRIPT_NAMES:
        value = scripts.get(name)
        if isinstance(value, str) and value.strip():
            found.append((name, value))
    return tuple(found)


def _script_line(content: str, body: str) -> int:
    """Return the 1-based line of a lifecycle script body in package.json."""
    if body in content:
        return _line_of(content, body)
    return _line_of(content, json.dumps(body)[1:-1])


def _package_lifecycle_hits(content: str) -> tuple[PluginHit, ...]:
    """Return unsigned-download findings from package.json lifecycle scripts.

    Only ``preinstall``, ``install``, and ``postinstall`` script strings are
    scanned. Other script names and non-script fields stay inventory.

    Args:
        content: Raw ``package.json`` text.

    Returns:
        Hits using the existing unsigned-download, pipe-to-shell, and
        unpinned-package rule identities. Empty when no lifecycle script
        downloads or executes an unsigned payload.
    """
    hits: list[PluginHit] = []
    for _name, body in _lifecycle_script_values(content):
        line = _script_line(content, body)
        match = _PIPE_TO_SHELL.search(body)
        if match is not None:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-pipe-to-shell",
                    line=line,
                    snippet=_sanitize_plugin_snippet(match.group(0).splitlines()[0]),
                    message=CLAUDE_PLUGIN_PIPE_TO_SHELL_MESSAGE,
                )
            )
        for hit in _unsigned_executable_download_hits(body):
            hits.append(
                PluginHit(
                    rule_id=hit.rule_id,
                    line=line,
                    snippet=hit.snippet,
                    message=hit.message,
                )
            )
        for hit in _unpinned_package_install_hits(body):
            hits.append(
                PluginHit(
                    rule_id=hit.rule_id,
                    line=line,
                    snippet=hit.snippet,
                    message=hit.message,
                )
            )
    return tuple(hits)


def _already_inspected_package_json(relative: str) -> bool:
    """Return whether ``relative`` is already scanned under plugin or hook dirs."""
    posix = relative.replace("\\", "/")
    if posix.startswith(".claude-plugin/"):
        return True
    return posix.split("/", 1)[0] in _HOOK_DIRS


def _package_lifecycle_file_hits(root: Path) -> tuple[PluginHit, ...]:
    """Inspect ``package.json`` files that hook and plugin-dir walks miss.

    Args:
        root: Materialized plugin tree.

    Returns:
        Lifecycle-script findings from package.json files outside
        ``.claude-plugin/`` and hook directories. Unreadable files yield no
        hits.
    """
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file() or path.name != "package.json":
            continue
        relative = path.relative_to(root).as_posix()
        if _already_inspected_package_json(relative):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            content = ""
        hits.extend(inspect_claude_plugin_file(path.name, relative, content))
    return tuple(hits)


def _github_write_token_hits(content: str) -> tuple[PluginHit, ...]:
    """Return hardcoded GitHub PAT or app-token findings without secret bodies."""
    match = _GITHUB_TOKEN.search(content)
    if match is None:
        return ()
    prefix = match.group("prefix")
    return (
        PluginHit(
            rule_id="claude-plugin-github-write-token",
            line=content[: match.start()].count("\n") + 1,
            snippet=prefix,
            message=CLAUDE_PLUGIN_GITHUB_WRITE_TOKEN_MESSAGE,
        ),
    )


def _dynamic_eval_hits(content: str) -> tuple[PluginHit, ...]:
    """Return findings for eval/exec/compile/Function on hook surfaces."""
    match = _DYNAMIC_EVAL.search(content)
    if match is None:
        return ()
    token = match.group(0).strip()
    if "(" in token:
        label = token.split("(", 1)[0].strip()[:40]
    else:
        label = token.split()[0][:40]
    return (
        PluginHit(
            rule_id="claude-plugin-dynamic-eval",
            line=content[: match.start()].count("\n") + 1,
            snippet=label,
            message=CLAUDE_PLUGIN_DYNAMIC_EVAL_MESSAGE,
        ),
    )


def _docker_socket_hits(content: str) -> tuple[PluginHit, ...]:
    """Return host Docker-socket findings from hook or manifest text."""
    match = _DOCKER_SOCKET.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-docker-socket",
            line=content[: match.start()].count("\n") + 1,
            snippet=match.group(0)[:120],
            message=CLAUDE_PLUGIN_DOCKER_SOCKET_MESSAGE,
        ),
    )


def _browser_profile_hits(content: str) -> tuple[PluginHit, ...]:
    """Return host browser-profile store findings from hook or manifest text.

    Path-like Chrome, Chromium, and Firefox profile stores fail closed.
    A bare product name such as ``Firefox`` is inventory, not this finding.

    Args:
        content: Hook or manifest text.

    Returns:
        Zero or one hit. Snippets omit secret literals and raw bidi.
    """
    match = _BROWSER_PROFILE.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-browser-profile-access",
            line=content[: match.start()].count("\n") + 1,
            snippet=_sanitize_plugin_snippet(match.group(0))[:120],
            message=CLAUDE_PLUGIN_BROWSER_PROFILE_MESSAGE,
        ),
    )


def _secret_to_network_hits(content: str) -> tuple[PluginHit, ...]:
    """Return findings when a named secret is copied into a network client."""
    match = _SECRET_TO_NETWORK.search(content)
    if match is None:
        return ()
    name = match.group("name")
    client = "curl"
    lowered = match.group(0).lower()
    if lowered.startswith("wget"):
        client = "wget"
    elif lowered.startswith("fetch"):
        client = "fetch"
    return (
        PluginHit(
            rule_id="claude-plugin-secret-to-network",
            line=content[: match.start()].count("\n") + 1,
            snippet=f"{client} ${name}"[:120],
            message=CLAUDE_PLUGIN_SECRET_TO_NETWORK_MESSAGE,
        ),
    )


def _sanitize_plugin_snippet(value: str) -> str:
    """Return a bidi-free snippet without token bodies or sk- secret literals."""
    cleaned = _CONCEALED_CHAR.sub("", value)
    cleaned = _GITHUB_TOKEN.sub(lambda match: match.group("prefix"), cleaned)
    cleaned = _SK_LITERAL.sub("sk-", cleaned)
    return cleaned.strip()[:120]


def _downloaded_path_executed(content: str, path: str) -> bool:
    """Return whether ``path`` is invoked as a command after download."""
    pattern = re.compile(
        rf"(?:^|&&|;|\n)\s*(?:(?:ba)?sh\s+)?{re.escape(path)}\b",
        re.MULTILINE,
    )
    return pattern.search(content) is not None


def _unsigned_executable_download_hits(content: str) -> tuple[PluginHit, ...]:
    """Return unsigned runtime-download findings from hook or script text."""
    hits: list[PluginHit] = []
    seen_lines: set[int] = set()

    def add(match: re.Match[str]) -> None:
        """Record one download finding, skipping a second hit on the same line."""
        line = content[: match.start()].count("\n") + 1
        if line in seen_lines:
            return
        seen_lines.add(line)
        hits.append(
            PluginHit(
                rule_id="claude-plugin-unsigned-executable-download",
                line=line,
                snippet=_sanitize_plugin_snippet(match.group(0).splitlines()[0]),
                message=CLAUDE_PLUGIN_UNSIGNED_EXECUTABLE_DOWNLOAD_MESSAGE,
            )
        )

    for match in _PIPE_TO_INTERPRETER.finditer(content):
        add(match)
    chmod_paths = {
        match.group("path").strip("'\"") for match in _CHMOD_PLUS_X.finditer(content)
    }
    for match in _DOWNLOAD_TO_FILE.finditer(content):
        path = match.group("path").strip("'\"")
        if path in chmod_paths or _downloaded_path_executed(content, path):
            add(match)
    return tuple(hits)


def _unpinned_package_install_hits(content: str) -> tuple[PluginHit, ...]:
    """Return unpinned URL package-install findings from hook or script text."""
    match = _UNPINNED_PACKAGE_INSTALL.search(content)
    if match is None:
        return ()
    return (
        PluginHit(
            rule_id="claude-plugin-unpinned-package-install",
            line=content[: match.start()].count("\n") + 1,
            snippet=_sanitize_plugin_snippet(match.group(0).splitlines()[0]),
            message=CLAUDE_PLUGIN_UNPINNED_PACKAGE_INSTALL_MESSAGE,
        ),
    )


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


def _is_git_metadata_path(relative: str) -> bool:
    """Return whether ``relative`` is Git metadata, not a plugin surface.

    ``.git/`` internals, gitlink files named ``.git``, and
    ignore/attributes/modules files are VCS metadata. They are not Claude
    plugin executable or config surfaces, including when nested under a
    vendor path.
    """
    return any(
        part == ".git" or part in _GIT_METADATA_NAMES for part in relative.split("/")
    )


def _is_hidden_plugin_path(relative: str) -> bool:
    """Return whether a package-relative path uses a hidden name or directory."""
    return any(part.startswith(".") for part in relative.split("/"))


def _is_hidden_executable_or_config_surface(path: Path, relative: str) -> bool:
    """Return whether a hidden path is an executable, script, or config surface.

    Documented ``.mcp.json`` and ``.claude-plugin`` manifests are not this
    class. Git metadata is not a plugin executable surface.
    """
    if not _is_hidden_plugin_path(relative) or _is_git_metadata_path(relative):
        return False
    if path.name in _MCP_FILENAMES:
        return False
    parts = relative.split("/")
    if (
        len(parts) >= 2
        and parts[-2] == ".claude-plugin"
        and parts[-1] in _CLAUDE_PLUGIN_MANIFEST_NAMES
    ):
        return False
    suffix = path.suffix.lower()
    return (
        suffix in _EXECUTABLE_SUFFIXES
        or suffix == ""
        or suffix in _HIDDEN_CONFIG_SUFFIXES
    )


def _hidden_undeclared_executable_hits(
    root: Path, declared: set[str]
) -> tuple[PluginHit, ...]:
    """Return findings for hidden undeclared executable or config surfaces.

    Args:
        root: Materialized plugin tree.
        declared: Hook and command paths declared in the plugin manifest.

    Returns:
        Hits for hidden paths such as ``.bin/run.sh`` or ``.hooks/secret.py``
        that are executable, script, or config surfaces and are not
        declared. Empty when every hidden surface is Git metadata,
        documented MCP or plugin manifest, or already declared. Non-hidden
        extras under ``hooks/``, ``scripts/``, or ``commands/`` stay
        ``claude-plugin-undeclared-executable``.
    """
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in declared:
            continue
        if not _is_hidden_executable_or_config_surface(path, relative):
            continue
        hits.append(
            PluginHit(
                rule_id="claude-plugin-hidden-undeclared-executable",
                line=1,
                snippet=_sanitize_path_snippet(path.name),
                message=CLAUDE_PLUGIN_HIDDEN_UNDECLARED_EXECUTABLE_MESSAGE,
                file=relative,
            )
        )
    return tuple(hits)


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
        for path in _license_evidence_paths(root)
    ]
    return ",".join(names) if names else "absent"


def _license_evidence_paths(root: Path) -> tuple[Path, ...]:
    """Return LICENSE* and NOTICE* regular files, never following symlinks."""
    found: list[Path] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file():
            continue
        upper = path.name.upper()
        if upper.startswith("LICENSE") or upper.startswith("NOTICE"):
            found.append(path)
    return tuple(found)


def _spdx_tokens_from_text(text: str) -> set[str]:
    """Return known SPDX identifiers found in ``text`` without legal approval."""
    return {match.group(1).upper() for match in _SPDX_TOKEN.finditer(text)}


def _declared_license_expression(payload: dict) -> str:
    """Return a string license field from a plugin manifest, if present."""
    value = payload.get("license")
    return value if isinstance(value, str) else ""


def _license_mismatch_hits(root: Path, payload: dict) -> tuple[PluginHit, ...]:
    """Return a finding when SPDX tokens in license evidence disagree."""
    tokens: set[str] = set()
    declared = _declared_license_expression(payload)
    tokens.update(_spdx_tokens_from_text(declared))
    for path in _license_evidence_paths(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        tokens.update(_spdx_tokens_from_text(text))
    if len(tokens) < 2:
        return ()
    snippet = ",".join(sorted(tokens))[:120]
    return (
        PluginHit(
            rule_id="claude-plugin-license-mismatch",
            line=1,
            snippet=snippet,
            message=CLAUDE_PLUGIN_LICENSE_MISMATCH_MESSAGE,
            file=".claude-plugin",
        ),
    )


def _empty_identity() -> dict[str, str]:
    """Return blank plugin identity fields."""
    return {
        "plugin_name": "",
        "plugin_version": "",
        "source_repository": "",
        "source_commit_sha": "",
        "source_path": "",
    }


def _empty_catalog_identity() -> dict[str, str]:
    """Return blank catalog and plugin identity fields."""
    return {
        "catalog_repository": "",
        "catalog_commit_sha": "",
        **_empty_identity(),
    }


def _catalog_identity(payload: object | None) -> dict[str, str]:
    """Return catalog repository/SHA plus first plugin identity from a catalog."""
    identity = _empty_catalog_identity()
    if not isinstance(payload, dict):
        return identity
    repo = payload.get("repository") or payload.get("catalog_repository")
    sha = (
        payload.get("commit")
        or payload.get("catalog_commit_sha")
        or payload.get("sha")
    )
    identity.update(_identity_from_payload(payload))
    if isinstance(repo, str):
        identity["catalog_repository"] = repo
    if isinstance(sha, str):
        identity["catalog_commit_sha"] = sha
    return identity


def _catalog_bind_hits(root: Path, catalog: dict[str, str]) -> tuple[PluginHit, ...]:
    """Return findings when an external catalog disagrees with the artifact."""
    hits: list[PluginHit] = []
    catalog_sha = catalog.get("catalog_commit_sha") or ""
    if catalog_sha and not _FULL_SHA.fullmatch(catalog_sha):
        hits.append(
            PluginHit(
                rule_id="claude-plugin-floating-git-ref",
                line=1,
                snippet=catalog_sha[:120],
                message=CLAUDE_PLUGIN_FLOATING_REF_MESSAGE,
                file="marketplace.json",
            )
        )
    plugin = _plugin_identity(root)
    for field in ("plugin_name", "source_repository", "source_commit_sha"):
        left, right = catalog.get(field) or "", plugin.get(field) or ""
        if left and right and left != right:
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-source-mismatch",
                    line=1,
                    snippet=field,
                    message=CLAUDE_PLUGIN_SOURCE_MISMATCH_MESSAGE,
                    file="marketplace.json",
                )
            )
            break
    return tuple(hits)


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
    """Combine package-level, hook, and package.json lifecycle findings."""
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
    hits.extend(_package_lifecycle_file_hits(root))
    hits.extend(_skill_supply_chain_hits(root))
    return tuple(hits)


def _is_skill_surface(path: Path) -> bool:
    """Return whether ``path`` is a released #1036 skill or agent surface."""
    name = path.name
    return name in _SKILL_SURFACE_NAMES or name.endswith(".skill.md")


def _skill_supply_chain_hits(root: Path) -> tuple[PluginHit, ...]:
    """Reuse released #1036 rule identities on plugin skill/agent files.

    Homoglyph, injection, exfiltration, and placeholder detection stay in
    ``scanner/rules/skill_supply_chain.yml``. This adapter does not copy those
    regular expressions. Missing rule files yield no hits.

    Args:
        root: Materialized plugin tree.

    Returns:
        Hits whose ``rule_id`` values are the released skill-supply-chain
        identities. Empty when no skill surface exists or the YAML pack is
        absent.
    """
    from scanner.cli.appguardrail import _scan_file

    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        if path.is_symlink() or not path.is_file() or not _is_skill_surface(path):
            continue
        relative = path.relative_to(root).as_posix()
        for finding in _scan_file(path, root):
            rule_id = str(finding.get("rule_id") or "")
            if rule_id not in _SKILL_SUPPLY_CHAIN_RULE_IDS:
                continue
            hits.append(
                PluginHit(
                    rule_id=rule_id,
                    line=int(finding.get("line") or 1),
                    snippet=str(finding.get("snippet") or path.name)[:120],
                    message=str(finding.get("message") or ""),
                    file=str(finding.get("file") or relative),
                )
            )
    return tuple(hits)


@dataclass(frozen=True, slots=True)
class _SubmodulePointer:
    """One nested submodule, gitlink, or .gitmodules path record."""

    path: str
    file: str
    recorded_sha: str


def _sanitize_path_snippet(value: str) -> str:
    """Return a bidi-free path label without file contents or secrets."""
    cleaned = _CONCEALED_CHAR.sub("", value.replace("\\", "/"))
    return cleaned[:120] or "path"


def _is_archive_path(path: Path) -> bool:
    """Return whether ``path`` uses a zip or tar suffix."""
    name = path.name.lower()
    return name.endswith(_ARCHIVE_SUFFIXES)


def _archive_display_path(archive_path: Path, extract_root: Path) -> str:
    """Return a root-relative archive path, or the basename when unbound."""
    try:
        return archive_path.relative_to(extract_root).as_posix()
    except ValueError:
        return archive_path.name


def _archive_member_escapes(member_name: str, extract_root: Path) -> bool:
    """Return whether an archive member would resolve outside ``extract_root``."""
    if not member_name or "\x00" in member_name or _CONCEALED_CHAR.search(member_name):
        return True
    stripped = _CONCEALED_CHAR.sub("", member_name)
    raw = stripped.replace("\\", "/")
    if (
        raw.startswith("/")
        or stripped.startswith("\\\\")
        or raw.startswith("//")
        or _WINDOWS_DRIVE.match(stripped)
        or _WINDOWS_DRIVE.match(raw)
    ):
        return True
    parts = [part for part in raw.split("/") if part not in {"", "."}]
    if any(part == ".." or part.startswith("..") for part in parts):
        return True
    try:
        root = extract_root.resolve()
    except OSError:
        return True
    dest = Path(os.path.normpath(os.path.join(str(root), raw)))
    try:
        dest.relative_to(root)
    except ValueError:
        return True
    return False


def _traversal_hit(archive_file: str, member_name: str) -> PluginHit:
    """Return one archive path-traversal finding with a sanitized snippet."""
    return PluginHit(
        rule_id="claude-plugin-archive-path-traversal",
        line=1,
        snippet=_sanitize_path_snippet(member_name),
        message=CLAUDE_PLUGIN_ARCHIVE_PATH_TRAVERSAL_MESSAGE,
        file=archive_file,
    )


def _archive_member_names(archive_path: Path) -> tuple[tuple[str, ...], bool]:
    """Return member names and whether ``archive_path`` opened as an archive."""
    try:
        if archive_path.is_symlink() or not archive_path.is_file():
            return (), False
    except OSError:
        return (), False
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                return tuple(archive.namelist()), True
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path) as archive:
                return tuple(member.name for member in archive.getmembers()), True
    except (OSError, zipfile.BadZipFile, tarfile.TarError, ValueError):
        return (), False
    return (), False


def _classify_archive_members(
    archive_path: Path, extract_root: Path
) -> tuple[tuple[PluginHit, ...], tuple[str, ...]]:
    """Split archive members into traversal hits and in-root extract names."""
    names, readable = _archive_member_names(archive_path)
    relative = _archive_display_path(archive_path, extract_root)
    if not readable:
        if _is_archive_path(archive_path):
            return ((_traversal_hit(relative, archive_path.name),), ())
        return (), ()
    hits: list[PluginHit] = []
    safe: list[str] = []
    for name in names:
        if _archive_member_escapes(name, extract_root):
            hits.append(_traversal_hit(relative, name))
            continue
        if name.endswith("/") or name.endswith("\\"):
            continue
        safe.append(name)
    return tuple(hits), tuple(safe)


def _read_archive_member(archive_path: Path, name: str) -> bytes | None:
    """Return one in-root archive member payload, or None on failure."""
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                return archive.read(name)
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path) as archive:
                extracted = archive.extractfile(name)
                if extracted is None:
                    return None
                return extracted.read()
    except (OSError, KeyError, zipfile.BadZipFile, tarfile.TarError, ValueError):
        return None
    return None


def _extract_archive_member(
    archive_path: Path, name: str, extract_root: Path
) -> None:
    """Write one in-root member under ``extract_root`` without following links."""
    dest = _bounded_destination(extract_root, name)
    if dest is None:
        return
    try:
        if dest.exists() and (dest.is_symlink() or dest.is_dir()):
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = _read_archive_member(archive_path, name)
        if payload is None:
            return
        dest.write_bytes(payload)
    except OSError:
        return


def _bounded_destination(extract_root: Path, member_name: str) -> Path | None:
    """Return the in-root destination for ``member_name``, or None if unsafe."""
    if _archive_member_escapes(member_name, extract_root):
        return None
    root = extract_root.resolve()
    return Path(os.path.normpath(os.path.join(str(root), member_name.replace("\\", "/"))))


def _archive_traversal_hits(root: Path) -> tuple[PluginHit, ...]:
    """Return traversal findings for zip/tar files inside ``root`` without extracting."""
    hits: list[PluginHit] = []
    for path in _walk_entries(root):
        try:
            if path.is_symlink() or not path.is_file() or not _is_archive_path(path):
                continue
        except OSError:
            continue
        member_hits, _safe = _classify_archive_members(path, root)
        hits.extend(member_hits)
    return tuple(hits)


def _unadmitted_submodule_hits(
    root: Path, *, _seen: frozenset[Path] | None = None
) -> tuple[PluginHit, ...]:
    """Return findings for nested git pointers without admitted SHA identity."""
    try:
        resolved = root.resolve()
    except OSError:
        resolved = root
    seen = set(_seen or ())
    if resolved in seen:
        return ()
    seen.add(resolved)
    hits: list[PluginHit] = []
    for pointer in _iter_submodules(root):
        if not _submodule_is_admitted(root, pointer):
            hits.append(
                PluginHit(
                    rule_id="claude-plugin-unadmitted-submodule",
                    line=1,
                    snippet=_sanitize_path_snippet(pointer.path or pointer.file),
                    message=CLAUDE_PLUGIN_UNADMITTED_SUBMODULE_MESSAGE,
                    file=pointer.file,
                )
            )
            continue
        hits.extend(
            _unadmitted_submodule_hits(root / pointer.path, _seen=frozenset(seen))
        )
    return tuple(hits)


def _iter_submodules(root: Path) -> tuple[_SubmodulePointer, ...]:
    """Discover .gitmodules entries and nested gitlink directories."""
    found: dict[str, _SubmodulePointer] = {}
    gitmodules = root / ".gitmodules"
    try:
        gitmodules_is_symlink = gitmodules.is_symlink()
        gitmodules_is_file = gitmodules.is_file()
    except OSError:
        gitmodules_is_symlink = False
        gitmodules_is_file = False
    if gitmodules_is_symlink:
        found[""] = _SubmodulePointer(path="", file=".gitmodules", recorded_sha="")
    elif gitmodules_is_file:
        for pointer in _parse_gitmodules(gitmodules):
            found[pointer.path] = pointer
    for path in _walk_entries(root):
        if path.name != ".git":
            continue
        try:
            if path.is_symlink() or not path.is_file():
                continue
            nested_root = path.parent
            rel = nested_root.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if rel in {".", ""}:
            continue
        sha = _gitlink_sha(nested_root)
        existing = found.get(rel)
        if existing is None:
            found[rel] = _SubmodulePointer(path=rel, file=rel, recorded_sha=sha)
        elif not existing.recorded_sha and sha:
            found[rel] = _SubmodulePointer(
                path=rel, file=existing.file, recorded_sha=sha
            )
    return tuple(found.values())


def _parse_gitmodules(path: Path) -> tuple[_SubmodulePointer, ...]:
    """Parse submodule path/url records; fail closed on unreadable INI."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return (_SubmodulePointer(path="", file=".gitmodules", recorded_sha=""),)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return (_SubmodulePointer(path="", file=".gitmodules", recorded_sha=""),)
    pointers: list[_SubmodulePointer] = []
    for section in parser.sections():
        if not section.lower().startswith("submodule"):
            continue
        sub_path = parser.get(section, "path", fallback="").strip()
        if not sub_path:
            sub_path = section.split(None, 1)[-1].strip().strip('"')
        sha = (
            parser.get(section, "sha", fallback="")
            or parser.get(section, "commit", fallback="")
        ).strip()
        pointers.append(
            _SubmodulePointer(path=sub_path, file=".gitmodules", recorded_sha=sha)
        )
    return tuple(pointers)


def _read_head_sha(gitdir: Path) -> str:
    """Return a 40-character SHA from ``gitdir/HEAD``, else empty."""
    head = gitdir / "HEAD"
    try:
        if head.is_symlink() or not head.is_file():
            return ""
        text = head.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return text if _FULL_SHA.fullmatch(text) else ""


def _gitlink_sha(nested_root: Path) -> str:
    """Return the recorded gitlink SHA for ``nested_root``, if present."""
    git_path = nested_root / ".git"
    try:
        if git_path.is_symlink():
            return ""
        if git_path.is_file():
            text = git_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("gitdir:"):
                    spec = stripped.split(":", 1)[1].strip()
                    gitdir = Path(spec)
                    if not gitdir.is_absolute():
                        gitdir = nested_root / spec
                    return _read_head_sha(gitdir)
                if _FULL_SHA.fullmatch(stripped):
                    return stripped
        if git_path.is_dir():
            return _read_head_sha(git_path)
    except (OSError, UnicodeDecodeError):
        return ""
    return ""


def _recorded_sha(root: Path, pointer: _SubmodulePointer) -> str:
    """Return a full SHA from gitmodules, gitlink file, or gitdir HEAD."""
    if _FULL_SHA.fullmatch(pointer.recorded_sha):
        return pointer.recorded_sha
    nested = root / pointer.path
    try:
        if nested.is_symlink():
            return ""
        if nested.is_file():
            body = nested.read_text(encoding="utf-8").strip()
            return body if _FULL_SHA.fullmatch(body) else ""
        if nested.is_dir():
            sha = _gitlink_sha(nested)
            return sha if _FULL_SHA.fullmatch(sha) else ""
    except (OSError, UnicodeDecodeError):
        return ""
    return ""


def _submodule_is_admitted(root: Path, pointer: _SubmodulePointer) -> bool:
    """Return whether a nested pointer has a complete admitted package identity."""
    if not pointer.path or pointer.path in {".", ".."}:
        return False
    parts = Path(pointer.path.replace("\\", "/")).parts
    if ".." in parts or pointer.path.startswith("/") or _WINDOWS_DRIVE.match(pointer.path):
        return False
    sha = _recorded_sha(root, pointer)
    if not sha:
        return False
    nested = root / pointer.path
    try:
        if nested.is_symlink() or not nested.is_dir():
            return False
    except OSError:
        return False
    if _license_summary(nested) == "absent":
        return False
    identity = _plugin_identity(nested)
    nested_sha = identity["source_commit_sha"]
    if not _FULL_SHA.fullmatch(nested_sha or ""):
        return False
    if nested_sha.lower() != sha.lower():
        return False
    plugin_dir = nested / ".claude-plugin"
    try:
        if not plugin_dir.is_dir() or plugin_dir.is_symlink():
            return False
    except OSError:
        return False
    return True
