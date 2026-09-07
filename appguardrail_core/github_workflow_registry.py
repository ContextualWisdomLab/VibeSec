"""Detect active GitHub Actions registry entries whose workflow files are deleted.

The detector binds the live workflow registry to one independently acquired,
protected default-branch commit and recursive Git tree. Missing, malformed,
truncated, permission-limited, or otherwise ambiguous evidence fails closed and
never becomes a clean result. The scanner is deliberately read-only: it can
recommend disabling a confirmed orphan but never mutates workflow state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

API_ORIGIN = "https://api.github.com"
API_VERSION = "2026-03-10"
WORKFLOW_DOCUMENTATION_URL = (
    "https://docs.github.com/en/rest/actions/workflows?apiVersion=2026-03-10"
)
TREE_DOCUMENTATION_URL = (
    "https://docs.github.com/en/rest/git/trees?apiVersion=2026-03-10"
)
PAGINATION_DOCUMENTATION_URL = (
    "https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api"
    "?apiVersion=2026-03-10"
)
MAX_RESPONSE_BYTES = 2_000_000
MAX_PAGES = 100
DEFAULT_TIMEOUT_SECONDS = 15.0
USER_AGENT = "appguardrail-workflow-registry/1"
_SHA_RE = re.compile(r"\A[0-9a-fA-F]{40}\Z")
_REPOSITORY_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_UTC_TIMESTAMP_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_DYNAMIC_WORKFLOW_RE = re.compile(
    r"\Adynamic/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\Z"
)
_WRITER_HINTS = ("once", "apply", "finalize", "repair", "bootstrap", "writer")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so registry evidence cannot be retargeted."""

    def redirect_request(
        self,
        req: object,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        """Return no redirected request, exposing the redirect as an HTTP error."""
        del req, fp, code, msg, headers, newurl
        return None


class EvidenceCollectionError(RuntimeError):
    """Report one bounded reason that authoritative GitHub evidence is unusable."""


@dataclass(frozen=True)
class WorkflowRegistryEntry:
    """One workflow registry identity classified against an exact Git tree."""

    workflow_id: int
    name: str
    path: str
    registry_state: str
    status: str
    writer_like: bool
    html_url: str


@dataclass(frozen=True)
class WorkflowInventory:
    """One source-bound GitHub Actions workflow inventory assessment."""

    repository: str
    default_branch: str
    default_branch_sha: str
    tree_sha: str
    verified_at: str
    complete: bool
    entries: tuple[WorkflowRegistryEntry, ...]
    reason: str = ""


def _utc_timestamp() -> str:
    """Return the current UTC timestamp in stable second-precision form."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_repository(value: str) -> str:
    """Require an owner/name repository identity without URL or path traversal."""
    repository = str(value or "").strip()
    if not _REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository must use owner/name form")
    return repository


def _same_repository(value: Any, repository: str) -> bool:
    """Compare GitHub repository identities without case-sensitive aliases."""
    return isinstance(value, str) and value.casefold() == repository.casefold()


def _normalize_verified_at(value: str | None) -> str:
    """Require one canonical UTC audit timestamp."""
    verified_at = str(value or "").strip()
    if not _UTC_TIMESTAMP_RE.fullmatch(verified_at):
        raise ValueError("verified_at must use YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(verified_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("verified_at must use YYYY-MM-DDTHH:MM:SSZ") from exc
    return verified_at


def _incomplete_inventory(
    repository: str,
    verified_at: str,
    reason: str,
    *,
    default_branch: str = "",
    default_branch_sha: str = "",
    tree_sha: str = "",
    entries: Iterable[WorkflowRegistryEntry] = (),
) -> WorkflowInventory:
    """Return a fail-closed inventory retaining any source identity acquired so far."""
    return WorkflowInventory(
        repository=repository,
        default_branch=default_branch,
        default_branch_sha=default_branch_sha,
        tree_sha=tree_sha,
        verified_at=verified_at,
        complete=False,
        entries=tuple(entries),
        reason=reason,
    )


def _nested_value(value: Any, *keys: str) -> Any:
    """Return a nested value or ``None`` when an intermediate level is not an object."""
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _valid_sha(value: Any) -> bool:
    """Return whether ``value`` is one exact forty-character Git SHA-1 string."""
    return isinstance(value, str) and bool(_SHA_RE.fullmatch(value))


def _valid_workflow_path(value: Any) -> bool:
    """Return whether ``value`` is a normalized workflow file path."""
    if not isinstance(value, str):
        return False
    if _DYNAMIC_WORKFLOW_RE.fullmatch(value):
        return True
    if not value.startswith(".github/workflows/"):
        return False
    if value.startswith("/") or ".." in value.split("/"):
        return False
    return value.endswith((".yml", ".yaml")) and len(value) > len(".github/workflows/.yml")


def _writer_like(name: str, path: str) -> bool:
    """Return whether an orphan identity looks like temporary/write-oriented tooling."""
    normalized = f"{name} {path}".lower()
    return any(hint in normalized for hint in _WRITER_HINTS)


def _parse_workflow_record(
    record: Any,
    *,
    tree_paths: frozenset[str],
) -> WorkflowRegistryEntry | None:
    """Parse and classify one workflow registry record, returning ``None`` if invalid."""
    if not isinstance(record, dict):
        return None
    workflow_id = record.get("id")
    name = record.get("name")
    path = record.get("path")
    state = record.get("state")
    html_url = record.get("html_url")
    if (
        not isinstance(workflow_id, int)
        or isinstance(workflow_id, bool)
        or workflow_id <= 0
        or not isinstance(name, str)
        or not name.strip()
        or not _valid_workflow_path(path)
        or not isinstance(state, str)
        or not state.strip()
        or not isinstance(html_url, str)
        or not html_url.startswith("https://github.com/")
    ):
        return None
    path = str(path)
    state = state.strip()
    if state == "active":
        if path.startswith("dynamic/"):
            status = "dynamic_managed"
        else:
            status = "present" if path in tree_paths else "orphaned_deleted"
    elif state.startswith("disabled"):
        status = "disabled"
    else:
        status = "unresolved"
    return WorkflowRegistryEntry(
        workflow_id=workflow_id,
        name=name.strip(),
        path=path,
        registry_state=state,
        status=status,
        writer_like=_writer_like(name, path),
        html_url=html_url,
    )


def build_workflow_inventory(
    *,
    repository: str,
    verified_at: str,
    repository_payload: Any,
    branch_payload: Any,
    tree_payload: Any,
    workflow_pages: Iterable[Any],
) -> WorkflowInventory:
    """Classify GitHub workflow records against one exact protected branch tree.

    Every source identity and pagination invariant is validated before a complete
    result is emitted. Unknown workflow states remain explicit and make the whole
    inventory incomplete, while still preserving their individual registry IDs.
    """
    repository = _normalize_repository(repository)
    verified_at = _normalize_verified_at(verified_at)
    if not isinstance(repository_payload, dict) or not _same_repository(
        repository_payload.get("full_name"), repository
    ):
        return _incomplete_inventory(repository, verified_at, "repository_identity_mismatch")
    default_branch = repository_payload.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch.strip():
        return _incomplete_inventory(repository, verified_at, "invalid_default_branch")
    default_branch = default_branch.strip()
    if not isinstance(branch_payload, dict) or branch_payload.get("name") != default_branch:
        return _incomplete_inventory(
            repository,
            verified_at,
            "default_branch_identity_mismatch",
            default_branch=default_branch,
        )
    if branch_payload.get("protected") is not True:
        return _incomplete_inventory(
            repository,
            verified_at,
            "default_branch_unprotected",
            default_branch=default_branch,
        )
    branch_sha = _nested_value(branch_payload, "commit", "sha")
    if not _valid_sha(branch_sha):
        return _incomplete_inventory(
            repository,
            verified_at,
            "invalid_default_branch_sha",
            default_branch=default_branch,
        )
    tree_sha = _nested_value(branch_payload, "commit", "commit", "tree", "sha")
    if not _valid_sha(tree_sha):
        return _incomplete_inventory(
            repository,
            verified_at,
            "invalid_tree_sha",
            default_branch=default_branch,
            default_branch_sha=str(branch_sha),
        )
    if not isinstance(tree_payload, dict) or tree_payload.get("sha") != tree_sha:
        return _incomplete_inventory(
            repository,
            verified_at,
            "tree_identity_mismatch",
            default_branch=default_branch,
            default_branch_sha=str(branch_sha),
            tree_sha=str(tree_sha),
        )
    if tree_payload.get("truncated") is not False:
        return _incomplete_inventory(
            repository,
            verified_at,
            "tree_truncated",
            default_branch=default_branch,
            default_branch_sha=str(branch_sha),
            tree_sha=str(tree_sha),
        )
    tree_entries = tree_payload.get("tree")
    if not isinstance(tree_entries, list):
        return _incomplete_inventory(
            repository,
            verified_at,
            "invalid_tree_entries",
            default_branch=default_branch,
            default_branch_sha=str(branch_sha),
            tree_sha=str(tree_sha),
        )
    if any(
        not isinstance(entry, dict)
        or entry.get("type") not in {"blob", "tree", "commit"}
        or not isinstance(entry.get("path"), str)
        or not entry["path"]
        for entry in tree_entries
    ):
        return _incomplete_inventory(
            repository,
            verified_at,
            "invalid_tree_entry",
            default_branch=default_branch,
            default_branch_sha=str(branch_sha),
            tree_sha=str(tree_sha),
        )
    tree_paths = frozenset(
        entry["path"]
        for entry in tree_entries
        if entry["type"] == "blob"
    )

    pages = list(workflow_pages)
    if not pages:
        return _incomplete_inventory(
            repository,
            verified_at,
            "missing_workflow_pages",
            default_branch=default_branch,
            default_branch_sha=str(branch_sha),
            tree_sha=str(tree_sha),
        )
    expected_total: int | None = None
    raw_records: list[Any] = []
    for page in pages:
        if not isinstance(page, dict):
            return _incomplete_inventory(
                repository,
                verified_at,
                "invalid_workflow_page",
                default_branch=default_branch,
                default_branch_sha=str(branch_sha),
                tree_sha=str(tree_sha),
            )
        total_count = page.get("total_count")
        if (
            not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < 0
        ):
            return _incomplete_inventory(
                repository,
                verified_at,
                "invalid_workflow_total_count",
                default_branch=default_branch,
                default_branch_sha=str(branch_sha),
                tree_sha=str(tree_sha),
            )
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            return _incomplete_inventory(
                repository,
                verified_at,
                "workflow_total_count_changed",
                default_branch=default_branch,
                default_branch_sha=str(branch_sha),
                tree_sha=str(tree_sha),
            )
        records = page.get("workflows")
        if not isinstance(records, list):
            return _incomplete_inventory(
                repository,
                verified_at,
                "invalid_workflow_records",
                default_branch=default_branch,
                default_branch_sha=str(branch_sha),
                tree_sha=str(tree_sha),
            )
        raw_records.extend(records)

    if expected_total != len(raw_records):
        return _incomplete_inventory(
            repository,
            verified_at,
            "workflow_count_mismatch",
            default_branch=default_branch,
            default_branch_sha=str(branch_sha),
            tree_sha=str(tree_sha),
        )

    entries: list[WorkflowRegistryEntry] = []
    seen_ids: set[int] = set()
    for record in raw_records:
        entry = _parse_workflow_record(record, tree_paths=tree_paths)
        if entry is None:
            return _incomplete_inventory(
                repository,
                verified_at,
                "invalid_workflow_record",
                default_branch=default_branch,
                default_branch_sha=str(branch_sha),
                tree_sha=str(tree_sha),
                entries=entries,
            )
        if entry.workflow_id in seen_ids:
            return _incomplete_inventory(
                repository,
                verified_at,
                "duplicate_workflow_id",
                default_branch=default_branch,
                default_branch_sha=str(branch_sha),
                tree_sha=str(tree_sha),
                entries=entries,
            )
        seen_ids.add(entry.workflow_id)
        entries.append(entry)

    complete = all(entry.status != "unresolved" for entry in entries)
    return WorkflowInventory(
        repository=repository,
        default_branch=default_branch,
        default_branch_sha=str(branch_sha),
        tree_sha=str(tree_sha),
        verified_at=verified_at,
        complete=complete,
        entries=tuple(entries),
        reason="" if complete else "unresolved_workflow_state",
    )


def _finding_base(inventory: WorkflowInventory, entry: WorkflowRegistryEntry) -> dict[str, Any]:
    """Return metadata shared by per-workflow governance findings."""
    return {
        "file": entry.path,
        "line": 1,
        "snippet": "",
        "source": "github-actions-workflow-registry",
        "category": "ci-governance",
        "context": "governance",
        "confidence": "high" if entry.status == "orphaned_deleted" else "medium",
        "references": [
            WORKFLOW_DOCUMENTATION_URL,
            TREE_DOCUMENTATION_URL,
            PAGINATION_DOCUMENTATION_URL,
            entry.html_url,
        ],
        "owasp": [],
        "cwe": [],
        "repository": inventory.repository,
        "default_branch": inventory.default_branch,
        "default_branch_sha": inventory.default_branch_sha,
        "tree_sha": inventory.tree_sha,
        "verified_at": inventory.verified_at,
        "workflow_id": entry.workflow_id,
        "workflow_name": entry.name,
        "workflow_path": entry.path,
        "registry_state": entry.registry_state,
        "evidence_status": entry.status,
        "writer_like": entry.writer_like,
    }


def inventory_to_findings(inventory: WorkflowInventory) -> tuple[dict[str, Any], ...]:
    """Convert unsafe or ambiguous workflow evidence into normalized findings."""
    findings: list[dict[str, Any]] = []
    for entry in inventory.entries:
        if entry.status == "orphaned_deleted":
            remediation = (
                "Confirm the workflow path remains absent on the exact protected default-branch "
                "commit, then have a trusted operator disable this workflow registry identity "
                "through GitHub's workflow lifecycle API. Do not recreate the deleted writer file."
            )
            finding = _finding_base(inventory, entry)
            finding.update(
                {
                    "rule_id": "github-actions-orphan-workflow",
                    "severity": "WARNING",
                    "message": (
                        f"Active GitHub Actions workflow registry ID {entry.workflow_id} points to "
                        f"deleted path {entry.path} on {inventory.default_branch_sha}."
                    ),
                    "remediation": remediation,
                    "fix_prompt": remediation,
                    "verification": (
                        "Rerun this source-bound inventory against default-branch commit "
                        f"{inventory.default_branch_sha} or its reviewed successor and verify the "
                        "registry state is disabled or the workflow path is intentionally present."
                    ),
                }
            )
            findings.append(finding)
        elif entry.status == "unresolved":
            remediation = (
                "Inspect the workflow registry state with current GitHub documentation and rerun "
                "the source-bound inventory before treating this repository as clean."
            )
            finding = _finding_base(inventory, entry)
            finding.update(
                {
                    "rule_id": "github-actions-workflow-evidence-unresolved",
                    "severity": "WARNING",
                    "message": (
                        f"Workflow registry ID {entry.workflow_id} has unsupported state "
                        f"{entry.registry_state!r}; no clean classification was made."
                    ),
                    "remediation": remediation,
                    "fix_prompt": remediation,
                    "verification": "Repeat the inventory after the workflow state is understood.",
                }
            )
            findings.append(finding)

    if not inventory.complete:
        remediation = (
            "Restore complete read-only GitHub metadata access and repeat the inventory. "
            "Do not interpret missing, truncated, stale, or malformed evidence as clean."
        )
        findings.append(
            {
                "rule_id": "github-actions-workflow-inventory-incomplete",
                "severity": "WARNING",
                "message": (
                    "GitHub Actions workflow inventory is incomplete; clean status is unavailable "
                    f"because {inventory.reason or 'evidence is unresolved'}."
                ),
                "file": ".github/workflows",
                "line": 1,
                "snippet": "",
                "source": "github-actions-workflow-registry",
                "category": "ci-governance",
                "context": "governance",
                "confidence": "high",
                "remediation": remediation,
                "fix_prompt": remediation,
                "verification": "Repeat the full paginated registry and exact-tree acquisition.",
                "references": [
                    WORKFLOW_DOCUMENTATION_URL,
                    TREE_DOCUMENTATION_URL,
                    PAGINATION_DOCUMENTATION_URL,
                ],
                "owasp": [],
                "cwe": [],
                "repository": inventory.repository,
                "default_branch": inventory.default_branch,
                "default_branch_sha": inventory.default_branch_sha,
                "tree_sha": inventory.tree_sha,
                "verified_at": inventory.verified_at,
                "evidence_status": "unresolved",
                "evidence_reason": inventory.reason,
            }
        )
    return tuple(findings)


def _normalize_api_url(url: str, repository: str) -> str:
    """Allow only exact-origin API URLs scoped to the requested repository."""
    parsed = urllib.parse.urlsplit(str(url or ""))
    repository_path = f"/repos/{repository}"
    expected_prefix = f"{repository_path}/"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not (parsed.path == repository_path or parsed.path.startswith(expected_prefix))
    ):
        raise EvidenceCollectionError("untrusted_pagination_url")
    return urllib.parse.urlunsplit(parsed)


def _is_json_media_type(value: Any) -> bool:
    """Return whether a Content-Type is JSON or a structured JSON subtype."""
    media_type = str(value or "").split(";", 1)[0].strip().lower()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _request_json(
    url: str,
    *,
    repository: str,
    opener: Any,
    token: str,
    timeout: float,
) -> tuple[Any, str]:
    """Fetch one bounded same-origin GitHub JSON response and its Link header."""
    normalized_url = _normalize_api_url(url, repository)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # _normalize_api_url pins HTTPS, api.github.com, and the requested repository scope.
    request = urllib.request.Request(normalized_url, headers=headers, method="GET")  # noqa: S310
    try:
        with opener.open(request, timeout=timeout) as response:
            if not _is_json_media_type(response.headers.get("Content-Type")):
                raise EvidenceCollectionError("non_json_response")
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise EvidenceCollectionError("response_too_large")
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise EvidenceCollectionError("malformed_json") from exc
            return payload, str(response.headers.get("Link") or "")
    except EvidenceCollectionError:
        raise
    except urllib.error.HTTPError as exc:
        raise EvidenceCollectionError(f"http_{exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise EvidenceCollectionError("transport_error") from exc


def _next_link(link_header: str, repository: str) -> str:
    """Return GitHub's validated ``rel=next`` URL or an empty string."""
    if not link_header:
        return ""
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        if not section.startswith("<") or ">" not in section:
            raise EvidenceCollectionError("malformed_pagination_link")
        candidate = section[1 : section.index(">")]
        return _normalize_api_url(candidate, repository)
    return ""


def _workflow_pages(
    repository: str,
    *,
    opener: Any,
    token: str,
    timeout: float,
) -> list[Any]:
    """Fetch every workflow page by following GitHub's authoritative Link header."""
    url = f"{API_ORIGIN}/repos/{repository}/actions/workflows?per_page=100"
    pages: list[Any] = []
    seen: set[str] = set()
    for _ in range(MAX_PAGES):
        if url in seen:
            raise EvidenceCollectionError("pagination_cycle")
        seen.add(url)
        payload, link = _request_json(
            url,
            repository=repository,
            opener=opener,
            token=token,
            timeout=timeout,
        )
        pages.append(payload)
        url = _next_link(link, repository)
        if not url:
            return pages
    raise EvidenceCollectionError("pagination_limit_exceeded")


def _workflow_evidence_snapshot(pages: Iterable[Any]) -> tuple[str, ...] | None:
    """Return a stable multiset of classification-relevant registry fields."""
    records: list[Any] = []
    expected_total: int | None = None
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("workflows"), list):
            return None
        total_count = page.get("total_count")
        if (
            not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < 0
            or (expected_total is not None and total_count != expected_total)
        ):
            return None
        expected_total = total_count
        records.extend(page["workflows"])
    if expected_total != len(records) or any(
        not isinstance(record, dict) for record in records
    ):
        return None
    return tuple(
        sorted(
            json.dumps(
                [
                    record.get("id"),
                    record.get("name"),
                    record.get("path"),
                    record.get("state"),
                    record.get("html_url"),
                ],
                ensure_ascii=False,
                sort_keys=True,
            )
            for record in records
        )
    )


def collect_workflow_inventory(
    repository: str,
    *,
    token: str = "",
    opener: Any | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    verified_at: str | None = None,
) -> WorkflowInventory:
    """Acquire and classify the live GitHub workflow registry without mutating it."""
    repository = _normalize_repository(repository)
    verified_at = _normalize_verified_at(verified_at or _utc_timestamp())
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect())
    base_url = f"{API_ORIGIN}/repos/{repository}"
    default_branch = ""
    default_branch_sha = ""
    tree_sha = ""
    try:
        repository_payload, _ = _request_json(
            base_url,
            repository=repository,
            opener=opener,
            token=token,
            timeout=timeout,
        )
        default_branch_value = (
            repository_payload.get("default_branch")
            if isinstance(repository_payload, dict)
            else None
        )
        if not isinstance(default_branch_value, str) or not default_branch_value:
            return build_workflow_inventory(
                repository=repository,
                verified_at=verified_at,
                repository_payload=repository_payload,
                branch_payload={},
                tree_payload={},
                workflow_pages=[],
            )
        default_branch = default_branch_value
        branch_url = f"{base_url}/branches/{urllib.parse.quote(default_branch, safe='')}"
        branch_payload, _ = _request_json(
            branch_url,
            repository=repository,
            opener=opener,
            token=token,
            timeout=timeout,
        )
        branch_sha = _nested_value(branch_payload, "commit", "sha")
        tree_sha_value = _nested_value(branch_payload, "commit", "commit", "tree", "sha")
        branch_identity_valid = (
            isinstance(branch_payload, dict)
            and branch_payload.get("name") == default_branch
            and branch_payload.get("protected") is True
            and _valid_sha(branch_sha)
        )
        if not branch_identity_valid or not _valid_sha(tree_sha_value):
            return build_workflow_inventory(
                repository=repository,
                verified_at=verified_at,
                repository_payload=repository_payload,
                branch_payload=branch_payload,
                tree_payload={},
                workflow_pages=[],
            )
        default_branch_sha = str(branch_sha)
        tree_sha = str(tree_sha_value)
        tree_url = f"{base_url}/git/trees/{tree_sha_value}?recursive=1"
        tree_payload, _ = _request_json(
            tree_url,
            repository=repository,
            opener=opener,
            token=token,
            timeout=timeout,
        )
        pages = _workflow_pages(
            repository,
            opener=opener,
            token=token,
            timeout=timeout,
        )
        verification_pages = _workflow_pages(
            repository,
            opener=opener,
            token=token,
            timeout=timeout,
        )
        snapshot = _workflow_evidence_snapshot(pages)
        verification_snapshot = _workflow_evidence_snapshot(verification_pages)
        if snapshot is None or snapshot != verification_snapshot:
            raise EvidenceCollectionError("registry_moved_during_collection")
        final_repository_payload, _ = _request_json(
            base_url,
            repository=repository,
            opener=opener,
            token=token,
            timeout=timeout,
        )
        final_branch_payload, _ = _request_json(
            branch_url,
            repository=repository,
            opener=opener,
            token=token,
            timeout=timeout,
        )
        if (
            not isinstance(final_repository_payload, dict)
            or not _same_repository(final_repository_payload.get("full_name"), repository)
            or final_repository_payload.get("default_branch") != default_branch
            or not isinstance(final_branch_payload, dict)
            or final_branch_payload.get("name") != default_branch
            or final_branch_payload.get("protected") is not True
            or _nested_value(final_branch_payload, "commit", "sha") != branch_sha
            or _nested_value(final_branch_payload, "commit", "commit", "tree", "sha")
            != tree_sha_value
        ):
            raise EvidenceCollectionError("source_moved_during_collection")
    except EvidenceCollectionError as exc:
        return _incomplete_inventory(
            repository,
            verified_at,
            str(exc),
            default_branch=default_branch,
            default_branch_sha=default_branch_sha,
            tree_sha=tree_sha,
        )
    return build_workflow_inventory(
        repository=repository,
        verified_at=verified_at,
        repository_payload=repository_payload,
        branch_payload=branch_payload,
        tree_payload=tree_payload,
        workflow_pages=pages,
    )


def _inventory_to_dict(inventory: WorkflowInventory) -> dict[str, Any]:
    """Serialize one immutable inventory into stable JSON-compatible values."""
    return {
        "repository": inventory.repository,
        "default_branch": inventory.default_branch,
        "default_branch_sha": inventory.default_branch_sha,
        "tree_sha": inventory.tree_sha,
        "verified_at": inventory.verified_at,
        "complete": inventory.complete,
        "entries": [asdict(entry) for entry in inventory.entries],
        "reason": inventory.reason,
    }


def main(argv: list[str] | None = None) -> int:
    """Run the read-only registry detector and return 0 clean, 1 orphan, or 2 unresolved."""
    parser = argparse.ArgumentParser(
        description="Detect active GitHub Actions workflow records whose files are deleted."
    )
    parser.add_argument("repository", help="GitHub repository in owner/name form")
    parser.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable containing a read-only GitHub token (default: GITHUB_TOKEN)",
    )
    args = parser.parse_args(argv)
    token = os.environ.get(args.token_env, "")
    inventory = collect_workflow_inventory(args.repository, token=token)
    findings = inventory_to_findings(inventory)
    print(
        json.dumps(
            {
                "schema_version": 1,
                "inventory": _inventory_to_dict(inventory),
                "findings": findings,
            },
            sort_keys=True,
        )
    )
    if not inventory.complete:
        return 2
    if any(entry.status == "orphaned_deleted" for entry in inventory.entries):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through ``main``.
    raise SystemExit(main())
