"""Adversarial contracts for source-bound GitHub workflow registry evidence."""
from __future__ import annotations

import json
import sys
import urllib.error

import pytest

from appguardrail_core import github_workflow_registry as m

REPO = "ContextualWisdomLab/appguardrail"
STAMP = "2026-08-15T14:00:00Z"
BRANCH_SHA = "a" * 40
TREE_SHA = "b" * 40
LIVE = ".github/workflows/live-once.yml"


def repo() -> dict[str, object]:
    """Build default-branch repository metadata."""
    return {"full_name": REPO, "default_branch": "develop"}


def branch(*, protected: bool = True) -> dict[str, object]:
    """Build protected branch metadata with exact commit and tree SHAs."""
    return {"name": "develop", "protected": protected, "commit": {"sha": BRANCH_SHA, "commit": {"tree": {"sha": TREE_SHA}}}}


def tree(*paths: str, truncated: bool = False) -> dict[str, object]:
    """Build one recursive Git tree response."""
    return {"sha": TREE_SHA, "truncated": truncated, "tree": [{"path": p, "type": "blob", "sha": f"{i + 1:040x}"} for i, p in enumerate(paths)]}


def workflow(identifier: int, path: str, *, state: str = "active", name: str = "Workflow") -> dict[str, object]:
    """Build one Actions workflow registry record."""
    return {"id": identifier, "name": name, "path": path, "state": state, "html_url": f"https://github.com/{REPO}/actions/workflows/{identifier}"}


def page(*items: dict[str, object], total: int | None = None) -> dict[str, object]:
    """Build one paginated workflow-list payload."""
    return {"total_count": len(items) if total is None else total, "workflows": list(items)}


def build(*, r: object | None = None, b: object | None = None, t: object | None = None, pages: object | None = None) -> m.WorkflowInventory:
    """Call the pure inventory builder with healthy defaults."""
    return m.build_workflow_inventory(repository=REPO, verified_at=STAMP, repository_payload=repo() if r is None else r, branch_payload=branch() if b is None else b, tree_payload=tree(LIVE) if t is None else t, workflow_pages=[page(workflow(1, LIVE))] if pages is None else pages)


def test_classification_is_exact_case_sensitive_and_state_aware() -> None:
    """Live-once, active orphan, disabled orphan, and case mismatch classify distinctly."""
    orphan = ".github/workflows/finalize-repair-once.yml"
    disabled = ".github/workflows/retired.yml"
    inventory = build(t=tree(LIVE, ".github/workflows/deploy.yml"), pages=[page(workflow(1, LIVE, name="Live once"), workflow(2, orphan, name="Finalize repair once"), workflow(3, disabled, state="disabled_manually"), workflow(4, ".github/workflows/Deploy.yml"))])
    assert inventory.complete
    assert [e.status for e in inventory.entries] == ["present", "orphaned_deleted", "disabled", "orphaned_deleted"]
    assert [e.writer_like for e in inventory.entries[:3]] == [True, True, False]


def test_github_managed_dynamic_workflows_are_not_source_orphans() -> None:
    """GitHub-owned dynamic workflows remain explicit without requiring tree files."""
    assert not m._valid_workflow_path(None)
    dynamic_paths = (
        "dynamic/agents/copilot-pull-request-reviewer",
        "dynamic/copilot-swe-agent/copilot",
        "dynamic/dependabot/dependabot-updates",
        "dynamic/github-code-scanning/codeql",
    )
    inventory = build(
        pages=[page(*(workflow(index, path) for index, path in enumerate(dynamic_paths, 1)))]
    )
    assert inventory.complete
    assert [entry.status for entry in inventory.entries] == ["dynamic_managed"] * 4
    assert m.inventory_to_findings(inventory) == ()


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"r": {"full_name": "other/repo", "default_branch": "develop"}}, "repository_identity_mismatch"),
        ({"r": {"full_name": REPO, "default_branch": ""}}, "invalid_default_branch"),
        ({"b": {**branch(), "name": "main"}}, "default_branch_identity_mismatch"),
        ({"b": branch(protected=False)}, "default_branch_unprotected"),
        ({"b": {"name": "develop", "protected": True, "commit": []}}, "invalid_default_branch_sha"),
        ({"b": {"name": "develop", "protected": True, "commit": {"sha": "short"}}}, "invalid_default_branch_sha"),
        ({"b": {"name": "develop", "protected": True, "commit": {"sha": BRANCH_SHA, "commit": {"tree": {"sha": "short"}}}}}, "invalid_tree_sha"),
        ({"t": {**tree(LIVE), "sha": "c" * 40}}, "tree_identity_mismatch"),
        ({"t": tree(LIVE, truncated=True)}, "tree_truncated"),
        ({"t": {"sha": TREE_SHA, "truncated": False, "tree": "bad"}}, "invalid_tree_entries"),
        ({"pages": []}, "missing_workflow_pages"),
        ({"pages": ["bad"]}, "invalid_workflow_page"),
        ({"pages": [{"total_count": True, "workflows": []}]}, "invalid_workflow_total_count"),
        ({"pages": [page(total=0), page(total=1)]}, "workflow_total_count_changed"),
        ({"pages": [{"total_count": 0, "workflows": "bad"}]}, "invalid_workflow_records"),
        ({"pages": [page(workflow(1, LIVE), total=2)]}, "workflow_count_mismatch"),
        ({"pages": [page(workflow(1, LIVE), workflow(1, ".github/workflows/two.yml"))]}, "duplicate_workflow_id"),
        ({"pages": [{"total_count": 1, "workflows": ["bad"]}]}, "invalid_workflow_record"),
        ({"pages": [page({"id": 0})]}, "invalid_workflow_record"),
        ({"pages": [page(workflow(8, "README.md"))]}, "invalid_workflow_record"),
        ({"pages": [page(workflow(8, ".github/workflows/../outside.yml"))]}, "invalid_workflow_record"),
    ],
)
def test_incomplete_or_ambiguous_source_evidence_fails_closed(kwargs: dict[str, object], reason: str) -> None:
    """Malformed, moved, truncated, duplicated, or incomplete source evidence is never clean."""
    inventory = build(**kwargs)
    assert not inventory.complete
    assert inventory.reason == reason


def test_malformed_tree_entry_cannot_create_a_false_orphan() -> None:
    """An uninterpretable blob entry makes source absence unprovable."""
    malformed_tree = tree(LIVE)
    malformed_tree["tree"] = [{"type": "blob", "sha": "c" * 40}]
    inventory = build(t=malformed_tree)
    assert not inventory.complete
    assert inventory.reason == "invalid_tree_entry"
    assert inventory.entries == ()


def test_repository_identity_comparison_is_case_insensitive() -> None:
    """GitHub's canonical repository casing remains equivalent to a lowercase request."""
    inventory = m.build_workflow_inventory(
        repository=REPO.lower(),
        verified_at=STAMP,
        repository_payload=repo(),
        branch_payload=branch(),
        tree_payload=tree(LIVE),
        workflow_pages=[page(workflow(1, LIVE))],
    )
    assert inventory.complete


def test_unknown_registry_state_is_unresolved_and_actionable() -> None:
    """Unknown future GitHub states remain explicit rather than guessed."""
    inventory = build(pages=[page(workflow(1, LIVE, state="mystery"))])
    assert not inventory.complete and inventory.reason == "unresolved_workflow_state"
    assert inventory.entries[0].status == "unresolved"
    findings = m.inventory_to_findings(inventory)
    assert [f["rule_id"] for f in findings] == ["github-actions-workflow-evidence-unresolved", "github-actions-workflow-inventory-incomplete"]


def test_findings_expose_provenance_and_read_only_remediation() -> None:
    """Confirmed orphan findings identify exact source state without secret or mutation data."""
    orphan = m.WorkflowRegistryEntry(9, "Apply once", ".github/workflows/apply-once.yml", "active", "orphaned_deleted", True, "https://example.test/9")
    live = m.WorkflowRegistryEntry(10, "Live", LIVE, "active", "present", False, "https://example.test/10")
    disabled = m.WorkflowRegistryEntry(11, "Old", ".github/workflows/old.yml", "disabled_manually", "disabled", False, "https://example.test/11")
    inventory = m.WorkflowInventory(REPO, "develop", BRANCH_SHA, TREE_SHA, STAMP, True, (orphan, live, disabled), "")
    findings = m.inventory_to_findings(inventory)
    assert len(findings) == 1 and findings[0]["severity"] == "WARNING"
    assert findings[0]["workflow_id"] == 9 and findings[0]["writer_like"] is True
    assert "trusted operator" in findings[0]["remediation"] and BRANCH_SHA in findings[0]["verification"]
    assert all("secret" not in key.lower() for key in findings[0])
    assert m.inventory_to_findings(m.WorkflowInventory(REPO, "develop", BRANCH_SHA, TREE_SHA, STAMP, True, (), "")) == ()


class Response:
    """Minimal bounded urllib response fixture."""
    def __init__(self, payload: object, *, link: str = "", content_type: str = "application/json", raw: bytes | None = None) -> None:
        self.body = json.dumps(payload).encode() if raw is None else raw
        self.headers = {"Content-Type": content_type, "Link": link}
    def __enter__(self) -> "Response":
        return self
    def __exit__(self, *args: object) -> None:
        del args
    def read(self, amount: int) -> bytes:
        return self.body[:amount]


class Opener:
    """Deterministic URL-to-response opener for collector tests."""
    def __init__(self, responses: dict[str, Response | Exception | list[Response]]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict[str, str]]] = []
    def open(self, request: object, *, timeout: float) -> Response:
        del timeout
        url = request.full_url
        self.requests.append((url, {k.lower(): v for k, v in request.header_items()}))
        result = self.responses[url]
        if isinstance(result, list):
            result = result.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def transport(*, second_page: bool = False) -> Opener:
    """Build a complete source-authoritative transport fixture."""
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    b_url = f"{base}/branches/develop"
    t_url = f"{base}/git/trees/{TREE_SHA}?recursive=1"
    p1 = f"{base}/actions/workflows?per_page=100"
    responses: dict[str, Response | Exception] = {base: Response(repo()), b_url: Response(branch()), t_url: Response(tree(LIVE))}
    if second_page:
        p2 = f"{p1}&page=2"
        responses[p1] = Response(page(workflow(1, LIVE), total=2), link=f'<{p2}>; rel="next"')
        responses[p2] = Response(page(workflow(2, ".github/workflows/orphan.yml"), total=2))
    else:
        responses[p1] = Response(page(workflow(1, LIVE)))
    return Opener(responses)


def test_collector_follows_link_pagination_and_pins_headers() -> None:
    """Collector follows GitHub Link pagination while preserving exact source identity."""
    opener = transport(second_page=True)
    inventory = m.collect_workflow_inventory(REPO, token="token-value", opener=opener, verified_at=STAMP)  # noqa: S106
    assert inventory.complete and [e.status for e in inventory.entries] == ["present", "orphaned_deleted"]
    assert len(opener.requests) == 9
    assert all(h["x-github-api-version"] == m.API_VERSION and h["authorization"] == "Bearer token-value" for _, h in opener.requests)


def test_collector_accepts_github_canonical_repository_casing() -> None:
    """Collector identity rechecks accept GitHub's canonical owner/repository spelling."""
    requested = REPO.lower()
    base = f"{m.API_ORIGIN}/repos/{requested}"
    branch_url = f"{base}/branches/develop"
    tree_url = f"{base}/git/trees/{TREE_SHA}?recursive=1"
    workflows_url = f"{base}/actions/workflows?per_page=100"
    opener = Opener(
        {
            base: Response(repo()),
            branch_url: Response(branch()),
            tree_url: Response(tree(LIVE)),
            workflows_url: Response(page(workflow(1, LIVE))),
        }
    )
    assert m.collect_workflow_inventory(
        requested, opener=opener, verified_at=STAMP
    ).complete


def test_collector_fails_closed_when_registry_changes_between_passes() -> None:
    """Same-count pagination cannot mix two different workflow registry snapshots."""
    assert m._workflow_evidence_snapshot(["bad"]) is None
    assert m._workflow_evidence_snapshot([{"workflows": ["bad"]}]) is None
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    first_page = f"{base}/actions/workflows?per_page=100"
    second_page = f"{first_page}&page=2"
    opener = transport(second_page=True)
    opener.responses[second_page] = [
        Response(page(workflow(2, ".github/workflows/orphan.yml"), total=2)),
        Response(page(workflow(3, ".github/workflows/replacement.yml"), total=2)),
    ]
    inventory = m.collect_workflow_inventory(REPO, opener=opener, verified_at=STAMP)
    assert not inventory.complete
    assert inventory.reason == "registry_moved_during_collection"


@pytest.mark.parametrize(
    "verification_page",
    [
        {"total_count": True, "workflows": [workflow(1, LIVE)]},
        page(workflow(1, LIVE), total=2),
    ],
)
def test_collector_rejects_incomplete_verification_pass(
    verification_page: dict[str, object],
) -> None:
    """The verification pass must be a complete registry inventory itself."""
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    workflows_url = f"{base}/actions/workflows?per_page=100"
    opener = transport()
    opener.responses[workflows_url] = [
        Response(page(workflow(1, LIVE))),
        Response(verification_page),
    ]
    inventory = m.collect_workflow_inventory(REPO, opener=opener, verified_at=STAMP)
    assert not inventory.complete
    assert inventory.reason == "registry_moved_during_collection"


@pytest.mark.parametrize("movement", ["repository", "branch"])
def test_collector_fails_closed_when_source_moves_during_collection(movement: str) -> None:
    """A repository default-branch or exact branch movement cannot yield clean evidence."""
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    branch_url = f"{base}/branches/develop"
    opener = transport()
    if movement == "repository":
        opener.responses[base] = [Response(repo()), Response({**repo(), "default_branch": "main"})]
    else:
        moved = branch()
        moved["commit"] = {"sha": "c" * 40, "commit": {"tree": {"sha": "d" * 40}}}
        opener.responses[branch_url] = [Response(branch()), Response(moved)]
    inventory = m.collect_workflow_inventory(REPO, opener=opener, verified_at=STAMP)
    assert not inventory.complete
    assert inventory.reason == "source_moved_during_collection"
    assert inventory.default_branch_sha == BRANCH_SHA
    assert inventory.tree_sha == TREE_SHA


@pytest.mark.parametrize(
    ("failure", "reason"),
    [(urllib.error.HTTPError("https://api.github.com", code, "error", {}, None), f"http_{code}") for code in (403, 404, 500)] + [(urllib.error.URLError("dns"), "transport_error")],
)
def test_transport_failures_are_unresolved(failure: Exception, reason: str) -> None:
    """Permission, missing-source, server, and network failures all fail closed."""
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    inventory = m.collect_workflow_inventory(REPO, opener=Opener({base: failure}), verified_at=STAMP)
    assert not inventory.complete and inventory.reason == reason
    assert m.inventory_to_findings(inventory)[0]["rule_id"] == "github-actions-workflow-inventory-incomplete"


def test_late_collection_failure_preserves_acquired_source_identity() -> None:
    """Late transport failure retains exact branch and tree provenance for operator triage."""
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    workflow_url = f"{base}/actions/workflows?per_page=100"
    opener = transport()
    opener.responses[workflow_url] = urllib.error.HTTPError(
        workflow_url,
        403,
        "error",
        {},
        None,
    )
    inventory = m.collect_workflow_inventory(REPO, opener=opener, verified_at=STAMP)
    assert not inventory.complete and inventory.reason == "http_403"
    assert inventory.default_branch == "develop"
    assert inventory.default_branch_sha == BRANCH_SHA
    assert inventory.tree_sha == TREE_SHA


def test_transport_rejects_hostile_media_size_json_and_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    """Origin, media type, response size, JSON syntax, and Link syntax stay bounded."""
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    assert m.collect_workflow_inventory(REPO, opener=Opener({base: Response({}, content_type="text/html")}), verified_at=STAMP).reason == "non_json_response"
    monkeypatch.setattr(m, "MAX_RESPONSE_BYTES", 2)
    assert m.collect_workflow_inventory(REPO, opener=Opener({base: Response({"x": "long"})}), verified_at=STAMP).reason == "response_too_large"
    monkeypatch.setattr(m, "MAX_RESPONSE_BYTES", 2_000_000)
    assert m.collect_workflow_inventory(REPO, opener=Opener({base: Response({}, raw=b"{bad")}), verified_at=STAMP).reason == "malformed_json"
    opener = transport()
    p1 = f"{base}/actions/workflows?per_page=100"
    opener.responses[p1] = Response(page(workflow(1, LIVE), total=2), link='<https://attacker.invalid/x>; rel="next"')
    assert m.collect_workflow_inventory(REPO, opener=opener, verified_at=STAMP).reason == "untrusted_pagination_url"
    assert m._next_link('<https://api.github.com/x>; rel="prev"', REPO) == ""
    with pytest.raises(m.EvidenceCollectionError, match="malformed_pagination_link"):
        m._next_link('bad; rel="next"', REPO)


def test_pagination_cycle_and_limit_are_non_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cyclic and unbounded Link chains cannot become complete evidence."""
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    p1 = f"{base}/actions/workflows?per_page=100"
    opener = transport()
    opener.responses[p1] = Response(page(workflow(1, LIVE)), link=f'<{p1}>; rel="next"')
    assert m.collect_workflow_inventory(REPO, opener=opener, verified_at=STAMP).reason == "pagination_cycle"
    opener = transport()
    p2 = f"{p1}&page=2"
    opener.responses[p1] = Response(page(workflow(1, LIVE), total=2), link=f'<{p2}>; rel="next"')
    monkeypatch.setattr(m, "MAX_PAGES", 1)
    assert m.collect_workflow_inventory(REPO, opener=opener, verified_at=STAMP).reason == "pagination_limit_exceeded"


def test_default_transport_timestamp_and_source_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default transport stamps UTC and malformed live source identity stops early."""
    handler = m.NoRedirect()
    assert handler.redirect_request(object(), object(), 302, "Moved", {}, "https://example.test") is None
    opener = transport()
    monkeypatch.setattr(m.urllib.request, "build_opener", lambda *handlers: opener)
    inventory = m.collect_workflow_inventory(REPO)
    assert inventory.complete and inventory.verified_at.endswith("Z")
    base = f"{m.API_ORIGIN}/repos/{REPO}"
    bad_repo = repo()
    bad_repo["default_branch"] = ""
    assert m.collect_workflow_inventory(REPO, opener=Opener({base: Response(bad_repo)}), verified_at=STAMP).reason == "invalid_default_branch"
    bad_branch = branch()
    bad_branch["commit"] = {"sha": BRANCH_SHA, "commit": {"tree": {"sha": "short"}}}
    assert m.collect_workflow_inventory(REPO, opener=Opener({base: Response(repo()), f"{base}/branches/develop": Response(bad_branch)}), verified_at=STAMP).reason == "invalid_tree_sha"
    assert m.collect_workflow_inventory(
        REPO,
        opener=Opener(
            {
                base: Response(repo()),
                f"{base}/branches/develop": Response(branch(protected=False)),
            }
        ),
        verified_at=STAMP,
    ).reason == "default_branch_unprotected"


def test_identity_inputs_and_cli_exit_contract(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Unsafe identities are rejected and CLI distinguishes clean, orphan, and unresolved."""
    with pytest.raises(ValueError, match="owner/name"):
        m.collect_workflow_inventory("owner/repo/extra", verified_at=STAMP)
    for stamp in ("yesterday", "2026-13-40T25:61:61Z"):
        with pytest.raises(ValueError, match="verified_at"):
            m.collect_workflow_inventory(REPO, verified_at=stamp)
    orphan = m.WorkflowRegistryEntry(9, "Apply once", ".github/workflows/apply-once.yml", "active", "orphaned_deleted", True, "https://example.test/9")
    cases = [(m.WorkflowInventory(REPO, "develop", BRANCH_SHA, TREE_SHA, STAMP, True, (orphan,), ""), 1), (m.WorkflowInventory(REPO, "develop", BRANCH_SHA, TREE_SHA, STAMP, True, (), ""), 0), (m.WorkflowInventory(REPO, "", "", "", STAMP, False, (), "http_403"), 2)]
    for inventory, code in cases:
        monkeypatch.setattr(m, "collect_workflow_inventory", lambda *args, _inventory=inventory, **kwargs: _inventory)
        assert m.main([REPO]) == code
        payload = json.loads(capsys.readouterr().out)
        assert payload["schema_version"] == 1
    monkeypatch.setattr(m, "collect_workflow_inventory", lambda *args, **kwargs: cases[1][0])
    monkeypatch.setattr(sys, "argv", ["appguardrail-workflow-registry", REPO])
    assert m.main() == 0
