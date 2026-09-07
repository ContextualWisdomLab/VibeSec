"""GitHub Actions concurrency contracts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PR_WORKFLOWS = (
    "security-process.yml",
    "tests.yml",
)
CONSOLIDATED_COVERAGE_WORKFLOWS = (
    "commercial-readiness-agent-coverage.yml",
    "controlplane-schema-coverage.yml",
    "openssf-evidence-coverage.yml",
    "pinned-https-coverage.yml",
    "retention-audit-coverage.yml",
    "scan-path-context-coverage.yml",
)
RELEASE_WORKFLOWS = ("prepare-pypi-release.yml", "publish-pypi.yml")


def _top_level_block(workflow: str, heading: str) -> str:
    lines = workflow.splitlines()
    start = lines.index(f"{heading}:")
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index] and not lines[index][0].isspace()
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _pull_request_block(workflow: str) -> str:
    lines = _top_level_block(workflow, "on").splitlines()
    start = lines.index("  pull_request:")
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("  ") and not lines[index].startswith("    ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def test_pr_workflows_cancel_only_superseded_heads() -> None:
    for name in PR_WORKFLOWS:
        workflow = (WORKFLOWS / name).read_text(encoding="utf-8")
        concurrency = _top_level_block(workflow, "concurrency")
        pull_request = _pull_request_block(workflow)
        assert (
            "group: ${{ github.workflow }}-${{ github.repository }}-"
            "${{ github.event_name == 'pull_request' && github.run_attempt == 1 "
            "&& github.event.pull_request.number || github.run_id }}"
        ) in concurrency
        assert (
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}"
            in concurrency
        )
        assert (
            "types: [opened, synchronize, reopened, ready_for_review]"
            in pull_request
        )
        assert "converted_to_draft" not in pull_request
        assert "closed" not in pull_request
        assert "github.event.pull_request.draft == false" in workflow
        assert "github.event.action != 'closed'" in workflow


def test_release_workflows_do_not_drop_pending_delivery() -> None:
    """Every release event needs its own run; GitHub concurrency replaces pending runs."""
    for name in RELEASE_WORKFLOWS:
        workflow = (WORKFLOWS / name).read_text(encoding="utf-8")
        assert not any(line.startswith("concurrency:") for line in workflow.splitlines())


def test_exact_coverage_uses_the_existing_tests_workflow() -> None:
    """Exact coverage must not allocate six duplicate Python bootstrap jobs."""
    assert all(not (WORKFLOWS / name).exists() for name in CONSOLIDATED_COVERAGE_WORKFLOWS)
    workflow = (WORKFLOWS / "tests.yml").read_text(encoding="utf-8")
    for module in (
        "appguardrail_core/audit_events.py",
        "appguardrail_core/controlplane_schema.py",
        "appguardrail_core/openssf_evidence.py",
        "appguardrail_core/openssf_report.py",
        "appguardrail_core/pinned_https.py",
        "appguardrail_core/retention_policy.py",
        "appguardrail_core/scan_paths.py",
        "scripts/ci/commercial_readiness_loop.py",
        "scripts/ci/commercial_readiness_reconcile.py",
    ):
        assert f"--module {module}" in workflow
