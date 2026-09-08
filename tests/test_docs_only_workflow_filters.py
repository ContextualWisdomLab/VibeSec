"""Contracts preventing CI admission gaps for documentation and stacked pull requests."""

from pathlib import Path

import pytest


CONTRACT_SENSITIVE_WORKFLOWS = (
    ".github/workflows/tests.yml",
    ".github/workflows/openssf-evidence-coverage.yml",
    ".github/workflows/pinned-https-coverage.yml",
    ".github/workflows/retention-audit-coverage.yml",
    ".github/workflows/scan-path-context-coverage.yml",
)

STACKED_PR_WORKFLOWS = (
    ".github/workflows/tests.yml",
    ".github/workflows/security-process.yml",
    ".github/workflows/openssf-evidence-coverage.yml",
    ".github/workflows/pinned-https-coverage.yml",
    ".github/workflows/retention-audit-coverage.yml",
    ".github/workflows/scan-path-context-coverage.yml",
    ".github/workflows/controlplane-schema-coverage.yml",
    ".github/workflows/commercial-readiness-agent-coverage.yml",
)


def _event_block(workflow: str, event: str) -> str:
    """Return one peer event block from the workflow's top-level ``on`` mapping."""
    lines = workflow.splitlines()
    marker = f"  {event}:"
    try:
        start = lines.index(marker)
    except ValueError as exc:
        raise AssertionError(f"missing workflow event: {event}") from exc

    block: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("  ") and not line.startswith("    "):
            break
        block.append(line)
    return "\n".join(block)


@pytest.mark.parametrize("workflow_path", CONTRACT_SENSITIVE_WORKFLOWS)
def test_contract_sensitive_workflows_do_not_skip_documentation(
    workflow_path: str,
) -> None:
    """Docs and policy Markdown remain covered until a dedicated contract lane exists."""
    workflow = Path(workflow_path).read_text(encoding="utf-8")

    for event in ("push", "pull_request"):
        assert "paths-ignore:" not in _event_block(workflow, event)


@pytest.mark.parametrize("workflow_path", STACKED_PR_WORKFLOWS)
def test_pull_request_checks_admit_stacked_bases(workflow_path: str) -> None:
    """PR checks must materialize when a reviewable stack targets another feature branch."""
    workflow = Path(workflow_path).read_text(encoding="utf-8")

    assert "branches:" not in _event_block(workflow, "pull_request")
