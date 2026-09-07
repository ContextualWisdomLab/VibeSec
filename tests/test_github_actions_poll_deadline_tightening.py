"""Regression tests for convergent deadline mutation in issue #1087 polling guards."""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_RULE_ID = "github-actions-poll-bound-state-reset"


def _scan(tmp_path: Path, deadline_mutation: str) -> list[str]:
    """Scan one polling workflow with a caller-selected deadline mutation."""
    workflow = f"""
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          api_error_streak=0
          transport_error_budget=4
          poll_deadline=$(( $(date +%s) + 300 ))
          while :; do
            {deadline_mutation}
            if [ "$(date +%s)" -ge "$poll_deadline" ]; then
              exit 1
            fi
            if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
              api_error_streak=$((api_error_streak + 1))
              if [ "$api_error_streak" -ge "$transport_error_budget" ]; then
                exit 1
              fi
              continue
            fi
            api_error_streak=0
            sleep 30
          done
"""
    path = tmp_path / ".github" / "workflows" / "required-review.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(workflow, encoding="utf-8")
    return [finding["rule_id"] for finding in _scan_file(path, tmp_path)]


def test_deadline_assignment_to_zero_is_not_nonconvergent(tmp_path: Path) -> None:
    """Setting a deadline to zero tightens the bound and must not be HIGH."""
    assert _RULE_ID not in _scan(tmp_path, "poll_deadline=0")


def test_deadline_subtraction_is_not_nonconvergent(tmp_path: Path) -> None:
    """Moving a deadline earlier is convergent safety, not a reset finding."""
    assert _RULE_ID not in _scan(
        tmp_path,
        "poll_deadline=$((poll_deadline - 30))",
    )


def test_deadline_refresh_from_current_time_remains_detectable(tmp_path: Path) -> None:
    """Refreshing from the current clock can move the deadline forward forever."""
    assert _scan(
        tmp_path,
        "poll_deadline=$(( $(date +%s) + 300 ))",
    ).count(_RULE_ID) == 1


def test_deadline_positive_extension_remains_detectable(tmp_path: Path) -> None:
    """Incrementing the deadline each iteration can prevent convergence."""
    assert _scan(
        tmp_path,
        "poll_deadline=$((poll_deadline + 30))",
    ).count(_RULE_ID) == 1
