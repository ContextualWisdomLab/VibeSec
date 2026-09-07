"""Regressions for shell whitespace accepted by polling-bound command grammar."""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_HISTORICAL_RULE = "github-actions-transport-only-poll-bound"
_GENERIC_RULE = "github-actions-transport-failure-budget-poll-bound"


def _scan(tmp_path: Path, content: str) -> list[str]:
    """Scan one workflow through the production scanner and return rule ids."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    return [finding["rule_id"] for finding in _scan_file(workflow, tmp_path)]


def _historical(command: str) -> str:
    """Build the pinned transport-budget shape with caller-selected gh spacing."""
    return f"""
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          review_poll_failures=0
          max_poll_transport_failures=3
          while :; do
            if ! reviews="$({command} repos/example/repo/pulls/1/reviews)"; then
              review_poll_failures=$((review_poll_failures + 1))
              if [ "$review_poll_failures" -ge "$max_poll_transport_failures" ]; then
                exit 1
              fi
              continue
            fi
            review_poll_failures=0
            sleep 30
          done
"""


def _generic(command: str) -> str:
    """Build the renamed transport-budget shape with caller-selected gh spacing."""
    return f"""
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          api_error_streak=0
          transport_error_budget=4
          while :; do
            if ! response="$({command} repos/example/repo/pulls/7/reviews)"; then
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


def test_historical_repeated_spaces_remain_detectable(tmp_path: Path) -> None:
    """A literal-substring prefilter must not reject valid repeated shell spaces."""
    assert _scan(tmp_path, _historical("gh  api")).count(_HISTORICAL_RULE) == 1


def test_historical_tab_remains_detectable(tmp_path: Path) -> None:
    """A tab between gh and api is accepted by the detector's command grammar."""
    assert _scan(tmp_path, _historical("gh\tapi")).count(_HISTORICAL_RULE) == 1


def test_generic_repeated_spaces_remain_detectable(tmp_path: Path) -> None:
    """The renamed companion must preserve the same shell-whitespace semantics."""
    assert _scan(tmp_path, _generic("gh  api")).count(_GENERIC_RULE) == 1


def test_generic_tab_remains_detectable(tmp_path: Path) -> None:
    """The generic companion accepts a tab wherever its regex accepts whitespace."""
    assert _scan(tmp_path, _generic("gh\tapi")).count(_GENERIC_RULE) == 1
