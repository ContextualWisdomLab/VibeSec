"""Regression boundaries for issue #1087 polling-loop control flow."""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_HISTORICAL_RULE = "github-actions-transport-only-poll-bound"
_GENERIC_RULE = "github-actions-transport-failure-budget-poll-bound"


def _scan(tmp_path: Path, content: str) -> list[str]:
    """Scan one GitHub Actions workflow through the production rule loader."""
    workflow_path = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(content, encoding="utf-8")
    return [finding["rule_id"] for finding in _scan_file(workflow_path, tmp_path)]


def test_historical_helper_deadline_does_not_bound_later_poll(tmp_path: Path) -> None:
    """A bounded helper loop cannot donate its deadline to a later poll."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          review_poll_failures=0
          max_poll_transport_failures=3
          helper_deadline=$(( $(date -u +%s) + 30 ))
          while :; do
            if [ "$(date -u +%s)" -ge "$helper_deadline" ]; then
              exit 1
            fi
            break
          done
          while :; do
            if ! reviews="$(gh api repos/example/repo/pulls/1/reviews)"; then
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

    assert _scan(tmp_path, workflow).count(_HISTORICAL_RULE) == 1


def test_renamed_helper_deadline_does_not_bound_later_poll(tmp_path: Path) -> None:
    """A helper deadline before retry state is not safety for the later poll."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          helper_deadline=$(( $(date -u +%s) + 30 ))
          while :; do
            if [ "$(date -u +%s)" -ge "$helper_deadline" ]; then
              exit 1
            fi
            break
          done
          api_error_streak=0
          transport_error_budget=4
          while :; do
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

    assert _scan(tmp_path, workflow).count(_GENERIC_RULE) == 1


def test_renamed_helper_deadline_after_retry_state_does_not_bound_poll(
    tmp_path: Path,
) -> None:
    """Safety state between retry setup and poll must belong to the poll loop."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          api_error_streak=0
          transport_error_budget=4
          helper_deadline=$(( $(date -u +%s) + 30 ))
          while :; do
            if [ "$(date -u +%s)" -ge "$helper_deadline" ]; then
              exit 1
            fi
            break
          done
          while :; do
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

    assert _scan(tmp_path, workflow).count(_GENERIC_RULE) == 1


def _quoted_only_poll(command: str) -> str:
    """Build a loop where gh api exists only as inert quoted text."""
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
            if ! {command}; then
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


def test_echoed_gh_api_text_is_not_executable_poll_evidence(tmp_path: Path) -> None:
    """An echo containing gh api is text, not a remote polling command."""
    rule_ids = _scan(tmp_path, _quoted_only_poll('echo "gh api"'))

    assert _GENERIC_RULE not in rule_ids


def test_printf_gh_api_text_is_not_executable_poll_evidence(tmp_path: Path) -> None:
    """A printf argument containing gh api is text, not executable evidence."""
    rule_ids = _scan(tmp_path, _quoted_only_poll("printf '%s\\n' 'gh api'"))

    assert _GENERIC_RULE not in rule_ids
