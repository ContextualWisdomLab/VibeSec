"""Bare-exit regressions for issue #1087 polling detector control flow."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.cli.appguardrail import _scan_file


_HISTORICAL = "github-actions-transport-only-poll-bound"
_GENERIC = "github-actions-transport-failure-budget-poll-bound"
_RESET = "github-actions-poll-bound-state-reset"
_UNREACHABLE = "github-actions-poll-bound-unreachable-exit"


def _scan(tmp_path: Path, shell: str) -> list[str]:
    """Scan one conventional literal-shell GitHub Actions workflow."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "name: Required review\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - run: |\n"
        + "\n".join(f"          {line}" for line in shell.strip().splitlines())
        + "\n",
        encoding="utf-8",
    )
    return [finding["rule_id"] for finding in _scan_file(workflow, tmp_path)]


def _termination(position: str) -> str:
    """Place one unconditional bare exit on either side of the polling sleep."""
    if position == "before_sleep":
        return "  exit\n  sleep 30"
    if position == "after_sleep":
        return "  sleep 30\n  exit"
    raise AssertionError(position)


def _historical_poll(position: str) -> str:
    """Return the historical transport-budget poll with a finite bare exit."""
    return f"""
review_poll_failures=0
max_poll_transport_failures=3
while :; do
  if ! reviews="$(gh api repos/example/repo/pulls/1/reviews)"; then
    review_poll_failures=$((review_poll_failures + 1))
    if [ "$review_poll_failures" -ge "$max_poll_transport_failures" ]; then
      exit 1
    fi
    continue
  fi
  review_poll_failures=0
{_termination(position)}
done
"""


def _renamed_poll(position: str) -> str:
    """Return an identifier-agnostic transport-budget poll with a finite bare exit."""
    return f"""
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
{_termination(position)}
done
"""


@pytest.mark.parametrize("position", ["before_sleep", "after_sleep"])
def test_historical_poll_with_unconditional_bare_exit_is_finite(
    tmp_path: Path, position: str
) -> None:
    """A bare exit terminates the shell, so the historical poll has no back edge."""
    assert _HISTORICAL not in _scan(tmp_path, _historical_poll(position))


@pytest.mark.parametrize("position", ["before_sleep", "after_sleep"])
def test_renamed_poll_with_unconditional_bare_exit_is_finite(
    tmp_path: Path, position: str
) -> None:
    """A bare exit terminates the shell, so the renamed poll has no back edge."""
    assert _GENERIC not in _scan(tmp_path, _renamed_poll(position))


@pytest.mark.parametrize("position", ["before_sleep", "after_sleep"])
def test_state_reset_poll_with_unconditional_bare_exit_is_finite(
    tmp_path: Path, position: str
) -> None:
    """Mutable bound state is irrelevant when a direct bare exit removes the back edge."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  poll_deadline=$(($(date +%s) + 300))
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
{_termination(position)}
done
"""
    assert _RESET not in _scan(tmp_path, shell)


@pytest.mark.parametrize("position", ["before_sleep", "after_sleep"])
def test_unreachable_exit_poll_with_unconditional_bare_exit_is_finite(
    tmp_path: Path, position: str
) -> None:
    """An unreachable fail-closed guard is not a blocker once a direct bare exit ends the poll."""
    shell = f"""
overall_deadline=$(($(date +%s) + 600))
while :; do
  if [ "$(date +%s)" -ge "$overall_deadline" ]; then
    continue
    exit 1
  fi
  if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
    continue
  fi
{_termination(position)}
done
"""
    assert _UNREACHABLE not in _scan(tmp_path, shell)
