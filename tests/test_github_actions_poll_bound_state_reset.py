"""Regressions for mutable total-bound state inside GitHub Actions polling loops."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.cli.appguardrail import _scan_file


_RULE = "github-actions-poll-bound-state-reset"


def _scan(tmp_path: Path, shell: str, *, timeout_minutes: int | None = None) -> list[str]:
    """Scan one conventional workflow through the production scanner."""
    timeout = f"    timeout-minutes: {timeout_minutes}\n" if timeout_minutes else ""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "name: Required review\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-24.04\n"
        f"{timeout}"
        "    steps:\n"
        "      - run: |\n"
        + "\n".join(f"          {line}" for line in shell.strip().splitlines())
        + "\n",
        encoding="utf-8",
    )
    return [finding["rule_id"] for finding in _scan_file(workflow, tmp_path)]


def _transport_failure_block(counter: str, limit: str) -> str:
    """Return the loop-local transport-error branch used by the reviewed incident family."""
    return f"""  if ! response=\"$(gh api repos/example/repo/pulls/7/reviews)\"; then
    {counter}=$(({counter} + 1))
    if [ \"${counter}\" -ge \"${limit}\" ]; then
      exit 1
    fi
    continue
  fi
  {counter}=0"""


@pytest.mark.parametrize(
    ("failure_counter", "failure_limit"),
    [
        ("review_poll_failures", "max_poll_transport_failures"),
        ("api_error_streak", "transport_error_budget"),
    ],
)
def test_resetting_deadline_inside_loop_remains_detectable(
    tmp_path: Path, failure_counter: str, failure_limit: str
) -> None:
    """Recomputing a deadline every iteration must not masquerade as a total bound."""
    shell = f"""
{failure_counter}=0
{failure_limit}=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  poll_deadline=$(($(date +%s) + 300))
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    exit 1
  fi
{_transport_failure_block(failure_counter, failure_limit)}
  sleep 30
done
"""
    assert _scan(tmp_path, shell).count(_RULE) == 1


@pytest.mark.parametrize(
    ("failure_counter", "failure_limit"),
    [
        ("review_poll_failures", "max_poll_transport_failures"),
        ("api_error_streak", "transport_error_budget"),
    ],
)
def test_resetting_total_attempt_counter_remains_detectable(
    tmp_path: Path, failure_counter: str, failure_limit: str
) -> None:
    """A loop-local reset prevents a total-attempt counter from ever reaching its limit."""
    shell = f"""
{failure_counter}=0
{failure_limit}=4
total_attempts=0
max_attempts=12
while :; do
  total_attempts=0
  total_attempts=$((total_attempts + 1))
  if [ \"$total_attempts\" -ge \"$max_attempts\" ]; then
    exit 1
  fi
{_transport_failure_block(failure_counter, failure_limit)}
  sleep 30
done
"""
    assert _scan(tmp_path, shell).count(_RULE) == 1


@pytest.mark.parametrize(
    ("failure_counter", "failure_limit"),
    [
        ("review_poll_failures", "max_poll_transport_failures"),
        ("api_error_streak", "transport_error_budget"),
    ],
)
def test_growing_total_attempt_limit_remains_detectable(
    tmp_path: Path, failure_counter: str, failure_limit: str
) -> None:
    """Growing the limit with the counter keeps an apparent total-attempt guard non-terminating."""
    shell = f"""
{failure_counter}=0
{failure_limit}=4
total_attempts=0
max_attempts=12
while :; do
  total_attempts=$((total_attempts + 1))
  max_attempts=$((max_attempts + 1))
  if [ \"$total_attempts\" -ge \"$max_attempts\" ]; then
    exit 1
  fi
{_transport_failure_block(failure_counter, failure_limit)}
  sleep 30
done
"""
    assert _scan(tmp_path, shell).count(_RULE) == 1


def test_stable_deadline_is_not_reported_as_mutable(tmp_path: Path) -> None:
    """A fixed pre-loop wall-clock deadline remains valid safety evidence."""
    shell = f"""
review_poll_failures=0
max_poll_transport_failures=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    exit 1
  fi
{_transport_failure_block("review_poll_failures", "max_poll_transport_failures")}
  sleep 30
done
"""
    assert _RULE not in _scan(tmp_path, shell)


def test_stable_total_attempt_bound_is_not_reported_as_mutable(tmp_path: Path) -> None:
    """A monotonically increasing counter toward a fixed limit is a valid total bound."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
total_attempts=0
max_attempts=12
while :; do
  total_attempts=$((total_attempts + 1))
  if [ \"$total_attempts\" -ge \"$max_attempts\" ]; then
    exit 1
  fi
{_transport_failure_block("api_error_streak", "transport_error_budget")}
  sleep 30
done
"""
    assert _RULE not in _scan(tmp_path, shell)


def test_job_timeout_bounds_mutable_loop(tmp_path: Path) -> None:
    """A positive timeout on the owning job remains an independent hard resource bound."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  poll_deadline=$(($(date +%s) + 300))
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    exit 1
  fi
{_transport_failure_block("api_error_streak", "transport_error_budget")}
  sleep 30
done
"""
    assert _RULE not in _scan(tmp_path, shell, timeout_minutes=20)


def test_post_loop_assignment_does_not_make_bound_mutable(tmp_path: Path) -> None:
    """A reassignment after the back edge cannot invalidate an otherwise fixed in-loop bound."""
    shell = f"""
review_poll_failures=0
max_poll_transport_failures=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    exit 1
  fi
{_transport_failure_block("review_poll_failures", "max_poll_transport_failures")}
  sleep 30
done
poll_deadline=$(($(date +%s) + 300))
"""
    assert _RULE not in _scan(tmp_path, shell)
