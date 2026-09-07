"""Regressions for total polling bounds whose fail-closed exit is unreachable."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.cli.appguardrail import _scan_file


_RULE = "github-actions-poll-bound-unreachable-exit"


def _scan(tmp_path: Path, shell: str) -> list[str]:
    """Scan one conventional workflow through the production scanner."""
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


def _transport_failure_block(counter: str, limit: str) -> str:
    """Return the transport-error budget from the reviewed incident family."""
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
def test_continue_before_deadline_exit_remains_detectable(
    tmp_path: Path, failure_counter: str, failure_limit: str
) -> None:
    """A continue before the nonzero exit makes a deadline guard non-enforcing."""
    shell = f"""
{failure_counter}=0
{failure_limit}=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    continue
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
def test_continue_before_total_attempt_exit_remains_detectable(
    tmp_path: Path, failure_counter: str, failure_limit: str
) -> None:
    """A continue before the nonzero exit leaves a total-attempt guard unbounded."""
    shell = f"""
{failure_counter}=0
{failure_limit}=4
total_attempts=0
max_attempts=12
while :; do
  total_attempts=$((total_attempts + 1))
  if [ \"$total_attempts\" -ge \"$max_attempts\" ]; then
    continue
    exit 1
  fi
{_transport_failure_block(failure_counter, failure_limit)}
  sleep 30
done
"""
    assert _scan(tmp_path, shell).count(_RULE) == 1


@pytest.mark.parametrize("terminator", ["exit 0", "break"])
def test_terminating_command_before_continue_is_not_reported(
    tmp_path: Path, terminator: str
) -> None:
    """A command that terminates first makes the later continue unreachable."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    {terminator}
    continue
    exit 1
  fi
{_transport_failure_block("api_error_streak", "transport_error_budget")}
  sleep 30
done
"""
    assert _RULE not in _scan(tmp_path, shell)


def test_continue_zero_is_not_reported_as_a_valid_back_edge(tmp_path: Path) -> None:
    """Invalid ``continue 0`` is not evidence of a reachable loop back edge."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    continue 0
    exit 1
  fi
{_transport_failure_block("api_error_streak", "transport_error_budget")}
  sleep 30
done
"""
    assert _RULE not in _scan(tmp_path, shell)


def test_continue_one_before_exit_remains_detectable(tmp_path: Path) -> None:
    """A directly reachable level-one continue is a real loop back edge."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    continue 1
    exit 1
  fi
{_transport_failure_block("api_error_streak", "transport_error_budget")}
  sleep 30
done
"""
    assert _scan(tmp_path, shell).count(_RULE) == 1


def test_reachable_deadline_exit_is_not_reported_by_unreachable_exit_companion(
    tmp_path: Path,
) -> None:
    """A directly reachable fail-closed deadline exit remains valid safety evidence."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  if [ \"$(date +%s)\" -ge \"$poll_deadline\" ]; then
    exit 1
  fi
{_transport_failure_block("api_error_streak", "transport_error_budget")}
  sleep 30
done
"""
    assert _RULE not in _scan(tmp_path, shell)


def test_reachable_total_attempt_exit_is_not_reported_by_unreachable_exit_companion(
    tmp_path: Path,
) -> None:
    """A directly reachable total-attempt exit is a real finite bound."""
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
