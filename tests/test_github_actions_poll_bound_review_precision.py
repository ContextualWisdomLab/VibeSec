"""Current-review regressions for GitHub Actions polling-bound precision."""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_GENERIC_RULE = "github-actions-transport-failure-budget-poll-bound"
_RESET_RULE = "github-actions-poll-bound-state-reset"


def _scan_ids(tmp_path: Path, shell: str) -> list[str]:
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


def _renamed_transport_branch() -> str:
    """Return the reviewed transport-failure-only retry branch."""
    return """  if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
    api_error_streak=$((api_error_streak + 1))
    if [ "$api_error_streak" -ge "$transport_error_budget" ]; then
      exit 1
    fi
    continue
  fi
  api_error_streak=0"""


def test_reverse_total_attempt_safety_declarations_bound_renamed_poll(
    tmp_path: Path,
) -> None:
    """A fixed total-attempt limit may precede its counter before the same loop."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
overall_attempt_limit=12
all_poll_attempts=0
while :; do
  all_poll_attempts=$((all_poll_attempts + 1))
  if [ "$all_poll_attempts" -ge "$overall_attempt_limit" ]; then
    exit 1
  fi
{_renamed_transport_branch()}
  sleep 30
done
"""

    assert _GENERIC_RULE not in _scan_ids(tmp_path, shell)


def test_deadline_refresh_with_nonempty_guard_is_not_state_reset(
    tmp_path: Path,
) -> None:
    """A refresh followed by an unconditional nonempty-value exit is finite."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  poll_deadline=$(($(date +%s) + 300))
  if [ -n "$poll_deadline" ]; then
    exit 1
  fi
{_renamed_transport_branch()}
  sleep 30
done
"""

    assert _RESET_RULE not in _scan_ids(tmp_path, shell)


def test_deadline_refresh_with_reversed_clock_guard_is_not_state_reset(
    tmp_path: Path,
) -> None:
    """A future deadline on the left of >= terminates immediately after refresh."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  poll_deadline=$(($(date +%s) + 300))
  if [ "$poll_deadline" -ge "$(date +%s)" ]; then
    exit 1
  fi
{_renamed_transport_branch()}
  sleep 30
done
"""

    assert _RESET_RULE not in _scan_ids(tmp_path, shell)


def test_deadline_refresh_with_expiration_guard_remains_state_reset(
    tmp_path: Path,
) -> None:
    """Refreshing a future deadline before a clock>=deadline guard can prevent expiry."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
poll_deadline=$(($(date +%s) + 300))
while :; do
  poll_deadline=$(($(date +%s) + 300))
  if [ "$(date +%s)" -ge "$poll_deadline" ]; then
    exit 1
  fi
{_renamed_transport_branch()}
  sleep 30
done
"""

    assert _scan_ids(tmp_path, shell).count(_RESET_RULE) == 1
