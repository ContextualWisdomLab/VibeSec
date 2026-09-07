"""Current-review regressions for issue #1087 shell control-flow boundaries."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.cli.appguardrail import _scan_file


_HISTORICAL_RULE = "github-actions-transport-only-poll-bound"
_GENERIC_RULE = "github-actions-transport-failure-budget-poll-bound"


def _scan(tmp_path: Path, shell: str) -> list[str]:
    """Scan a conventional literal-shell Actions workflow through production."""
    workflow_path = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
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
    return [finding["rule_id"] for finding in _scan_file(workflow_path, tmp_path)]


@pytest.mark.parametrize("termination", ["break", "exit 0"])
def test_historical_conditional_success_termination_does_not_hide_poll(
    tmp_path: Path,
    termination: str,
) -> None:
    """A same-indent conditional termination is not an unconditional back-edge cut."""
    shell = f"""
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
  if [ -n "$reviews" ]; then
  {termination}
  fi
  sleep 30
done
"""

    assert _scan(tmp_path, shell).count(_HISTORICAL_RULE) == 1


@pytest.mark.parametrize("termination", ["break", "exit 0"])
def test_generic_conditional_success_termination_does_not_hide_poll(
    tmp_path: Path,
    termination: str,
) -> None:
    """Conditional success termination must not suppress the renamed detector."""
    shell = f"""
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
  if [ -n "$response" ]; then
  {termination}
  fi
  sleep 30
done
"""

    assert _scan(tmp_path, shell).count(_GENERIC_RULE) == 1


def test_generic_reversed_retry_declarations_remain_detectable(tmp_path: Path) -> None:
    """Counter/limit declaration order before the loop is semantically irrelevant."""
    shell = """
transport_error_budget=4
api_error_streak=0
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

    assert _scan(tmp_path, shell).count(_GENERIC_RULE) == 1
