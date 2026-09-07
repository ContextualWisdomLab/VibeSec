"""Current-review regressions for GitHub Actions polling-bound detectors.

These cases pin causal state locality for issue #1087: safety state must be
initialized before the same vulnerable loop, an earlier helper loop cannot
donate a bound, and a healthy API path that terminates before the back edge is
finite rather than resource-retaining.
"""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_HISTORICAL_RULE = "github-actions-transport-only-poll-bound"
_GENERIC_RULE = "github-actions-transport-failure-budget-poll-bound"


def _scan(tmp_path: Path, content: str) -> list[str]:
    """Scan one temporary workflow through the production scanner."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    return [finding["rule_id"] for finding in _scan_file(workflow, tmp_path)]


def _historical(body_prefix: str = "", body_middle: str = "") -> str:
    """Build the historical-name polling shape with caller-controlled guards."""
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
{body_prefix}          while :; do
{body_middle}            if ! reviews="$(gh api repos/example/repo/pulls/1/reviews)"; then
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


def _renamed_poll(*, successful_termination: str = "") -> str:
    """Build the identifier-agnostic transport-only polling shape."""
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
            if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
              api_error_streak=$((api_error_streak + 1))
              if [ "$api_error_streak" -ge "$transport_error_budget" ]; then
                exit 1
              fi
              continue
            fi
{successful_termination}            api_error_streak=0
            sleep 30
          done
"""


def test_historical_uninitialized_deadline_does_not_suppress(tmp_path: Path) -> None:
    """An unset historical deadline variable is not causal safety evidence."""
    workflow = _historical(
        body_middle=(
            "            if [ \"$(date -u +%s)\" -ge \"$poll_deadline_epoch\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
        )
    )

    assert _scan(tmp_path, workflow).count(_HISTORICAL_RULE) == 1


def test_historical_uninitialized_attempt_limit_does_not_suppress(
    tmp_path: Path,
) -> None:
    """An unset historical total-attempt limit cannot bound successful polls."""
    workflow = _historical(
        body_prefix="          poll_attempts=0\n",
        body_middle=(
            "            poll_attempts=$((poll_attempts + 1))\n"
            "            if [ \"$poll_attempts\" -ge \"$max_poll_attempts\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
        ),
    )

    assert _scan(tmp_path, workflow).count(_HISTORICAL_RULE) == 1


def test_historical_late_deadline_initialization_does_not_suppress(
    tmp_path: Path,
) -> None:
    """Initializing a deadline after its guard cannot retroactively bound it."""
    workflow = _historical(
        body_middle=(
            "            if [ \"$(date -u +%s)\" -ge \"$poll_deadline_epoch\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
            "            poll_deadline_epoch=$(( $(date -u +%s) + 600 ))\n"
        )
    )

    assert _scan(tmp_path, workflow).count(_HISTORICAL_RULE) == 1


def test_earlier_bounded_deadline_loop_cannot_hide_later_renamed_poll(
    tmp_path: Path,
) -> None:
    """A helper loop deadline is not a bound for a later vulnerable loop."""
    workflow = _renamed_poll().replace(
        "          api_error_streak=0\n",
        "          helper_deadline=$(( $(date -u +%s) + 30 ))\n"
        "          while :; do\n"
        "            if [ \"$(date -u +%s)\" -ge \"$helper_deadline\" ]; then\n"
        "              exit 1\n"
        "            fi\n"
        "            break\n"
        "          done\n"
        "          api_error_streak=0\n",
        1,
    )

    assert _scan(tmp_path, workflow).count(_GENERIC_RULE) == 1


def test_earlier_bounded_attempt_loop_cannot_hide_later_renamed_poll(
    tmp_path: Path,
) -> None:
    """A helper-loop attempt budget cannot sanitize a later polling loop."""
    workflow = _renamed_poll().replace(
        "          api_error_streak=0\n",
        "          helper_attempts=0\n"
        "          helper_limit=2\n"
        "          while :; do\n"
        "            helper_attempts=$((helper_attempts + 1))\n"
        "            if [ \"$helper_attempts\" -ge \"$helper_limit\" ]; then\n"
        "              exit 1\n"
        "            fi\n"
        "            break\n"
        "          done\n"
        "          api_error_streak=0\n",
        1,
    )

    assert _scan(tmp_path, workflow).count(_GENERIC_RULE) == 1


def test_historical_success_break_before_sleep_is_finite(tmp_path: Path) -> None:
    """An unconditional successful-path break prevents the polling back edge."""
    workflow = _historical(body_middle="").replace(
        "            review_poll_failures=0\n            sleep 30\n",
        "            break\n            review_poll_failures=0\n            sleep 30\n",
    )

    assert _HISTORICAL_RULE not in _scan(tmp_path, workflow)


def test_renamed_success_exit_zero_before_sleep_is_finite(tmp_path: Path) -> None:
    """An unconditional successful-path exit 0 makes the remote poll finite."""
    workflow = _renamed_poll(successful_termination="            exit 0\n")

    assert _GENERIC_RULE not in _scan(tmp_path, workflow)
