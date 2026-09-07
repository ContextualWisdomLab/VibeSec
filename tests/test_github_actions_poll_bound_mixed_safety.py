"""Regression tests for historical transport names with renamed safety state."""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_RULE_ID = "github-actions-transport-only-poll-bound"


def _scan(tmp_path: Path, content: str) -> list[str]:
    """Scan one workflow through the production scanner and return rule ids."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    return [finding["rule_id"] for finding in _scan_file(workflow, tmp_path)]


def _historical(*, prefix: str = "", guard: str = "") -> str:
    """Build the historical transport budget with caller-selected safety state."""
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
{prefix}          while :; do
{guard}            if ! reviews="$(gh api repos/example/repo/pulls/1/reviews)"; then
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


def test_historical_transport_with_renamed_deadline_is_bounded(tmp_path: Path) -> None:
    """Safety semantics must not depend on the historical deadline identifier."""
    workflow = _historical(
        prefix="          overall_stop_epoch=$(( $(date -u +%s) + 600 ))\n",
        guard=(
            "            if [ \"$(date -u +%s)\" -ge \"$overall_stop_epoch\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
        ),
    )

    assert _RULE_ID not in _scan(tmp_path, workflow)


def test_historical_transport_with_renamed_total_attempts_is_bounded(
    tmp_path: Path,
) -> None:
    """Renamed loop-wide attempt state is equivalent fail-closed safety evidence."""
    workflow = _historical(
        prefix=(
            "          all_poll_attempts=0\n"
            "          overall_attempt_limit=12\n"
        ),
        guard=(
            "            all_poll_attempts=$((all_poll_attempts + 1))\n"
            "            if [ \"$all_poll_attempts\" -ge \"$overall_attempt_limit\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
        ),
    )

    assert _RULE_ID not in _scan(tmp_path, workflow)


def test_historical_transport_with_reversed_renamed_attempt_declarations_is_bounded(
    tmp_path: Path,
) -> None:
    """Declaration order does not change a valid pre-loop total-attempt bound."""
    workflow = _historical(
        prefix=(
            "          overall_attempt_limit=12\n"
            "          all_poll_attempts=0\n"
        ),
        guard=(
            "            all_poll_attempts=$((all_poll_attempts + 1))\n"
            "            if [ \"$all_poll_attempts\" -ge \"$overall_attempt_limit\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
        ),
    )

    assert _RULE_ID not in _scan(tmp_path, workflow)


def test_historical_transport_with_uninitialized_renamed_deadline_remains_vulnerable(
    tmp_path: Path,
) -> None:
    """Identifier-agnostic safety must still require causal initialization."""
    workflow = _historical(
        guard=(
            "            if [ \"$(date -u +%s)\" -ge \"$overall_stop_epoch\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
        )
    )

    assert _scan(tmp_path, workflow).count(_RULE_ID) == 1
