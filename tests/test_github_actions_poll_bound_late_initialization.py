"""Regression tests for late initialization of transport-poll safety guards.

A total deadline or attempt limit is only causal safety evidence when its state
exists before the polling loop starts. Assignments after the guard or after the
loop cannot retroactively bound the successful-no-result path.
"""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_RULE_ID = "github-actions-transport-failure-budget-poll-bound"


def _scan(tmp_path: Path, shell: str) -> list[str]:
    """Scan one conventional GitHub Actions workflow through production code."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "name: Required review\non: pull_request_target\njobs:\n"
        "  review:\n    runs-on: ubuntu-24.04\n    steps:\n"
        "      - run: |\n" + shell,
        encoding="utf-8",
    )
    return [finding["rule_id"] for finding in _scan_file(workflow, tmp_path)]


def _body(prefix: str = "", loop_prefix: str = "", suffix: str = "") -> str:
    """Build the renamed vulnerable transport-only polling loop."""
    return (
        "          api_error_streak=0\n"
        "          transport_error_budget=4\n"
        + prefix
        + "          while :; do\n"
        + loop_prefix
        + "            if ! response=\"$(gh api repos/example/repo/pulls/7/reviews)\"; then\n"
        "              api_error_streak=$((api_error_streak + 1))\n"
        "              if [ \"$api_error_streak\" -ge \"$transport_error_budget\" ]; then\n"
        "                exit 1\n"
        "              fi\n"
        "              sleep 5\n"
        "              continue\n"
        "            fi\n"
        "            sleep 30\n"
        "          done\n"
        + suffix
    )


def test_deadline_initialized_after_done_does_not_suppress(tmp_path: Path) -> None:
    """A post-loop deadline assignment cannot bound the loop that preceded it."""
    shell = _body(
        loop_prefix=(
            "            if [ \"$(date -u +%s)\" -ge \"$overall_stop_epoch\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
        ),
        suffix="          overall_stop_epoch=$(( $(date -u +%s) + 600 ))\n",
    )

    assert _scan(tmp_path, shell).count(_RULE_ID) == 1


def test_deadline_initialized_after_guard_does_not_suppress(tmp_path: Path) -> None:
    """Initializing a deadline after its guard cannot prove the first iteration safe."""
    shell = _body(
        loop_prefix=(
            "            if [ \"$(date -u +%s)\" -ge \"$overall_stop_epoch\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
            "            overall_stop_epoch=$(( $(date -u +%s) + 600 ))\n"
        )
    )

    assert _scan(tmp_path, shell).count(_RULE_ID) == 1


def test_attempt_limit_initialized_after_done_does_not_suppress(tmp_path: Path) -> None:
    """A post-loop attempt limit cannot bound iterations that already executed."""
    shell = _body(
        prefix="          all_poll_attempts=0\n",
        loop_prefix=(
            "            all_poll_attempts=$((all_poll_attempts + 1))\n"
            "            if [ \"$all_poll_attempts\" -ge \"$overall_attempt_limit\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
        ),
        suffix="          overall_attempt_limit=12\n",
    )

    assert _scan(tmp_path, shell).count(_RULE_ID) == 1


def test_attempt_limit_initialized_after_guard_does_not_suppress(tmp_path: Path) -> None:
    """A limit assigned after comparison is not a pre-loop finite bound."""
    shell = _body(
        prefix="          all_poll_attempts=0\n",
        loop_prefix=(
            "            all_poll_attempts=$((all_poll_attempts + 1))\n"
            "            if [ \"$all_poll_attempts\" -ge \"$overall_attempt_limit\" ]; then\n"
            "              exit 1\n"
            "            fi\n"
            "            overall_attempt_limit=12\n"
        ),
    )

    assert _scan(tmp_path, shell).count(_RULE_ID) == 1
