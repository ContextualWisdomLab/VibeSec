"""Structural GitHub Actions poll-bound analyzer regressions for issue #1087.

These tests are the G-06 RED contract. They call ``classify_poll_loops``
directly against realistic workflow YAML so the analyzer can replace regex
adjacency windows without inventing a new detector family. Existing packaged
identities remain migration oracles.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from appguardrail_core.actions_poll_analyzer import (
    TRANSPORT_FAILURE_BUDGET_POLL_BOUND,
    TRANSPORT_ONLY_POLL_BOUND,
    PollLoopAssessment,
    additional_poll_bound_rule_ids,
    classify_poll_loops,
    poll_bound_rule_ids,
)


_FIXTURES = Path(__file__).parent / "fixtures" / "security_corpus"
_HISTORICAL_VULN = _FIXTURES / "github_actions_transport_only_poll_vulnerable.yml"
_HISTORICAL_FIXED = _FIXTURES / "github_actions_transport_only_poll_fixed.yml"


def _workflow(
    shell: str,
    *,
    job: str = "review",
    timeout: str | None = None,
    extra_jobs: str = "",
    run_key: str = "run: |",
) -> str:
    """Wrap a literal shell block in conventional two-space Actions YAML."""
    timeout_line = f"    timeout-minutes: {timeout}\n" if timeout is not None else ""
    body = "\n".join(f"          {line}" if line else "          " for line in shell.strip("\n").splitlines())
    return (
        "name: Required review\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        f"{extra_jobs}"
        f"  {job}:\n"
        "    runs-on: ubuntu-24.04\n"
        f"{timeout_line}"
        "    steps:\n"
        "      - name: Wait for current-head verdict\n"
        "        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        f"        {run_key}\n"
        f"{body}\n"
    )


def _historical_transport_shell(*, extra_before: str = "", extra_in_loop: str = "") -> str:
    """Return the verified transport-failure budget from the source incident."""
    before = extra_before.rstrip("\n")
    prefix = f"{before}\n" if before else ""
    in_loop = extra_in_loop.rstrip("\n")
    loop_extra = f"\n{in_loop}" if in_loop else ""
    return f"""
{prefix}set -euo pipefail
verdict=""
review_poll_failures=0
max_poll_transport_failures=3
poll_interval_seconds=60
while :; do{loop_extra}
  if ! reviews="$(timeout 30s gh api --paginate "repos/${{GITHUB_REPOSITORY}}/pulls/1/reviews?per_page=100")"; then
    review_poll_failures=$((review_poll_failures + 1))
    if [ "$review_poll_failures" -ge "$max_poll_transport_failures" ]; then
      exit 1
    fi
    sleep "$poll_interval_seconds"
    continue
  fi
  review_poll_failures=0
  verdict="$(printf '%s\\n' "$reviews" | jq -r '.[] | select(.state == "APPROVED") | .state' | tail -1)"
  if [ -n "$verdict" ]; then
    break
  fi
  sleep "$poll_interval_seconds"
done
"""


def _renamed_transport_shell(*, extra_before: str = "", extra_in_loop: str = "") -> str:
    """Return the identifier-agnostic transport-failure budget companion."""
    before = extra_before.rstrip("\n")
    prefix = f"{before}\n" if before else ""
    in_loop = extra_in_loop.rstrip("\n")
    loop_extra = f"\n{in_loop}" if in_loop else ""
    return f"""
{prefix}set -euo pipefail
api_error_streak=0
transport_error_budget=4
poll_interval_seconds=30
while :; do{loop_extra}
  if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
    api_error_streak=$((api_error_streak + 1))
    if [ "$api_error_streak" -ge "$transport_error_budget" ]; then
      exit 1
    fi
    continue
  fi
  api_error_streak=0
  sleep "$poll_interval_seconds"
done
"""


def _polls(workflow: str) -> tuple[PollLoopAssessment, ...]:
    """Classify every polling loop in one workflow document."""
    return classify_poll_loops(workflow)


def _unbounded(workflow: str) -> tuple[PollLoopAssessment, ...]:
    """Return only the transport-only unbounded assessments."""
    return tuple(item for item in _polls(workflow) if item.is_transport_only_unbounded)


def test_assessment_is_frozen_and_exposes_causal_fields() -> None:
    """Callers cannot mutate a classified loop after the analyzer returns."""
    assessment = PollLoopAssessment(
        job_name="review",
        transport_failure_budget=True,
        loop_local_total_bound=False,
        owning_job_timeout=False,
        comparison_converges=False,
        exit_reachable=False,
        is_transport_only_unbounded=True,
    )

    with pytest.raises(FrozenInstanceError):
        assessment.is_transport_only_unbounded = False  # type: ignore[misc]
    assert assessment.job_name == "review"
    assert TRANSPORT_ONLY_POLL_BOUND == "github-actions-transport-only-poll-bound"
    assert (
        TRANSPORT_FAILURE_BUDGET_POLL_BOUND
        == "github-actions-transport-failure-budget-poll-bound"
    )


def test_historical_vulnerable_poll_is_transport_only_unbounded() -> None:
    """The protected-predecessor incident remains a positive structural finding."""
    workflow = _HISTORICAL_VULN.read_text(encoding="utf-8")

    findings = _unbounded(workflow)

    assert len(findings) == 1
    item = findings[0]
    assert item.job_name == "review-verdict"
    assert item.transport_failure_budget is True
    assert item.loop_local_total_bound is False
    assert item.owning_job_timeout is False
    assert item.comparison_converges is False
    assert item.is_transport_only_unbounded is True
    assert poll_bound_rule_ids(findings) == (TRANSPORT_ONLY_POLL_BOUND,)


def test_helper_deadline_loop_cannot_donate_safety_to_later_poll() -> None:
    """A bounded helper loop is not causal safety for a later transport-only poll."""
    shell = """
set -euo pipefail
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
    workflow = _workflow(shell)

    findings = _unbounded(workflow)

    assert len(findings) == 1
    assert findings[0].job_name == "review"
    assert findings[0].transport_failure_budget is True
    assert findings[0].loop_local_total_bound is False
    assert findings[0].is_transport_only_unbounded is True
    assert poll_bound_rule_ids(findings) == (TRANSPORT_ONLY_POLL_BOUND,)


def test_same_loop_wall_clock_deadline_is_a_total_bound() -> None:
    """A loop-local date +%s -ge deadline with reachable exit 1 is finite."""
    workflow = _HISTORICAL_FIXED.read_text(encoding="utf-8")

    assessments = _polls(workflow)

    assert assessments
    assert not _unbounded(workflow)
    item = assessments[0]
    assert item.job_name == "review-verdict"
    assert item.transport_failure_budget is True
    assert item.loop_local_total_bound is True
    assert item.comparison_converges is True
    assert item.exit_reachable is True
    assert item.is_transport_only_unbounded is False
    assert poll_bound_rule_ids(assessments) == ()


def test_same_loop_total_attempt_counter_is_a_total_bound() -> None:
    """A loop-local attempt counter compared with -ge and exit 1 bounds the poll."""
    shell = """
set -euo pipefail
review_poll_failures=0
max_poll_transport_failures=3
poll_attempts=0
max_poll_attempts=120
while :; do
  poll_attempts=$((poll_attempts + 1))
  if [ "$poll_attempts" -ge "$max_poll_attempts" ]; then
    exit 1
  fi
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
    workflow = _workflow(shell)

    item = _polls(workflow)[0]

    assert item.loop_local_total_bound is True
    assert item.comparison_converges is True
    assert item.exit_reachable is True
    assert item.is_transport_only_unbounded is False


def test_owning_job_timeout_minutes_literal_is_a_total_bound() -> None:
    """A statically positive owning-job timeout-minutes is a hard runner bound."""
    workflow = _workflow(_historical_transport_shell(), timeout="30")

    item = _polls(workflow)[0]

    assert item.owning_job_timeout is True
    assert item.transport_failure_budget is True
    assert item.is_transport_only_unbounded is False


def test_owning_job_timeout_minutes_constant_expression_is_a_total_bound() -> None:
    """A statically positive ${{ N }} timeout expression bounds the owning job."""
    workflow = _workflow(_renamed_transport_shell(), job="required-review", timeout="${{ 30 }}")

    item = _polls(workflow)[0]

    assert item.owning_job_timeout is True
    assert item.is_transport_only_unbounded is False
    assert poll_bound_rule_ids((item,)) == ()


def test_reversed_deadline_comparison_is_not_a_total_bound() -> None:
    """A -lt clock comparison does not expire and cannot suppress the finding."""
    extra = '  if [ "$(date -u +%s)" -lt "$poll_deadline_epoch" ]; then\n    exit 1\n  fi'
    shell = _historical_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date -u +%s) + 10800 ))",
        extra_in_loop=extra,
    )
    workflow = _workflow(shell)

    item = _polls(workflow)[0]

    assert item.comparison_converges is False
    assert item.loop_local_total_bound is False
    assert item.is_transport_only_unbounded is True


def test_unreachable_exit_after_unconditional_break_is_not_safety() -> None:
    """Textual exit 1 after an unconditional break cannot establish finiteness."""
    extra = '  if [ "$(date -u +%s)" -ge "$poll_deadline_epoch" ]; then\n    break\n    exit 1\n  fi'
    shell = _historical_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date -u +%s) + 10800 ))",
        extra_in_loop=extra,
    )
    workflow = _workflow(shell)

    item = _polls(workflow)[0]

    assert item.exit_reachable is False
    assert item.loop_local_total_bound is False
    assert item.is_transport_only_unbounded is True


def test_unreachable_exit_after_unconditional_exit_zero_is_not_safety() -> None:
    """An exit 0 transfer makes a later fail-closed exit unreachable."""
    extra = '  if [ "$(date -u +%s)" -ge "$poll_deadline_epoch" ]; then\n    exit 0\n    exit 1\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date -u +%s) + 600 ))",
        extra_in_loop=extra,
    )
    workflow = _workflow(shell)

    item = _polls(workflow)[0]

    assert item.exit_reachable is False
    assert item.is_transport_only_unbounded is True
    assert poll_bound_rule_ids((item,)) == (TRANSPORT_FAILURE_BUDGET_POLL_BOUND,)


def test_quoted_and_comment_poll_tokens_are_not_loops() -> None:
    """Quoted or commented while/gh api/exit 1 text is not executable evidence."""
    workflow = _workflow(
        """
set -euo pipefail
# while :; do gh api repos/example/repo; exit 1; done
echo "while :; do gh api repos/example/repo/pulls/1/reviews; sleep 30; done"
printf '%s\\n' 'while true; do gh api; exit 1; done'
cat <<'EOF'
while :; do
  gh api repos/example/repo
  exit 1
done
EOF
"""
    )

    assert _polls(workflow) == ()
    assert poll_bound_rule_ids(()) == ()


def test_sibling_job_timeout_does_not_sanitize_unbounded_poll() -> None:
    """A timeout on another job cannot terminate this job's polling loop."""
    helper = """  bounded-helper:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: |
          max_poll_attempts=2
          poll_attempts=0
          poll_deadline_epoch=$(( $(date -u +%s) + 60 ))
          while :; do
            poll_attempts=$((poll_attempts + 1))
            if [ "$poll_attempts" -ge "$max_poll_attempts" ]; then exit 1; fi
            if [ "$(date -u +%s)" -ge "$poll_deadline_epoch" ]; then exit 1; fi
            gh api repos/example/repo
            sleep 1
          done
"""
    workflow = _workflow(
        _historical_transport_shell(),
        job="required-review",
        extra_jobs=helper,
    )

    findings = _unbounded(workflow)
    jobs = {item.job_name: item for item in _polls(workflow)}

    assert "required-review" in jobs
    assert jobs["required-review"].owning_job_timeout is False
    assert jobs["required-review"].is_transport_only_unbounded is True
    assert jobs["bounded-helper"].owning_job_timeout is True
    assert jobs["bounded-helper"].is_transport_only_unbounded is False
    assert any(item.job_name == "required-review" for item in findings)


@pytest.mark.parametrize("operator", ["-gt", "-ge"])
def test_forward_clock_operator_is_a_converging_total_bound(operator: str) -> None:
    """Forward -gt and -ge clock comparisons both expire."""
    extra = f'  if [ "$(date -u +%s)" {operator} "$poll_deadline_epoch" ]; then\n    exit 1\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date +%s) + 600 ))",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.comparison_converges is True
    assert item.loop_local_total_bound is True
    assert item.is_transport_only_unbounded is False


@pytest.mark.parametrize("operator", ["-gt", "-ge"])
def test_forward_attempt_operator_is_a_converging_total_bound(operator: str) -> None:
    """Forward -gt and -ge total-attempt comparisons both terminate the loop."""
    extra = f'  poll_attempts=$((poll_attempts + 1))\n  if [ "$poll_attempts" {operator} "$max_poll_attempts" ]; then\n    exit 1\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_attempts=0\nmax_poll_attempts=12",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.comparison_converges is True
    assert item.is_transport_only_unbounded is False


@pytest.mark.parametrize("timeout", ["0", "${{ 0 }}", "${{ -1 }}", "${{ inputs.timeout }}", ""])
def test_unproved_timeout_expression_is_not_owning_job_safety(timeout: str) -> None:
    """Zero, negative, empty, and dynamic timeouts do not bound the runner."""
    workflow = _workflow(_renamed_transport_shell(), timeout=timeout)

    item = _polls(workflow)[0]

    assert item.owning_job_timeout is False
    assert item.is_transport_only_unbounded is True


def test_timeout_after_steps_still_belongs_to_the_owning_job() -> None:
    """YAML key order must not hide a statically positive owning-job timeout."""
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
          while true; do
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
    timeout-minutes: 20
"""

    item = _polls(workflow)[0]

    assert item.owning_job_timeout is True
    assert item.is_transport_only_unbounded is False


def test_continue_before_deadline_exit_is_unreachable() -> None:
    """An unconditional continue before exit 1 leaves the clock guard unenforced."""
    extra = '  if [ "$(date +%s)" -ge "$poll_deadline_epoch" ]; then\n    continue\n    exit 1\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date +%s) + 300 ))",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.exit_reachable is False
    assert item.is_transport_only_unbounded is True


def test_late_deadline_initialization_is_not_causal_safety() -> None:
    """A deadline first assigned after the loop begins cannot precede the loop."""
    shell = """
set -euo pipefail
api_error_streak=0
transport_error_budget=4
while :; do
  poll_deadline_epoch=$(( $(date +%s) + 300 ))
  if [ "$(date +%s)" -ge "$poll_deadline_epoch" ]; then
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
  sleep 30
done
"""

    item = _polls(_workflow(shell))[0]

    assert item.loop_local_total_bound is False
    assert item.is_transport_only_unbounded is True


def test_logging_only_deadline_comparison_is_not_a_guard() -> None:
    """A converging comparison that only logs does not terminate the runner."""
    extra = '  if [ "$(date +%s)" -ge "$poll_deadline_epoch" ]; then\n    echo "deadline passed"\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date +%s) + 300 ))",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.exit_reachable is False
    assert item.loop_local_total_bound is False
    assert item.is_transport_only_unbounded is True


def test_empty_and_non_workflow_text_has_no_poll_loops() -> None:
    """Documents without conventional jobs and literal run blocks are empty."""
    assert classify_poll_loops("") == ()
    assert classify_poll_loops("name: not a workflow\n") == ()
    assert classify_poll_loops("jobs:\n") == ()
    assert classify_poll_loops("jobs:\n  review:\n    runs-on: ubuntu-24.04\n") == ()


def test_run_block_chomp_marker_is_still_literal_shell() -> None:
    """The YAML block chomp marker must not hide an executable poll."""
    workflow = _workflow(_historical_transport_shell(), run_key="run: |-")

    assert _unbounded(workflow)
    assert _unbounded(workflow)[0].is_transport_only_unbounded is True


def test_poll_without_transport_budget_is_not_the_transport_only_finding() -> None:
    """The G-06 finding is a transport-failure budget that is not a total bound."""
    workflow = _workflow(
        """
set -euo pipefail
while :; do
  reviews="$(gh api repos/example/repo/pulls/1/reviews)"
  sleep 30
done
"""
    )

    assessments = _polls(workflow)

    assert assessments
    assert assessments[0].transport_failure_budget is False
    assert assessments[0].is_transport_only_unbounded is False
    assert poll_bound_rule_ids(assessments) == ()


def test_swapped_forward_clock_operands_still_converge() -> None:
    """deadline -lt now is the same expiring relation as now -gt deadline."""
    extra = '  if [ "$poll_deadline_epoch" -lt "$(date +%s)" ]; then\n    exit 1\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date +%s) + 600 ))",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.comparison_converges is True
    assert item.loop_local_total_bound is True
    assert item.is_transport_only_unbounded is False


def test_tab_separated_gh_api_remains_executable() -> None:
    """Command evidence uses word adjacency, not a single-space token."""
    workflow = _workflow(
        """
set -euo pipefail
review_poll_failures=0
max_poll_transport_failures=3
while :; do
  if ! reviews="$(gh\tapi repos/example/repo/pulls/1/reviews)"; then
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
    )

    assert _unbounded(workflow)[0].is_transport_only_unbounded is True


def test_double_quoted_command_substitution_is_executable_poll() -> None:
    """gh api inside $(...) remains executable even when the expansion is quoted."""
    workflow = _workflow(
        """
set -euo pipefail
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
    )

    assert _unbounded(workflow)[0].transport_failure_budget is True


def test_one_line_fail_closed_deadline_guard_is_a_total_bound() -> None:
    """A compact if/then/exit/fi clock guard is still loop-local safety."""
    extra = '  if [ "$(date +%s)" -ge "$poll_deadline_epoch" ]; then exit 1; fi'
    shell = _renamed_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date +%s) + 10800 ))",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.loop_local_total_bound is True
    assert item.exit_reachable is True
    assert item.is_transport_only_unbounded is False


def test_coverage_edges_keep_causal_boundaries() -> None:
    """Parser edges must not invent loops or donate non-causal safety."""
    workflow = """
name: Required review
on: pull_request_target
jobs: # mapping
    ignored-before-first-job: true
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          set -euo pipefail
          echo \\x
          echo "foo\\"bar"
          echo 'unterminated
          echo "unterminated
          echo ${UNCLOSED
          echo $(unclosed
          echo $
          broken=$((1+
          nested="$(echo $(date +%s))"
          cat <<EOF
          while :; do gh api; done
          EOF
          cat <<"END"
          while true; do gh api; done
          END

          flag=1
          while [ -n "$flag" ]; do
            gh api repos/example/repo
            break
          done
          while :; do gh api repos/example/repo/pulls/1/reviews; sleep 1; done
          done extra
          fi
          api_error_streak=0
          transport_error_budget=4
          while :; do
            fi
            if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
              echo transport-failed
              continue
            fi
            if [ 1 -ge 2 ]; then
              exit 1
            fi
            sleep 30
          done
"""
    assessments = _polls(workflow)
    jobs = {item.job_name for item in assessments}
    assert "review" in jobs
    assert all(item.job_name != "ignored-before-first-job" for item in assessments)
    assert any(item.transport_failure_budget is False for item in assessments)


def test_swapped_reversed_clock_operands_are_not_safety() -> None:
    """deadline -gt now does not expire and cannot bound the poll."""
    extra = '  if [ "$poll_deadline_epoch" -gt "$(date +%s)" ]; then\n    exit 1\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date +%s) + 600 ))",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.comparison_converges is False
    assert item.is_transport_only_unbounded is True


def test_reversed_attempt_comparison_is_not_a_total_bound() -> None:
    """A -lt attempt comparison does not terminate when the counter grows."""
    extra = '  poll_attempts=$((poll_attempts + 1))\n  if [ "$poll_attempts" -lt "$max_poll_attempts" ]; then\n    exit 1\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_attempts=0\nmax_poll_attempts=12",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.comparison_converges is False
    assert item.is_transport_only_unbounded is True


def test_then_without_if_and_le_deadline_remain_unbounded() -> None:
    """A dangling then and a non-expiring -le clock guard are not safety."""
    extra = '  then\n  if [ "$(date +%s)" -le "$poll_deadline_epoch" ]; then\n    exit 1\n  fi'
    shell = _renamed_transport_shell(
        extra_before="poll_deadline_epoch=$(( $(date +%s) + 600 ))",
        extra_in_loop=extra,
    )

    item = _polls(_workflow(shell))[0]

    assert item.comparison_converges is False
    assert item.is_transport_only_unbounded is True


def test_additional_poll_bound_rule_ids_skips_regex_hits_for_the_same_file() -> None:
    """File-scoped merge keeps the packaged identity when regex already reported it."""
    workflow = _HISTORICAL_VULN.read_text(encoding="utf-8")

    assert additional_poll_bound_rule_ids(workflow) == (TRANSPORT_ONLY_POLL_BOUND,)
    assert additional_poll_bound_rule_ids(
        workflow, (TRANSPORT_ONLY_POLL_BOUND,)
    ) == ()
    assert additional_poll_bound_rule_ids(
        _HISTORICAL_FIXED.read_text(encoding="utf-8")
    ) == ()


def test_additional_poll_bound_rule_ids_emits_each_identity_once() -> None:
    """Two unbounded loops of the same family still contribute one rule ID."""
    other = """  sibling-poll:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          review_poll_failures=0
          max_poll_transport_failures=3
          while :; do
            if ! reviews="$(gh api repos/example/repo/pulls/2/reviews)"; then
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
    workflow = _workflow(_historical_transport_shell(), extra_jobs=other)
    ids = poll_bound_rule_ids(_polls(workflow))

    assert ids == (TRANSPORT_ONLY_POLL_BOUND, TRANSPORT_ONLY_POLL_BOUND)
    assert additional_poll_bound_rule_ids(workflow) == (TRANSPORT_ONLY_POLL_BOUND,)
    assert additional_poll_bound_rule_ids(
        workflow, (TRANSPORT_ONLY_POLL_BOUND,)
    ) == ()


def test_additional_poll_bound_rule_ids_keeps_renamed_budget_identity() -> None:
    """Renamed transport budgets stay on the identifier-agnostic packaged ID."""
    workflow = _workflow(_renamed_transport_shell())

    assert additional_poll_bound_rule_ids(workflow) == (
        TRANSPORT_FAILURE_BUDGET_POLL_BOUND,
    )
    assert additional_poll_bound_rule_ids(
        workflow, (TRANSPORT_FAILURE_BUDGET_POLL_BOUND,)
    ) == ()


@pytest.mark.parametrize("terminator", ["break", "exit", "exit 0", "exit 1", "return"])
def test_unconditional_success_path_terminator_is_finite(terminator: str) -> None:
    """A reachable top-level transfer removes the polling back edge."""
    extra = f"  {terminator}"
    shell = _historical_transport_shell(extra_in_loop=extra)

    item = _polls(_workflow(shell))[0]

    assert item.transport_failure_budget is True
    assert item.is_transport_only_unbounded is False
    assert additional_poll_bound_rule_ids(_workflow(shell)) == ()


def test_top_level_continue_does_not_terminate_the_poll() -> None:
    """A top-level continue skips later commands and repeats the loop."""
    extra = "  continue\n  break"
    shell = _historical_transport_shell(extra_in_loop=extra)

    item = _polls(_workflow(shell))[0]

    assert item.is_transport_only_unbounded is True
    assert additional_poll_bound_rule_ids(_workflow(shell)) == (
        TRANSPORT_ONLY_POLL_BOUND,
    )


