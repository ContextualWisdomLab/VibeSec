"""Regression tests for renamed transport-failure polling budgets.

The organization incident in issue #1087 is a control-flow defect, not a
requirement to spell its retry variables exactly like the historical .github
workflow. These tests exercise a companion production detector with unrelated
identifier names so isomorphic transport-only bounds remain detectable without
making the historical rule less precise.
"""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


_RULE_ID = "github-actions-transport-failure-budget-poll-bound"


def _scan_workflow(tmp_path: Path, content: str) -> list[dict]:
    """Run production scanning against a workflow-scoped temporary file."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    return _scan_file(workflow, tmp_path)


def _rule_ids(findings: list[dict]) -> list[str]:
    """Return finding identities in scan order."""
    return [finding["rule_id"] for finding in findings]


def _renamed_poll(*, total_deadline: bool = False) -> str:
    """Return one causal retry-budget loop using non-historical identifiers."""
    deadline_setup = (
        "          overall_stop_epoch=$(( $(date -u +%s) + 600 ))\n"
        if total_deadline
        else ""
    )
    deadline_guard = (
        "            if [ \"$(date -u +%s)\" -ge \"$overall_stop_epoch\" ]; then\n"
        "              exit 1\n"
        "            fi\n"
        if total_deadline
        else ""
    )
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
{deadline_setup}          while :; do
{deadline_guard}            if ! response="$(timeout 20s gh api repos/example/repo/pulls/7/reviews)"; then
              api_error_streak=$((api_error_streak + 1))
              if [ "$api_error_streak" -ge "$transport_error_budget" ]; then
                exit 1
              fi
              sleep 5
              continue
            fi
            api_error_streak=0
            if [ -n "$response" ]; then
              break
            fi
            sleep 30
          done
"""


def test_generic_transport_budget_rule_is_packaged_once() -> None:
    """The alias-safe causal companion must be a single packaged HIGH rule."""
    rules = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]

    assert len(rules) == 1
    assert rules[0]["severity"] == "HIGH"
    assert rules[0]["include_paths"] == [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    ]


def test_renamed_transport_failure_budget_is_reported(tmp_path: Path) -> None:
    """Identifier renaming must not evade an otherwise isomorphic defect."""
    findings = _scan_workflow(tmp_path, _renamed_poll())

    assert _rule_ids(findings).count(_RULE_ID) == 1


def test_renamed_budget_with_total_deadline_is_not_reported(tmp_path: Path) -> None:
    """A fail-closed total deadline terminates the successful-no-result path."""
    findings = _scan_workflow(tmp_path, _renamed_poll(total_deadline=True))

    assert _RULE_ID not in _rule_ids(findings)


def test_renamed_budget_with_total_attempt_limit_is_not_reported(
    tmp_path: Path,
) -> None:
    """A loop-wide attempt budget bounds both transport and no-result paths."""
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
          all_poll_attempts=0
          overall_attempt_limit=12
          while :; do
            all_poll_attempts=$((all_poll_attempts + 1))
            if [ "$all_poll_attempts" -ge "$overall_attempt_limit" ]; then
              exit 1
            fi
            if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
              api_error_streak=$((api_error_streak + 1))
              if [ "$api_error_streak" -ge "$transport_error_budget" ]; then
                exit 1
              fi
              sleep 5
              continue
            fi
            api_error_streak=0
            sleep 30
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_non_enforcing_clock_comparison_does_not_hide_renamed_poll(
    tmp_path: Path,
) -> None:
    """Clock text without fail-closed termination is not a total deadline."""
    workflow = _renamed_poll().replace(
        "          while :; do\n",
        "          overall_stop_epoch=$(( $(date -u +%s) + 600 ))\n"
        "          while :; do\n"
        "            if [ \"$(date -u +%s)\" -ge \"$overall_stop_epoch\" ]; then\n"
        "              echo \"still waiting\"\n"
        "            fi\n",
    )

    assert _rule_ids(_scan_workflow(tmp_path, workflow)).count(_RULE_ID) == 1


def test_uninitialized_deadline_does_not_hide_renamed_poll(tmp_path: Path) -> None:
    """A deadline comparison is not a bound unless its deadline is initialized."""
    workflow = _renamed_poll().replace(
        "          while :; do\n",
        "          while :; do\n"
        "            if [ \"$(date -u +%s)\" -ge \"$missing_deadline\" ]; then\n"
        "              exit 1\n"
        "            fi\n",
    )

    assert _rule_ids(_scan_workflow(tmp_path, workflow)).count(_RULE_ID) == 1


def test_uninitialized_attempt_limit_does_not_hide_renamed_poll(
    tmp_path: Path,
) -> None:
    """A total-attempt comparison needs a finite initialized limit."""
    workflow = _renamed_poll().replace(
        "          while :; do\n",
        "          all_poll_attempts=0\n"
        "          while :; do\n"
        "            all_poll_attempts=$((all_poll_attempts + 1))\n"
        "            if [ \"$all_poll_attempts\" -ge \"$missing_limit\" ]; then\n"
        "              exit 1\n"
        "            fi\n",
    )

    assert _rule_ids(_scan_workflow(tmp_path, workflow)).count(_RULE_ID) == 1


def test_unused_numeric_variables_do_not_create_transport_budget_evidence(
    tmp_path: Path,
) -> None:
    """Numbers near a poll are not a causal retry budget unless linked by flow."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          unrelated_zero=0
          unrelated_limit=4
          while :; do
            if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
              echo "network failed"
              sleep 5
              continue
            fi
            sleep 30
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_historical_named_rule_is_not_duplicated_by_generic_companion(
    tmp_path: Path,
) -> None:
    """The generic companion must yield to the pinned historical rule identity."""
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
          while :; do
            if ! reviews="$(gh api repos/example/repo/pulls/7/reviews)"; then
              review_poll_failures=$((review_poll_failures + 1))
              if [ "$review_poll_failures" -ge "$max_poll_transport_failures" ]; then
                exit 1
              fi
              sleep 5
              continue
            fi
            review_poll_failures=0
            sleep 30
          done
"""

    findings = _scan_workflow(tmp_path, workflow)

    assert _RULE_ID not in _rule_ids(findings)
    assert _rule_ids(findings).count("github-actions-transport-only-poll-bound") == 1
