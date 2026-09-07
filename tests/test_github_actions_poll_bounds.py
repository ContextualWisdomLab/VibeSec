"""Regression tests for transport-only GitHub Actions polling bounds.

The historical vulnerable/fixed fixtures are answer-free source-code oracles
pinned to the verified ContextualWisdomLab/.github incident in AppGuardrail
issue #1087. Tests execute the packaged production scanner rather than reading
an expected-result field from the fixtures.
"""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


_RULE_ID = "github-actions-transport-only-poll-bound"
_FIXTURES = Path(__file__).parent / "fixtures" / "security_corpus"


def _rule() -> dict:
    """Return the single packaged transport-only polling rule."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1
    return matches[0]


def _scan_workflow(tmp_path: Path, content: str) -> list[dict]:
    """Run production scanning against a workflow-scoped temporary file."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    return _scan_file(workflow, tmp_path)


def _rule_ids(findings: list[dict]) -> list[str]:
    """Return finding identities in scan order."""
    return [finding["rule_id"] for finding in findings]


def test_transport_only_poll_rule_is_packaged_and_workflow_scoped() -> None:
    """The detector must load once and only target GitHub Actions YAML paths."""
    rule = _rule()

    assert rule["severity"] == "HIGH"
    assert rule["extensions"] is None
    assert rule["include_paths"] == [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    ]


def test_verified_vulnerable_control_plane_poll_is_reported(tmp_path: Path) -> None:
    """The protected-predecessor incident must remain a positive regression."""
    content = (
        _FIXTURES / "github_actions_transport_only_poll_vulnerable.yml"
    ).read_text(encoding="utf-8")

    findings = _scan_workflow(tmp_path, content)

    assert _rule_ids(findings).count(_RULE_ID) == 1


def test_protected_wall_clock_repair_is_not_reported(tmp_path: Path) -> None:
    """The causal .github wall-clock repair must remain a fixed oracle."""
    content = (
        _FIXTURES / "github_actions_transport_only_poll_fixed.yml"
    ).read_text(encoding="utf-8")

    findings = _scan_workflow(tmp_path, content)

    assert _RULE_ID not in _rule_ids(findings)


def test_finite_total_attempt_bound_is_not_reported(tmp_path: Path) -> None:
    """A finite total attempt budget bounds successful-no-verdict polling too."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          max_poll_attempts=120
          poll_attempts=0
          while :; do
            poll_attempts=$((poll_attempts + 1))
            if [ "$poll_attempts" -ge "$max_poll_attempts" ]; then
              exit 1
            fi
            reviews="$(gh api repos/example/repo/pulls/1/reviews)"
            [ -n "$reviews" ] && break
            sleep 30
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_explicit_job_timeout_is_a_bounded_negative(tmp_path: Path) -> None:
    """An explicit job wall-clock bound prevents an indefinitely held runner."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - run: |
          max_poll_transport_failures=3
          while true; do
            reviews="$(gh api repos/example/repo/pulls/1/reviews)"
            [ -n "$reviews" ] && break
            sleep 30
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_job_timeout_after_steps_is_still_a_bounded_negative(tmp_path: Path) -> None:
    """YAML key order must not change the owning job's timeout semantics."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          while true; do
            reviews="$(gh api repos/example/repo/pulls/1/reviews)"
            sleep 30
          done
    timeout-minutes: 20
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_late_job_timeout_after_more_than_300_lines_is_bounded_negative(
    tmp_path: Path,
) -> None:
    """Owning-job timeout discovery must not depend on an arbitrary line cap."""
    spacer = "\n".join("    # realistic large-job spacer" for _ in range(305))
    workflow = f"""
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          while true; do
            reviews="$(gh api repos/example/repo/pulls/1/reviews)"
            sleep 30
          done
{spacer}
    timeout-minutes: 20
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_sibling_job_bounds_do_not_suppress_vulnerable_poll(tmp_path: Path) -> None:
    """A bound in another job cannot terminate the vulnerable polling job."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  bounded-helper:
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
  required-review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
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
            [ -n "$reviews" ] && break
            sleep 30
          done
"""

    assert _rule_ids(_scan_workflow(tmp_path, workflow)).count(_RULE_ID) == 1


def test_split_steps_do_not_donate_poll_evidence(tmp_path: Path) -> None:
    """Transport budget and poll evidence must belong to one shell run block."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - name: Configure retry policy
        run: |
          max_poll_transport_failures=3
          echo "configuration only"
      - name: Independent bounded watcher
        run: |
          while :; do
            gh api repos/example/repo
            sleep 30
            break
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_remote_poll_and_sleep_must_be_inside_the_unbounded_loop(tmp_path: Path) -> None:
    """Commands elsewhere in one run block cannot fabricate a polling loop."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          while :; do
            echo "local loop"
            break
          done
          gh api repos/example/repo
          sleep 30
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_quoted_poll_commands_are_not_executable_evidence(tmp_path: Path) -> None:
    """Echoed or printf-only command text must not create a HIGH finding."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          while :; do
            echo "gh api repos/example/repo"
            printf '%s\\n' 'sleep 30'
            break
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_indented_shell_comments_are_not_executable_poll_evidence(
    tmp_path: Path,
) -> None:
    """Whitespace before a shell comment marker must not bypass comment filtering."""
    workflow = """
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          while :; do
              # gh api repos/example/repo
              # sleep 30
            break
          done
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_unrelated_post_loop_deadline_comparison_does_not_suppress(
    tmp_path: Path,
) -> None:
    """A comparison outside the poll cannot bound the successful-no-result path."""
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
          poll_deadline_epoch=$(( $(date -u +%s) + 60 ))
          while :; do
            if ! reviews="$(gh api repos/example/repo/pulls/1/reviews)"; then
              review_poll_failures=$((review_poll_failures + 1))
              if [ "$review_poll_failures" -ge "$max_poll_transport_failures" ]; then
                exit 1
              fi
              continue
            fi
            review_poll_failures=0
            [ -n "$reviews" ] && break
            sleep 30
          done
          if [ "$(date -u +%s)" -ge "$poll_deadline_epoch" ]; then
            echo "too late to bound the completed loop"
          fi
"""

    assert _rule_ids(_scan_workflow(tmp_path, workflow)).count(_RULE_ID) == 1


def test_transport_counter_without_remote_sleeping_poll_is_not_reported(
    tmp_path: Path,
) -> None:
    """A transport counter alone is not the causal resource-retention path."""
    workflow = """
name: One-shot API read
on: workflow_dispatch
jobs:
  inspect:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          gh api repos/example/repo
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_comment_only_poll_example_is_not_reported(tmp_path: Path) -> None:
    """Documentation comments must not masquerade as executable polling."""
    workflow = """
name: Docs
on: push
# max_poll_transport_failures=3
# while :; do
#   gh api repos/example/repo
#   sleep 60
# done
jobs:
  docs:
    runs-on: ubuntu-24.04
    steps:
      - run: echo ok
"""

    assert _RULE_ID not in _rule_ids(_scan_workflow(tmp_path, workflow))


def test_rule_respects_workflow_path_scope(tmp_path: Path) -> None:
    """The same shell text outside .github/workflows must not be scanned."""
    content = (
        _FIXTURES / "github_actions_transport_only_poll_vulnerable.yml"
    ).read_text(encoding="utf-8")
    documentation = tmp_path / "docs" / "polling-example.yml"
    documentation.parent.mkdir(parents=True)
    documentation.write_text(content, encoding="utf-8")

    findings = _scan_file(documentation, tmp_path)

    assert _RULE_ID not in _rule_ids(findings)
