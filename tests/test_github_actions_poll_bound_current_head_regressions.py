"""Current-head regressions for issue #1087 polling detector precision."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.cli.appguardrail import _scan_file


_HISTORICAL = "github-actions-transport-only-poll-bound"
_GENERIC = "github-actions-transport-failure-budget-poll-bound"
_RESET = "github-actions-poll-bound-state-reset"
_UNREACHABLE = "github-actions-poll-bound-unreachable-exit"
_FAMILY = {_HISTORICAL, _GENERIC, _RESET, _UNREACHABLE}


def _scan(tmp_path: Path, shell: str) -> list[str]:
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


def _scan_with_timeout(tmp_path: Path, shell: str, timeout: str) -> list[str]:
    """Scan a workflow whose owning job declares the supplied timeout expression."""
    workflow = tmp_path / ".github" / "workflows" / "required-review.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "name: Required review\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-24.04\n"
        f"    timeout-minutes: {timeout}\n"
        "    steps:\n"
        "      - run: |\n"
        + "\n".join(f"          {line}" for line in shell.strip().splitlines())
        + "\n",
        encoding="utf-8",
    )
    return [finding["rule_id"] for finding in _scan_file(workflow, tmp_path)]


def _renamed_transport_branch(command: str = "gh api repos/example/repo/pulls/7/reviews") -> str:
    """Return the reviewed renamed transport-failure branch."""
    return '''  if ! response="$(%s)"; then
    api_error_streak=$((api_error_streak + 1))
    if [ "$api_error_streak" -ge "$transport_error_budget" ]; then
      exit 1
    fi
    continue
  fi
  api_error_streak=0''' % command


def _historical_transport_branch(command: str = "gh api repos/example/repo/pulls/7/reviews") -> str:
    """Return the source-incident transport-failure branch."""
    return '''  if ! response="$(%s)"; then
    review_poll_failures=$((review_poll_failures + 1))
    if [ "$review_poll_failures" -ge "$max_poll_transport_failures" ]; then
      exit 1
    fi
    continue
  fi
  review_poll_failures=0''' % command


def _transport_case(historical: bool) -> tuple[str, str, str]:
    """Return setup, transport branch, and detector identity for one primary rule."""
    if historical:
        return (
            "review_poll_failures=0\nmax_poll_transport_failures=3",
            _historical_transport_branch(),
            _HISTORICAL,
        )
    return (
        "api_error_streak=0\ntransport_error_budget=4",
        _renamed_transport_branch(),
        _GENERIC,
    )


def test_mutable_retry_deadline_is_safe_with_independent_total_deadline(tmp_path: Path) -> None:
    """One mutable candidate cannot invalidate a separate monotonic wall-clock bound."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
retry_deadline=$(($(date +%s) + 30))
overall_deadline=$(($(date +%s) + 600))
while :; do
  retry_deadline=$(($(date +%s) + 30))
  if [ "$(date +%s)" -ge "$retry_deadline" ]; then
    exit 1
  fi
  if [ "$(date +%s)" -ge "$overall_deadline" ]; then
    exit 1
  fi
{_renamed_transport_branch()}
  sleep 30
done
"""
    assert _RESET not in _scan(tmp_path, shell)


@pytest.mark.parametrize(
    "declarations",
    [
        "overall_attempts=0\noverall_attempt_limit=12",
        "overall_attempt_limit=12\noverall_attempts=0",
    ],
)
def test_mutable_retry_counter_is_safe_with_independent_total_attempt_bound(
    tmp_path: Path, declarations: str
) -> None:
    """A separate monotonic total-attempt guard bounds the loop in either declaration order."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
retry_attempts=0
retry_limit=4
{declarations}
while :; do
  retry_attempts=0
  retry_attempts=$((retry_attempts + 1))
  if [ "$retry_attempts" -ge "$retry_limit" ]; then
    exit 1
  fi
  overall_attempts=$((overall_attempts + 1))
  if [ "$overall_attempts" -ge "$overall_attempt_limit" ]; then
    exit 1
  fi
{_renamed_transport_branch()}
  sleep 30
done
"""
    assert _RESET not in _scan(tmp_path, shell)


@pytest.mark.parametrize("termination", ["break", "exit 0"])
def test_state_reset_loop_with_unconditional_post_sleep_termination_is_finite(
    tmp_path: Path, termination: str
) -> None:
    """A direct successful termination before done removes the polling back edge."""
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
  {termination}
done
"""
    assert _RESET not in _scan(tmp_path, shell)


@pytest.mark.parametrize("historical", [False, True])
@pytest.mark.parametrize("termination", ["break", "exit 0"])
def test_primary_poll_with_unconditional_post_sleep_termination_is_finite(
    tmp_path: Path, historical: bool, termination: str
) -> None:
    """A direct termination after sleep still removes the primary polling back edge."""
    setup, branch, target = _transport_case(historical)
    shell = f"""
{setup}
while :; do
{branch}
  sleep 30
  {termination}
done
"""
    assert target not in _scan(tmp_path, shell)


@pytest.mark.parametrize("historical", [False, True])
@pytest.mark.parametrize("termination", ["break", "exit 0"])
def test_primary_poll_keeps_same_indent_conditional_post_sleep_termination_positive(
    tmp_path: Path, historical: bool, termination: str
) -> None:
    """A conditional termination after sleep does not remove the repeatable healthy path."""
    setup, branch, target = _transport_case(historical)
    shell = f"""
{setup}
while :; do
{branch}
  sleep 30
  if [ -n "$REVIEW_RESULT" ]; then
  {termination}
  fi
done
"""
    assert target in _scan(tmp_path, shell)


@pytest.mark.parametrize(
    "fake_command",
    [
        "echo 'gh api repos/example/repo/pulls/7/reviews'",
        "printf '%s\\n' 'gh api repos/example/repo/pulls/7/reviews'",
        "printf '%s\\n' '$(gh api repos/example/repo/pulls/7/reviews)'",
    ],
)
def test_quoted_command_substitution_is_not_executable_poll_evidence(
    tmp_path: Path, fake_command: str
) -> None:
    """Text produced by echo/printf must not impersonate an executable gh command token."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
while :; do
{_renamed_transport_branch(fake_command)}
  sleep 30
done
"""
    assert _FAMILY.isdisjoint(_scan(tmp_path, shell))


def test_unreachable_exit_requires_executable_poll_command(tmp_path: Path) -> None:
    """Quoted nested command text cannot witness an unreachable-bound polling defect."""
    shell = """
overall_deadline=$(($(date +%s) + 600))
while :; do
  if [ "$(date +%s)" -ge "$overall_deadline" ]; then
    continue
    exit 1
  fi
  if ! response="$(printf '%s\\n' '$(gh api repos/example/repo/pulls/7/reviews)')"; then
    continue
  fi
  sleep 30
done
"""
    assert _UNREACHABLE not in _scan(tmp_path, shell)


def test_unreachable_exit_keeps_direct_poll_command_positive(tmp_path: Path) -> None:
    """A directly executed gh api poll keeps the unreachable-exit finding positive."""
    shell = """
overall_deadline=$(($(date +%s) + 600))
while :; do
  if [ "$(date +%s)" -ge "$overall_deadline" ]; then
    continue
    exit 1
  fi
  if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
    continue
  fi
  sleep 30
done
"""
    assert _UNREACHABLE in _scan(tmp_path, shell)


@pytest.mark.parametrize("historical", [False, True])
def test_unconditional_break_is_not_made_conditional_by_unrelated_later_fi(
    tmp_path: Path, historical: bool
) -> None:
    """A later unrelated if/fi block cannot change ownership of an earlier direct break."""
    setup, branch, target = _transport_case(historical)
    shell = f"""
{setup}
while :; do
{branch}
  break
  if [ -n "$GITHUB_ACTIONS" ]; then
    echo done
  fi
  sleep 30
done
"""
    assert target not in _scan(tmp_path, shell)


def test_unused_historical_transport_budget_is_not_transport_bound_evidence(
    tmp_path: Path,
) -> None:
    """A named retry limit alone cannot fabricate the historical transport pattern."""
    shell = """
max_poll_transport_failures=3
while :; do
  if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
    continue
  fi
  sleep 30
done
"""
    assert _HISTORICAL not in _scan(tmp_path, shell)


def test_historical_transport_budget_requires_complete_counter_flow(tmp_path: Path) -> None:
    """The source-incident counter/limit flow remains positive after precision repair."""
    shell = f"""
review_poll_failures=0
max_poll_transport_failures=3
while :; do
{_historical_transport_branch()}
  sleep 30
done
"""
    assert _HISTORICAL in _scan(tmp_path, shell)


@pytest.mark.parametrize("historical", [False, True])
def test_primary_poll_accepts_strict_total_deadline_bound(
    tmp_path: Path, historical: bool
) -> None:
    """A strict clock-greater-than deadline is still a finite total poll bound."""
    setup, branch, target = _transport_case(historical)
    shell = f"""
{setup}
overall_deadline=$(($(date +%s) + 600))
while :; do
  if [ "$(date +%s)" -gt "$overall_deadline" ]; then
    exit 1
  fi
{branch}
  sleep 30
done
"""
    assert target not in _scan(tmp_path, shell)


@pytest.mark.parametrize("historical", [False, True])
@pytest.mark.parametrize(
    "declarations",
    [
        "overall_attempts=0\noverall_attempt_limit=12",
        "overall_attempt_limit=12\noverall_attempts=0",
    ],
)
def test_primary_poll_accepts_strict_total_attempt_bound(
    tmp_path: Path, historical: bool, declarations: str
) -> None:
    """A strict total-attempt comparison bounds either declaration order."""
    setup, branch, target = _transport_case(historical)
    shell = f"""
{setup}
{declarations}
while :; do
  overall_attempts=$((overall_attempts + 1))
  if [ "$overall_attempts" -gt "$overall_attempt_limit" ]; then
    exit 1
  fi
{branch}
  sleep 30
done
"""
    assert target not in _scan(tmp_path, shell)


@pytest.mark.parametrize("historical", [False, True])
def test_primary_poll_accepts_positive_constant_timeout_expression(
    tmp_path: Path, historical: bool
) -> None:
    """A statically positive Actions timeout expression bounds the owning job."""
    setup, branch, target = _transport_case(historical)
    shell = f"""
{setup}
while :; do
{branch}
  sleep 30
done
"""
    assert target not in _scan_with_timeout(tmp_path, shell, "${{ 20 }}")


def test_state_reset_accepts_positive_constant_timeout_expression(tmp_path: Path) -> None:
    """The mutable-state companion respects a static positive owning-job timeout."""
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
    assert _RESET not in _scan_with_timeout(tmp_path, shell, "${{ 20 }}")


def test_unreachable_exit_accepts_positive_constant_timeout_expression(tmp_path: Path) -> None:
    """The unreachable-exit companion respects a static positive owning-job timeout."""
    shell = """
overall_deadline=$(($(date +%s) + 600))
while :; do
  if [ "$(date +%s)" -ge "$overall_deadline" ]; then
    continue
    exit 1
  fi
  if ! response="$(gh api repos/example/repo/pulls/7/reviews)"; then
    continue
  fi
  sleep 30
done
"""
    assert _UNREACHABLE not in _scan_with_timeout(tmp_path, shell, "${{ 20 }}")


@pytest.mark.parametrize(
    "timeout",
    ["${{ 0 }}", "${{ -1 }}", "${{ inputs.timeout }}"],
)
def test_unproved_timeout_expression_does_not_suppress_poll_finding(
    tmp_path: Path, timeout: str
) -> None:
    """Zero, negative, or dynamic timeout expressions are not static safety evidence."""
    shell = f"""
api_error_streak=0
transport_error_budget=4
while :; do
{_renamed_transport_branch()}
  sleep 30
done
"""
    assert _GENERIC in _scan_with_timeout(tmp_path, shell, timeout)
