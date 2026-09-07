"""Emit structural poll-bound findings through production ``_scan_file``.

G-06 successor of the additive analyzer: regex adjacency still misses split
``while``/``do`` helper loops, unreachable fail-closed exits, and renamed
budgets with the same shape. Production scanning must surface those with the
existing detector identities and must not double-count the #1088 corpus.
"""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import (
    SCAN_RULES,
    _append_actions_poll_analyzer_findings,
    _poll_analyzer_location,
    _scan_file,
)


_HISTORICAL = "github-actions-transport-only-poll-bound"
_GENERIC = "github-actions-transport-failure-budget-poll-bound"
_POLL_IDS = {_HISTORICAL, _GENERIC}
_FIXTURES = Path(__file__).parent / "fixtures" / "security_corpus"


def _scan_workflow(
    tmp_path: Path, content: str, *, name: str = "required-review.yml"
) -> list[dict]:
    """Scan one GitHub Actions workflow through the production file scanner."""
    workflow = tmp_path / ".github" / "workflows" / name
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(content, encoding="utf-8")
    return _scan_file(workflow, tmp_path)


def _poll_ids(findings: list[dict]) -> list[str]:
    """Return the two poll-bound identities in scan order."""
    return [finding["rule_id"] for finding in findings if finding["rule_id"] in _POLL_IDS]


def _workflow(shell: str) -> str:
    """Wrap a literal shell block in conventional two-space Actions YAML."""
    body = "\n".join(
        f"          {line}" if line else "          "
        for line in shell.strip("\n").splitlines()
    )
    return (
        "name: Required review\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - name: Wait for current-head verdict\n"
        "        run: |\n"
        f"{body}\n"
    )


def _historical_transport_split_do(*, extra_before: str = "", extra_in_loop: str = "") -> str:
    """Return the historical transport budget with ``do`` on the following line.

    Packaged regex requires ``while :; do`` on one line, so this shape is an
    analyzer-only positive unless production ``_scan_file`` runs the classifier.
    """
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
while :
do{loop_extra}
  if ! reviews="$(timeout 30s gh api --paginate "repos/${{GITHUB_REPOSITORY}}/pulls/1/reviews?per_page=100")"; then
    review_poll_failures=$((review_poll_failures + 1))
    if [ "$review_poll_failures" -ge "$max_poll_transport_failures" ]; then
      exit 1
    fi
    sleep "$poll_interval_seconds"
    continue
  fi
  review_poll_failures=0
  [ -n "$verdict" ] && break
  sleep "$poll_interval_seconds"
done
"""


def _renamed_transport_split_do() -> str:
    """Return the identifier-agnostic transport budget with split ``do``."""
    return """
set -euo pipefail
api_error_streak=0
transport_error_budget=4
poll_interval_seconds=30
while :
do
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


def test_packaged_poll_identities_remain_the_only_two_rule_ids() -> None:
    """Emission must reuse the #1088 identities; it must not invent a third."""
    poll_rules = [rule for rule in SCAN_RULES if rule["id"] in _POLL_IDS]
    assert {rule["id"] for rule in poll_rules} == _POLL_IDS
    assert "github-actions-poll-structural-analyzer" not in {
        rule["id"] for rule in SCAN_RULES
    }


def test_historical_vulnerable_fixture_emits_the_rule_once(tmp_path: Path) -> None:
    """Regex plus analyzer must not double-count the pinned vulnerable oracle."""
    content = (
        _FIXTURES / "github_actions_transport_only_poll_vulnerable.yml"
    ).read_text(encoding="utf-8")

    findings = _scan_workflow(tmp_path, content)

    assert _poll_ids(findings).count(_HISTORICAL) == 1
    assert _GENERIC not in _poll_ids(findings)


def test_historical_fixed_fixture_stays_negative_for_both_identities(
    tmp_path: Path,
) -> None:
    """The protected wall-clock repair remains a negative oracle for both IDs."""
    content = (
        _FIXTURES / "github_actions_transport_only_poll_fixed.yml"
    ).read_text(encoding="utf-8")

    assert _poll_ids(_scan_workflow(tmp_path, content)) == []


def test_scan_file_emits_analyzer_only_helper_loop_with_split_do(
    tmp_path: Path,
) -> None:
    """A bounded helper loop cannot hide a later split-do transport-only poll."""
    shell = """
set -euo pipefail
review_poll_failures=0
max_poll_transport_failures=3
helper_deadline=$(( $(date -u +%s) + 30 ))
while :
do
  if [ "$(date -u +%s)" -ge "$helper_deadline" ]; then
    exit 1
  fi
  break
done
while :
do
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

    findings = _scan_workflow(tmp_path, _workflow(shell))

    assert _poll_ids(findings).count(_HISTORICAL) == 1
    assert _GENERIC not in _poll_ids(findings)


def test_scan_file_emits_renamed_budget_when_do_is_on_the_next_line(
    tmp_path: Path,
) -> None:
    """Identifier-agnostic transport budgets with split ``do`` stay detectable."""
    findings = _scan_workflow(tmp_path, _workflow(_renamed_transport_split_do()))

    assert _poll_ids(findings).count(_GENERIC) == 1
    assert _HISTORICAL not in _poll_ids(findings)


def test_scan_file_emits_reversed_clock_comparison_with_split_do(
    tmp_path: Path,
) -> None:
    """A ``-lt`` deadline comparison does not expire and must remain a finding."""
    shell = _historical_transport_split_do(
        extra_before="poll_deadline_epoch=$(( $(date -u +%s) + 10800 ))",
        extra_in_loop='  if [ "$(date -u +%s)" -lt "$poll_deadline_epoch" ]; then\n    exit 1\n  fi',
    )

    assert _poll_ids(_scan_workflow(tmp_path, _workflow(shell))).count(_HISTORICAL) == 1


def test_scan_file_emits_unreachable_exit_after_unconditional_break(
    tmp_path: Path,
) -> None:
    """Textual ``exit 1`` after ``break`` cannot donate loop-local safety."""
    shell = _historical_transport_split_do(
        extra_before="poll_deadline_epoch=$(( $(date -u +%s) + 10800 ))",
        extra_in_loop=(
            '  if [ "$(date -u +%s)" -ge "$poll_deadline_epoch" ]; then\n'
            "    break\n"
            "    exit 1\n"
            "  fi"
        ),
    )

    assert _poll_ids(_scan_workflow(tmp_path, _workflow(shell))).count(_HISTORICAL) == 1


def test_quoted_and_comment_poll_text_stays_negative(tmp_path: Path) -> None:
    """Quoted, commented, and heredoc poll tokens are not executable evidence."""
    shell = """
set -euo pipefail
# while :; do gh api repos/example/repo; exit 1; done
echo "while :; do gh api repos/example/repo/pulls/1/reviews; sleep 30; done"
printf '%s\\n' 'while true; do gh api; exit 1; done'
cat <<'EOF'
while :
do
  gh api repos/example/repo
  exit 1
done
EOF
"""

    assert _poll_ids(_scan_workflow(tmp_path, _workflow(shell))) == []


def test_quoted_decoy_does_not_hide_split_do_poll(tmp_path: Path) -> None:
    """Quoted command text next to a real split-do poll is not a suppressor."""
    shell = """
set -euo pipefail
review_poll_failures=0
max_poll_transport_failures=3
echo "while :; do gh api repos/example/repo/pulls/1/reviews; sleep 30; done"
while :
do
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

    assert _poll_ids(_scan_workflow(tmp_path, _workflow(shell))).count(_HISTORICAL) == 1


def test_non_workflow_yaml_does_not_emit_poll_identities(tmp_path: Path) -> None:
    """Analyzer emission stays scoped to GitHub Actions workflow paths."""
    target = tmp_path / "deploy.yml"
    target.write_text(_workflow(_historical_transport_split_do()), encoding="utf-8")

    assert _poll_ids(_scan_file(target, tmp_path)) == []


def test_yaml_extension_workflow_emits_analyzer_only_helper_loop(
    tmp_path: Path,
) -> None:
    """The ``*.yaml`` workflow glob must emit the same analyzer-only identity."""
    findings = _scan_workflow(
        tmp_path,
        _workflow(_historical_transport_split_do()),
        name="required-review.yaml",
    )

    assert _poll_ids(findings).count(_HISTORICAL) == 1


def test_workflow_without_poll_tokens_does_not_emit(tmp_path: Path) -> None:
    """A conventional workflow with no polling loop stays negative."""
    content = """name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: echo hi
"""

    assert _poll_ids(_scan_workflow(tmp_path, content)) == []


def test_poll_analyzer_location_uses_while_line_or_falls_back() -> None:
    """Analyzer-only findings point at the first while line when one exists."""
    assert _poll_analyzer_location("name: x\n") == (1, "")
    line, snippet = _poll_analyzer_location("name: x\n          while :\n")
    assert line == 2
    assert snippet.startswith("while")


def test_append_is_a_no_op_when_regex_already_reported_the_identity() -> None:
    """Direct merge keeps a pre-existing regex finding as the sole identity."""
    findings = [{"rule_id": _HISTORICAL}]
    _append_actions_poll_analyzer_findings(
        (
            _FIXTURES / "github_actions_transport_only_poll_vulnerable.yml"
        ).read_text(encoding="utf-8"),
        findings,
        ".github/workflows/required-review.yml",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("regex hit must not grow an analyzer duplicate")
        ),
    )

    assert findings == [{"rule_id": _HISTORICAL}]
