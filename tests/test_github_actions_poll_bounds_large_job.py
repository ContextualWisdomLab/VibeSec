"""Large-job regression for the transport-only polling detector."""

from __future__ import annotations

from pathlib import Path

from scanner.cli.appguardrail import _scan_file


_RULE_ID = "github-actions-transport-only-poll-bound"


def test_late_same_job_timeout_still_bounds_poll(tmp_path: Path) -> None:
    """A valid timeout remains job-scoped even after more than 300 YAML lines."""
    filler = "    env:\n" + "".join(
        f"      LARGE_JOB_FILLER_{index}: value_{index}\n" for index in range(305)
    )
    workflow = f"""
name: Required review
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          max_poll_transport_failures=3
          while :; do
            reviews="$(gh api repos/example/repo/pulls/1/reviews)"
            [ -n "$reviews" ] && break
            sleep 30
          done
{filler}    timeout-minutes: 20
"""
    path = tmp_path / ".github" / "workflows" / "required-review.yml"
    path.parent.mkdir(parents=True)
    path.write_text(workflow, encoding="utf-8")

    findings = _scan_file(path, tmp_path)

    assert _RULE_ID not in [finding["rule_id"] for finding in findings]
