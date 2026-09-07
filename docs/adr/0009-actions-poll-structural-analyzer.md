# ADR-0009: Structural GitHub Actions poll-bound analyzer

**Status:** Proposed  
**Date:** 2026-09-07

## Context

Issue #1087 records a verified control-plane defect: a GitHub Actions verdict poll whose retry budget counted only `gh api` transport failures. Healthy API responses with no verdict could sleep and repeat until a shared runner was retained. PR #1088 packages that pattern as regex detectors (`github-actions-transport-only-poll-bound` and `github-actions-transport-failure-budget-poll-bound`) with a reviewed adjacency-window grammar.

Those regex rules are migration oracles, not a claim of universal shell parsing. Helper loops, reversed comparisons, unreachable `exit`, quoted or comment text, and sibling-job timeouts are causal control-flow facts. Encoding each new shape as another regex family widens false-positive/false-negative risk and still cannot prove that initialization precedes the candidate loop.

G-06 therefore needs a bounded structural analyzer over conventional Actions jobs and literal `run: |` shell, without replacing or rewriting the packaged regex identities.

## Decision

Add `appguardrail_core.actions_poll_analyzer.classify_poll_loops` as an additive structural classifier:

- Parse only the conventional two-space workflow subset (`jobs.*.timeout-minutes` and `jobs.*.steps[*].run` block scalars). Do not add a YAML dependency.
- Classify infinite `while :` / `while true` loops that execute `gh api`.
- Treat a transport-failure counter as a budget, not a total bound.
- Accept a total bound only when deadline or attempt state is initialized before this loop, the comparison converges with forward `-gt`/`-ge` (or the swapped equivalent), and a nonzero `exit` is reachable on that path.
- Treat statically positive owning-job `timeout-minutes` literals and `${{ N }}` constant expressions as runner bounds. Zero, negative, empty, dynamic, and sibling-job values are not safety.
- Ignore quoted, commented, and heredoc text when recovering executable commands.
- Map unbounded historical `max_poll_transport_failures` loops onto `github-actions-transport-only-poll-bound` and renamed budgets onto `github-actions-transport-failure-budget-poll-bound` without changing regex IDs.

This slice does not hook `_scan_file`. The regex corpus remains the production scanner oracle until a later, separately reviewed emission path is proven not to double-count findings.

## Consequences

Positive:

- Causal poll-bound facts (init-before-loop, loop-local convergence, reachable fail-closed exit, owning-job timeout) are testable without a new regex family.
- Existing #1088 detector IDs and fixtures remain migration oracles.

Negative:

- Composite actions, generated workflows, cross-file state, noncanonical YAML, and unmodeled shell/fail-fast selection stay out of scope.
- Production scans still emit findings from the regex rules until an emission hook is reviewed.

## Alternatives

- **Keep expanding the regex grammar.** Rejected: adjacency windows cannot prove causal initialization or unreachable transfers, and each repair tends to create a new false-positive class.
- **Add PyYAML or a general shell parser.** Rejected for this slice: the packaged scanner has no YAML dependency, and a general parser would overclaim coverage of unreviewed shell.
- **Replace regex IDs immediately via `_scan_file`.** Rejected: a scanner hook can double-emit against the #1088 corpus. Analyzer-only classification preserves the regex owner and keeps this successor stacked.
