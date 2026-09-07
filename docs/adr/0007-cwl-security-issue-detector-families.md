# ADR-0007: Map frozen CWL security issues to SAST/DAST families, not ticket count

**Status:** Proposed  
**Date:** 2026-09-07

## Context

ContextualWisdomLab/appguardrail accumulates OPEN security issues that mix
executable source defects, live GitHub registry drift, product UX gaps, and
hundreds of org-security-failure tickets that only record cancelled CI. Treating
each ticket as a unique detector would explode the rule surface and still miss
the causal pattern.

## Decision

Freeze OPEN security issues at the start of a coverage goal and cluster them
into detector families:

- Static source, workflow, manifest, and package-graph classes are SAST and run
  on `appguardrail scan` without a network target.
- Classes that are unobservable without an authorized live API or URL are DAST
  and require an explicit target (`--zap-baseline`, `APPGUARDRAIL_TARGET_URL`,
  or an explicit repository plus API base). The scanner never guesses a host
  from source.
- Tickets with no copied vulnerability evidence, and UX/control-plane product
  gaps, are documented `non-detectable` rather than invented findings.

A family is satisfied only when the shipped scanner or classifier produces the
finding from answer-free evidence (ADR-0001). Duplicate incidents share a
family. Mapping a family in inventory or doctoring does not transfer
implementation ownership.

Canonical writers remain:

- PR #1088 / issue #1087 owns transport-only GitHub Actions poll-bound
  detectors (YAML rules and current RED precision contracts), including the
  #938 vertical slice.
- PR #966 / issue #929 owns orphaned GitHub Actions workflow registry DAST.
- This successor implements Claude plugin supply-chain SAST (#1099) and the
  password-indirection precision regression lock (#1106). It maps #1087 and
  #929; it does not close or replace those owners.

This ADR stays Proposed until a protected merge. It is not Accepted on this
branch.

## Consequences

Coverage work is bounded by family count, not by the live issue queue. New
issues opened after the freeze are a later snapshot. Speed work may retarget
wall-clock of the same `appguardrail scan` command but must not regress these
families. A later PR must not claim `Closes` on an issue whose canonical writer
is a different open PR.
