# ADR-0008: Deterministic remediation evidence handoff

## Status

Accepted for the non-UI contract slice of Issue #928.

## Context

AppGuardrail findings already contain remediation and verification text, but a
developer or agent cannot safely transfer that material as a bounded,
machine-readable artifact. Clipboard/UI code must not become the source of
truth, and caller-provided assessment or digest fields must not be treated as
acquired evidence.

## Decision

`appguardrail_core.evidence_handoff` defines the standalone
`appguardrail.remediation-handoff.v1` envelope. It:

- normalizes findings through the existing report-safe findings contract;
- copies only remediation fields and bounded provenance identifiers;
- redacts obvious secrets through the existing IssueOps redaction helper;
- serializes with sorted keys, compact JSON, UTF-8, and a trailing newline;
- derives `bundle_sha256` from the exact payload without the digest field; and
- requires schema, version, shape, size, and digest verification before an
  agent consumes the artifact.

This contract is transport-neutral and can be consumed by standalone tools,
naruon, or contextual-orchestrator without importing dashboard code. It does
not claim cryptographic provenance for caller-supplied source evidence; source
authority remains the responsibility of the producing acquisition path.

## Consequences

The contract makes redaction, deterministic serialization, and tamper rejection
testable without a browser or external service. It does not yet implement the
Issue #928 dashboard actions, clipboard fallback, live-region announcements,
focus behavior, or a machine-readable UI export control. Those changes require
the current dashboard design decision, Figma File ID, and Storybook/design-token
evidence before implementation.

## Verification

`tests/test_evidence_handoff.py` covers hostile inert text, secret suppression,
provenance selection, deterministic bytes, schema/version rejection, digest
tampering, malformed wire input, and the 2 MiB bound. The module has exact
100% statement and branch coverage.

## References (APA 7th)

Bray, T. (2017). *The JavaScript Object Notation (JSON) data interchange format*
(RFC 8259). Internet Engineering Task Force. https://doi.org/10.17487/RFC8259

OWASP Foundation. (2025). *OWASP Application Security Verification Standard
(ASVS) 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/
