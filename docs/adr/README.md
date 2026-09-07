# AppGuardrail Architecture Decision Record Index

`Accepted` means the decision governs architecture; implementation maturity remains separate and is tracked in PRD/Traceability.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-executable-detector-truth.md) | Detection truth comes from executable evidence, not registry assertions | Accepted |
| [0002](0002-prevention-versus-detection.md) | Prevention/hardening and scanner detection are separate obligations | Accepted |
| [0003](0003-external-engine-provenance.md) | External scanner provenance remains explicit | Accepted |
| [0004](0004-tenant-network-boundaries.md) | Tenant authority and outbound destinations are explicit security boundaries | Accepted |
| [0005](0005-remediation-authority.md) | Deterministic autofix is limited to proven semantics-preserving transforms | Accepted |
| [0006](0006-automation-authority.md) | Autonomous development remains separate from independent merge/release authority | Accepted |
| [0008](0008-remediation-evidence-handoff.md) | Remediation handoff is bounded, redacted, deterministic, and digest-verified | Accepted for non-UI contract slice |

## ADR triggers

Create or update an ADR when changing detector truth semantics, issue obligation coverage, built-in versus external execution, autofix authority, persistent tenant schema/authz, outbound webhook/DAST egress, normalized finding/SARIF identity, evidence handoff/transport trust, or autonomous/release credentials.

Implementation PRs must reconcile PRD/TRD/Architecture/UML/ERD/Threat/Test/Operability/Traceability and CHANGELOG where those contracts move.
