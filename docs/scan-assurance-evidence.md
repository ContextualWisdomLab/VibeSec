# Evidence-qualified scan assurance

**Status:** active PR slice for issue #927; not protected-branch shipped truth until merged.

## Decision boundary

A scanner that reports zero findings is not automatically a clean scan. `appguardrail_core.scan_assurance` consumes the existing `appguardrail.findings.v1` artifact plus a separate `appguardrail.scan-evidence.v1` manifest and emits `appguardrail.scan-assurance.v1` with exactly one outcome code:

- `clean` — zero findings and every required trust/completeness/freshness condition is satisfied;
- `findings_present` — trusted, complete, fresh evidence contains one or more findings;
- `incomplete` — evidence is structurally trusted but detector, requested-engine, execution, or freshness obligations are incomplete;
- `failed` — the scan execution or a requested external engine failed;
- `untrusted` — identity, digest, schema, timestamp, count, or artifact shape cannot be trusted.

Unknown, malformed, stale, future-dated, oversized, mismatched, and missing evidence never degrades to `clean`.

## Standalone interface

The module is executable without changing the main scanner CLI, which is intentionally left untouched while another active PR owns that file:

```bash
python -m appguardrail_core.scan_assurance \
  --findings appguardrail-findings.json \
  --evidence appguardrail-scan-evidence.json \
  --out appguardrail-scan-assurance.json \
  --repository OWNER/REPOSITORY \
  --commit 0123456789abcdef0123456789abcdef01234567
```

Exit status is `0` only for `clean`, `1` for trusted `findings_present`, and `2` for `incomplete`, `failed`, `untrusted`, invalid, or unavailable evidence. This makes a shell gate fail closed without conflating a trusted finding-bearing scan with an evidence failure.

## Evidence contract

The evidence producer supplies:

- exact repository and 40-character commit identity;
- generation time and AppGuardrail/scanner version;
- configured and completed built-in detector families;
- requested external engines and each engine state (`completed`, `unavailable`, `failed`, or `not_requested`);
- scanned file count, path roots, detected language axes, and explicit exclusions;
- configured blocking threshold plus blocker/non-blocker counts;
- SHA-256 of the exact findings JSON bytes;
- scan execution state (`completed`, `failed`, or `incomplete`).

The evaluator independently recomputes the findings SHA-256, checks exact caller-supplied repository/commit trust anchors, checks gate counts against the findings length, enforces a caller-selected freshness bound, and validates the manifest shape before classifying the outcome. Each input artifact is bounded to 2 MiB before JSON evaluation.

## Trust boundary and limitations

This slice verifies artifact integrity and self-consistency; it does **not** yet make the evidence producer cryptographically authoritative. A trusted CI or scanner integration must construct `appguardrail.scan-evidence.v1` from scanner-owned counters and exact checkout identity rather than from user-editable form fields. A malicious producer that controls both the evidence manifest and the caller's expected repository/commit trust anchors remains outside this slice's trust boundary.

The digest is a direct byte-level binding to the findings artifact, not a SLSA provenance attestation. The contract is compatible with a later signed-attestation layer but does not claim a SLSA level, certification, or provenance signature. SLSA 1.2 explicitly treats provenance verification and subject matching as separate trust work; this slice implements only the local artifact/identity qualification needed before AppGuardrail can label a result `clean`. SARIF parity and dashboard rendering remain separate parts of #927 and must not be inferred from this module.

## Verification

`tests/test_scan_assurance.py` exercises the public API and command contract with clean, finding-bearing, incomplete, failed, stale, future-dated, wrong-repository, wrong-commit, digest-mismatch, malformed, oversized, missing-file, and invalid-shape fixtures. `tests/test_scan_assurance_module_entrypoint.py` executes the shipped module as `__main__` against real temporary findings/evidence files so packaging-only code remains observable. The dedicated `Scan assurance coverage` workflow runs these tests with Coverage.py branch measurement and fails below exact 100% statement or branch coverage for `appguardrail_core/scan_assurance.py`; the suite also asserts that every production function has a readable docstring.

## References (APA 7th)

Bray, T. (2017). *The JavaScript Object Notation (JSON) data interchange format* (RFC 8259). Internet Engineering Task Force. https://doi.org/10.17487/RFC8259

OASIS Open. (2023). *Static Analysis Results Interchange Format (SARIF) Version 2.1.0 Plus Errata 01*. OASIS Standard. https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Supply-chain Levels for Software Artifacts. (n.d.). *SLSA specification (Version 1.2).* Retrieved August 16, 2026, from https://slsa.dev/spec/v1.2/
