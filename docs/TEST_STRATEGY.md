# AppGuardrail Test and Detector Validation Strategy

**Status:** Accepted quality baseline  
**Last reviewed:** 2026-08-12

## Mandatory gates

- production statement coverage exactly 100%;
- production branch coverage exactly 100%;
- public module/API docstrings 100%;
- complete pytest/security/process suites;
- package/build/install smoke;
- current-head SAST/security/review/branch protection;
- detector-obligation tests independent of source-line coverage.

No skipped, cancelled, absent, stale, predecessor-head, synthetic-only, action-required, rate-limited, or failed required evidence is passing.

## Detector test contract

Every detector family must include:

1. realistic vulnerable positive fixture;
2. minimally fixed negative fixture;
3. near-miss benign negative fixture to control false positives;
4. malformed/unknown evidence classification where relevant;
5. stable rule/severity/location/evidence assertions;
6. remediation/verification contract;
7. engine/provenance assertion for external tools.

Fixtures must contain input evidence, not an expected-answer field consumed by the detector.

## Issue-to-detector validation

The issue/claim inventory must be independently generated or authenticated and then mapped to obligations. Tests verify every retained detectable claim maps to a detector family and that every obligation executes actual detector code. Duplicate historical incidents may share a detector family but cannot be silently dropped.

PR #911 is active-PR evidence; until merged, no-exclusions issue coverage is not a protected-branch claim.

## SSRF tests

Cover direct and stored variants:

- user-controlled URL sent immediately;
- user-controlled webhook/callback stored then executed;
- validated-before-store versus validated-before-send;
- loopback/private/link-local/metadata addresses;
- hostname resolving to disallowed IP;
- redirect to disallowed destination;
- allowed HTTPS public destination;
- malformed/ambiguous URL and encoded host/path forms;
- framework/library sink/source variants supported by the detector;
- control-plane write-path regressions integrated through PR #924;
- packaged `python-stored-ssrf-webhook-url` scanner regressions integrated through PR #910, including direct, subscript, attribute, one-hop, ignored-validator, conditional/non-enforcing guard, guarded-then-unguarded sink, and fail-closed cases.

A prevention test and a scanner-detection test are both required where AppGuardrail claims both controls. The current built-in rule's passing corpus proves its bounded Python `set_webhook` contract, not universal interprocedural SSRF coverage.

## External engine tests

Adapters distinguish tool unavailable, tool failed, clean, and findings. Normalize sample outputs without erasing engine/rule/version/source. Runtime target tests such as ZAP use explicitly authorized test hosts only.

## Control-plane tests

- role-scoped API keys and cross-tenant negative cases;
- bounded scan ingestion and schema validation;
- drift calculation across scans;
- webhook config URL validation and execution safety;
- API-key bootstrap/revocation/logging;
- idempotency/concurrency where endpoints can be retried;
- SQLite migration/upgrade/backup/recovery for changed persistent state.

## Remediation tests

Autofix tests prove preview/apply idempotence and semantics preservation for each supported transformation. Behavior-changing fixes remain guidance and are verified only after an independent source change plus rescan.

## Reporting/SBOM tests

Normalize deterministic finding envelopes, SARIF validity, buyer/founder/agency/fix-pack rendering, raw-secret omission, evidence warnings, remediation-handoff schema/version/digest validation, lockfile/version provenance, SBOM deterministic component identity, and organization bundle manifest integrity. The handoff module requires exact 100% statement and branch coverage for its focused tests.

## Performance

For optimizations distinguish operation-count complexity from wall-clock performance. Benchmarks include representative repositories/findings and must preserve identical detector output. A reduced loop count is not marketed as faster without measured time/resource evidence.

## Automation security tests

Verify immutable action refs, RCA-first feasibility, no provider/reviewer secrets in untrusted repo execution, exact-head classification, no false-green GitHub API failure, and separation of development from qualifying approval/merge/release.

## Release acceptance

A release requires one exact integrated protected head satisfying detector positive/negative obligations, tenant/network security, exact coverage, packaging/SBOM/provenance, migration/rollback where state changes, independent review, and post-publish smoke.
