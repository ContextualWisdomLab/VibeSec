# AppGuardrail Technical Requirements Document

**Status:** Accepted cross-cutting technical baseline for protected `develop`  
**Last reviewed:** 2026-08-12

## 1. Technical objective

AppGuardrail is a modular security-analysis product with four separable planes:

```text
scan plane       built-in detectors + optional external engines
remediation      safe transforms + fix/verification guidance
control plane    tenant scan history, drift, API keys, webhooks
assurance plane  SARIF, reports, SBOM, issue/detection audit, CI/release evidence
```

Each plane must remain usable independently where practical and communicate through normalized typed findings/evidence rather than hidden shared state.

## 2. Built-in scanner architecture

The built-in scanner owns deterministic language/path discovery, Python detectors, supported YAML `pattern-regex` rules, finding normalization, gate classification, and configured exclusions. A rule file containing structural `pattern:` syntax is documentation/test data unless an executable structural matcher or external Semgrep integration actually evaluates it.

Detector contracts include:

- stable rule/family identifier;
- evidence fields and required/optional shape;
- finding severity/category/location;
- positive/negative/inconclusive semantics;
- remediation and verification guidance;
- external-engine provenance when not built in.

## 3. Issue-to-detector architecture

Issue history is an input to requirements traceability, not detector truth. An executable issue-detection audit should use an independent issue inventory and map issue/claim identity to detector family and obligation. It must then call the actual detector adapter over closed evidence fixtures or authenticated workflow evidence. Self-declared `state`, answer-bearing fixtures, or a registry-derived “live” inventory are circular and prohibited.

PR #911 implements this boundary on an active branch; it is not yet protected-develop behavior.

## 4. Workflow-result evidence

Operational/CI incident detector families require authenticated structured results rather than free-form log substring guesses. Evidence should bind exact repository, workflow/job identity, run/attempt, head SHA, conclusion/classification, payload digest, and producer capability/signature when the environment supports it. Unknown/malformed provenance returns inconclusive/fail-closed.

## 5. SSRF detector requirements

Scanner rules must distinguish at least:

```text
user-controlled URL/source
→ validation/canonicalization
→ persistence or immediate request
→ later webhook/callback execution
→ network/redirect/DNS resolution
```

Stored SSRF exists when unsafe user-controlled destination data crosses a durable boundary and is later executed. Detection should recognize validation-before-store, validation-before-send, private/link-local/loopback/metadata targets, redirect policy, scheme/port restrictions, hostname/IP resolution semantics, and framework-specific request sinks where feasible.

Prevention and scanner detection remain separate technical controls. PR #924 integrated the control plane's fail-closed webhook write boundary. PR #910 independently integrated the packaged `python-stored-ssrf-webhook-url` built-in rule and its focused direct, accessor, one-hop, ignored-validator, conditional/non-enforcing guard, guarded-then-unguarded sink, and fail-closed regression corpus. That implementation is bounded to its declared Python `set_webhook` contract and is not a universal interprocedural SSRF analyzer.

## 6. External engine adapters

Trivy/Bandit/Ruff/Semgrep/ZAP/CodeGraph integrations are optional and capability-detected. Adapter output is normalized without losing engine/rule/version/source provenance. Tool absence is distinguishable from a clean result. Authorized running URL is required for ZAP/runtime checks; AppGuardrail does not discover or attack arbitrary targets.

## 7. Gate semantics

Findings remain visible even when excluded from deploy blocking. Default blocking policy focuses on application production code while docs/tests/examples/fixtures remain evidence but do not fail the deploy gate unless configured. Invalid `.appguardrail.json` fails loudly.

`Clean Scan` requires successful completion of the selected detector/toolset; failure/unavailability cannot be rendered as clean merely because findings are absent.

## 8. Remediation architecture

Deterministic autofix is allowed only for transformations whose semantic preservation is covered by tests. Other changes produce reviewable structured guidance (`Problem`, `Fix Prompt`, `Verification`) and must rerun the detector after user/agent changes.

## 9. Control-plane architecture

Current standalone profile uses Python stdlib + SQLite behind repository functions. It provides organization/API-key roles, scan ingestion/history, deploy-blocking drift, webhook configuration/notification, health, and static dashboard/API use.

Persistent state must enforce organization ownership independent from request-provided repo/org strings. Key material is stored/returned only through intended bootstrap/key-management paths. Webhook destination validation occurs before persistence and again as appropriate before network execution.

## 10. Reporting/SBOM

Normalized findings are the source contract for reports/dashboard/control-plane ingestion. Reports and org evidence bundle separate verified counts, source warnings, and unavailable evidence. SBOM inventory records lock/manifests and component provenance according to supported formats; no invented version is accepted as a locked version.

The standalone remediation handoff reuses report-safe normalized findings,
IssueOps redaction, bounded provenance identifiers, and a deterministic compact
JSON envelope. Its schema/version and `bundle_sha256` are verified before an
agent consumes it; it is transport-neutral for standalone, naruon, and
contextual-orchestrator use. Caller-supplied provenance remains an assertion,
not cryptographic acquisition proof.

## 11. Security boundaries

- repository-under-scan is untrusted input;
- no raw secret should be emitted by a finding/report/log when a fingerprint/location suffices;
- external tool invocation and output are bounded;
- control-plane HTTP input is tenant-authenticated and size-bounded;
- outbound webhook/DAST targets are authorization/SSRF boundaries;
- GitHub/NVIDIA/reviewer credentials do not enter scanned repository-controlled execution;
- autonomous development uses RCA-first feasibility and independent merge/release authority.

## 12. Quality/evidence

Every detector family requires realistic positive/negative/unknown tests and exact production statement/branch coverage. Security detector coverage is measured by obligations, not just source line coverage. Performance changes require operation-count or wall-clock evidence matching the claim.

## 13. Change control

Changes to detector truth semantics, issue-coverage policy, external-engine provenance, autofix authority, tenant/authz, webhook/egress, persistent schemas, evidence/report formats, or automation credentials require an ADR and PRD/TRD/Architecture/UML/ERD/Threat/Test/Operability/Traceability reconciliation.
