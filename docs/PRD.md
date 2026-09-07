# AppGuardrail Product Requirements Document

**Status:** Accepted cross-cutting product baseline for protected `develop` at `77e3e0c5867b1143970fcdce80962bda8a8fc80f`  
**Last reviewed:** 2026-08-12

## 1. Product purpose

AppGuardrail is a persistent security layer for AI-assisted application development. It combines installable security guardrails, deterministic/lightweight static detection, optional external SAST/runtime scanners, normalized findings/SARIF, fix/reverification workflows, continuous GitHub monitoring, multi-tenant scan history/drift, buyer/audit reports, SBOM generation, and organization-wide security-evidence aggregation.

The product goal is not merely to prevent one defect after a review. Security defect classes surfaced by AppGuardrail's own issue history should become durable, executable detection obligations whenever technically detectable from available evidence.

## 2. Current protected-branch capabilities

- CLI initialization/guardrail installation for AI coding tools and stacks;
- lightweight built-in Python/YAML-regex scanning plus optional Trivy/Bandit/Ruff/Semgrep/ZAP integration;
- bounded built-in detection of tested Python stored-webhook persistence patterns through `python-stored-ssrf-webhook-url`;
- normalized findings JSON and SARIF 2.1.0 output;
- deploy gate with severity/config exclusions;
- conservative deterministic autofix for semantics-preserving cases and reviewable fix prompts for behavior changes;
- static local dashboard;
- SQLite-backed multi-tenant control plane for scan ingestion/history/drift/API keys/webhook configuration;
- monitoring/pre-commit workflow installers;
- buyer/founder/agency/fix-pack reports;
- CycloneDX SBOM generation;
- organization buyer-evidence bundle;
- continuous security/process workflows and RCA-first autonomous development policy.

## 3. Current and active-PR product boundaries

- PR #924 is **implemented-main** prevention at the control-plane webhook write boundary: malformed bodies, non-string values, and unsafe destinations fail closed before persistence.
- PR #910 is **implemented-main** scanner detection for the separate stored-webhook coding pattern through the packaged `python-stored-ssrf-webhook-url` rule. Its supported scope is the tested Python `set_webhook` direct and one-hop flows, including conditional/non-enforcing guard regressions; it is not a claim of universal interprocedural SSRF detection.
- PR #911 proposes a no-exclusions registry mapping the repository's retained issue history to executable detector-family obligations and authenticated workflow-result evidence. It remains an active-PR product capability until merged and independently verified.
- Open UX/performance Jules PRs remain active-PR and must not be described as current release behavior before integration.

## 4. Primary users

- AI-assisted founder/developer needing fast, explainable security feedback.
- Agency/security reviewer needing repeatable client evidence and retest guidance.
- Platform/security engineer needing deploy gates, SARIF, SBOM, continuous monitoring, and drift history.
- Acquisition/buyer/security auditor needing machine-readable evidence and traceability.
- AppGuardrail maintainer needing every valid issue class to remain detectable rather than disappear into historical coordination metadata.

## 5. Core product invariants

1. A finding is produced by executable evidence logic, not by a registry row asserting that a condition exists.
2. Prevention/hardening and detection coverage are distinct; fixing one vulnerable endpoint does not satisfy scanner-detection obligations automatically.
3. Every supported detector has realistic positive, negative, and inconclusive evidence.
4. Inconclusive/malformed evidence fails closed and is not promoted to a clean result.
5. External scanner findings preserve engine/source provenance and are not silently relabelled as built-in AppGuardrail detections.
6. Issue/detection coverage may deduplicate repeated incidents into detector families, but retained issue identities/claims remain traceable without waiver-by-omission.
7. Secrets/raw sensitive payloads are not copied into normal findings, logs, reports, or dashboards.
8. Deploy-gate exclusions are explicit configuration and do not erase findings/evidence.
9. AI fix prompts are assistance, not proof; verification must rerun deterministic/security checks.
10. A `Clean Scan` state means completed evidence under the configured detector/toolset, not “no scanner ran” or “workflow failed.”
11. Tenant API keys authorize explicit roles; organization/repository strings are data, not authorization.
12. Webhook/egress destinations are validated at both storage and execution boundaries where applicable.
13. Autonomous development cannot manufacture its own review/merge/release acceptance.

## 6. Functional requirements

### PRD-FR-001 Detector engine

AppGuardrail SHALL support built-in deterministic detector families with stable rule identity, severity, evidence location, remediation, verification guidance, and machine-readable output. A structural `pattern:` fixture is not built-in execution: structural patterns that cannot be represented safely by the lightweight matcher remain external-engine or planned until a real structural engine exists; rule fixtures alone are not detection.

### PRD-FR-002 Issue-to-detection contract

Every retained repository issue/claim that represents a detectable application/security anti-pattern SHALL map to an executable detector obligation or a documented non-detectable/external-evidence category with explicit rationale. The audit must exercise actual detector code and independent inventory evidence rather than circular self-assertion.

### PRD-FR-003 SSRF detection

AppGuardrail SHALL distinguish direct SSRF, stored SSRF, unsafe webhook/callback URL persistence, DNS/IP allow/deny validation, redirect/rebinding risk, and execution-time egress controls where evidence supports those distinctions. A safe write-path implementation must have corresponding negative/positive scanner tests before the product claims the class is automatically detected.

### PRD-FR-004 Findings interoperability

Findings SHALL serialize to normalized JSON and SARIF with deterministic severity/rule/provenance/location data. Optional external engines retain their engine identity.

### PRD-FR-005 Safe remediation

Autofix SHALL be restricted to transformations proven semantics-preserving for the targeted rule. Behavior-changing fixes are reviewable prompts/patch guidance and require explicit verification.

### PRD-FR-006 Continuous monitoring

Installed GitHub workflows SHALL run AppGuardrail with pinned dependencies/actions, emit evidence, and never turn unavailable/failed required analysis into success. Monitoring remains usable without exposing provider/reviewer credentials to scanned repository code.

### PRD-FR-007 Control plane

The control plane SHALL provide tenant-isolated scan history, drift, scoped API keys, webhook notification, bounded payloads, and audit/recovery semantics. SQLite is acceptable for the current standalone profile; enterprise scale may use a managed database behind stable repository interfaces.

### PRD-FR-008 Evidence reporting

Buyer/agency/founder/fix-pack/org evidence SHALL be derived from normalized findings and current repository evidence, clearly separate verified facts from gaps/warnings, and omit raw secrets.

The Issue #928 handoff contract SHALL provide a bounded, deterministic,
machine-readable remediation artifact with schema/version and source-artifact
digest fields. It SHALL remain usable without the dashboard or control plane;
UI copy actions are consumers and SHALL NOT become the source of truth.

### PRD-FR-009 SBOM/supply chain

AppGuardrail SHALL produce deterministic component inventory with lockfile provenance where available and preserve tool/source/version evidence required for review or acquisition diligence.

## 7. Security/privacy requirements

- scan targets and their source may contain PII/secrets; minimize retention/disclosure rather than blindly copying findings/context;
- control-plane tenant/authz boundaries are explicit and testable;
- webhook URLs and outbound destinations are validated and constrained against SSRF/unsafe egress;
- scanner/external-tool execution is bounded and treats target repository content as untrusted data;
- GitHub Actions/review/model credentials remain outside untrusted target-code execution;
- reports never claim certification (CSAP/SOC 2) from code alone, but may collect control evidence.

## 8. Quality requirements

- production statement and branch coverage exactly 100%;
- public API/module docstrings sufficient for beginner-readable behavior;
- positive/negative/inconclusive tests for every detector obligation;
- realistic vulnerable/fixed fixtures and adversarial malformed evidence;
- exact-current-head CI/SAST/security/review evidence;
- benchmark claims require reproducible measurement; loop-count micro-optimizations must not be marketed as wall-clock gains without data.

## 9. Non-goals

- pretending every Semgrep-style fixture is executed by the lightweight regex engine;
- replacing specialist external SAST/DAST/dependency scanners where AppGuardrail has no equivalent implementation;
- automatically applying behavior-changing security fixes without review;
- treating no findings as proof of full security;
- using issue metadata alone as proof that a detector works;
- granting model/reviewer bots broad write authority to manufacture merge approval.

## 10. Release acceptance

A release requires one exact protected head with full detector/test coverage, control-plane/security regressions, exact CI/security/review, packaging/SBOM/provenance, migration/recovery evidence for changed persistent state, updated CHANGELOG/version/artifacts, and post-publish smoke. PR #910 scanner detection and PR #924 write-boundary prevention are current protected-branch controls; PR #911 claims become current only after protected-branch integration and fresh protected-head verification.

Issue #928's current branch slice implements only the standalone handoff
contract. Dashboard clipboard actions, fallback UI, announcements, and focus
behavior remain unimplemented until their design/Storybook gate is satisfied.
