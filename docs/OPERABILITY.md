# AppGuardrail Operability, Recovery, and Release Guide

**Status:** Accepted operating baseline  
**Last reviewed:** 2026-08-09

## Operating model

AppGuardrail can run as a local/CI scanner, optional multi-tenant control plane, continuous GitHub monitor, and organization evidence aggregator. The product remains useful when optional external scanners or the control plane are absent; capability/unavailability must be explicit in evidence.

The remediation handoff is a local, bounded artifact operation. Build it from
normalized findings, keep the exact serialized bytes when transporting it, and
verify schema, size, and `bundle_sha256` before agent consumption. A successful
clipboard operation is not evidence of source authenticity, and a failed UI
copy must not silently discard the handoff.

## Scan health states

Distinguish:

- `completed_clean` — selected detector/toolset completed with zero findings;
- `completed_findings` — completed with findings;
- `inconclusive` — evidence malformed/insufficient for a detector obligation;
- `engine_unavailable` — selected optional tool absent/unusable;
- `engine_failed` — tool ran but analysis failed;
- `policy_blocked` — finding set violates deploy gate;
- `evidence_untrusted` — workflow/issue provenance cannot be authenticated.

Do not collapse non-completion into “clean.”

## Key SLIs

- scan completion/findings/blocker counts by engine/family;
- detector false-positive/false-negative benchmark where maintained;
- issue-obligation executable coverage after PR #911 integration;
- engine unavailable/failure rate;
- scan/control-plane latency and finding volume;
- new blocker drift count;
- webhook delivery success/SSRF-policy rejection;
- control-plane auth failures and cross-tenant-denial events;
- remediation/rescan closure rate;
- SBOM/evidence bundle provenance completeness;
- scheduler/API/reviewer infrastructure failures distinct from product findings.

## Failure recovery

### Scanner

Fix the first owning detector/adapter or input-classification boundary, add a regression, then rescan the exact target. Do not suppress a finding merely because a fix is inconvenient.

### External engine

Verify installation/version/config/authorization and distinguish provider/tool infrastructure from target vulnerability. One transient rerun may be appropriate after RCA; repeated retries are not a substitute for fixing deterministic failure.

### Control plane

Preserve scan/audit state, restore SQLite/managed database from verified backup when necessary, rotate/revoke compromised API keys, and revalidate tenant ownership before resuming writes. Schema changes require forward migration and rollback/recovery evidence.

### Webhook

On destination-policy failure, do not send. The current generic unauthenticated webhook path is **at-most-once per local scan event**: after destination validation it makes one best-effort POST and does not automatically retry a transport failure. Record only bounded non-secret delivery evidence; do not create an implicit retry loop that can duplicate receiver-side effects.

If retries are introduced later, they require a versioned delivery contract before enablement: a stable `delivery_id` persisted across attempts, receiver-side deduplication on that identifier, destination and redirect revalidation for every attempt, bounded response/error evidence, capped retry count/backoff, and explicit terminal failure state. Without those controls, retries remain prohibited rather than “best effort.”

For both the current one-shot send and any future retry, every send attempt and redirect hop must resolve and evaluate all destination addresses under the current policy. The connector rejects every private, loopback, link-local, metadata, unspecified, multicast, or reserved address and uses connection-time address pinning (or an equivalently strong connector) to prevent DNS rebinding between validation and connect. It retains the original hostname for TLS SNI and certificate verification, bounds redirects, and verifies that the connected peer address is one of the approved addresses before sending request bytes. Contract tests must exercise rebinding, mixed public/private answers, redirects to denied ranges, and peer-address mismatch; a stored `valid` flag or prior DNS result is never authorization for a later connection.

## Stored SSRF operation

Webhook destination validation must be revisited when DNS resolution/redirect conditions can change between storage and execution. A stored `valid` flag alone is not permanent authorization to access an arbitrary resolved network endpoint.

## Issue-to-detector audit operation

After PR #911 merges, run the executable audit from authenticated retained issue inventory and closed evidence corpus. Fail if a detectable obligation lacks a detector family or detector execution is inconclusive. Historical issue count alone is not a success metric; obligation execution and evidence provenance are.

## Upgrade and rollback

1. review CHANGELOG/ADR/detector changes;
2. run full detector/security/control-plane suite;
3. compare finding set on representative benchmark repositories;
4. rehearse persistent schema migration/rollback if changed;
5. canary continuous monitor/control plane where deployed;
6. retain previous package/image/db backup until new evidence is accepted;
7. rollback software/config on regression and re-run the benchmark scan.

## Release gate

Release only from exact protected head with all required CI/security/review, 100% production coverage/docs, detector-obligation evidence, package/SBOM/provenance, persistent-state migration/recovery, control-plane auth/network security, CHANGELOG/version, and post-publish smoke. A merged detector PR is not a release by itself.
