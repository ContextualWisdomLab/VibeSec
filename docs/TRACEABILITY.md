# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-08-15

| Requirement / security class | Detector/control boundary | Evidence maturity |
|---|---|---|
| built-in deterministic scanning | `scanner.py`, rule adapters, normalized findings | implemented-main |
| optional Trivy/Bandit/Ruff/Semgrep/ZAP | external-engine adapters | implemented-main when tool present; capability explicit |
| JSON/SARIF findings | reporting serializers | implemented-main |
| deploy gate/exclusions | gate policy | implemented-main |
| safe deterministic autofix | fix engine | implemented-main for supported transforms only |
| multi-tenant scan/history/drift/API keys | control plane | implemented-main |
| webhook config/notification | control plane/network boundary | implemented-main; storage-boundary SSRF hardening integrated through PR #924 |
| buyer/founder/agency/fix-pack reports | report modules | implemented-main |
| CycloneDX SBOM | SBOM module | implemented-main |
| organization buyer evidence | org evidence aggregator | implemented-main |
| RCA-first feasibility scheduler | CI/agent policy | implemented-main |
| every retained issue claim mapped to executable detector obligation | issue-detection audit | PR #911 active-PR |
| authenticated workflow-result detector evidence | issue-detection audit workflow evidence | PR #911 active-PR |
| automatic scanner detection of unsafe stored-webhook SSRF pattern | built-in `python-stored-ssrf-webhook-url` rule | implemented-main through PR #910 for tested Python `set_webhook` direct and one-hop persistence flows; bounded scope |
| active GitHub Actions registry identity whose source is absent from one exact protected default-branch tree | `appguardrail_core.github_workflow_registry`, `tests/test_github_workflow_registry.py` | issue #929 active implementation; read-only detection/proposal only until protected merge and operator cleanup |
| structural Semgrep-style `pattern:` execution by lightweight engine | built-in scanner | not implemented unless a real structural matcher is added; fixtures are not execution |

## Promotion rules

- `implemented-main` requires source/tests on protected `develop`, not an issue/PR description.
- `active-PR` becomes current only after merge plus fresh protected-head required evidence.
- External-engine capability must name the engine and availability; normalization does not convert it into a built-in detector.
- A prevention/hardening change does not automatically promote the matching scanner-detection row; PR #924 and PR #910 were verified and promoted independently.
- An issue registry mapping cannot promote an obligation unless actual detector execution derives its result from independent/closed evidence.
- GitHub workflow-registry evidence becomes clean only when the complete live registry is bound to one exact non-truncated protected default-branch tree; missing, permission-limited, moved, malformed, or truncated source evidence stays unresolved.

## Issue #911 traceability contract

When PR #911 is accepted, the authoritative obligation system should preserve issue number/claim identity, detector family, evidence fixture/workflow provenance, execution result, and detector rule/finding evidence. Deduplicating equivalent incidents into one detector family is allowed; dropping a retained claim through an exclusion/waiver list is not.

## Issue #929 workflow-registry traceability contract

For retained GitHub Actions workflow identities, trace separately:

1. repository identity and current default branch;
2. protected default-branch commit SHA and exact recursive tree SHA;
3. completeness of the recursive tree (`truncated: false` required);
4. two matching complete paginated workflow snapshots, stable `total_count`, and unchanged case-insensitive repository/protected-branch identity after pagination;
5. exact case-sensitive workflow path membership in that tree for source-backed records, with validated GitHub-managed `dynamic/...` records classified separately;
6. registry state (`active`, disabled states, or explicitly unresolved future states);
7. workflow ID, path, state, verification timestamp, and read-only remediation;
8. trusted-operator workflow disablement and post-integration live inventory, which remain operational actions rather than scanner-side mutations.

A workflow name containing `once`, `apply`, `finalize`, `repair`, or similar text is supporting prioritization evidence only. It does not establish an orphan if the exact workflow source is present. Conversely, an active registry identity absent from the exact protected tree is an orphaned-deleted identity even when its name does not contain a temporary-writer hint. The detector never recreates or disables workflow files or registry identities itself.

## SSRF traceability contract

For stored webhook/callback SSRF, trace separately:

1. application prevention at configuration storage;
2. execution-time URL/DNS/IP/redirect/egress validation;
3. AppGuardrail scanner rule capable of finding missing prevention in target code;
4. positive vulnerable fixture;
5. fixed negative fixture;
6. control-plane self-regression;
7. exact-head security/review evidence.

Current protected-branch evidence keeps those controls distinct: PR #924 supplies the fail-closed webhook storage boundary, and PR #910 supplies the packaged `python-stored-ssrf-webhook-url` detector plus focused regression corpus. Neither control expands the detector beyond its declared source/sink and flow contract.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

The issue #929 workflow-registry boundary is driven by GitHub's official repository, Actions workflow, Git tree, API-versioning, and REST pagination contracts. Its focused doctoring document records the current primary-source URLs and APA 7 references; no CWE/OWASP mapping is asserted for this governance-inventory class.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
