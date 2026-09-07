# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-09-02

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
| empty-host URL-validator SSRF fail-open prevention | control-plane `_is_safe_url`; CLI helper is defense-in-depth only | integration evidence: PR #1068; maturity is resolved from protected `develop` source plus fresh protected-head evidence |
| automatic scanner detection of missing/empty-host DNS fail-open validators | built-in `python-ssrf-empty-host-fail-open` rule | integration evidence: PR #1068; historical vulnerable/fixed fixtures and production `_scan_file` regressions are required to remain with the implementation |
| structural Semgrep-style `pattern:` execution by lightweight engine | built-in scanner | not implemented unless a real structural matcher is added; fixtures are not execution |

## Promotion rules

- `implemented-main` requires source/tests on protected `develop`, not an issue/PR description.
- A PR reference records candidate/integration evidence only; `implemented-main` becomes current only after merge plus fresh protected-head required evidence.
- External-engine capability must name the engine and availability; normalization does not convert it into a built-in detector.
- A prevention/hardening change does not automatically promote the matching scanner-detection row; PR #924 and PR #910 were verified and promoted independently.
- An issue registry mapping cannot promote an obligation unless actual detector execution derives its result from independent/closed evidence.

## Issue #911 traceability contract

When PR #911 is accepted, the authoritative obligation system should preserve issue number/claim identity, detector family, evidence fixture/workflow provenance, execution result, and detector rule/finding evidence. Deduplicating equivalent incidents into one detector family is allowed; dropping a retained claim through an exclusion/waiver list is not.

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

## Empty-host validator SSRF traceability

PR #1068 is the integration record for the missing/empty-host DNS fail-open defect. Its open/merged lifecycle is intentionally not encoded as maturity here: current maturity is determined from the protected `develop` source and fresh evidence under the promotion rules above. The integration preserves two independent obligations:

- **Runtime prevention:** the causal control-plane validator rejects a missing/empty parsed hostname before DNS/IP resolution. The analogous CLI helper is defense-in-depth and is not evidence for push-delivery transport behavior.
- **Scanner detection:** `python-ssrf-empty-host-fail-open` detects the bounded source-derived flow from a direct `parsed.hostname` assignment or an explicit empty-string fallback through DNS resolution, a non-terminating `socket.gaierror` path, and successful return when no dominating missing/empty-host rejection exists.
- **Positive oracle:** `tests/fixtures/security_corpus/appguardrail_empty_host_ssrf_vulnerable.py` preserves the historical vulnerable flow.
- **Fixed oracle:** `tests/fixtures/security_corpus/appguardrail_empty_host_ssrf_fixed.py` preserves the unconditional empty-host rejection.
- **Production-path regressions:** `tests/test_ssrf_empty_host_validator_rule.py` and `tests/test_ssrf_empty_host_current_review_regressions.py` execute `_scan_file` and fix the reviewed FP/FN boundaries. Direct `parsed.hostname` and commented empty-string fallbacks remain detectable when they can fail open; a direct assignment with a dominating `None` rejection is negative. Nonempty fallbacks such as `hostname or "localhost"` are negative; parenthesized and `or`-joined unconditional empty-string guards are negative; `and`-conditional or nested guards remain positive; after `(hostname or "").lower()`, None-only guards remain positive. Harmless logging/comments/blank lines before a same-scope fail-closed empty-host return or raise remain negative. Common statically falsy guard returns—including `False`, `None`, zero-valued numerics, empty string/container literals, and their reviewed parenthesized forms—terminate the empty-host path, while compound expressions that can evaluate truthy remain positive. For `socket.gaierror`, direct and tuple exception handlers are covered: `pass`, logging-only, diagnostic assignment, ellipsis, parenthesized `True`, and reviewed nonzero-integer success are positive when control can reach success, while a same-handler fail-closed `return` or `raise` terminates that failure path even after diagnostic statements.

Do not infer `implemented-main` from predecessor checks, PR state, or fixture existence. Promotion requires the exact merged protected head to retain the detector, the prevention control, the regression corpus, and terminal-success required evidence.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
