# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-09-07

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
| GitHub Actions transport-only polling bound | `github-actions-transport-only-poll-bound`, identifier-agnostic `github-actions-transport-failure-budget-poll-bound`, mutable-safety companion `github-actions-poll-bound-state-reset`, unreachable-exit companion `github-actions-poll-bound-unreachable-exit` | Issue #1087 / active PR #1088; verified causal owner wall-clock repair is protected `ContextualWisdomLab/.github@e29302c05eade7da7b0bdbb453e53980bc9d577b`; stronger event-driven runner-release owner work remains Proposed in `.github` PR #1706 |
| structural Semgrep-style `pattern:` execution by lightweight engine | built-in scanner | not implemented unless a real structural matcher is added; fixtures are not execution |

## Promotion rules

- `implemented-main` requires source/tests on protected `develop`, not an issue/PR description.
- `active-PR` becomes current only after merge plus fresh protected-head required evidence.
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

## GitHub Actions polling-bound traceability contract

Issue #1087 records a verified control-plane availability defect from `ContextualWisdomLab/.github`. At vulnerable protected predecessor `5c561a65cca3b925d533e4b40c5c3ac00f16524e`, the required OpenCode verdict step used a transport-failure counter around `gh api` calls but had no total bound for the path where every API call succeeded and no verdict appeared. Protected repair `e29302c05eade7da7b0bdbb453e53980bc9d577b` adds a 10,800-second wall-clock deadline checked on every loop iteration and fails closed when it expires. `.github` PR #1706 separately owns the stronger Proposed event-driven/one-shot runner-release architecture; its open writer branch and temporary source-fix machinery are not protected production evidence.

The AppGuardrail obligation is the reusable causal pattern, not the workflow, issue title, or historical shell identifier spelling. `github-actions-transport-only-poll-bound` now requires the historical `max_poll_transport_failures` budget to participate in the same executable transport-failure data flow: a zeroed failure counter is incremented on the failing `gh api` branch, compared with that positive budget, and reaches a nonzero threshold exit. A merely declared setting is not transport-bound evidence. Safety semantics remain identifier-agnostic: a deadline or total-attempt guard suppresses only when the exact captured state is initialized before that same loop and consumed by the same fail-closed in-loop guard. `github-actions-transport-failure-budget-poll-bound` closes the identifier-renaming false-negative boundary by capturing arbitrary shell identifiers when the same counter/limit/failure/increment/threshold/exit relationship is present while the healthy-transport/no-result path can still sleep and repeat. The companion excludes the historical `max_poll_transport_failures` form so one incident is not emitted twice.

Syntactically present safety state is not automatically a real bound. `github-actions-poll-bound-state-reset` retains HIGH evidence only for reviewed non-convergent mutations such as refreshing a deadline from the current clock, resetting a total-attempt counter, or growing a total limit alongside its counter. State mutations that tighten a deadline or otherwise move monotonically toward termination are safe lookalikes and must remain negative. `github-actions-poll-bound-unreachable-exit` separately preserves HIGH evidence when an apparent total deadline or total-attempt guard contains an unconditional `continue` before the nonzero fail-closed exit, so the textual exit is unreachable and cannot establish finiteness. Its reviewed positive path is confined to the same conventional literal-shell polling loop and does not fire when the owning job has a positive `timeout-minutes` or when the fail-closed exit is directly reachable.

The temporary `github-actions-poll-invalid-break-zero` companion is not retained. A current-head review established that GitHub's default Linux Actions shell is fail-fast Bash, so a shell-agnostic HIGH rule for `break 0` creates a blocker-class false positive: the invalid command can terminate the step instead of reaching the loop back edge. Explicit non-errexit invalid-break behavior is an unclaimed false-negative boundary until the detector models the selected Actions shell and fail-fast state. Removing an unsound detector is not evidence that the main #1087 control-flow family covers that shell-specific behavior.

The family is deliberately bounded to conventional two-space GitHub Actions job syntax and literal block shell steps. Evidence split across jobs, across run steps, or after the loop is negative; quoted `gh api`/`sleep` strings and shell comments are not executable evidence. Safety evidence is local to the same candidate job and loop: an explicit positive timeout on that job is a bound, including a statically positive integer literal or `${{ N }}` constant expression, and a loop deadline/attempt guard is a bound only when its state is initialized before the loop, remains convergent for the loop lifetime, is reachable on the relevant path, and the same state is consumed by an in-loop nonzero-exit guard. Forward shell `-gt` is finite just like `-ge`; reversed or non-expiring comparisons, and zero/negative/empty/dynamic timeout expressions, do not suppress findings. Uninitialized variables, state first assigned after the guard, and a fail-closed exit made unreachable by an earlier unconditional control transfer do not establish safety. A bounded helper loop cannot donate deadline/attempt evidence to a later vulnerable poll. A comparison that only logs without terminating is not a safety guard, and unrelated numeric variables are not a transport-failure budget unless the failure branch links the counter, limit, increment, threshold, and nonzero exit.

The large regular-expression rules use only cheap `while` / `sleep` prefilters. Executable command evidence remains governed by the detector grammar `gh[ \t]+api`, so repeated spaces or a tab between `gh` and `api` cannot disappear behind a literal `gh api` fast-path filter. Explicit bounded adjacency windows remain declared false-negative boundaries rather than implied structural coverage.

Regression evidence lives in the production `_scan_file` suites for poll bounds, renamed aliases, late initialization, current-review causal safety, mixed safety identifiers, command whitespace, mutable bound state, unreachable fail-closed exits, the causal historical-budget negative/positive pair introduced in `df4ff1c3f724764b1d047b2cb95ef491c096356c`, and the pinned answer-free source fixtures under `tests/fixtures/security_corpus/github_actions_transport_only_poll_{vulnerable,fixed}.yml`. Production repair `a467678c7e3b4bedca8092eec28072fdd0aae90a` enforces the historical budget data flow, and `5d87c36251391e5f0254eb915ca7f3068a22b21c` keeps sibling-job and post-loop-safety scope regressions positive under that causal contract. Exact-head workflow success remains a separate promotion requirement; queued or startup-failed runs are not source GREEN.

Current false-negative boundaries include cross-file/composite-action polling, non-shell control flow, dynamically generated workflows, quoted/nonstandard job-key syntax, noncanonical YAML indentation, declaration/control-flow or multiple-helper shapes outside the reviewed companion grammar, materially different loop/retry frameworks, shell-error behavior whose fail-fast state is not modeled, and relationships beyond bounded adjacency windows. Those limits constitute a concrete Gap for a future structural GitHub Actions + shell control-flow/state analyzer; PR #1088 does not claim that analyzer exists. The detector family remains active-PR evidence until its unchanged exact head passes required checks and ordinary protected integration; the already-protected `.github` wall-clock repair is prevention/control-plane evidence only and does not itself satisfy AppGuardrail scanner coverage.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
