# AppGuardrail

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/appguardrail)
[![Security Process](https://github.com/ContextualWisdomLab/appguardrail/actions/workflows/security-process.yml/badge.svg)](https://github.com/ContextualWisdomLab/appguardrail/actions/workflows/security-process.yml)

**Security guardrails for AI-built apps.**

AppGuardrail was formerly developed as VibeSec. The rename avoids the occupied third-party PyPI `vibesec` namespace.

AppGuardrail helps builders using Cursor, Claude Code, Lovable, Replit, Bolt, Supabase, Firebase, Vercel, and Netlify find and fix security issues introduced during AI-assisted development.

> **AI 생성 앱을 위한 보안 가드레일.**
> AppGuardrail은 Cursor, Claude Code, Lovable, Replit, Bolt, Supabase, Firebase, Vercel, Netlify로 만든 앱에서 자주 발생하는 보안 문제를 찾고 고칠 수 있게 돕습니다.

---

## What is AppGuardrail?

AppGuardrail is a **persistent security layer for AI-assisted builders** — not a one-time pentest, but a security co-pilot that stays with you through the entire lifecycle of your AI-built app: coding, deployment, operation, updates, and incident response.

> AppGuardrail = AI 앱 빌더의 미니 보안팀

---

## What AppGuardrail Provides

| Layer | Description |
|---|---|
| 🛡️ **AppGuardrail Rules** | Security rules for AI coding assistants (Cursor, Claude Code, Windsurf, Lovable) |
| 🔍 **AppGuardrail Scan** | Lightweight static analysis for secrets, auth gaps, misconfigurations, and packaged YAML regex rules |
| 👁️ **AppGuardrail Review** | Human-readable review templates and AI-powered audit prompts |
| 📡 **AppGuardrail Monitor** | GitHub Actions workflow installer for continuous AppGuardrail checks |
| 🔧 **AppGuardrail Fix** | AI-ready fix prompts + patch guidance + re-verification steps |

---

## Quick Start

### Run the CLI

Requires Python 3.11 or newer.

Install from PyPI:

```bash
python3 -m pip install appguardrail
appguardrail --help
```

Maintainers can prepare PyPI releases with GitHub Actions Bot and OpenCode
Agent. See [Release Automation](docs/release-automation.md).

For the productization roadmap, see the
[2B KRW sale readiness plan](docs/product/2026-07-02-2b-krw-sale-readiness-plan.md).

### Initialize security rules in your project

```bash
# Recommended: install guardrails for Codex, Copilot, Claude Code, Cursor, and Windsurf
appguardrail init

# Or install for one tool explicitly
appguardrail init --tool cursor
appguardrail init --tool claude-code
appguardrail init --tool codex
appguardrail init --tool copilot
appguardrail init --tool lovable

# For a Next.js + Supabase stack
appguardrail init --stack nextjs-supabase
```

This creates:
- `.cursor/rules/appguardrail.md`
- `.windsurf/rules/appguardrail.md`
- `CLAUDE.md`
- `AGENTS.md`
- `.github/copilot-instructions.md`
- `APPGUARDRAIL_CHECKLIST.md`

`appguardrail init --tool lovable` creates `LOVABLE_SECURITY_CHECKLIST.md`.

### Scan your codebase

```bash
appguardrail scan .

# Also run Trivy FS for dependency CVEs, secrets, and IaC misconfigurations
appguardrail scan --trivy .

# The scanner detects Python, Java, JavaScript, TypeScript, and web files
# automatically. If supported external SAST tools are installed and runnable,
# scan auto mode can include Bandit/Ruff/Semgrep without choosing a language profile.

# Run OWASP ZAP baseline only when you have an authorized running URL
APPGUARDRAIL_TARGET_URL=https://your-authorized-test-host.example appguardrail scan .

# If CodeGraph is installed, prepare structural context for deeper review
appguardrail scan --codegraph .

# Save normalized findings for report generation or dashboard ingestion
appguardrail scan --findings-json reports/findings.json .

# Emit SARIF 2.1.0 for GitHub code scanning, VS Code, and other tools
appguardrail scan --sarif appguardrail.sarif .
```

The SARIF output feeds GitHub code scanning
(`github/codeql-action/upload-sarif`), the VS Code SARIF viewer, and any other
SARIF consumer — findings appear in the GitHub **Security** tab and as inline PR
annotations, ranked by `security-severity`. `appguardrail monitor` installs a
workflow that emits and uploads SARIF automatically while preserving the deploy
gate. Set the `APPGUARDRAIL_CONTROL_PLANE_URL` and `APPGUARDRAIL_API_KEY`
repository secrets and that workflow also pushes every scan to your control
plane for history and drift tracking.

Detects:
- Hardcoded secrets (`SUPABASE_SERVICE_ROLE_KEY`, `STRIPE_SECRET_KEY`, etc.)
- Hardcoded provider API tokens by distinctive prefix: OpenAI/Anthropic (`sk-`, `sk-ant-`), AWS (`AKIA`/`ASIA`), GitHub (`ghp_`/`github_pat_`), Google (`AIza`), Slack (`xoxb-…` tokens and `hooks.slack.com` webhooks), Twilio (`AC…`/`SK…`), SendGrid (`SG.…`), npm (`npm_…`), and PyPI (`pypi-AgEIcHlwaS…`)
- Trivy-backed dependency vulnerabilities, secrets, and misconfigurations
- Bandit/Ruff/Semgrep/ZAP findings when their optional external engines are available
- Dangerous Supabase/Firebase usage patterns
- AWS CloudFormation template misconfigurations (public S3 ACLs, world-open
  security groups, `*:*` IAM policies, public/unencrypted databases, secret
  parameter defaults)
- API routes missing authentication
- Public Firebase rules (`read/write: true`)
- Dangerous CORS settings (`origin: "*"`)
- Missing Stripe webhook signature verification
- Unprotected admin routes
- Risky file upload handlers

The scanner loads built-in Python rules and supported `pattern-regex` entries
from `scanner/rules/*.yml`. Semgrep-style structural `pattern:` entries remain
documented rule fixtures until the lightweight engine grows structural matching.

Deploy-blocking counts focus on app code. Findings in docs, tests, examples,
and scanner fixtures stay visible but do not fail the deploy gate by default.

#### Tune the gate with `.appguardrail.json` (optional)

Commit a `.appguardrail.json` at the repo root to configure the deploy gate for
the whole team — no CLI flags needed:

```json
{
  "fail_on": "HIGH",
  "exclude_rules": ["some-noisy-rule-id"]
}
```

- `fail_on` — minimum severity that fails the gate (`CRITICAL`, `HIGH`,
  `WARNING`, or `INFO`). Default gate blocks `CRITICAL` and `HIGH`.
- `exclude_rules` — rule ids to drop from the gate (findings still show, but
  don't fail the build). An invalid config fails the scan loudly rather than
  silently passing.

### Auto-fix safe issues

```bash
# Preview safe, deterministic fixes (dry-run diff)
appguardrail fix .

# Apply them
appguardrail fix --apply .
```

`appguardrail fix` applies only **purely additive, semantics-preserving**
fixes — it will not silently rewrite behavior-changing code. The first
transform adds `rel="noopener noreferrer"` to external `target="_blank"` links
(reverse-tabnabbing). Behavior-changing fixes (moving a secret to an env var,
flipping TLS verification) stay as reviewable prompts — see
`appguardrail report fix-pack`. This closes the scan → fix → verify loop safely.

### Run the control-plane API (scan history)

```bash
# Provision an org + API key file (defaults to cp.db.api-key)
appguardrail serve --db cp.db --create-org "Acme" --api-key-file acme.api-key

# Run the API (bootstraps a default org + key on an empty DB)
appguardrail serve --db cp.db --port 8788
```

`appguardrail serve` turns AppGuardrail from a one-shot CLI into a persistent,
multi-tenant surface: CI pushes each scan and the org queries its history.
New bootstrap keys are written to a local key file instead of console logs.

```bash
# From CI, after `appguardrail scan --findings-json findings.json .`
curl -X POST http://localhost:8788/api/v1/scans \
  -H "Authorization: Bearer $APPGUARDRAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d @findings.json     # or {"repo":"...","commit":"...","findings":[...]}

curl http://localhost:8788/api/v1/scans -H "Authorization: Bearer $APPGUARDRAIL_API_KEY"
```

Push scans from CI with `appguardrail scan --push http://your-control-plane .`
(key from `APPGUARDRAIL_API_KEY`). The control plane computes **drift** — the
number of deploy-blocking findings newly introduced since the repo's previous
scan. Open the **org console** at `http://localhost:8788/` — a single static page that
connects with your API key and shows scan history, the deploy-blocking trend,
and per-scan detail.

Issue role-scoped API keys with `POST /api/v1/keys` (owner only): `viewer`
(read), `member` (ingest scans), or `owner` (full). The bootstrap key is an
owner.

Set a drift-alert webhook (`POST /api/v1/webhook` with `{"url":"…"}`) and the
control plane notifies it whenever a scan introduces new deploy-blocking
findings. If the URL is a Slack Incoming Webhook (`hooks.slack.com`), the alert
is automatically formatted as a Slack Block Kit message — a header with the new
blocker count plus the org, repo, scan id, and the top offending rule ids and
files — so Slack renders a readable card. Any other URL receives the generic
JSON payload unchanged.

Endpoints: `POST /api/v1/scans`, `GET /api/v1/scans`, `GET /api/v1/scans/{id}`,
`POST /api/v1/webhook`, `GET /api/v1/health`. Tenant-isolated by API key. Stdlib + SQLite (swap for a
managed database behind the same functions at scale).

### Generate a CycloneDX SBOM

```bash
# Inventory dependencies as a CycloneDX 1.5 SBOM
appguardrail sbom . --out sbom.json
```

Parses `package-lock.json`/`package.json`, `pnpm-lock.yaml`, `yarn.lock`,
`requirements.txt`, and `poetry.lock` into a CycloneDX software bill of
materials — the component inventory buyers and auditors expect for
supply-chain diligence. Versions are resolved from the lockfile when present,
otherwise taken from the manifest (recorded per component). No third-party
dependency.

### Generate reports from findings

```bash
appguardrail report buyer-diligence \
  --findings reports/findings.json \
  --assurance reports/scan-assurance.json \
  --out reports/buyer-diligence.md \
  --app-name "Demo SaaS" \
  --repository "ContextualWisdomLab/demo"

appguardrail report founder-friendly \
  --findings reports/findings.json \
  --out reports/founder-security-review.md \
  --app-name "Demo SaaS"

appguardrail report agency \
  --findings reports/findings.json \
  --out reports/agency-security-review.md \
  --app-name "Demo SaaS" \
  --client-name "Demo Client" \
  --reviewer "Demo Agency"

appguardrail report fix-pack \
  --findings reports/findings.json \
  --out reports/fix-pack.md \
  --based-on "pre-launch-review-001"
```

`appguardrail scan --findings-json` writes the normalized findings envelope that
the report command accepts. You can also pass a raw JSON array of findings or
any object with a `findings` array. Report types are:

- `buyer-diligence`: buyer-readable launch posture and evidence checklist.
- `founder-friendly`: plain-language summary for non-security founders.
- `agency`: client-ready technical review and retest notes.
- `fix-pack`: AI-ready remediation prompts and verification steps.

Reports omit raw secrets and expand normalized metadata into launch posture,
finding summaries, remediation, and verification checklists.
When `--assurance` is supplied, reports also carry the evaluator's
`clean`, `findings_present`, `incomplete`, `failed`, or `untrusted` outcome;
only `clean` may produce a qualified-clean launch status.

### View findings in a dashboard

```bash
# Generate findings, then open the local dashboard in your browser
appguardrail scan --findings-json reports/findings.json .
appguardrail dashboard
```

`appguardrail dashboard` serves a self-contained web dashboard that renders the
`appguardrail.findings.v1` file produced by `scan --findings-json`. It shows
severity counts, the deploy-blocking gate, findings by category, and a per-finding
detail view with the AppGuardrail Fix Format (Problem / Fix Prompt / Verification).

```bash
appguardrail dashboard --findings reports/findings.json  # custom findings path
appguardrail dashboard --port 8899                       # custom port
appguardrail dashboard --no-open                          # don't launch a browser
```

No build step or dependencies — the dashboard is a single static page shipped
with the package (`scanner/dashboard/index.html`), so it also works from a
`pip install`. You can open it manually and drag a `findings.json` onto it.

### Generate an organization buyer evidence bundle

```bash
appguardrail org-bundle
```

This writes `appguardrail-buyer-evidence/` with:

- `org-readiness.md`: buyer-readable organization readiness narrative.
- `buyer-evidence.json`: machine-readable KPI payload.
- `manifest.json`: source, timestamp, warning, repository, PR, and action bucket metadata.
- `README.md`: how to use the generated evidence packet.

Use `--owner`, `--bundle-dir`, `--repos-json`, or `--prs-json` only when you
need a non-default organization, custom artifact path, or offline snapshot.

### Install continuous monitoring

```bash
appguardrail monitor
```

This installs `.github/workflows/appguardrail-monitor.yml`, which runs
`appguardrail scan .` on pull requests, pushes to common default branches, and
manual workflow dispatches.

### Install the pre-commit hook

```bash
appguardrail hook

# Recommended when CodeGraph is available
appguardrail hook --codegraph
```

The CodeGraph mode initializes or syncs the local structural index before each
scan. This gives human reviewers and AI review agents better call-graph context
for authorization, webhook, secret-handling, and other security-sensitive flows.
The repository Security Process workflow also runs AppGuardrail with CodeGraph
enabled, so pull requests get the same structural security context in CI.

### Generate a security review prompt

```bash
appguardrail review --stack nextjs --db supabase --payments stripe
```

Outputs a prompt you can paste directly into Claude Code or Cursor.

---

## Repository Structure

```
appguardrail/
├── README.md
├── rules/                        # Security rules for AI coding tools
│   ├── cursor/
│   ├── claude-code/
│   ├── windsurf/
│   └── lovable/
├── checklists/                   # Stack-specific security checklists
│   ├── auth.md
│   ├── authorization.md
│   ├── supabase.md
│   ├── firebase.md
│   ├── stripe.md
│   ├── file-upload.md
│   ├── api-security.md
│   ├── secrets.md
│   └── deployment.md
├── prompts/                      # AI fix and review prompts
│   ├── secure-code-review.md
│   ├── fix-authz-bugs.md
│   ├── supabase-rls-review.md
│   ├── stripe-webhook-review.md
│   └── admin-route-review.md
├── scanner/                      # Lightweight static analysis engine
│   ├── rules/
│   │   ├── secrets.yml
│   │   ├── authz.yml
│   │   ├── supabase.yml
│   │   ├── firebase.yml
│   │   ├── nextjs.yml
│   │   └── stripe.yml
│   └── cli/
│       └── appguardrail.py
├── reports/                      # Report templates
│   └── templates/
│       ├── founder-friendly-report.md
│       ├── agency-report.md
│       └── fix-pack.md
├── examples/                     # Sample vulnerable and fixed apps
│   ├── vulnerable-vibe-app/
│   └── fixed-vibe-app/
└── docs/                         # Methodology and responsible testing
    ├── methodology.md
    ├── scope-and-authorization.md
    └── responsible-testing.md
```

---

## The AppGuardrail Fix Format

AppGuardrail doesn't hand you a traditional security report. Every finding comes with:

```
Problem:
  User A can access User B's project data by supplying B's project_id.

Risk:
  Customer data may be exposed across users.

Fix Prompt:
  "Update all project API routes to verify that the authenticated user's id
   matches project.owner_id before returning data. Return 403 when ownership
   does not match. Add tests for cross-user access."

Verification:
  Request User B's project_id using User A's token → expect HTTP 403.
```

---

## Why AppGuardrail is Different from Traditional SAST

Traditional scanners target classic vulnerabilities (SQLi, XSS). AI-coded apps fail differently:

| AI-coding failure mode | Example |
|---|---|
| Missing ownership check | Any user can read any record |
| Public storage bucket | Files accessible without auth |
| Exposed service role key | Full DB access from the browser |
| Supabase/Firebase rule mistake | RLS disabled or `allow read: if true` |
| Insecure webhook | No Stripe signature verification |
| AI-generated temporary code | `// TODO: add auth later` left in production |

---

## Services (Paid)

| Product | Description |
|---|---|
| **AppGuardrail Snapshot** | One-time security assessment of your current app |
| **AppGuardrail Review** | Code, config, and authorization structure review |
| **AppGuardrail Red Team Lite** | Defensive penetration test based on real user scenarios |
| **AppGuardrail Fix Pack** | Patches and prompts to fix discovered issues |
| **AppGuardrail Retainer** | Monthly security review of every change |
| **AppGuardrail Monitor** | Continuous automated monitoring on commits and pull requests |

---

## Contributing

This project is open-source and welcomes contributions of:
- New security rules for AI coding tools
- Stack-specific checklists
- Fix prompts for common vulnerability patterns
- Scanner detection rules

Please read [docs/responsible-testing.md](docs/responsible-testing.md) before contributing scanner rules.

---

## License

MIT — see [LICENSE](LICENSE)
