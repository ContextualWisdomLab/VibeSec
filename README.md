# AppGuardrail

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/appguardrail)
[![Security Process](https://github.com/ContextualWisdomLab/appguardrail/actions/workflows/security-process.yml/badge.svg)](https://github.com/ContextualWisdomLab/appguardrail/actions/workflows/security-process.yml)

**Security guardrails for AI-built apps.**

AppGuardrail helps teams catch common security failures introduced during AI-assisted development, turn findings into reviewable fixes, and keep those checks running as the application changes.

It is designed for builders working with AI coding tools and modern application stacks—not as a replacement for application authorization, threat modeling, penetration testing, incident response, or production security ownership.

## Why AppGuardrail

AI-assisted development can ship useful software quickly, but it also makes it easy to repeat security mistakes at scale: missing ownership checks, exposed credentials, permissive CORS or storage rules, unsigned webhooks, unsafe file handling, and temporary code that quietly becomes production code.

AppGuardrail makes that work repeatable across five connected surfaces:

| Surface | What it does |
| --- | --- |
| **Rules** | Installs security guidance for supported AI coding assistants and project workflows. |
| **Scan** | Finds secrets, authorization gaps, risky configuration, packaged rule matches, and supported external-scanner findings. |
| **Review** | Produces human-readable security review guidance and AI-ready review prompts. |
| **Monitor** | Installs continuous GitHub Actions checks and emits normalized findings/SARIF. |
| **Fix** | Provides bounded remediation prompts, safe deterministic fixes, and re-verification steps. |

## Quick start

Requires Python 3.11 or newer.

```bash
python3 -m pip install appguardrail

# Add guardrails to the current project.
appguardrail init

# Scan the repository.
appguardrail scan .
```

Initialize one supported tool explicitly when you do not want the default set:

```bash
appguardrail init --tool cursor
appguardrail init --tool claude-code
appguardrail init --tool codex
appguardrail init --tool copilot
appguardrail init --tool lovable
```

Stack-aware initialization is also available:

```bash
appguardrail init --stack nextjs-supabase
```

## Scan, review, fix

Run the built-in scanner directly:

```bash
appguardrail scan .
```

Useful output and optional analysis paths include:

```bash
# Normalized findings for reports or dashboard ingestion.
appguardrail scan --findings-json reports/findings.json .

# SARIF 2.1.0 for GitHub code scanning and other SARIF consumers.
appguardrail scan --sarif appguardrail.sarif .

# Add Trivy when it is installed and you want dependency/IaC coverage.
appguardrail scan --trivy .

# Add structural context when CodeGraph is installed.
appguardrail scan --codegraph .
```

Supported external scanners are optional extensions. AppGuardrail's Python package currently declares no required runtime dependencies; external tools keep their own installation, execution, and license boundaries.

For an authorized running application, OWASP ZAP baseline can be invoked explicitly. Do not point active testing at a system you are not authorized to assess.

```bash
appguardrail scan --zap-baseline https://your-authorized-test-host.example .
```

### Fix safely

Preview deterministic fixes before changing source:

```bash
appguardrail fix .
```

Apply only the supported safe transforms:

```bash
appguardrail fix --apply .
```

AppGuardrail does not silently apply behavior-changing remediation. Changes that affect authentication, authorization, TLS, credentials, data access, or other security semantics stay reviewable and require explicit verification.

### Review and report

Generate a security-review prompt:

```bash
appguardrail review --stack nextjs --db supabase --payments stripe
```

Turn normalized findings into a bounded report:

```bash
appguardrail report founder-friendly \
  --findings reports/findings.json \
  --out reports/security-review.md \
  --app-name "Demo SaaS"
```

Additional report profiles include `buyer-diligence`, `agency`, and `fix-pack`. Reports are designed to omit raw secrets while retaining actionable finding, remediation, and verification evidence.

## Continuous security

Install the repository monitoring workflow:

```bash
appguardrail monitor
```

For local commit-time checks:

```bash
appguardrail hook
```

When CodeGraph is available:

```bash
appguardrail hook --codegraph
```

The monitor and hook paths keep security review close to the change that introduced it instead of treating security as a one-time release exercise.

## Findings dashboard

Create normalized findings and open the bundled dashboard:

```bash
appguardrail scan --findings-json reports/findings.json .
appguardrail dashboard
```

The dashboard shows severity, deploy-blocking state, categories, and per-finding remediation/verification detail. It is shipped as a self-contained static page with the package.

## Control-plane mode

Teams that need scan history can run the built-in control-plane surface:

```bash
appguardrail serve --db cp.db --create-org "Demo Organization" --api-key-file demo.api-key
appguardrail serve --db cp.db --port 8788
```

This mode provides tenant-scoped scan ingestion/history and bounded API-key roles. Newly generated bootstrap keys are written to a local key file instead of being printed to console output. Deployment identity, network exposure, database durability, backup/recovery, and secret management remain operator responsibilities; the local SQLite path is not itself a production-readiness claim.

See the canonical architecture, security, and operability documents for the authority boundary before exposing this surface outside a controlled environment.

## Supply-chain evidence

Generate a CycloneDX SBOM from supported project manifests and lockfiles:

```bash
appguardrail sbom . --out sbom.json
```

The resulting inventory is evidence about the scanned project. It does not relicense third-party components or by itself establish vulnerability-free, compliant, or production-ready status.

## Security model

AppGuardrail follows a fail-closed bias for security-sensitive boundaries and keeps prevention, detection, and remediation authority distinct.

- Findings are evidence to review; they are not proof that an application is secure.
- Optional external engines extend coverage but do not silently become required runtime dependencies.
- Deploy gates focus on application code by default while retaining non-blocking evidence from docs, tests, examples, and scanner fixtures.
- Invalid `.appguardrail.json` policy fails loudly rather than silently relaxing the gate.
- Active testing must stay within explicit authorization and scope.
- Security-sensitive fixes remain reviewable when a deterministic semantics-preserving transform is not possible.

For reporting vulnerabilities in AppGuardrail itself, follow [SECURITY.md](SECURITY.md).

## Configuration

A repository can commit `.appguardrail.json` to define the team-wide deploy threshold and bounded rule exclusions:

```json
{
  "fail_on": "HIGH",
  "exclude_rules": ["reviewed-rule-id"]
}
```

`fail_on` accepts `CRITICAL`, `HIGH`, `WARNING`, or `INFO`. Exclusions remove a rule from the deploy gate while leaving its findings visible for review.

## Architecture and documentation

AppGuardrail keeps detailed implementation, detector, evidence, and operating contracts outside the landing page so the README stays usable for builders and evaluators.

- [Documentation map](DOCUMENTATION.md)
- [Product requirements](docs/PRD.md)
- [Technical requirements](docs/TRD.md)
- [Architecture](ARCHITECTURE.md)
- [Architecture decisions](docs/adr/README.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Test strategy](docs/TEST_STRATEGY.md)
- [Operability](docs/OPERABILITY.md)
- [Traceability](docs/TRACEABILITY.md)
- [Responsible testing](docs/responsible-testing.md)
- [Release automation](docs/release-automation.md)
- [Public documentation landing](docs/index.md)

Package metadata currently classifies AppGuardrail as **Alpha**. Release, deployment, certification, customer, and commercial-readiness claims require their own current evidence; source documentation and passing development checks do not create those claims by themselves.

## Contributing

Contributions that improve security rules, stack-specific checks, remediation guidance, scanner detection, tests, or documentation are welcome. Read [docs/responsible-testing.md](docs/responsible-testing.md) before adding security tests or detector fixtures, and keep examples free of live credentials or unauthorized target data.

## License

AppGuardrail source is licensed under the [MIT License](LICENSE). Third-party tools, dependencies, services, rulesets, and referenced standards retain their own terms.
