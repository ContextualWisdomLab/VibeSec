# SAST/DAST Rule Research Notes

Date: 2026-06-30

Goal: add only direct, low-ambiguity code patterns from public SAST/DAST rule
families. Keep CVE/KEV/KNVD-style product advisories in Trivy/SCA scope unless
they imply a recurring code pattern.

User model: the default scanner must not ask beginners to choose a language
profile. AppGuardrail treats languages as independent axes discovered from the
files being scanned, then applies the union of relevant checks. Examples:

- Python + web: Python rules plus browser/HTTP/web-misconfiguration rules.
- Java only: generic built-in checks plus Semgrep/Trivy integration paths when
  available.
- Java + Node.js + TypeScript: Java, JavaScript, and TypeScript axes are merged;
  no special combo name or preset is required.

## Sources Reviewed

- Bandit plugin docs: request certificate validation disabled, Flask debug mode,
  and Jinja2 autoescape checks.
  - https://bandit.readthedocs.io/en/latest/plugins/b501_request_with_no_cert_validation.html
  - https://bandit.readthedocs.io/en/latest/plugins/b201_flask_debug_true.html
  - https://bandit.readthedocs.io/en/latest/plugins/b701_jinja2_autoescape_false.html
- Python standard library tempfile docs for `mktemp` deprecation guidance.
  - https://docs.python.org/3/library/tempfile.html#tempfile.mktemp
- CodeQL query help: JavaScript/TypeScript security queries around TLS,
  JWT/signature verification, XSS, and web misconfiguration.
  - https://codeql.github.com/codeql-query-help/javascript/js-disabling-certificate-validation/
  - https://codeql.github.com/codeql-query-help/javascript/js-jwt-missing-verification/
- CodeQL query help: Java unsafe hostname verification, disabled Spring CSRF
  protection, and unsafe deserialization.
  - https://codeql.github.com/codeql-query-help/java/java-unsafe-hostname-verification/
  - https://codeql.github.com/codeql-query-help/java/java-spring-disabled-csrf-protection/
  - https://codeql.github.com/codeql-query-help/java/java-unsafe-deserialization/
- Semgrep public rules: framework misuse patterns for Express, CORS, JWT, and
  response sinks.
  - https://github.com/semgrep/semgrep-rules
- OWASP ZAP passive alerts: CSP, clickjacking, CORS, anti-CSRF, and information
  disclosure classes that can be partially represented as static config checks.
  - https://www.zaproxy.org/docs/alerts/10038/
  - https://www.zaproxy.org/docs/alerts/10055/
- MITRE CWE: CWE-79, CWE-295, CWE-352, CWE-377, CWE-489, CWE-693, CWE-942,
  CWE-1021.
  - https://cwe.mitre.org/data/definitions/295.html
  - https://cwe.mitre.org/data/definitions/377.html
  - https://cwe.mitre.org/data/definitions/489.html
- CVE and CISA KEV catalogs: used as prioritization context, not as regex source.
  - https://www.cve.org/About/Overview
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Korean vulnerability feeds: no stable public KVE rule format was found; KNVD
  style advisory data maps better to dependency/product scanning than local regex.

## Promoted Rules

- `python-requests-verify-false`: Bandit B501/CWE-295-style disabled TLS cert
  validation.
- `python-tempfile-mktemp`: Python tempfile/CWE-377 predictable temp file creation.
- `python-flask-debug-true`: Bandit B201/CWE-489 active debug code.
- `python-jinja-autoescape-disabled`: Bandit B701/CWE-79 template XSS control off.
- `python-django-csrf-exempt`: CSRF protection bypass marker, CWE-352.
- `node-tls-validation-disabled`: CodeQL/Semgrep-style Node TLS validation off.
- `node-jwt-none-algorithm`: unsigned JWT algorithm allowance, CWE-347.
- `node-cors-wildcard-with-credentials`: ZAP/Semgrep CORS misconfiguration.
- `node-helmet-csp-disabled`: ZAP CSP class represented as explicit Helmet CSP off.
- `node-clickjacking-protection-disabled`: ZAP clickjacking class represented as
  explicit frame protection off.
- `express-reflected-input-send`: direct request-to-response sink without nearby
  encoding marker.
- `java-spring-csrf-disabled`: CodeQL CWE-352-style Spring CSRF disable marker.
- `java-hostname-verifier-allow-all`: CodeQL CWE-295-style allow-all
  HostnameVerifier marker.
- `java-cookie-secure-false`: explicit disabling of the HTTPS-only cookie
  transport control.
- `java-jwt-none-algorithm`: JWT none algorithm marker.
- `java-objectinputstream-deserialization`: direct Java native deserialization
  entry point, CWE-502.
- `claude-plugin-*`: CWE-494/CWE-798/CWE-829/CWE-250/CWE-200/CWE-451/CWE-693 plugin
  marketplace provenance, provider secrets, GitHub write tokens, Docker
  socket binds, secret-to-network flows, secret-to-prompt and secret-to-log
  copies, pipe-to-shell installers,
  unsigned executable downloads including package.json lifecycle scripts,
  unpinned package URL installs,
  undeclared executables, undeclared vendored or generated code scope,
  reused #1036 skill-supply-chain identities on
  plugin skill/agent/command surfaces, hide-actions / self-modify /
  goal-escalation instruction wording on those surfaces, and fail-closed
  replay of a stale or mismatched scan receipt.
- Mapped, not owned here: GitHub Actions transport-only poll loops (#1087,
  PR #1088) and orphaned workflow registry DAST (#929, PR #966).
- `tool-execute-parameters-passthrough`: Strix-observed dynamic tool execution
  endpoint pattern where request `parameters` are dispatched directly into a
  registry/handler without a nearby schema boundary. This is language-agnostic
  because the risky shape is the `/tools/{code}/execute` dispatch surface, not
  one framework.

## Integration Paths

- Built-in AppGuardrail rules remain the beginner-safe default and are selected
  by file extension.
- `--external auto` is the CLI default for real CLI invocations. It detects
  runnable Bandit/Ruff for Python, Semgrep for Python/Java/JavaScript/
  TypeScript/web files, and ZAP only when `APPGUARDRAIL_TARGET_URL` or
  `--zap-baseline` supplies an authorized target URL.
- External CLIs that are missing or broken are skipped in auto mode. Explicit
  force flags (`--bandit`, `--ruff`, `--semgrep`, `--zap-baseline`) fail loudly
  because the user has asked for that engine.
- ZAP is not guessed from source code. DAST requires an authorized running URL,
  so AppGuardrail only runs it when a target URL is present.

## Not Promoted

- CVE, KEV, and KNVD/KVE product identifiers: handled by Trivy/SCA because a CVE
  ID usually needs package/version or product fingerprinting, not a code regex.
- Missing security headers by absence: too noisy for a file-local scanner. Only
  explicit disabled controls are promoted.
- Broad weak hash use: `md5`/`sha1` often appears in checksums, fixtures, and
  cache keys. Promote later only with a security-context marker.
- Generic SSRF URL fetch from request input: useful, but too context-dependent
  without framework routing and allowlist analysis.
- Generic SQL/XSS/command injection families already covered by existing
  AppGuardrail rules or Trivy/CodeQL integration paths. Tool execution dispatch
  is promoted only for the specific endpoint-plus-parameters pattern above.
