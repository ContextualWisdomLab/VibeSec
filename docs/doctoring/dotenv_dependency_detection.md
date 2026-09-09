# Dotenv dependency detection for the Keyverse migration

Date: 2026-09-09. Status: proposed declarative detector; not organization-wide
enforcement or proof of credential migration.

## Responsibility and implementation decision

Central migration: ContextualWisdomLab/.github#2063.
Keyverse owner repair: ContextualWisdomLab/keyverse#151, stacked on #129.

Keyverse owns credential lifecycle and workload resolution; AppGuardrail owns
source-pattern detection. This change adds YAML regex rules to the existing
packaged engine rather than copying scanners into consumers or `.github`.
It adds no new Python runtime or alternative vault. New security-runtime
capabilities remain subject to the organization Rust policy.

The exact engine read was `e71d37e7c58118e6764c96ab7c4492fe33eed6f8`:
`scanner/cli/appguardrail.py` parses supported `pattern-regex` entries,
compiles them and loads `scanner/rules/*.yml`. A Semgrep structural `pattern:`
file alone would not execute in this built-in path, so it was not used.

## Detected syntax

Six IDs cover direct Python load_dotenv/dotenv_values calls, simple Pydantic
`env_file` assignments, direct Rust dotenv/dotenvy calls, direct Node dotenv
loading, shell source/dot of `.env`, and literal Compose/container dotenv-file
transport. Single and double quotes, home/relative paths, common one-line
settings and simple multiline Compose lists are included in the test corpus.

The rules do not read a referenced dotenv file. They detect code syntax, not
secret values. Ordinary imports, comments in the tested forms, disabling dotenv,
`env_file=None`, non-dotenv configuration and `/dev/null` are negative controls.
Transitive lockfile dependencies and the mere existence of an example are not
claims that a runtime loader executed.

## Interpretation and limits

WARNING is intentional: use of dotenv by arbitrary AppGuardrail users is not
proof of an exploitable vulnerability. CWL's central migration gate must adopt
these IDs explicitly for new production regressions while tracking existing
legacy findings to their owner. This PR does not turn all warnings into errors,
change deployment protections or break unrelated standalone consumers.

The matcher is lexical and bounded, not an AST/alias/taint engine. Dynamic file
variables, wrapper functions, unusual inline control flow, long/multiline calls,
Docker implicit `.env` interpolation, Java/Go/C# sources, framework-native
implicit loading, complex YAML anchors/lists and strings containing code may
need separate evidence or structural detectors. Absence of a finding is not
proof that a repository does not depend on dotenv or that it uses Keyverse.

Organization inventory must project only rule ID, repository, exact revision,
path, line and reviewed disposition. Do not export generic scanner source
snippets or raw settings as migration evidence; the surrounding code could
contain confidential data. Preserve all unreadable/unscanned repositories in
the denominator. Do not run credential-bearing application source just to scan
it, and do not follow a matched dotenv locator.

## Verification and remaining gates

An initial local run failed all 43 syntax/contract tests with the rules absent.
After the YAML was added, 43 passed using the retrieved production parser and
compiler logic in a local excerpt harness. The harness is not committed: the
repository test imports the real owner engine. This is not a complete scanner
checkout and does not establish end-to-end packaging or full coverage.

Six additional integration cases require actual SCAN_RULES discovery and
`_scan_file` execution in the complete repository. They have been added but
have not been executed in the local excerpt environment. Full repository CI,
coverage/docstrings, packaging, security checks and independent review must
pass before merge/release. This PR adds no workflow copies or model credentials.

Reproduction in the complete repository:

```sh
python -m pytest -q tests/test_dotenv_dependency_rules.py tests/test_dotenv_scanner_integration.py
```

## Primary references — APA 7th

OWASP Foundation. (n.d.). *Secrets management cheat sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

GitHub. (n.d.). *OpenID Connect reference*. https://docs.github.com/en/actions/reference/security/oidc

The former motivates explicit custody/lifecycle rather than simply renaming
configuration transport. The latter informs the owner workload-authentication
contract, not this source-pattern detector. Neither is a claim of certification.
