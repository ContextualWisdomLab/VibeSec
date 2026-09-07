# Python shell-call AST detector

**Status:** Active successor to PR #983; not protected-`develop` truth until integration.

## Decision

The built-in `python-command-injection` rule uses Python's abstract syntax tree
for the supported high-confidence source shapes instead of a multiline regular
expression. The detector resolves direct and aliased imports of `os` and
`subprocess`, tracks lexical shadowing, and records:

1. `os.system(...)` and `os.popen(...)`, which execute through a shell;
2. `subprocess.getoutput(...)` and `subprocess.getstatusoutput(...)`, which
   always execute through `/bin/sh`; and
3. `subprocess.Popen`, `run`, `call`, `check_call`, or `check_output` only when
   the parsed call contains literal `shell=True`.

The AST boundary removes regex parenthesis-depth limits and ignores matching
text inside comments and string literals. Production findings retain the
existing rule ID, CRITICAL severity, public taxonomy message, and buyer-facing
remediation contract.

## Scope and failure behavior

Malformed or non-text work-in-progress input produces no AST finding rather
than crashing the scan. Other applicable AppGuardrail regex rules continue to
run on the same file. Dynamic shell flags, `**kwargs`, helper-mediated aliases,
conditional control-flow joins, runtime monkey-patching, and cross-file binding
resolution remain outside this high-confidence slice; those cases require a
separately reviewed data-flow detector rather than speculative inference.

The scope engine supports module and direct-function aliases, nested functions,
function-local imports, function-local lexical shadowing, class/method closure
rules, lambda parameters, and comprehension-local targets. Reassigning an
imported name suppresses later findings for that name to avoid attributing a
shell API to an unrelated object.

## Executable evidence

- `tests/test_python_command_injection_ast.py` contains deep-nesting, module and
  function alias, nested-function, shadowing, comprehension, malformed-source,
  positive integration, and unrelated-regex coexistence contracts.
- `.github/workflows/python-shell-ast-coverage.yml` measures the dedicated
  production module at 100% statements and branches using hash-pinned
  Coverage.py 7.15.4.
- The complete repository Tests, Security Process, Security Scan, Semgrep, and
  central current-head review remain separate merge requirements.

## Remediation guidance

Avoid invoking a command interpreter where possible. Prefer argument arrays
with `shell=False`, validate and constrain externally influenced values, run
with least privilege, and isolate any unavoidable shell execution behind a
small reviewed adapter and realistic adversarial tests.

## Rollback

Do not restore the regex-only rule. A rollback must either remove the affected
source support or preserve alias resolution, arbitrary parsed nesting,
comment/string immunity, safe malformed-source handling, and the exact
coverage contract through an equally strong implementation.

## References

MITRE. (2026). *CWE-78: Improper neutralization of special elements used in an
OS command ('OS Command Injection')*. Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/78.html

OWASP Foundation. (n.d.). *OS command injection defense cheat sheet*. OWASP
Cheat Sheet Series. Retrieved August 20, 2026, from
https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

Python Software Foundation. (2026a). *ast—Abstract syntax trees: Python 3.14.3
documentation*. https://docs.python.org/3/library/ast.html

Python Software Foundation. (2026b). *os—Miscellaneous operating system
interfaces: Python 3.14.3 documentation*. https://docs.python.org/3/library/os.html

Python Software Foundation. (2026c). *subprocess—Subprocess management: Python
3.14.3 documentation*. https://docs.python.org/3/library/subprocess.html
