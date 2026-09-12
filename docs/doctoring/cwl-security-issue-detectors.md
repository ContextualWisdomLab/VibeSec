# CWL security-issue detector families

**Status:** Active mapping on this successor branch; not protected-`develop`
truth until merge. ADR-0007 remains Proposed.

## Decision

AppGuardrail turns frozen ContextualWisdomLab/appguardrail security issues into
executable SAST or DAST families. Detection truth is the scanner or classifier
over answer-free fixtures (ADR-0001), not the issue title. This successor maps
every frozen family. It implements only the unique families it owns.

## Families

| Family | Kind | Issues | Owner | This successor |
|---|---|---|---|---|
| Transport-only Actions polling | SAST | #1087, #938 | PR #1088 / issue #1087 | maps only |
| Secret indirection / auth comments | SAST | #1106 | this successor | implements regression lock on existing `_scan_file` rules, including LifeOS #247 test-title/authority wording |
| Claude plugin supply chain | SAST | #1099 | this successor | implements `claude-plugin-*` findings including unsigned executable downloads, unpinned package URL installs, GitHub write tokens, Docker socket binds, and secret-to-network flows, capability inventory evidence, undeclared-executable admission, a secret-free scan receipt, and fail-closed stale/mismatched receipt verification |
| Orphaned Actions workflows | DAST | #929 | PR #966 / issue #929 | maps only |
| Org CI failure without evidence | non-detectable | 353 tickets | inventory snapshot | maps only |
| UX / control-plane product gaps | non-detectable | #871, #928 | out of SAST/DAST scope | maps only |
| Imported Scorecard CII alert | non-detectable | #309 | no local source location | maps only |

## Standards

Uncontrolled CI wait is CWE-400 resource consumption (MITRE, n.d.-a). Hard-coded
credentials are CWE-798 (MITRE, n.d.-b). Unsigned installer execution is CWE-494
(MITRE, n.d.-c). Symlink follow during package admission is CWE-59 (MITRE,
n.d.-d). GitHub Actions workflow identities persist after file deletion
and must be disabled through the lifecycle API (GitHub, n.d.). Those last two
workflow families remain owned by PRs #1088 and #966.

## Executable evidence on this successor

- `tests/test_claude_plugin_supply_chain.py`
- `tests/test_password_indirection_precision.py`
- `tests/test_cwl_security_issue_inventory.py`
- `tests/fixtures/cwl-security-issue-inventory.json`

Poll-loop and orphan-workflow production detectors, tests, and changelog
fragments are not shipped here. Answer-free corpus files may still illustrate
mapped families without replacing the canonical writers.

## References

GitHub. (n.d.). *REST API endpoints for workflows*. GitHub Docs.
https://docs.github.com/en/rest/actions/workflows

MITRE. (n.d.-a). *CWE-400: Uncontrolled resource consumption*.
https://cwe.mitre.org/data/definitions/400.html

MITRE. (n.d.-b). *CWE-798: Use of hard-coded credentials*.
https://cwe.mitre.org/data/definitions/798.html

MITRE. (n.d.-c). *CWE-494: Download of code without integrity check*.
https://cwe.mitre.org/data/definitions/494.html

MITRE. (n.d.-d). *CWE-59: Improper link resolution before file access*.
https://cwe.mitre.org/data/definitions/59.html
