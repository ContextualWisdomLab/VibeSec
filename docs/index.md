# AppGuardrail

AppGuardrail is a security guardrail for AI-built applications. It helps teams catch common security problems during AI-assisted coding, deployment, operation, updates, and incident response instead of treating security as a one-time review.

[Ask DeepWiki](https://deepwiki.com/ContextualWisdomLab/appguardrail) · [Repository](https://github.com/ContextualWisdomLab/appguardrail) · [Releases](https://github.com/ContextualWisdomLab/appguardrail/releases)

## Start here

```bash
python3 -m pip install appguardrail
appguardrail init
appguardrail scan .
```

The repository README contains the complete quick-start, supported tooling, optional scanners, reporting formats, and deployment-gate behavior.

## Product surface

AppGuardrail combines five complementary layers:

- **Rules** for AI coding assistants and project guardrails.
- **Scan** for lightweight static checks, secrets, authentication gaps, configuration risks, and supported external scanners.
- **Review** for human-readable audit guidance and AI-assisted review prompts.
- **Monitor** for continuous GitHub Actions checks and normalized findings.
- **Fix** for remediation prompts, patch guidance, and re-verification.

The CLI can emit normalized findings and SARIF for GitHub code scanning and other compatible consumers. Optional integrations extend coverage without changing AppGuardrail's core role as a developer-facing security control layer.

## Documentation

- [README and quick start](https://github.com/ContextualWisdomLab/appguardrail#quick-start)
- [Release automation](release-automation.md)
- [Security policy](https://github.com/ContextualWisdomLab/appguardrail/blob/develop/SECURITY.md)
- [Contributing](https://github.com/ContextualWisdomLab/appguardrail#contributing)

Product plans, threat-model material, detector doctoring, operational guidance, and evidence stay versioned with the source so security claims can be reviewed alongside implementation changes.

## Scope boundary

AppGuardrail is not a substitute for authorization, threat modeling, dependency hygiene, runtime observability, penetration testing, or incident response. It provides repeatable guardrails and evidence that help teams find and remediate security risks earlier and more consistently.

## Releases

Published releases are the versioned delivery record. See the repository's [Releases](https://github.com/ContextualWisdomLab/appguardrail/releases) page for current release artifacts and notes.
