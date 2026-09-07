# Remediation evidence handoff

The standalone contract is importable without dashboard or control-plane
dependencies:

```python
from appguardrail_core.evidence_handoff import (
    serialize_evidence_handoff,
    verify_evidence_handoff,
)

wire_bytes = serialize_evidence_handoff(
    findings,
    provenance={"repository": "OWNER/REPOSITORY", "commit": commit_sha},
    assurance=scan_assurance,
)
handoff = verify_evidence_handoff(wire_bytes)
```

The resulting `appguardrail.remediation-handoff.v1` artifact includes the
normalized finding remediation and verification fields, safe provenance
identifiers, optional assurance state, and a recomputable `bundle_sha256`.
Unknown or malformed optional identifiers are omitted. Raw source logs and
unbounded snippets are not part of the contract; obvious secrets are redacted
before serialization.

This is the transport contract only. The CSP-safe dashboard buttons,
clipboard rejection fallback, accessible announcements, and UI evidence
bundle export remain the next Issue #928 slice after the design/Storybook gate.
