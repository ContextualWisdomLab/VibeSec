# Evidence-qualified clean scan assurance

- Add `appguardrail.scan-assurance.v1` outcome classification so zero findings alone cannot be reported as a clean scan.
- Verify the exact findings SHA-256, repository/commit trust anchors, detector and requested-engine completion, scope/gate accounting, execution state, and evidence freshness before returning `clean`.
- Expose the fail-closed standalone `python -m appguardrail_core.scan_assurance` interface for CI, control-plane, and modular integrations. This is a bounded slice of #927 and does not claim the full issue is complete.
