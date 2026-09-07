### Security

- Scan Claude plugin marketplace/package manifests as hostile supply-chain
  artifacts: floating Git refs, provider API keys, `curl|sh` installers, and
  undeclared hook/script surfaces. `.claude-plugin/` is included in the scan
  walk. Findings are policy evidence for admission, not activation.
