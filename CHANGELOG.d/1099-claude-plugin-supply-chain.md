### Security

- Scan Claude plugin marketplace/package manifests as hostile supply-chain
  artifacts: floating Git refs, provider API keys, `curl|sh` installers,
  undeclared hook/script surfaces, symlink escapes, duplicate JSON members,
  unbounded MCP servers, missing LICENSE evidence, concealed bidi/control
  identity, oversized package trees, and marketplace/artifact source mismatch. A deterministic scan
  receipt binds policy/artifact digests without echoing secrets; `pass` means
  the exact tree satisfied the exact AppGuardrail policy, not activation.
  `.claude-plugin/` is included in the scan walk.
