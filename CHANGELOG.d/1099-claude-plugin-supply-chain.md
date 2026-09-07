### Security

- Scan Claude plugin marketplace/package manifests as hostile supply-chain
  artifacts: floating Git refs, provider API keys, `curl|sh` installers,
  undeclared hook/script surfaces, symlink escapes, archive path traversal,
  nested gitmodules/gitlinks without a recursively admitted SHA, duplicate
  JSON members, unbounded MCP servers, missing LICENSE evidence, concealed
  bidi/control identity, oversized package trees, and marketplace/artifact
  source mismatch.
  A machine-readable capability inventory records filesystem, process, MCP,
  GitHub, deploy, and provider presence as evidence, not permission; the
  receipt binds `capability_inventory_sha256` over canonical JSON without
  secret literals. Undeclared executable surfaces that appear after manifest
  inventory fail admission. `pass` means the exact tree satisfied the exact
  AppGuardrail policy, not activation. `.claude-plugin/` is included in the
  scan walk.
