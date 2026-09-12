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
  AppGuardrail policy, not activation. Retained receipts fail closed on a
  wrong artifact digest, wrong scanner policy digest, stale catalog, source,
  or marketplace identity, or replay against mutated bytes; verification is
  not Noema admission. Hardcoded GitHub PAT or app tokens, host Docker
  socket binds, and named secrets copied into curl/wget/fetch fail
  admission as policy findings; `gh issue create` and `docker push` stay
  inventory evidence. Secret references require a complete environment-variable
  name, so longer documentation variables do not collide with protected names.
  Unsigned `curl`/`wget` executable fetches and
  unpinned pip/npm/cargo URL installs fail admission; a `package.json`
  plus lockfile without a postinstall download stays `package_install`
  inventory. Plugin skill/agent surfaces reuse released #1036 rule
  identities (`skill-name-homoglyph-confusable`,
  `skill-manifest-prompt-injection-payload`,
  `skill-doc-exfiltration-endpoint-directive`,
  `skill-placeholder-template-unresolved`) on the admission receipt without
  copying those regular expressions. `.claude-plugin/` is included in the
  scan walk.
