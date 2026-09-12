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
  unpinned pip/npm/cargo URL installs fail admission; `package.json`
  `preinstall`/`install`/`postinstall` scripts that download or execute
  an unsigned payload fail closed on the same rules, while a lockfile-only
  tree without those downloads stays `package_install` inventory. Plugin skill/agent surfaces reuse released #1036 rule
  identities (`skill-name-homoglyph-confusable`,
  `skill-manifest-prompt-injection-payload`,
  `skill-doc-exfiltration-endpoint-directive`,
  `skill-placeholder-template-unresolved`) on the admission receipt without
  copying those regular expressions. `appguardrail scan-plugin
  --plugin-root <path> [--marketplace-entry <path>] [--receipt-json <path>]`
  scans a materialized plugin tree, emits that same receipt JSON, and exits
  nonzero unless `scan_result` is pass. An external marketplace catalog
  binds `catalog_repository`, `catalog_commit_sha`, and
  `marketplace_blob_sha`; a floating catalog commit or a catalog plugin
  identity that disagrees with the retrieved artifact fails closed.
  Receipt `sarif_sha256` is the SHA-256 of a deterministic SARIF 2.1.0
  document covering the same finding rule_ids as `finding_summary`.
  LICENSE/NOTICE absence still fails closed; conflicting SPDX identifiers
  across the declared license field, LICENSE, and NOTICE fail as
  `claude-plugin-license-mismatch` without inventing legal approval.
  Hook `eval`/`exec`/`compile`/`Function` and shell `eval` fail as
  `claude-plugin-dynamic-eval`. Hidden undeclared executable or config
  surfaces (``.bin/run.sh``, ``.hooks/secret.py``) fail as
  `claude-plugin-hidden-undeclared-executable`. `.git/` metadata,
  `.gitignore`, LICENSE, declared `hooks/pre.sh`, and `.mcp.json` are
  not that class. `.claude-plugin/` is included in the scan walk.
  Host Chrome, Chromium, and Firefox profile stores on hook or manifest
  surfaces fail as `claude-plugin-browser-profile-access`. A README path
  mention and a bare ``Firefox`` product name stay inventory, not that
  class. Docker sockets stay `claude-plugin-docker-socket`.
  Plugin, skill, or command descriptions that claim innocuous, read-only,
  or local-only behavior while the capability inventory shows write,
  network egress, GitHub write, credential access, remote MCP, or shell
  execution that the description denies fail as
  `claude-plugin-deceptive-description`. An honest network mention, an
  empty description, and a matching local echo helper are not that class.
  Inventory remains evidence, not permission.
  Manifest ``NaN``, ``Infinity``, and ``-Infinity`` fail as
  `claude-plugin-nonstandard-json-constant`. Duplicate object members stay
  `claude-plugin-duplicate-json-member`. A finite JSON number is not that
  class. Marketplace, plugin, and MCP JSON bytes that are not valid UTF-8
  fail as `claude-plugin-malformed-utf8`. Valid CJK stays admitted. Bidi
  and control concealment stay `claude-plugin-concealed-identity`.
  Snippets are short labels and omit raw invalid bytes.
  Plugin or marketplace identity names that are not Unicode NFC fail as
  `claude-plugin-inconsistent-normalized-name`. Precomposed Latin and
  Hangul names stay admitted. Combining-mark bytes do not appear in
  snippets.
