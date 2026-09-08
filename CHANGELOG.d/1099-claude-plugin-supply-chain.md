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
  AppGuardrail policy, not activation. Receipts bind `policy_provenance`
  (`schema_version`, `source_repository` identity
  `ContextualWisdomLab/appguardrail`, `scanner_release_version` from the
  existing scanner version, and the same `scanner_policy_sha256` digest)
  to the exact AppGuardrail release and scan-policy bytes. Retained
  receipts fail closed on a wrong artifact digest, wrong scanner policy
  digest, disagreeing scanner version, swapped provenance, stale catalog,
  source, or marketplace identity, or replay against mutated bytes;
  verification is not Noema admission. Hardcoded GitHub PAT or app tokens, host Docker
  socket binds, and named secrets copied into curl/wget/fetch fail
  admission as policy findings; `gh issue create` stays inventory
  evidence. Unsigned `curl`/`wget` executable fetches and
  unpinned pip/npm/cargo URL installs fail admission; `package.json`
  `preinstall`/`install`/`postinstall` scripts that download or execute
  an unsigned payload fail closed on the same rules, while a lockfile-only
  tree without those downloads stays `package_install` inventory. Plugin skill,
  agent, and command markdown surfaces reuse released #1036 rule
  identities (`skill-name-homoglyph-confusable`,
  `skill-manifest-prompt-injection-payload`,
  `skill-doc-exfiltration-endpoint-directive`,
  `skill-placeholder-template-unresolved`) on the admission receipt without
  copying those regular expressions. `commands/*.md` and `agents/*.md` reuse
  the injection and exfil identities; root `AGENTS.md` stays repository
  guidance, not that class. `appguardrail scan-plugin
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
  Undeclared `vendor/`, `node_modules/`, `dist/`, or `*.min.js` copies
  fail as `claude-plugin-vendored-scope-undeclared` so admission cannot
  treat the tree as first-party. A `package.json` plus lockfile without
  those copies stays inventory. Generated files listed in plugin.json
  `files[]` are declared scope. Vendored trees emit one scope finding,
  not per-file hook findings.
  Duplicate plugin, skill, or command NFC names fail as
  `claude-plugin-conflicting-identity`. Non-NFC names stay
  `claude-plugin-inconsistent-normalized-name`. One collision emits one
  finding. Snippets are the label ``name``.
  Named secrets copied into a prompt file, log, or subprocess ``env``
  dict fail as `claude-plugin-secret-to-prompt`. Curl, wget, and fetch
  copies stay `claude-plugin-secret-to-network`. Hardcoded ``sk-``
  literals stay `claude-plugin-provider-secret`. Reading a secret into
  a local variable is not this class. Snippets omit secret values.
  Named secrets copied into MCP ``env``, ``args``, or ``command`` fail as
  `claude-plugin-secret-to-mcp`. Curl copies stay
  `claude-plugin-secret-to-network`. Prompt and log copies stay
  `claude-plugin-secret-to-prompt`. Snippets are the env name only.
  Skill, command, or agent text that hides tool use, rewrites the system
  prompt, or expands the declared goal fails as
  `claude-plugin-hide-actions-directive`,
  `claude-plugin-self-modify-directive`, or
  `claude-plugin-goal-escalation-directive`. Honest ``report each tool
  call to the user`` wording, README prose, and vendored copies are not
  that class. #1036 injection and exfil identities stay on their rules.
  Setuid or setgid executable and hook files fail as
  `claude-plugin-setuid-executable`. World-writable executable and hook
  files fail as `claude-plugin-world-writable-executable`. A declared
  ``0755`` hook, world-writable LICENSE, vendored copies, Git metadata,
  and ``.mcp.json`` are not that class.
  Zip or tar members whose uncompressed size divided by compressed size
  exceeds 100, nested archives deeper than one zip/tar layer, or archives
  whose regular in-root members sum above the package byte budget, fail as
  `claude-plugin-decompression-bomb` without extracting the payload.
  Honest small zip/tar of plugin.json and LICENSE, ``../`` path
  traversal, and oversized file-count or byte-count trees stay their
  own classes.
  Receipt ``sbom_sha256`` is SHA-256 of a deterministic CycloneDX 1.5
  document from the existing SBOM parsers. It is not a second policy
  digest. Verify fails closed when the digest disagrees. Malformed
  manifests yield an empty-component SBOM, not a crash.
  First-party ``SHA256SUMS``, ``SHA256SUMS.txt``, ``checksums.sha256``,
  or ``*.sha256`` next to ``plugin.json`` that names the plugin artifact
  or enumerated files fails as `claude-plugin-checksum-mismatch` when the
  digest disagrees with bytes on disk. Matching checksums, comment-only
  rows, and missing checksum files are not that class. Cosign or GPG
  network verification is not required. Snippets are path labels, not
  hashes or secrets. ``sbom_sha256`` stays the CycloneDX receipt digest.
  Hook or manifest ``gh pr merge`` fails as
  `claude-plugin-github-merge-command`. ``gh release create``,
  ``upload``, ``delete``, or ``edit`` fails as
  `claude-plugin-github-release-command`. Hook or manifest
  ``kubectl apply`` fails as `claude-plugin-kubectl-apply-command`.
  ``docker push`` and ``docker image push`` fail as
  `claude-plugin-docker-push-command`. ``gh issue create``,
  ``gh pr review``, ``gh release list``, ``kubectl get``, ``docker ps``,
  ``terraform apply`` fails as `claude-plugin-terraform-apply-command`.
  ``helm install`` fails as `claude-plugin-helm-install-command`.
  ``terraform plan``, ``helm list``, ``vercel deploy``, and ``fly deploy``
  stay inventory. Hardcoded
  PATs stay `claude-plugin-github-write-token`. Snippets are command
  labels, not tokens.
  Hook or manifest paths into ``~/.netrc``, ``~/.aws/credentials``,
  ``~/.config/gh/hosts.yml``, Docker ``config.json`` auth, ``cookies.txt``,
  ``~/.curl_home``, and ``~/.ssh/id_*`` private keys fail as
  `claude-plugin-credential-store-access`. Chrome and Firefox profile
  stores stay `claude-plugin-browser-profile-access`. README AWS wording,
  ``gh issue create``, and a declared ``0755`` echo hook
  are not that class. Snippets are path labels, not secret values.
