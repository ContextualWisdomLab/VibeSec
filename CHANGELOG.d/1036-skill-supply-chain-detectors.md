### Added

- `scanner/rules/skill_supply_chain.yml`: four executable detectors turning the malicious shared-skill threat inventory (#1032) into detection obligations — Cyrillic homoglyph skill names, prompt-injection payloads in skill manifests, exfiltration directives, and unresolved placeholder templates — scoped to SKILL.md/skill.json/agent surfaces with clean-manifest negative tests.

### Fixed

- Preserve mixed-script skill-name detection when an already-supported uppercase Cyrillic letter is serialized as a JSON Unicode escape. The raw-letter and escaped-codepoint alternatives now cover the same declared 78-letter lower/uppercase alphabet; rule identity, severity, manifest paths, and unrelated rules are unchanged.
- Add 164 production `_scan_file` regression cases covering raw/lowercase-hex/uppercase-hex spellings, Cyrillic-only negative identities, description-prose negatives, and the alternate `skill` property. RED commit `e33988082a5a2c146d4fa27087c3e766a5409603` produced 43 expected failures and 1,161 passes in hosted Python 3.13 Tests run `34682100611`, job `103522497980`; implementation commit `79531336a02a05e10fb194b6b021e91ba48e3353` repairs the escaped-codepoint alternative. Fresh final-head CI and independent review remain release gates.

### Boundary and source

This is serialization parity within the existing bounded detector, not a universal confusable-name or JSON parser claim. ASCII-only and Cyrillic-only identities remain outside this mixed-script finding; an absence of this finding is not artifact admission. The closed incident #1031 remains regression provenance, and #1099 package admission must consume the released rule rather than copy this candidate source.

Bray, T. (Ed.). (2017). *The JavaScript Object Notation (JSON) data interchange format* (RFC 8259, sections 7 and 8.3). Internet Engineering Task Force. https://doi.org/10.17487/RFC8259
