"""Tests for SARIF 2.1.0 output (appguardrail_core.sarif)."""

import appguardrail_core.sarif as sarif_module

FINDINGS = [
    {
        "severity": "CRITICAL",
        "rule_id": "hardcoded-stripe-secret-key",
        "message": "Hardcoded Stripe key\nsecond line",
        "file": "src/pay.ts",
        "line": 12,
        "cwe": ["CWE-798"],
        "owasp": ["A05:2021"],
        "context": "app-code",
        "references": ["https://stripe.com/docs/keys"],
    },
    {
        "severity": "WARNING",
        "rule_id": "hardcoded-stripe-secret-key",
        "message": "Hardcoded Stripe key",
        "file": "src/other.ts",
        "line": 3,
        "context": "app-code",
    },
    {
        "severity": "INFO",
        "rule_id": "note",
        "message": "fyi",
        "file": "README.md",
        "line": 1,
        "context": "doc",
    },
]


def test_sarif_shape_and_version():
    log = sarif_module.findings_to_sarif(FINDINGS, tool_version="1.2.3")
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "AppGuardrail"
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert len(run["results"]) == 3


def test_levels_and_security_severity():
    run = sarif_module.findings_to_sarif(FINDINGS)["runs"][0]
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error", "warning", "note"]
    # rules deduped by id (stripe rule appears once), plus the note rule
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["hardcoded-stripe-secret-key", "note"]
    stripe_rule = run["tool"]["driver"]["rules"][0]
    assert stripe_rule["properties"]["security-severity"] == "9.0"
    assert "CWE-798" in stripe_rule["properties"]["tags"]


def test_location_and_deploy_blocking():
    run = sarif_module.findings_to_sarif(FINDINGS)["runs"][0]
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/pay.ts"
    assert loc["region"]["startLine"] == 12
    # CRITICAL app-code is deploy-blocking; INFO doc is not
    assert run["results"][0]["properties"]["deployBlocking"] is True
    assert run["results"][2]["properties"]["deployBlocking"] is False
    # fingerprints are stable + unique per location
    fps = {r["partialFingerprints"]["appguardrail/v1"] for r in run["results"]}
    assert len(fps) == 3


def test_empty_findings_valid():
    run = sarif_module.findings_to_sarif([])["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_rule_index_lookup_does_not_scan_prior_rules(monkeypatch):
    class CountingRuleId(str):
        comparisons = 0
        __hash__ = str.__hash__

        def __eq__(self, other):
            type(self).comparisons += 1
            return super().__eq__(other)

    normalized = tuple(
        {
            "severity": "INFO",
            "rule_id": CountingRuleId(f"rule-{index}"),
            "message": "finding",
            "file": f"src/{index}.py",
            "line": 1,
            "category": "misconfig",
            "context": "test",
            "references": (),
            "cwe": (),
            "owasp": (),
            "remediation": "",
        }
        for index in range(200)
    )
    monkeypatch.setattr(sarif_module, "normalize_findings", lambda _findings: normalized)

    run = sarif_module.findings_to_sarif(())["runs"][0]

    assert [result["ruleIndex"] for result in run["results"]] == list(range(200))
    assert CountingRuleId.comparisons < 1_000
