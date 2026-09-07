"""Audit the frozen ContextualWisdomLab security-issue inventory mapping.

The inventory is a snapshot of OPEN issues at goal start. This test does not
consult detector pass/fail fields; it only checks identity and family coverage.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "tests" / "fixtures" / "cwl-security-issue-inventory.json"
REQUIRED_ISSUE_NUMBERS = (309, 871, 928, 929, 938, 1087, 1099, 1106)
ALLOWED_DETECTION = frozenset({"SAST", "DAST", "non-detectable"})


def _load_inventory() -> dict:
    """Return the frozen issue inventory as a JSON object."""
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def test_inventory_snapshot_exists_and_names_required_issues() -> None:
    """The freeze must exist and include every named security issue."""
    inventory = _load_inventory()
    numbers = {issue["number"] for issue in inventory["issues"]}

    assert inventory["repository"] == "ContextualWisdomLab/appguardrail"
    assert inventory["issue_count"] == len(inventory["issues"])
    assert numbers.issuperset(REQUIRED_ISSUE_NUMBERS)


def test_every_issue_has_a_family_and_detection_class() -> None:
    """No retained issue may omit a family or use an unknown detection class."""
    inventory = _load_inventory()
    missing = []
    for issue in inventory["issues"]:
        family = issue.get("family")
        detection = issue.get("detection")
        if not family or detection not in ALLOWED_DETECTION:
            missing.append(issue["number"])
    assert missing == []


def test_detectable_claims_are_not_family_less() -> None:
    """Every SAST/DAST claim must name a non-empty detector family."""
    inventory = _load_inventory()
    detectable = [
        issue
        for issue in inventory["issues"]
        if issue["detection"] in {"SAST", "DAST"}
    ]
    assert detectable, "expected at least one detectable family in the freeze"
    assert all(issue["family"] for issue in detectable)


def test_family_index_covers_every_snapshot_id() -> None:
    """Family buckets must list every issue number exactly once."""
    inventory = _load_inventory()
    indexed: list[int] = []
    for family in inventory["families"]:
        indexed.extend(family["issue_numbers"])
        assert family["detection"] in ALLOWED_DETECTION
        assert family["family"]
        assert family.get("successor_role") in {"maps", "implements"}
    assert sorted(indexed) == sorted(issue["number"] for issue in inventory["issues"])


def test_mapped_families_keep_canonical_owners() -> None:
    """#1087 and #929 stay owned by PRs #1088 and #966; this successor only maps them."""
    inventory = _load_inventory()
    by_family = {family["family"]: family for family in inventory["families"]}

    poll = by_family["github-actions-transport-only-poll-loop"]
    assert poll["successor_role"] == "maps"
    assert poll["canonical_owner_issue"] == 1087
    assert poll["canonical_owner_pr"] == 1088
    assert 1087 in poll["issue_numbers"]
    assert 938 in poll["issue_numbers"]

    orphan = by_family["orphaned-github-actions-workflow"]
    assert orphan["successor_role"] == "maps"
    assert orphan["canonical_owner_issue"] == 929
    assert orphan["canonical_owner_pr"] == 966
    assert orphan["issue_numbers"] == [929]

    plugin = by_family["claude-plugin-supply-chain"]
    assert plugin["successor_role"] == "implements"
    assert plugin["canonical_owner_issue"] == 1099

    secrets = by_family["secret-indirection-and-auth-comment-precision"]
    assert secrets["successor_role"] == "implements"
    assert secrets["canonical_owner_issue"] == 1106
