from unittest.mock import patch

import pytest

from scanner.cli.appguardrail import _load_packaged_regex_rules, _scan_file


RULE_ID = "skill-name-homoglyph-confusable"


def _rule_ids(path, root):
    with patch("scanner.cli.appguardrail.SCAN_RULES", _load_packaged_regex_rules()):
        return {finding["rule_id"] for finding in _scan_file(path, root)}


@pytest.mark.parametrize(
    "name",
    [
        "reаd_data",  # Cyrillic а (U+0430) inside a Latin identifier.
        "read_јobs",  # Cyrillic ј (U+0458), outside the а-я range.
        "ѕkill-reader",  # Cyrillic ѕ (U+0455), another Latin-lookalike.
        "јob-runner",  # Cyrillic-first mixed-script identifier.
    ],
)
def test_homoglyph_detector_flags_mixed_latin_cyrillic_skill_names(tmp_path, name):
    manifest = tmp_path / "SKILL.md"
    manifest.write_text(f"---\nname: {name}\ndescription: test\n---\n", encoding="utf-8")

    assert RULE_ID in _rule_ids(manifest, tmp_path)


@pytest.mark.parametrize(
    "name",
    [
        "read_data",  # ASCII-only identifier.
        "данные",  # Cyrillic-only identifier: mixed-script attack path is absent.
    ],
)
def test_homoglyph_detector_requires_both_latin_and_cyrillic_scripts(tmp_path, name):
    manifest = tmp_path / "SKILL.md"
    manifest.write_text(f"---\nname: {name}\ndescription: test\n---\n", encoding="utf-8")

    assert RULE_ID not in _rule_ids(manifest, tmp_path)


def test_homoglyph_detector_remains_scoped_to_skill_surfaces(tmp_path):
    unrelated = tmp_path / "README.md"
    unrelated.write_text("name: read_јobs\n", encoding="utf-8")

    assert RULE_ID not in _rule_ids(unrelated, tmp_path)
