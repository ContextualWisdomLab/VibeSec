from unittest.mock import patch

import pytest

from scanner.cli.appguardrail import _load_packaged_regex_rules, _scan_file


RULE_ID = "skill-placeholder-template-unresolved"


def _rule_ids(path, root):
    with patch("scanner.cli.appguardrail.SCAN_RULES", _load_packaged_regex_rules()):
        return {finding["rule_id"] for finding in _scan_file(path, root)}


@pytest.mark.parametrize(
    "name_line",
    [
        'name: "{skill-name}"',
        "name: '{skill_name}'",
        "name: {skill-name}",
        "name: {{SKILL_NAME}}",
        'name: "{{Skill_Name}}"',
    ],
)
def test_placeholder_detector_flags_common_unrendered_template_forms(tmp_path, name_line):
    manifest = tmp_path / "SKILL.md"
    manifest.write_text(f"---\n{name_line}\ndescription: template\n---\n", encoding="utf-8")

    assert RULE_ID in _rule_ids(manifest, tmp_path)


@pytest.mark.parametrize(
    "name_line",
    [
        "name: skill-name",
        'name: "skill_name"',
        "name: read_data",
    ],
)
def test_placeholder_detector_does_not_flag_rendered_skill_names(tmp_path, name_line):
    manifest = tmp_path / "SKILL.md"
    manifest.write_text(f"---\n{name_line}\ndescription: real skill\n---\n", encoding="utf-8")

    assert RULE_ID not in _rule_ids(manifest, tmp_path)
