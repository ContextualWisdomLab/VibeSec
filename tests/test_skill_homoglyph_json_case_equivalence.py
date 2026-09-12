"""Preserve the declared homoglyph alphabet across equivalent JSON spellings.

Issue #1031 / #1099 and PR #1036 require mixed-script identity evidence, not
raw serialization differences. RFC 8259 section 7 allows Unicode escapes for
any character; escaping an already-supported uppercase letter must not hide it.
"""

import json
from pathlib import Path

import pytest

from scanner.cli import appguardrail as scanner_module


HOMOGLYPH_RULE_ID = "skill-name-homoglyph-confusable"
SUPPORTED_CYRILLIC_POINTS = (
    *range(0x0410, 0x0450),
    0x0401, 0x0404, 0x0405, 0x0406, 0x0407, 0x0408, 0x0490,
    0x0451, 0x0454, 0x0455, 0x0456, 0x0457, 0x0458, 0x0491,
)


@pytest.fixture(scope="module")
def packaged_rule_inventory():
    """Load the real packaged rule inventory once for this regression module."""
    return scanner_module._load_packaged_regex_rules()


@pytest.fixture(autouse=True)
def use_packaged_rule_inventory(monkeypatch, packaged_rule_inventory):
    """Exercise production scanning without inheriting another test's rules."""
    monkeypatch.setattr(scanner_module, "SCAN_RULES", packaged_rule_inventory)


def _homoglyph_findings(manifest_path: Path, scan_root: Path) -> list[dict]:
    """Keep only this detector's findings from the real file-scanning path."""
    return [
        finding
        for finding in scanner_module._scan_file(manifest_path, scan_root)
        if finding["rule_id"] == HOMOGLYPH_RULE_ID
    ]


@pytest.mark.parametrize("code_point", SUPPORTED_CYRILLIC_POINTS)
def test_json_cyrillic_case_preserves_mixed_script_detection(
    tmp_path: Path, code_point: int
) -> None:
    """Raw, lowercase-hex and uppercase-hex spellings have one identical finding."""
    manifest_path = tmp_path / "skill.json"
    payload_value = {"name": f"re{chr(code_point)}d_data"}
    escaped_text = json.dumps(payload_value, ensure_ascii=True)
    uppercase_hex_text = escaped_text.replace(
        f"\\u{code_point:04x}", f"\\u{code_point:04X}"
    )
    for payload_text in (
        json.dumps(payload_value, ensure_ascii=False),
        escaped_text,
        uppercase_hex_text,
    ):
        assert json.loads(payload_text) == payload_value
        manifest_path.write_text(payload_text, encoding="utf-8")
        assert len(_homoglyph_findings(manifest_path, tmp_path)) == 1, payload_text


@pytest.mark.parametrize("code_point", SUPPORTED_CYRILLIC_POINTS)
def test_json_cyrillic_only_identity_stays_negative(
    tmp_path: Path, code_point: int
) -> None:
    """Hexadecimal letters in an escape never count as Latin identity evidence."""
    manifest_path = tmp_path / "skill.json"
    for ensure_ascii in (False, True):
        payload_text = json.dumps({"name": chr(code_point)}, ensure_ascii=ensure_ascii)
        manifest_path.write_text(payload_text, encoding="utf-8")
        assert not _homoglyph_findings(manifest_path, tmp_path), payload_text


@pytest.mark.parametrize("code_point", (0x0410, 0x041F, 0x0408, 0x0490))
def test_json_description_does_not_donate_escaped_identity(
    tmp_path: Path, code_point: int
) -> None:
    """An escaped mixed-script name in description prose is not the skill name."""
    manifest_path = tmp_path / "skill.json"
    payload_text = json.dumps(
        {"name": "read_data", "description": f"example ,name: re{chr(code_point)}d_data"},
        ensure_ascii=True,
    )
    manifest_path.write_text(payload_text, encoding="utf-8")
    assert not _homoglyph_findings(manifest_path, tmp_path)


@pytest.mark.parametrize("code_point", (0x0410, 0x041F, 0x0408, 0x0490))
def test_json_skill_key_retains_escaped_uppercase_detection(
    tmp_path: Path, code_point: int
) -> None:
    """The alternate skill key preserves the same serialization invariant."""
    manifest_path = tmp_path / "skill.json"
    payload_text = json.dumps({"skill": f"read_{chr(code_point)}obs"}, ensure_ascii=True)
    manifest_path.write_text(payload_text, encoding="utf-8")
    assert len(_homoglyph_findings(manifest_path, tmp_path)) == 1
