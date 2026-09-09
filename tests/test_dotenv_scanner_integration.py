"""The complete installed scanner must load and execute migration rules."""
import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file


@pytest.mark.parametrize("rule_id,file_name,source", [
    ("python-dotenv-runtime-load", "runtime_config.py", "load_dotenv()\n"),
    ("python-dotenv-settings-source", "runtime_settings.py", 'env_file=".env"\n'),
    ("rust-dotenv-runtime-load", "runtime_config.rs", "dotenvy::dotenv().ok();\n"),
    ("node-dotenv-runtime-load", "runtime_config.js", "require('dotenv').config();\n"),
    ("shell-dotenv-source", "runtime_start.sh", 'source "$HOME/.env"\n'),
    ("compose-dotenv-transport", "compose_runtime.yml", "env_file: .env\n"),
])
def test_packaged_scanner_executes_dotenv_rule(tmp_path, rule_id, file_name, source):
    """A rule file alone is insufficient: production discovery must execute it."""
    registered = [rule for rule in SCAN_RULES if rule["id"] == rule_id]
    assert len(registered) == 1
    source_file = tmp_path / file_name
    source_file.write_text(source, encoding="utf-8")
    findings = [finding for finding in _scan_file(source_file, tmp_path)
                if finding["rule_id"] == rule_id]
    assert len(findings) == 1
    assert findings[0]["line"] == 1
    assert findings[0]["severity"] == "WARNING"
