"""Bounded syntax evidence for the CWL Keyverse credential migration."""
from pathlib import Path

import pytest

from scanner.cli.appguardrail import _compile_yaml_regex_rule, _parse_yaml_regex_rules

RULE_PATH = Path(__file__).resolve().parents[1] / "scanner/rules/dotenv_dependencies.yml"
RULE_IDS = {
    "python-dotenv-runtime-load", "python-dotenv-settings-source",
    "rust-dotenv-runtime-load", "node-dotenv-runtime-load",
    "shell-dotenv-source", "compose-dotenv-transport",
}


def loaded_rules():
    """Compile through the owner's supported YAML engine, not Semgrep fixtures."""
    assert RULE_PATH.is_file(), "the executable dotenv migration rules are missing"
    parsed_rules = _parse_yaml_regex_rules(RULE_PATH.read_text(encoding="utf-8"))
    compiled_rules = [compiled for parsed in parsed_rules
                      for compiled in _compile_yaml_regex_rule(parsed)]
    assert {rule["id"] for rule in compiled_rules} == RULE_IDS
    assert len(compiled_rules) == len(RULE_IDS), "one executable pattern per ID"
    return {rule["id"]: rule for rule in compiled_rules}


@pytest.mark.parametrize("rule_id,source", [
    ("python-dotenv-runtime-load", "load_dotenv()"),
    ("python-dotenv-runtime-load", "    dotenv.load_dotenv(override=True)"),
    ("python-dotenv-runtime-load", 'settings = dotenv_values(".env")'),
    ("python-dotenv-runtime-load", 'values: dict[str, str] = dotenv_values(".env")'),
    ("python-dotenv-runtime-load", "values = dotenv.dotenv_values()"),
    ("python-dotenv-settings-source", '    env_file=".env",'),
    ("python-dotenv-settings-source", 'model_config = SettingsConfigDict(env_file="../.env")'),
    ("python-dotenv-settings-source", 'model_config = SettingsConfigDict(\n    env_file=".env",\n)'),
    ("python-dotenv-settings-source", '    env_file = "~/.env.production"'),
    ("rust-dotenv-runtime-load", "    dotenvy::dotenv().ok();"),
    ("rust-dotenv-runtime-load", 'let _ = dotenv::from_filename(".env");'),
    ("rust-dotenv-runtime-load", 'dotenvy::from_path("private.env")?;'),
    ("node-dotenv-runtime-load", "dotenv.config();"),
    ("node-dotenv-runtime-load", "require('dotenv').config();"),
    ("node-dotenv-runtime-load", 'require("dotenv/config");'),
    ("node-dotenv-runtime-load", 'import "dotenv/config";'),
    ("shell-dotenv-source", 'source "$HOME/.env"'),
    ("shell-dotenv-source", ". .env"),
    ("shell-dotenv-source", ". '/run/app/.env.production'"),
    ("compose-dotenv-transport", '  env_file: .env'),
    ("compose-dotenv-transport", '  env_file:\n    - .env.production'),
    ("compose-dotenv-transport", '  env_file: ["../.env"]'),
    ("compose-dotenv-transport", 'docker compose --env-file "$HOME/.env" up'),
    ("compose-dotenv-transport", 'COMPOSE := docker compose --env-file "$$HOME/.env"'),
    ("compose-dotenv-transport", 'podman run --env-file .env application'),
])
def test_declared_runtime_dependency_is_detected(rule_id, source):
    """The tested literal loader/transport syntax produces evidence."""
    assert loaded_rules()[rule_id]["pattern"].search(source)


@pytest.mark.parametrize("rule_id,source", [
    ("python-dotenv-runtime-load", "# load_dotenv()"),
    ("python-dotenv-runtime-load", "from dotenv import load_dotenv"),
    ("python-dotenv-runtime-load", 'description = "load_dotenv()"'),
    ("python-dotenv-runtime-load", "def load_dotenv():"),
    ("python-dotenv-runtime-load", 'os.environ["PYTHON_DOTENV_DISABLED"] = "1"'),
    ("python-dotenv-settings-source", "env_file = None"),
    ("python-dotenv-settings-source", 'env_file = "settings.toml"'),
    ("python-dotenv-settings-source", '# env_file = ".env"'),
    ("rust-dotenv-runtime-load", "// dotenvy::dotenv().ok();"),
    ("rust-dotenv-runtime-load", "use dotenvy::dotenv;"),
    ("node-dotenv-runtime-load", "// dotenv.config();"),
    ("node-dotenv-runtime-load", 'import dotenv from "dotenv";'),
    ("node-dotenv-runtime-load", 'const note = "dotenv.config()";'),
    ("shell-dotenv-source", "# source ~/.env"),
    ("shell-dotenv-source", "source /run/configuration/settings.sh"),
    ("compose-dotenv-transport", "# env_file: .env"),
    ("compose-dotenv-transport", 'env_file: settings.config'),
    ("compose-dotenv-transport", "docker compose --env-file /dev/null up"),
])
def test_negative_control_is_not_a_migration_finding(rule_id, source):
    """Imports, comments, disabled dotenv and non-dotenv config are distinct."""
    assert not loaded_rules()[rule_id]["pattern"].search(source)


def test_migration_rules_do_not_claim_a_proven_secret_leak():
    """Syntax evidence is advisory until an explicit organization gate adopts it."""
    for rule in loaded_rules().values():
        assert rule["severity"] == "WARNING"
        assert "Keyverse" in rule["message"]
        assert "secret leak" not in rule["message"].lower()


def test_patterns_stay_bounded_on_long_nonmatching_lines():
    """Do not introduce unbounded wildcard alternatives into migration scanning."""
    for rule in loaded_rules().values():
        assert not rule["pattern"].search("x" * 100_000)
        assert ".*" not in rule["pattern"].pattern
