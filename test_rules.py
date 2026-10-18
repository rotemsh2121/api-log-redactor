import pytest
from rules import load_rules


# --- Helpers (not tests: their names do not start with test_) ---

def find_rule_by_name(rule_list, name):
    """Return the rule called `name`, so tests do not depend on rule order."""
    for rule in rule_list:
        if rule["name"] == name:
            return rule
    raise AssertionError(f"no rule named {name!r}")


def write_rules(tmp_path, text):
    """Write `text` as a rules file in a temporary folder and return its path."""
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# --- A valid file is loaded correctly ---

def test_loads_provided_rules_file():
    # The rules file we were given must load without errors.
    rules = load_rules("rules.yaml")

    assert len(rules["key_rules"]) == 5
    assert len(rules["value_rules"]) == 4


def test_exact_names_are_lower_case():
    # Header names are case-insensitive: an "AUTHORIZATION" header must still match.
    rules = load_rules("rules.yaml")

    auth = find_rule_by_name(rules["key_rules"], "auth-headers")
    assert auth["exact"] == {"authorization", "proxy-authorization", "x-auth-token", "cookie", "set-cookie"}


# --- A broken file is rejected, so the tool never runs without working rules ---

def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "does-not-exist.yaml")


def test_empty_file_is_rejected(tmp_path):
    path = write_rules(tmp_path, "")
    with pytest.raises(ValueError):
        load_rules(path)


def test_file_without_rules_is_rejected(tmp_path):
    # A file with no rules would let all traffic through unredacted.
    path = write_rules(tmp_path, "version: 1\n")
    with pytest.raises(ValueError, match="no rules"):
        load_rules(path)


def test_unknown_action_is_rejected(tmp_path):
    # A typo in the action would silently disable the rule.
    path = write_rules(tmp_path, "value_rules: [{name: r, pattern: x, action: maskk}]")
    with pytest.raises(ValueError, match="unknown action"):
        load_rules(path)


def test_unknown_validator_is_rejected(tmp_path):
    # A typo in the validator would skip the Luhn check and redact every long number.
    path = write_rules(tmp_path, "value_rules: [{name: r, pattern: x, validator: lunh, action: mask}]")
    with pytest.raises(ValueError, match="unknown validator"):
        load_rules(path)


def test_invalid_regex_is_rejected(tmp_path):
    # A broken regex must fail at startup, not in the middle of processing.
    path = write_rules(tmp_path, "value_rules: [{name: r, pattern: '[abc', action: mask}]")
    with pytest.raises(ValueError, match="invalid regex"):
        load_rules(path)
