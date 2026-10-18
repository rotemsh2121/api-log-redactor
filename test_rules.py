import pytest
from rules import load_rules


def find_rule_by_name(rule_list, name):
    for rule in rule_list:
        if rule["name"] == name:
            return rule
    raise AssertionError(f"no rule named {name!r}")

def test_loads_provided_rules_file():
    rules = load_rules("rules.yaml")

    assert len(rules["key_rules"]) == 5
    assert len(rules["value_rules"]) == 4

def test_exact_names_are_lower_case():
    # Header names are case-insensitive
    rules = load_rules("rules.yaml")

    auth = find_rule_by_name(rules["key_rules"], "auth-headers")
    assert auth["exact"] == {"authorization", "proxy-authorization", "x-auth-token", "cookie", "set-cookie"}

def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "does-not-exist.yaml")