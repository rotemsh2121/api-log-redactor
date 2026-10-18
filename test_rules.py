import pytest
from rules import load_rules


def find_rule_by_name(rule_list, name):
    for rule in rule_list:
        if rule["name"] == name:
            return rule
    raise AssertionError(f"no rule named {name!r}")


def write_rules(tmp_path, text):
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


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


def test_empty_file_is_rejected(tmp_path):
    path = write_rules(tmp_path, "")
    with pytest.raises(ValueError):
        load_rules(path)


def test_file_without_rules_is_rejected(tmp_path):
    # A file with no rules would let all traffic through unredacted.
    path = write_rules(tmp_path, "version: 1\n")
    with pytest.raises(ValueError, match="no rules"):
        load_rules(path)