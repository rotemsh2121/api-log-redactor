"""Loads the rules file and prepares it for the redaction engine."""

import re
import yaml

ACTIONS = {"mask", "partial", "hash", "remove"}
SCOPES = {"headers", "body", "any"}
VALIDATORS = {"luhn"}


def load_rules(path):
    """Read the rules file at `path`. Raises ValueError if the file is invalid."""
    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        raise ValueError("rules file must contain a mapping at the top level")

    return {
        "settings": config.get("settings", {}),
        "key_rules": [prepare_key_rule(rule) for rule in config.get("key_rules", [])],
        "value_rules": [prepare_value_rule(rule) for rule in config.get("value_rules", [])],
    }


def prepare_key_rule(rule):
    name = rule.get("name", "<unnamed>")
    check_action(name, rule.get("action"))

    scope = rule.get("scope", "any")
    if scope not in SCOPES:
        raise ValueError(f"key rule {name!r}: unknown scope {scope!r}")

    match = rule.get("match", {})
    exact = None
    regex = None
    if "exact" in match:
        # Header names are case-insensitive, so compare everything in lower case.
        exact = {key.lower() for key in match["exact"]}
    elif "regex" in match:
        regex = compile_pattern(name, match["regex"])
    else:
        raise ValueError(f"key rule {name!r}: match needs 'exact' or 'regex'")

    return {"name": name, "scope": scope, "action": rule["action"], "exact": exact, "regex": regex}


def prepare_value_rule(rule):
    name = rule.get("name", "<unnamed>")
    check_action(name, rule.get("action"))

    if "pattern" not in rule:
        raise ValueError(f"value rule {name!r}: missing 'pattern'")

    validator = rule.get("validator")
    if validator is not None and validator not in VALIDATORS:
        raise ValueError(f"value rule {name!r}: unknown validator {validator!r}")

    return {
        "name": name,
        "pattern": compile_pattern(name, rule["pattern"]),
        "validator": validator,
        "action": rule["action"],
    }


def check_action(name, action):
    if action not in ACTIONS:
        raise ValueError(f"rule {name!r}: unknown action {action!r}")


def compile_pattern(name, pattern):
    try:
        return re.compile(pattern)
    except re.error as e:
        raise ValueError(f"rule {name!r}: invalid regex: {e}") from None
