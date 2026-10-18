"""The redaction engine: finds sensitive data and replaces it."""

from actions import apply_action
from validators import luhn


def redact_record(record, rules, counts):
    """Redact one parsed NDJSON line and return the redacted copy."""
    if not isinstance(record, dict):
        # A line that is valid JSON but not an object (a number, a list...).
        return redact_value(record, None, rules, counts)
    return redact_section(record, rules, counts)


def redact_section(section, rules, counts):
    """Redact a request or a response: its headers, its body and its other fields."""
    result = {}
    for key, value in section.items():
        if key in ("headers", "body"):
            # Everything inside gets this scope, however deep it is.
            result[key] = redact_value(value, key, rules, counts)
        elif key == "response" and isinstance(value, dict):
            result[key] = redact_section(value, rules, counts)
        else:
            # Fields like ts, method and path are neither headers nor body.
            redact_entry(result, key, value, None, rules, counts)
    return result


def redact_value(value, scope, rules, counts):
    """Redact any JSON value, going into objects and arrays recursively."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            redact_entry(result, key, item, scope, rules, counts)
        return result
    if isinstance(value, list):
        return [redact_value(item, scope, rules, counts) for item in value]
    if isinstance(value, str):
        return redact_string(value, rules["value_rules"], rules["settings"], counts)
    # Numbers, true/false and null have no text to search.
    return value


def redact_entry(result, key, value, scope, rules, counts):
    """Add `key` to `result` with its redacted value, or leave it out if a rule removes it."""
    rule = find_key_rule(key, scope, rules["key_rules"])
    if rule is None:
        result[key] = redact_value(value, scope, rules, counts)
    elif rule["action"] == "remove":
        counts[rule["name"]] = counts.get(rule["name"], 0) + 1
    else:
        result[key] = redact_whole(value, rule, rules["settings"], counts)


def find_key_rule(key, scope, key_rules):
    """Return the first key rule that matches the name `key` in this scope, or None."""
    for rule in key_rules:
        if rule["scope"] != "any" and rule["scope"] != scope:
            continue
        if rule["exact"] is not None and key.lower() in rule["exact"]:
            return rule
        if rule["regex"] is not None and rule["regex"].search(key):
            return rule
    return None


def redact_whole(value, rule, settings, counts):
    """Apply a key rule's action to the whole value, keeping lists and objects in shape."""
    if value is None or value == "":
        return value  # Nothing secret to hide.
    if isinstance(value, list):
        return [redact_whole(item, rule, settings, counts) for item in value]
    if isinstance(value, dict):
        return {key: redact_whole(item, rule, settings, counts) for key, item in value.items()}
    counts[rule["name"]] = counts.get(rule["name"], 0) + 1
    # Numbers and true/false become text, e.g. a card number stored as a JSON number.
    return apply_action(rule["action"], str(value), settings)


def redact_string(text, value_rules, settings, counts):
    """Apply every value rule to `text` and return the redacted text."""
    for rule in value_rules:

        def replace(match):
            found = match.group()
            if rule["validator"] == "luhn" and not luhn(found):
                return found  # Not a real card number: leave it as it is.
            counts[rule["name"]] = counts.get(rule["name"], 0) + 1
            return apply_action(rule["action"], found, settings)

        text = rule["pattern"].sub(replace, text)
    return text
