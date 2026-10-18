"""The redaction engine: finds sensitive data and replaces it."""

import json
from urllib.parse import parse_qsl, quote

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
        if key == "body" and isinstance(value, str):
            # A string body may hold JSON or a form, not just plain text.
            result[key] = redact_body_string(value, content_type(section), rules, counts)
        elif key in ("headers", "body"):
            # Everything inside gets this scope
            result[key] = redact_value(value, key, rules, counts)
        elif key == "response" and isinstance(value, dict):
            result[key] = redact_section(value, rules, counts)
        else:
            redact_entry(result, key, value, None, rules, counts)
    return result


def content_type(section):
    """Return the Content-Type header of a request or response in lower case, or ""."""
    headers = section.get("headers")
    if isinstance(headers, dict):
        for name, value in headers.items():
            if name.lower() == "content-type" and isinstance(value, str):
                return value.lower()
    return ""


def redact_body_string(text, content_type, rules, counts):
    """Redact a body that is a string: a form, JSON inside a string, or plain text."""
    if content_type.startswith("application/x-www-form-urlencoded"):
        return redact_form(text, rules, counts)

    if text.lstrip().startswith(("{", "[")):
        try:
            inner = json.loads(text)
        except ValueError:
            pass  # It only looked like JSON: treat it as plain text below.
        else:
            redacted = redact_value(inner, "body", rules, counts)
            if redacted == inner:
                return text  # Nothing to redact: keep the original formatting.
            return json.dumps(redacted, ensure_ascii=False, separators=(",", ":"))

    return redact_string(text, rules["value_rules"], rules["settings"], counts)


def redact_form(text, rules, counts):
    """Redact a form body like "email=a%40b.com&password=x" field by field."""
    fields = parse_qsl(text, keep_blank_values=True)
    parts = []
    changed = False
    for key, value in fields:
        # Each field is checked like a JSON key: key rules on the name, value rules on the value.
        entry = {}
        redact_entry(entry, key, value, "body", rules, counts)
        if key not in entry:
            changed = True  # A remove rule dropped this field.
            continue
        if entry[key] != value:
            changed = True
        parts.append(quote(key, safe="") + "=" + quote(entry[key], safe="*:"))
    if not changed:
        return text  # Nothing to redact: keep the original encoding.
    return "&".join(parts)


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
    # numbers, true/false and null have no text to search.
    return value


def redact_entry(result, key, value, scope, rules, counts):
    """Add `key` to `result` with its redacted value, or leave it out if a rule removes it."""
    rule = find_key_rule(key, scope, rules["key_rules"])
    if rule is None:
        result[key] = redact_value(value, scope, rules, counts)
    elif rule["action"] == "remove":
        # Drop the key entirely, so it won't appear in the output.
        counts[rule["name"]] = counts.get(rule["name"], 0) + 1
    else:
        # mask, partial or hash: redact the whole value, keeping lists and objects in shape.
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
    # Numbers and true/false become text, e.g. a card number stored as a JSON number.
    text = str(value)
    redacted = apply_action(rule["action"], text, settings)
    if redacted != text:
        # Count only real changes, so a second run over our own output counts nothing.
        counts[rule["name"]] = counts.get(rule["name"], 0) + 1
    return redacted


def redact_string(text, value_rules, settings, counts):
    """Apply every value rule to `text` and return the redacted text."""
    for rule in value_rules:

        def replace(match):
            found = match.group()
            if rule["validator"] == "luhn" and not luhn(found):
                return found  # Not a real card number: leave it as it is.
            redacted = apply_action(rule["action"], found, settings)
            if redacted != found:
                counts[rule["name"]] = counts.get(rule["name"], 0) + 1
            return redacted

        text = rule["pattern"].sub(replace, text)
    return text
