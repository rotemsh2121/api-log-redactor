
"""The redaction engine: finds sensitive data and replaces it."""

from actions import apply_action
from validators import luhn


def redact_string(text, value_rules, settings, counts):
    """Apply every value rule to `text` and return the redacted text."""

    # Iterate through each rule in value_rules
    for rule in value_rules:

        def replace(match):
            found = match.group()

            if rule["validator"] == "luhn" and not luhn(found):
                return found  # Not a real card number: leave it as it is.
            
            counts[rule["name"]] = counts.get(rule["name"], 0) + 1
            return apply_action(rule["action"], found, settings)
        
        text = rule["pattern"].sub(replace, text)
    return text
