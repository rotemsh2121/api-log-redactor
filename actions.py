"""The four redaction actions: mask, partial, hash and remove."""

import hashlib
import re

ALREADY_HASHED = re.compile(r"sha256:[0-9a-f]{64}")


def apply_action(action, text, settings):
    """Return what `text` should be replaced with."""
    if action == "mask":
        return mask(settings)
    elif action == "partial":
        return partial(text, settings)
    elif action == "hash":
        return hash_text(text)
    elif action == "remove":
        return ""
    else:
        raise ValueError(f"unknown action {action!r}")

    
def mask(settings):
    return settings.get("mask", {}).get("replacement", "****")


def partial(text, settings):
    keep_last = settings.get("partial", {}).get("keep_last", 4)
    fill = settings.get("partial", {}).get("fill", "*")
    
    if len(text) <= keep_last:
        # Keeping the last 4 characters of a 4-character value would reveal all of it.
        return fill * len(text)
    
    hidden = len(text) - keep_last
    return fill * hidden + text[hidden:]


def hash_text(text):
    # Hashing a hash again would change it, and the tool would not be idempotent.
    if ALREADY_HASHED.fullmatch(text):
        return text
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{h}"

