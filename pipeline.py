"""Turns raw input lines into redacted output lines, without ever crashing on bad input."""

import json

from engine import redact_record


def process_line(raw, line_number, rules, counts):
    """Redact one raw input line (bytes).

    Returns (output, error):
    - output is the text to write (without a newline), or None for a blank line.
    - error is a short error kind like "invalid_json", or None if the line was fine.
    """
    if not raw.strip():
        return None, None  # Blank lines carry no data: skip them.

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return error_record("invalid_utf8", line_number), "invalid_utf8"

    try:
        record = json.loads(text)
    except RecursionError:
        return error_record("too_deep", line_number), "too_deep"
    except ValueError:
        return error_record("invalid_json", line_number), "invalid_json"

    # Count into a copy, so a line that fails half way does not leave partial counts.
    line_counts = {}
    try:
        redacted = redact_record(record, rules, line_counts)
        output = to_json(redacted)
    except RecursionError:
        return error_record("too_deep", line_number), "too_deep"
    except Exception:
        return error_record("internal_error", line_number), "internal_error"

    for name, count in line_counts.items():
        counts[name] = counts.get(name, 0) + count
    return output, None


def error_record(kind, line_number):
    """The line we write instead of a line we cannot process safely: no original content at all."""
    return to_json({"_redactor_error": kind, "line": line_number})


def to_json(value):
    """Serialize `value` as one compact JSON line."""
    try:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        text.encode("utf-8")  # Fails on broken characters such as a lone "\ud800".
        return text
    except UnicodeEncodeError:
        # Escape everything that is not ASCII instead: still valid JSON, still the same data.
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
