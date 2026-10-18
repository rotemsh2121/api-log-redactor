"""Turns raw input lines into redacted output lines, without ever crashing on bad input."""

import json

from engine import redact_record

# A longer line is replaced by an error record. This bounds the memory one line can use.
MAX_LINE_BYTES = 10 * 1024 * 1024


def process_stream(in_stream, out_stream, rules, max_line_bytes=MAX_LINE_BYTES):
    """Redact every line of `in_stream` into `out_stream`, one line at a time.

    Returns (counts, errors): redactions per rule, and a list of (line number, error kind).
    """
    counts = {}
    errors = []
    for output in redact_lines(in_stream, rules, counts, errors, max_line_bytes):
        out_stream.write(output)
    return counts, errors


def redact_lines(in_stream, rules, counts, errors, max_line_bytes=MAX_LINE_BYTES):
    """Yield the redacted output lines (bytes ending in a newline) one by one, as they are read.

    Used by the CLI (written to stdout) and by the service (sent in the HTTP response).
    Fills `counts` and `errors` along the way.
    """
    for line_number, raw in enumerate(read_lines(in_stream, max_line_bytes), start=1):
        if raw is None:
            output, error = error_record("line_too_long", line_number), "line_too_long"
        else:
            output, error = process_line(raw, line_number, rules, counts)
        if error is not None:
            errors.append((line_number, error))
        if output is not None:
            yield output.encode("utf-8") + b"\n"


def read_lines(stream, max_bytes):
    """Yield the lines of a binary stream one by one, or None for a line longer than `max_bytes`.

    Only one line (at most `max_bytes`) is held in memory at a time.
    """
    while True:
        line = stream.readline(max_bytes + 1)
        if not line:
            return  # End of the input.
        if len(line) > max_bytes:
            # Too long: read past the rest of it without keeping it in memory.
            while line and not line.endswith(b"\n"):
                line = stream.readline(max_bytes + 1)
            yield None
        else:
            yield line


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
