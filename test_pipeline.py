import io
import json

from pipeline import process_line, process_stream
from rules import load_rules

RULES = load_rules("rules.yaml")


def process(raw, line_number=1):
    """Process one raw line with the provided rules and return the output, the error and the counts."""
    counts = {}
    output, error = process_line(raw, line_number, RULES, counts)
    return output, error, counts


# --- good lines ---

def test_valid_line_is_redacted():
    output, error, counts = process(b'{"body":{"email":"a@b.com"}}')

    assert error is None
    assert "a@b.com" not in output
    assert counts == {"email": 1}


def test_output_is_one_line_even_if_the_text_has_newlines():
    # From input line 9: the body contains "\n", which must stay escaped.
    output, _, _ = process(b'{"body":"Hi team,\\nplease call"}')

    assert "\n" not in output
    assert json.loads(output)["body"] == "Hi team,\nplease call"


def test_non_english_text_is_kept_readable():
    # From input line 47: Hebrew stays Hebrew
    output, _, _ = process('{"note":"מספר כרטיס"}'.encode("utf-8"))

    assert "מספר כרטיס" in output


def test_broken_unicode_character_does_not_crash():
    # A lone "\ud800" is valid JSON but cannot be written as UTF-8.
    output, error, _ = process(b'{"note":"\\ud800"}')

    assert error is None
    assert json.loads(output)["note"] == "\ud800"


# --- lines we skip ---

def test_blank_lines_are_skipped():
    # From input lines 19 and 22.
    assert process(b"") == (None, None, {})
    assert process(b"   \n") == (None, None, {})


# --- lines we cannot process ---

def test_truncated_json_becomes_an_error_record():
    # From input line 20: cut in the middle of a JWT.
    raw = b'{"headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi'
    output, error, counts = process(raw, line_number=20)

    assert error == "invalid_json"
    assert json.loads(output) == {"_redactor_error": "invalid_json", "line": 20}
    assert counts == {}


def test_plain_log_line_is_not_passed_through():
    # From input line 21: not JSON, and it contains an email.
    output, error, _ = process(b"2025-01-15 10:00:20 WARN upstream timeout user=erin@example.com")

    assert error == "invalid_json"
    assert "erin" not in output


def test_invalid_utf8_becomes_an_error_record():
    output, error, _ = process(b'{"note":"\xff\xfe"}')

    assert error == "invalid_utf8"
    assert json.loads(output)["_redactor_error"] == "invalid_utf8"


def test_too_deeply_nested_json_becomes_an_error_record():
    # Python stops recursing after about 1000 levels; this must not crash the tool.
    output, error, _ = process(b"[" * 100000)

    assert error == "too_deep"
    assert json.loads(output)["_redactor_error"] == "too_deep"


# --- whole streams ---

def test_stream_writes_one_output_line_per_input_line():
    data = b'{"body":{"email":"a@b.com"}}\n\nnot json\n{"ok":true}\n'
    out = io.BytesIO()

    counts, errors = process_stream(io.BytesIO(data), out, RULES)

    lines = out.getvalue().decode("utf-8").splitlines()
    assert len(lines) == 3  # The blank line is skipped.
    assert json.loads(lines[1]) == {"_redactor_error": "invalid_json", "line": 3}
    assert errors == [(3, "invalid_json")]
    assert counts == {"email": 1}


def test_too_long_line_is_replaced_and_the_next_line_still_works():
    data = b'{"note":"' + b"x" * 1000 + b'"}\n{"ok":true}\n'
    out = io.BytesIO()

    _, errors = process_stream(io.BytesIO(data), out, RULES, max_line_bytes=100)

    lines = out.getvalue().decode("utf-8").splitlines()
    assert json.loads(lines[0]) == {"_redactor_error": "line_too_long", "line": 1}
    assert json.loads(lines[1]) == {"ok": True}
    assert errors == [(1, "line_too_long")]
