from engine import redact_record, redact_string
from rules import load_rules

RULES = load_rules("rules.yaml")


# --- redact_string: value rules on one string ---

def redact(text):
    """Redact `text` with the provided rules and return the result and the counts."""
    counts = {}
    result = redact_string(text, RULES["value_rules"], RULES["settings"], counts)
    return result, counts


def test_valid_card_is_redacted():
    result, counts = redact("card 4111111111111111")
    assert result == "card ************1111"
    assert counts == {"credit-card": 1}


def test_invalid_card_is_not_redacted():
    result, counts = redact("card 4111111111111112")
    assert result == "card 4111111111111112"
    assert counts == {}


def test_only_the_sensitive_part_is_redacted():
    result, counts = redact("contact a@b.com today")
    assert result.startswith("contact sha256:")
    assert result.endswith("today")
    assert counts == {"email": 1}


def test_every_match_is_counted():
    result, counts = redact("contact a@b.com and c@b.com and d@b.com")
    assert "@" not in result
    assert result.count("sha256:") == 3
    assert counts == {"email": 3}


def test_redacting_twice_changes_nothing():
    result, _ = redact("contact a@b.com with card 4111111111111111")
    result2, counts2 = redact(result)
    assert result2 == result
    assert counts2 == {}


# --- redact_record: a whole NDJSON line ---

def redact_line(record):
    """Redact a parsed line with the provided rules and return the result and the counts."""
    counts = {}
    result = redact_record(record, RULES, counts)
    return result, counts


def test_email_deep_inside_arrays_is_redacted():
    # From input line 3: an email inside a list, inside a list, inside an object.
    result, counts = redact_line({"body": {"items": [[{"deep": ["carol@example.net"]}]]}})

    assert result["body"]["items"][0][0]["deep"][0].startswith("sha256:")
    assert counts == {"email": 1}


def test_header_rule_ignores_letter_case():
    # From input line 14: "AUTHORIZATION" must match the rule for "Authorization".
    result, _ = redact_line({"headers": {"AUTHORIZATION": "Basic dXNlcjpwYXNz"}})

    assert result["headers"]["AUTHORIZATION"] == "****"


def test_body_rule_does_not_apply_to_headers():
    # secret-fields has scope "body", so a header called "token" is not masked by it.
    result, _ = redact_line({"headers": {"token": "abc"}, "body": {"token": "abc"}})

    assert result["headers"]["token"] == "abc"
    assert result["body"]["token"] == "****"


def test_response_headers_and_body_are_redacted():
    result, _ = redact_line({"response": {"headers": {"Set-Cookie": "s=1"}, "body": {"password": "x"}}})

    assert result["response"]["headers"]["Set-Cookie"] == "****"
    assert result["response"]["body"]["password"] == "****"


def test_remove_action_drops_the_key():
    result, counts = redact_line({"body": {"card": {"number": "1", "cvv": "123"}}})

    assert result["body"]["card"] == {"number": "1"}
    assert counts == {"cvv-fields": 1}


def test_key_rule_replaces_the_whole_value():
    # The key rule wins: the email inside is not hashed separately, the whole value is masked.
    result, counts = redact_line({"body": {"password": "my email is a@b.com"}})

    assert result["body"]["password"] == "****"
    assert counts == {"secret-fields": 1}


def test_key_rule_on_a_number():
    # From input line 28: a card number stored as a JSON number.
    result, _ = redact_line({"body": {"card_number": 4111111111111111}})

    assert result["body"]["card_number"] == "************1111"


def test_key_rule_keeps_null_and_empty_values():
    # From input line 13: there is nothing secret to hide in null or "".
    result, counts = redact_line({"body": {"password": None, "secret": ""}})

    assert result["body"] == {"password": None, "secret": ""}
    assert counts == {}


def test_key_rule_on_a_list_redacts_each_item():
    # From input line 31: Set-Cookie can be a list of values.
    result, _ = redact_line({"headers": {"Set-Cookie": ["session=abc123", "csrf=zzz"]}})

    assert result["headers"]["Set-Cookie"] == ["****", "****"]


def test_already_redacted_values_are_not_counted_again():
    # From input line 12: a key rule over our own output changes nothing and counts nothing.
    first, _ = redact_line({"headers": {"X-Api-Key": "abc", "Authorization": "Bearer x"}})
    second, counts = redact_line(first)

    assert second == first
    assert counts == {}


# --- string bodies: JSON inside a string, forms, plain text ---

def test_json_inside_a_string_body_is_redacted():
    # From input line 10: the body is a string that holds JSON.
    body = '{"email":"carol@example.com","password":"p@ssw0rd!"}'
    result, counts = redact_line({"body": body})

    assert isinstance(result["body"], str)  # Still a string, like in the input.
    assert "carol@example.com" not in result["body"]
    assert '"password":"****"' in result["body"]
    assert counts == {"email": 1, "secret-fields": 1}


def test_json_string_body_without_secrets_keeps_its_formatting():
    body = '{ "id": 42,  "ok": true }'
    result, _ = redact_line({"body": body})

    assert result["body"] == body


def test_body_that_only_looks_like_json_is_treated_as_text():
    result, counts = redact_line({"body": "{not json, mail a@b.com"})

    assert result["body"].startswith("{not json, mail sha256:")
    assert counts == {"email": 1}


def test_form_body_is_redacted_field_by_field():
    # From input line 8: the password is found by its field name, and %40 is decoded before matching.
    record = {
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "email=bob%40example.com&password=hunter2&remember=on",
    }
    result, counts = redact_line(record)

    assert "hunter2" not in result["body"]
    assert "bob" not in result["body"]
    assert "password=****" in result["body"]
    assert "remember=on" in result["body"]
    assert counts == {"email": 1, "secret-fields": 1}


def test_form_body_is_idempotent():
    record = {
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "email=bob%40example.com&password=hunter2",
    }
    first, _ = redact_line(record)
    second, _ = redact_line(first)

    assert second == first


def test_plain_text_body_gets_value_rules():
    # From input line 9: a text/plain body with an email and an API key inside a sentence.
    result, counts = redact_line({"body": "reset dave@example.com. Temporary key: sk_live_9fA2kLmQ7x. Thanks!"})

    assert result["body"].endswith("Temporary key: ****. Thanks!")
    assert counts == {"email": 1, "api-key-prefix": 1}


def test_line_that_is_not_an_object():
    # From input line 24: valid JSON, but a list instead of an object.
    result, counts = redact_line(["a@b.com", "4111111111111111"])

    assert result[0].startswith("sha256:")
    assert result[1] == "************1111"
    assert counts == {"email": 1, "credit-card": 1}