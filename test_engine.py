from engine import redact_string
from rules import load_rules

RULES = load_rules("rules.yaml")

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