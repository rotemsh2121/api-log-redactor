import pytest
from actions import apply_action 

SETTINGS = {
    "mask": {"replacement": "****"},
    "partial": {"keep_last": 4, "fill": "*"},
}

def test_mask_uses_replacement_from_settings():
    settings = {"mask": {"replacement": "[X]"}}
    assert apply_action("mask", "hunter2", settings) == "[X]"


def test_partial_keeps_last_four_characters():
    assert apply_action("partial", "4111111111111111", SETTINGS) == "************1111"


def test_partial_hides_short_values():
    # Keeping the last 4 characters of a 4-character value would reveal all of it.
    assert apply_action("partial", "1234", SETTINGS) == "****"
    assert apply_action("partial", "123", SETTINGS) == "***"

def test_partial_with_keep_last_zero_hides_everything():
    # text[-0:] is the whole text, so a naive slice would reveal the full value.
    settings = {"partial": {"keep_last": 0, "fill": "*"}}
    assert apply_action("partial", "1234", settings) == "****"

def test_partial_is_idempotent():
    # Applying partial twice should not reveal more than applying it once.
    first = apply_action("partial", "4111111111111111", SETTINGS)
    second = apply_action("partial", first, SETTINGS)
    assert second == first


def test_hash_does_not_contain_original():
    # The original value must not appear in the output.
    hashed = apply_action("hash", "hunter2", SETTINGS)
    assert "hunter2" not in hashed


def test_hash_is_idempotent():
    # Hashing a hash again would change it, and the tool would not be idempotent.
    first = apply_action("hash", "hunter2", SETTINGS)
    second = apply_action("hash", first, SETTINGS)
    assert second == first


def test_text_that_only_starts_like_a_hash_is_hashed():
    # A secret hidden after a real-looking hash must not pass through unhashed.
    text = "sha256:" + "a" * 64 + "secret"
    result = apply_action("hash", text, SETTINGS)
    assert "secret" not in result


def test_remove_returns_empty_string():
    assert apply_action("remove", "hunter2", SETTINGS) == ""


def test_unknown_action_raises_value_error():
    with pytest.raises(ValueError, match="unknown action"):
        apply_action("unknown", "hunter2", SETTINGS)