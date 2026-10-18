from validators import luhn

def test_valid_card_number_is_valid():
    assert luhn("4111 1111 1111 1111")
    assert luhn("4111-1111-1111-1111")
    assert luhn("4111111111111111")


def test_card_number_with_large_digits():
    assert luhn("5555555555554444")


def test_invalid_card_number_is_invalid():
    assert not luhn("4111 1111 1111 1112")


def test_empty_string_is_invalid():
    assert not luhn("")

