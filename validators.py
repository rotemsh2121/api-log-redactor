
def luhn(number):
    """Return True if the number passes the Luhn algorithm, else False."""

    # Ignore spaces and dashes, so "4111 1111 1111 1111" is checked too.
    digits = [int(c) for c in number if c in "0123456789"]
    if not digits:
        return False
    
    checksum = 0
    even = False
    for d in reversed(digits):
        if even:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        even = not even
    return checksum % 10 == 0