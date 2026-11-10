from pgw.checksum import internet_checksum


def test_known_vector() -> None:
    # Example from RFC 1071 section 3.
    assert internet_checksum(bytes([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7])) == 0x220D


def test_odd_length_is_padded() -> None:
    assert internet_checksum(b"\x01") == internet_checksum(b"\x01\x00")


def test_empty_payload() -> None:
    assert internet_checksum(b"") == 0xFFFF
