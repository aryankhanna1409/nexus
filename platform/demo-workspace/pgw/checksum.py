"""Internet checksum (RFC 1071) over a byte payload."""


def internet_checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    total = 0
    for i in range(0, len(payload), 2):
        total += (payload[i] << 8) + payload[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF
