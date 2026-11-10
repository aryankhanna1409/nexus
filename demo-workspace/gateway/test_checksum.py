import unittest

from checksum import internet_checksum


class ChecksumTest(unittest.TestCase):
    def test_known_value(self):
        # Example from RFC 1071 section 3.
        self.assertEqual(internet_checksum(bytes([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7])), 0x220D)

    def test_odd_length_is_padded(self):
        self.assertEqual(internet_checksum(b"\x01"), internet_checksum(b"\x01\x00"))

    def test_requirements_are_pinned(self):
        with open("requirements.txt") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        self.assertTrue(all("==" in l for l in lines), lines)


if __name__ == "__main__":
    unittest.main()
