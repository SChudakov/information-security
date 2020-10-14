import unittest
import sha256


class SHA256(unittest.TestCase):
    def test_pad_message(self):
        message1 = b''
        expected_padded_message1 = b'\x80' + b'\x00' * 63
        actual_padded_message1 = sha256.SHA256._pad_message(message1)

        self.assertEqual(expected_padded_message1, actual_padded_message1)

        message2 = b'\x00' * 64
        expected_padded_message2 = b'\x00' * 64
        actual_padded_message2 = sha256.SHA256._pad_message(message2)

        self.assertEqual(expected_padded_message2, actual_padded_message2)

        message3 = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        expected_padded_message3 = b'\x00\x01\x02\x03\x04\x05\x06\x07' + b'\x80' + b'\x00' * 47 \
                                   + b'\x00\x00\x00\x00\x00\x00\x00\x08'
        actual_padded_message3 = sha256.SHA256._pad_message(message3)

        self.assertEqual(expected_padded_message3, actual_padded_message3)

        message4 = b'\x00' * 65
        expected_padded_message4 = b'\x00' * 65 + b'\x80' + b'\x00' * 54 + b'\x00\x00\x00\x00\x00\x00\x00\x41'
        actual_padded_message4 = sha256.SHA256._pad_message(message4)

        self.assertEqual(expected_padded_message4, actual_padded_message4)

    def test_hash(self):
        message = b'abc'
        expected_hash = b'\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad'
        actual_hash = sha256.SHA256.hash(message)
        self.assertEqual(256 // 8, len(actual_hash))
        self.assertEqual(expected_hash, actual_hash)
