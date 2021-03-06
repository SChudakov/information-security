from typing import List
import unittest
import kupyna

_input = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
          0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
          0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
          0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
          0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
          0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
          0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
          0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
          0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
          0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
          0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
          0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
          0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
          0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
          0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF]


def _str_to_list_int(s: str):
    return list(map(lambda x: int(x, 16), s.split()))


class TestKupynaHash(unittest.TestCase):
    def test_kupyna_hash_256_6(self):
        message = []
        expected_hash = [0xCD, 0x51, 0x01, 0xD1, 0xCC, 0xDF, 0x0D, 0x1D, 0x1F, 0x4A, 0xDA, 0x56, 0xE8, 0x88, 0xCD, 0x72,
                         0x4C, 0xA1, 0xA0, 0x83, 0x8A, 0x35, 0x21, 0xE7, 0x13, 0x1D, 0x4F, 0xB7, 0x8D, 0x0F, 0x5E, 0xB6]

        self._helper_test_kupyna_hash(256, message, expected_hash)

    def test_kupyna_hash_256_4(self):
        message = [0xFF]
        expected_hash = [0xEA, 0x76, 0x77, 0xCA, 0x45, 0x26, 0x55, 0x56, 0x80, 0x44, 0x1C, 0x11, 0x79, 0x82, 0xEA, 0x14,
                         0x05, 0x9E, 0xA6, 0xD0, 0xD7, 0x12, 0x4D, 0x6E, 0xCD, 0xB3, 0xDE, 0xEC, 0x49, 0xE8, 0x90, 0xF4]

        self._helper_test_kupyna_hash(256, message, expected_hash)

    def test_kupyna_hash_256_1(self):
        message = _input[:64]
        expected_hash = [0x08, 0xF4, 0xEE, 0x6F, 0x1B, 0xE6, 0x90, 0x3B, 0x32, 0x4C, 0x4E, 0x27, 0x99, 0x0C, 0xB2, 0x4E,
                         0xF6, 0x9D, 0xD5, 0x8D, 0xBE, 0x84, 0x81, 0x3E, 0xE0, 0xA5, 0x2F, 0x66, 0x31, 0x23, 0x98, 0x75]

        self._helper_test_kupyna_hash(256, message, expected_hash)

    def test_kupyna_hash_256_5(self):
        message = _input[:95]
        expected_hash = [0x10, 0x75, 0xC8, 0xB0, 0xCB, 0x91, 0x0F, 0x11, 0x6B, 0xDA, 0x5F, 0xA1, 0xF1, 0x9C, 0x29, 0xCF,
                         0x8E, 0xCC, 0x75, 0xCA, 0xFF, 0x72, 0x08, 0xBA, 0x29, 0x94, 0xB6, 0x8F, 0xC5, 0x6E, 0x8D, 0x16]

        self._helper_test_kupyna_hash(256, message, expected_hash)

    def test_kupyna_hash_256_2(self):
        message = _input[:128]
        expected_hash = [0x0A, 0x94, 0x74, 0xE6, 0x45, 0xA7, 0xD2, 0x5E, 0x25, 0x5E, 0x9E, 0x89, 0xFF, 0xF4, 0x2E, 0xC7,
                         0xEB, 0x31, 0x34, 0x90, 0x07, 0x05, 0x92, 0x84, 0xF0, 0xB1, 0x82, 0xE4, 0x52, 0xBD, 0xA8, 0x82]

        self._helper_test_kupyna_hash(256, message, expected_hash)

    def test_kupyna_hash_256_3(self):
        message = _input[:256]
        expected_hash = [0xD3, 0x05, 0xA3, 0x2B, 0x96, 0x3D, 0x14, 0x9D, 0xC7, 0x65, 0xF6, 0x85, 0x94, 0x50, 0x5D, 0x40,
                         0x77, 0x02, 0x4F, 0x83, 0x6C, 0x1B, 0xF0, 0x38, 0x06, 0xE1, 0x62, 0x4C, 0xE1, 0x76, 0xC0, 0x8F]

        self._helper_test_kupyna_hash(256, message, expected_hash)

    def test_kupyna_hash_48(self):
        message = _input[:64]
        expected_hash = [0x2F, 0x66, 0x31, 0x23, 0x98, 0x75]

        self._helper_test_kupyna_hash(48, message, expected_hash)

    def test_kupyna_hash_512_1(self):
        message = _input[:64]
        expected_hash = [0x38, 0x13, 0xE2, 0x10, 0x91, 0x18, 0xCD, 0xFB, 0x5A, 0x6D, 0x5E, 0x72, 0xF7, 0x20, 0x8D, 0xCC,
                         0xC8, 0x0A, 0x2D, 0xFB, 0x3A, 0xFD, 0xFB, 0x02, 0xF4, 0x69, 0x92, 0xB5, 0xED, 0xBE, 0x53, 0x6B,
                         0x35, 0x60, 0xDD, 0x1D, 0x7E, 0x29, 0xC6, 0xF5, 0x39, 0x78, 0xAF, 0x58, 0xB4, 0x44, 0xE3, 0x7B,
                         0xA6, 0x85, 0xC0, 0xDD, 0x91, 0x05, 0x33, 0xBA, 0x5D, 0x78, 0xEF, 0xFF, 0xC1, 0x3D, 0xE6, 0x2A]

        self._helper_test_kupyna_hash(512, message, expected_hash)

    def test_kupyna_hash_512_2(self):
        message = _input[:128]
        expected_hash = [0x76, 0xED, 0x1A, 0xC2, 0x8B, 0x1D, 0x01, 0x43, 0x01, 0x3F, 0xFA, 0x87, 0x21, 0x3B, 0x40, 0x90,
                         0xB3, 0x56, 0x44, 0x12, 0x63, 0xC1, 0x3E, 0x03, 0xFA, 0x06, 0x0A, 0x8C, 0xAD, 0xA3, 0x2B, 0x97,
                         0x96, 0x35, 0x65, 0x7F, 0x25, 0x6B, 0x15, 0xD5, 0xFC, 0xA4, 0xA1, 0x74, 0xDE, 0x02, 0x9F, 0x0B,
                         0x1B, 0x43, 0x87, 0xC8, 0x78, 0xFC, 0xC1, 0xC0, 0x0E, 0x87, 0x05, 0xD7, 0x83, 0xFD, 0x7F, 0xFE]

        self._helper_test_kupyna_hash(512, message, expected_hash)

    def test_kupyna_hash_512_3(self):
        message = _input[:256]
        expected_hash = [0x0D, 0xD0, 0x3D, 0x73, 0x50, 0xC4, 0x09, 0xCB, 0x3C, 0x29, 0xC2, 0x58, 0x93, 0xA0, 0x72, 0x4F,
                         0x6B, 0x13, 0x3F, 0xA8, 0xB9, 0xEB, 0x90, 0xA6, 0x4D, 0x1A, 0x8F, 0xA9, 0x3B, 0x56, 0x55, 0x66,
                         0x11, 0xEB, 0x18, 0x7D, 0x71, 0x5A, 0x95, 0x6B, 0x10, 0x7E, 0x3B, 0xFC, 0x76, 0x48, 0x22, 0x98,
                         0x13, 0x3A, 0x9C, 0xE8, 0xCB, 0xC0, 0xBD, 0x5E, 0x14, 0x36, 0xA5, 0xB1, 0x97, 0x28, 0x4F, 0x7E]

        self._helper_test_kupyna_hash(512, message, expected_hash)

    def test_kupyna_hash_512_4(self):
        message = [0xFF]
        expected_hash = [0x87, 0x1B, 0x18, 0xCF, 0x75, 0x4B, 0x72, 0x74, 0x03, 0x07, 0xA9, 0x7B, 0x44, 0x9A, 0xBE, 0xB3,
                         0x2B, 0x64, 0x44, 0x4C, 0xC0, 0xD5, 0xA4, 0xD6, 0x58, 0x30, 0xAE, 0x54, 0x56, 0x83, 0x7A, 0x72,
                         0xD8, 0x45, 0x8F, 0x12, 0xC8, 0xF0, 0x6C, 0x98, 0xC6, 0x16, 0xAB, 0xE1, 0x18, 0x97, 0xF8, 0x62,
                         0x63, 0xB5, 0xCB, 0x77, 0xC4, 0x20, 0xFB, 0x37, 0x53, 0x74, 0xBE, 0xC5, 0x2B, 0x6D, 0x02, 0x92]

        self._helper_test_kupyna_hash(512, message, expected_hash)

    def test_kupyna_hash_512_5(self):
        message = _input[:192]
        expected_hash = [0xB1, 0x89, 0xBF, 0xE9, 0x87, 0xF6, 0x82, 0xF5, 0xF1, 0x67, 0xF0, 0xD7, 0xFA, 0x56, 0x53, 0x30,
                         0xE1, 0x26, 0xB6, 0xE5, 0x92, 0xB1, 0xC5, 0x5D, 0x44, 0x29, 0x90, 0x64, 0xEF, 0x95, 0xB1, 0xA5,
                         0x7F, 0x3C, 0x2D, 0x0E, 0xCF, 0x17, 0x86, 0x9D, 0x1D, 0x19, 0x9E, 0xBB, 0xD0, 0x2E, 0x88, 0x57,
                         0xFB, 0x8A, 0xDD, 0x67, 0xA8, 0xC3, 0x1F, 0x56, 0xCD, 0x82, 0xC0, 0x16, 0xCF, 0x74, 0x31, 0x21]

        self._helper_test_kupyna_hash(512, message, expected_hash)

    def test_kupyna_hash_512_6(self):
        message = []
        expected_hash = [0x65, 0x6B, 0x2F, 0x4C, 0xD7, 0x14, 0x62, 0x38, 0x8B, 0x64, 0xA3, 0x70, 0x43, 0xEA, 0x55, 0xDB,
                         0xE4, 0x45, 0xD4, 0x52, 0xAE, 0xCD, 0x46, 0xC3, 0x29, 0x83, 0x43, 0x31, 0x4E, 0xF0, 0x40, 0x19,
                         0xBC, 0xFA, 0x3F, 0x04, 0x26, 0x5A, 0x98, 0x57, 0xF9, 0x1B, 0xE9, 0x1F, 0xCE, 0x19, 0x70, 0x96,
                         0x18, 0x7C, 0xED, 0xA7, 0x8C, 0x9C, 0x1C, 0x02, 0x1C, 0x29, 0x4A, 0x06, 0x89, 0x19, 0x85, 0x38]

        self._helper_test_kupyna_hash(512, message, expected_hash)

    def test_kupyna_hash_304(self):
        message = _input[:128]
        expected_hash = [0x0A, 0x8C, 0xAD, 0xA3, 0x2B, 0x97, 0x96, 0x35, 0x65, 0x7F, 0x25, 0x6B, 0x15, 0xD5, 0xFC, 0xA4,
                         0xA1, 0x74, 0xDE, 0x02, 0x9F, 0x0B, 0x1B, 0x43, 0x87, 0xC8, 0x78, 0xFC, 0xC1, 0xC0, 0x0E, 0x87,
                         0x05, 0xD7, 0x83, 0xFD, 0x7F, 0xFE]

        self._helper_test_kupyna_hash(304, message, expected_hash)

    def test_kupyna_hash_384_1(self):
        message = _input[:95]
        expected_hash = [0xD9, 0x02, 0x16, 0x92, 0xD8, 0x4E, 0x51, 0x75, 0x73, 0x56, 0x54, 0x84, 0x6B, 0xA7, 0x51, 0xE6,
                         0xD0, 0xED, 0x0F, 0xAC, 0x36, 0xDF, 0xBC, 0x08, 0x41, 0x28, 0x7D, 0xCB, 0x0B, 0x55, 0x84, 0xC7,
                         0x50, 0x16, 0xC3, 0xDE, 0xCC, 0x2A, 0x6E, 0x47, 0xC5, 0x0B, 0x2F, 0x38, 0x11, 0xE3, 0x51, 0xB8]

        self._helper_test_kupyna_hash(384, message, expected_hash)

    def _helper_test_kupyna_hash(self, hash_length: int, message: List[int], expected_hash: List[int]):
        message = bytes(message)
        expected_hash = bytes(expected_hash)

        algorithm = kupyna.Kupyna(hash_length)
        hashed = algorithm.hash(message)

        self.assertEqual(expected_hash, hashed)


class TestKupynaUtility(unittest.TestCase):

    def test_init(self):
        algorithm1 = kupyna.Kupyna(8)
        self._helper_test_init(algorithm1, 8, 512, 10, 8, 64)
        algorithm2 = kupyna.Kupyna(256)
        self._helper_test_init(algorithm2, 256, 512, 10, 8, 64)
        algorithm3 = kupyna.Kupyna(264)
        self._helper_test_init(algorithm3, 264, 1024, 14, 16, 128)
        algorithm3 = kupyna.Kupyna(512)
        self._helper_test_init(algorithm3, 512, 1024, 14, 16, 128)
        with self.assertRaises(AssertionError) as _:
            kupyna.Kupyna(0)
        with self.assertRaises(AssertionError) as _:
            kupyna.Kupyna(262)
        with self.assertRaises(AssertionError) as _:
            kupyna.Kupyna(513)
        with self.assertRaises(AssertionError) as _:
            kupyna.Kupyna(520)

    def _helper_test_init(self, algorithm, n, l, t, c, nbytes):
        self.assertEqual(n, algorithm.n)
        self.assertEqual(l, algorithm._l)
        self.assertEqual(t, algorithm._t)
        self.assertEqual(c, algorithm._c)
        self.assertEqual(nbytes, algorithm._nbytes)

    def test_pad(self):
        message1 = bytes(_input[:64])
        expected_padding1 = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0]
        self._helper_test_pad(kupyna.Kupyna(256), message1, 64, expected_padding1)

        message2 = bytes(_input[:128])
        expected_padding2 = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0]
        self._helper_test_pad(kupyna.Kupyna(256), message2, 64, expected_padding2)

        message3 = bytes(_input[:95])
        expected_padding3 = [64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
                             87, 88, 89, 90, 91, 92, 93, 94, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 248, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._helper_test_pad(kupyna.Kupyna(256), message3, 64, expected_padding3)

        message4 = bytes(_input[:64])
        expected_padding4 = [128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0]
        self._helper_test_pad(kupyna.Kupyna(48), message4, 64, expected_padding4)

        message4 = bytes(_input[:64])
        expected_padding4 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                             25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
                             48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 128, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._helper_test_pad(kupyna.Kupyna(512), message4, 128, expected_padding4)

        message5 = bytes([0xFF])
        expected_padding5 = [255, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0]
        self._helper_test_pad(kupyna.Kupyna(256), message5, 64, expected_padding5)

        message6 = bytes(
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
             27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
             51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63])
        expected_padding6 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                             25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
                             48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 128, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self._helper_test_pad(kupyna.Kupyna(512), message6, 128, expected_padding6)

    def _helper_test_pad(self, algorithm, message, expected_pad_nbytes, expected_padding):
        actual_padding = algorithm._pad_block(message)
        self.assertEqual(expected_pad_nbytes, algorithm._pad_nbytes)
        self.assertEqual(expected_padding, actual_padding[:expected_pad_nbytes])

    def test_digest(self):
        expected_padding = [128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0]
        data = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                      27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
                      51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63])
        state = [
            [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ]
        expected_state = [
            [0x56, 0xc9, 0x26, 0xaf, 0xf9, 0xcd, 0xe4, 0x53],
            [0x40, 0xdf, 0xb1, 0x5c, 0x75, 0x94, 0x1b, 0xeb],
            [0x6a, 0x65, 0x00, 0xde, 0x35, 0x31, 0x9b, 0x4a],
            [0x49, 0x05, 0xb5, 0x65, 0x85, 0xf6, 0xb1, 0xf2],
            [0x93, 0x3e, 0x37, 0x37, 0xfc, 0x1a, 0x0b, 0xdc],
            [0x9f, 0x94, 0xb3, 0x25, 0x40, 0x66, 0x91, 0x7e],
            [0x00, 0xfc, 0x28, 0x9d, 0x02, 0x7e, 0xf1, 0x38],
            [0x71, 0x32, 0x0f, 0xa9, 0xa5, 0x45, 0x30, 0x4c]
        ]
        algorithm = kupyna.Kupyna(256)
        self._helper_test_diges(expected_padding, data, state, expected_state, algorithm)

        expected_padding = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
                            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 128, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        data = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                      27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
                      51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63])
        state = [
            [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ]
        expected_state = [
            [0xf6, 0x67, 0x15, 0x1f, 0x25, 0x65, 0xc5, 0xc0],
            [0x3b, 0x16, 0xca, 0x22, 0xcf, 0xa2, 0x99, 0x14],
            [0x6c, 0xa8, 0xd5, 0x36, 0x5f, 0xd4, 0x73, 0x56],
            [0x91, 0xe5, 0xd6, 0x57, 0x7c, 0x1a, 0xf9, 0x01],
            [0x7a, 0x61, 0x7f, 0x1b, 0xa0, 0xb4, 0xb1, 0xd0],
            [0x1f, 0x0c, 0x49, 0x7d, 0x5c, 0x94, 0x43, 0xc3],
            [0x05, 0xf7, 0xf6, 0x9c, 0x1d, 0x81, 0xad, 0x6d],
            [0x26, 0x81, 0x74, 0xd3, 0x1b, 0x7b, 0x03, 0xf4],
            [0x51, 0xd6, 0xcb, 0xf8, 0xd0, 0x66, 0xc5, 0x86],
            [0x50, 0x2f, 0xd7, 0x26, 0x95, 0xb9, 0x1a, 0x71],
            [0xee, 0x49, 0x0c, 0x5e, 0x92, 0x94, 0xdc, 0x08],
            [0x09, 0x3e, 0xfa, 0xd3, 0xa8, 0x96, 0x98, 0xaa],
            [0xfd, 0x45, 0x0b, 0xb8, 0x22, 0x57, 0x84, 0xb0],
            [0xb1, 0xfd, 0xe9, 0xcc, 0xa6, 0x57, 0x33, 0x2b],
            [0x97, 0x5b, 0x59, 0x7f, 0x8f, 0xec, 0x74, 0x00],
            [0xb3, 0xcc, 0xdb, 0x6b, 0x4c, 0x6e, 0x46, 0xc0]
        ]
        algorithm = kupyna.Kupyna(512)
        self._helper_test_diges(expected_padding, data, state, expected_state, algorithm, 128)

    def _helper_test_diges(self, expected_padding, data, state, expected_state, algorithm, pad_nbytes=64):
        padding = algorithm._pad_block(data)
        self.assertEqual(expected_padding, padding[:pad_nbytes])
        algorithm._digest(state, expected_padding, data)
        self.assertEqual(expected_state, state)

    def test_trunc(self):
        state = [
            [0x86, 0xa9, 0xd2, 0x4e, 0x23, 0xf4, 0xb1, 0x03],
            [0xb7, 0x2b, 0x8c, 0x69, 0xd1, 0xf1, 0xbb, 0xb5],
            [0x11, 0x7e, 0xc3, 0x01, 0x76, 0x04, 0xdc, 0xdf],
            [0x6b, 0xf0, 0x4f, 0x3d, 0xa9, 0x5c, 0x02, 0x68],
            [0x08, 0xf4, 0xee, 0x6f, 0x1b, 0xe6, 0x90, 0x3b],
            [0x32, 0x4c, 0x4e, 0x27, 0x99, 0x0c, 0xb2, 0x4e],
            [0xf6, 0x9d, 0xd5, 0x8d, 0xbe, 0x84, 0x81, 0x3e],
            [0xe0, 0xa5, 0x2f, 0x66, 0x31, 0x23, 0x98, 0x75]
        ]
        expected_hash_code = [8, 244, 238, 111, 27, 230, 144, 59, 50, 76, 78, 39, 153, 12, 178, 78, 246, 157, 213, 141,
                              190, 132, 129, 62, 224, 165, 47, 102, 49, 35, 152, 117]

        algorithm = kupyna.Kupyna(256)
        hash_code = algorithm._truncate_hash(state)
        self.assertEqual(expected_hash_code, hash_code)

    def test_output_transformation(self):
        state = [
            [0x56, 0xc9, 0x26, 0xaf, 0xf9, 0xcd, 0xe4, 0x53],
            [0x40, 0xdf, 0xb1, 0x5c, 0x75, 0x94, 0x1b, 0xeb],
            [0x6a, 0x65, 0x00, 0xde, 0x35, 0x31, 0x9b, 0x4a],
            [0x49, 0x05, 0xb5, 0x65, 0x85, 0xf6, 0xb1, 0xf2],
            [0x93, 0x3e, 0x37, 0x37, 0xfc, 0x1a, 0x0b, 0xdc],
            [0x9f, 0x94, 0xb3, 0x25, 0x40, 0x66, 0x91, 0x7e],
            [0x00, 0xfc, 0x28, 0x9d, 0x02, 0x7e, 0xf1, 0x38],
            [0x71, 0x32, 0x0f, 0xa9, 0xa5, 0x45, 0x30, 0x4c]
        ]
        expected_state = [
            [0x86, 0xa9, 0xd2, 0x4e, 0x23, 0xf4, 0xb1, 0x03],
            [0xb7, 0x2b, 0x8c, 0x69, 0xd1, 0xf1, 0xbb, 0xb5],
            [0x11, 0x7e, 0xc3, 0x01, 0x76, 0x04, 0xdc, 0xdf],
            [0x6b, 0xf0, 0x4f, 0x3d, 0xa9, 0x5c, 0x02, 0x68],
            [0x08, 0xf4, 0xee, 0x6f, 0x1b, 0xe6, 0x90, 0x3b],
            [0x32, 0x4c, 0x4e, 0x27, 0x99, 0x0c, 0xb2, 0x4e],
            [0xf6, 0x9d, 0xd5, 0x8d, 0xbe, 0x84, 0x81, 0x3e],
            [0xe0, 0xa5, 0x2f, 0x66, 0x31, 0x23, 0x98, 0x75]
        ]
        algorithm = kupyna.Kupyna(256)
        algorithm._output_transformation(state)
        self.assertEqual(expected_state, state)

    def test_P(self):
        state1 = [
            [0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
            [0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
            [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27],
            [0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f],
            [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37],
            [0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]
        ]
        expected_state1 = [
            [0x5e, 0x47, 0x6b, 0xae, 0x2e, 0xee, 0x6e, 0x3e],
            [0x8e, 0x19, 0xb8, 0x45, 0x09, 0x22, 0x61, 0xa3],
            [0x7c, 0xb7, 0xc0, 0xf0, 0x80, 0x82, 0x82, 0x70],
            [0x09, 0x39, 0x19, 0x42, 0xf3, 0x9b, 0x48, 0x1a],
            [0xaa, 0xd5, 0x12, 0x24, 0x55, 0x40, 0x2b, 0xc0],
            [0x56, 0xfe, 0xc0, 0xd1, 0xc3, 0x3e, 0x6e, 0x85],
            [0x1d, 0x53, 0xa6, 0x08, 0xae, 0x02, 0x70, 0xd7],
            [0x9a, 0xa8, 0x9c, 0x75, 0xa4, 0xba, 0xb8, 0x89]
        ]
        algorithm1 = kupyna.Kupyna(256)
        algorithm1._p(state1)
        self.assertEqual(expected_state1, state1)

        state2 = [
            [0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
            [0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
            [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27],
            [0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f],
            [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37],
            [0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f],
            [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ]
        expected_state2 = [
            [0x2e, 0x94, 0x8e, 0x96, 0xcb, 0x67, 0xbf, 0x6f],
            [0xeb, 0x72, 0xf5, 0x46, 0xcc, 0x71, 0x8f, 0x58],
            [0x75, 0x72, 0x08, 0x4b, 0xc8, 0x73, 0xe2, 0xe2],
            [0x64, 0x75, 0xe8, 0x34, 0x18, 0x80, 0x4a, 0xe9],
            [0x37, 0x56, 0x70, 0xa3, 0xc0, 0xd5, 0x3d, 0xbd],
            [0x5d, 0x36, 0x99, 0xe6, 0x0d, 0x92, 0x36, 0x35],
            [0xec, 0x1c, 0xba, 0xea, 0x02, 0xec, 0xbc, 0x01],
            [0xd9, 0x04, 0x59, 0x42, 0xac, 0x71, 0x89, 0x81],
            [0xec, 0x2e, 0x3e, 0xab, 0xe0, 0x8d, 0x9a, 0x0d],
            [0xc6, 0x12, 0x42, 0xc4, 0x03, 0xb2, 0x66, 0xaf],
            [0x86, 0x56, 0x3b, 0xf1, 0xe0, 0x87, 0x12, 0x31],
            [0xf5, 0xc7, 0xe0, 0xf9, 0xa3, 0x93, 0xb7, 0xcb],
            [0xf8, 0x66, 0xeb, 0x22, 0x67, 0xbd, 0xa0, 0xbd],
            [0x84, 0xad, 0x26, 0xa6, 0xb7, 0x8f, 0x56, 0xda],
            [0x32, 0xf7, 0x06, 0xa9, 0x2b, 0x34, 0x07, 0x7d],
            [0x58, 0x58, 0xaf, 0x31, 0x47, 0xb7, 0xd7, 0x80]
        ]
        algorithm2 = kupyna.Kupyna(512)
        algorithm2._p(state2)
        self.assertEqual(state2, expected_state2)

    def test_Q(self):
        state = [
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
            [0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
            [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27],
            [0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f],
            [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37],
            [0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]
        ]
        expected_state = [
            [0x2d, 0x6f, 0x3a, 0x8e, 0x12, 0xf1, 0x62, 0xae],
            [0xc3, 0xf7, 0x6e, 0x04, 0x02, 0x57, 0x50, 0x68],
            [0x67, 0x18, 0x24, 0xef, 0x72, 0xfe, 0xa1, 0xcd],
            [0x7d, 0x71, 0xfd, 0x4d, 0x8e, 0x6a, 0x27, 0xa1],
            [0x0c, 0x2b, 0xa7, 0xeb, 0xf3, 0x1c, 0x27, 0x7f],
            [0x91, 0xdd, 0x38, 0x47, 0x31, 0x02, 0x5a, 0x8d],
            [0xf3, 0x01, 0x30, 0x49, 0x27, 0x9c, 0xf4, 0x72],
            [0x51, 0xb2, 0x43, 0x4f, 0x26, 0x32, 0xf0, 0x0a]
        ]
        algorithm = kupyna.Kupyna(256)
        algorithm._q(state)
        self.assertEqual(expected_state, state)

    def test_add_round_constant_p(self):
        state = [
            [0xe5, 0xad, 0xf9, 0x3c, 0x85, 0x11, 0x8b, 0x9c],
            [0x65, 0xf1, 0xec, 0xf4, 0xca, 0xbd, 0xe7, 0xfd],
            [0xbd, 0xa4, 0x55, 0x42, 0xfa, 0x26, 0xc6, 0x80],
            [0xed, 0x22, 0x6b, 0x20, 0x01, 0x59, 0x9b, 0xeb],
            [0x0b, 0x2d, 0x16, 0x67, 0x92, 0xfe, 0x93, 0x8a],
            [0xa1, 0xf8, 0xf2, 0xd3, 0x4a, 0x5d, 0x08, 0xea],
            [0xc9, 0x9c, 0x1d, 0x19, 0xc2, 0x00, 0xae, 0xd3],
            [0xdc, 0xe1, 0x00, 0xa0, 0xd1, 0x2b, 0xe9, 0x31]
        ]
        expected_state = [
            [0xec, 0xad, 0xf9, 0x3c, 0x85, 0x11, 0x8b, 0x9c],
            [0x7c, 0xf1, 0xec, 0xf4, 0xca, 0xbd, 0xe7, 0xfd],
            [0x94, 0xa4, 0x55, 0x42, 0xfa, 0x26, 0xc6, 0x80],
            [0xd4, 0x22, 0x6b, 0x20, 0x01, 0x59, 0x9b, 0xeb],
            [0x42, 0x2d, 0x16, 0x67, 0x92, 0xfe, 0x93, 0x8a],
            [0xf8, 0xf8, 0xf2, 0xd3, 0x4a, 0x5d, 0x08, 0xea],
            [0xa0, 0x9c, 0x1d, 0x19, 0xc2, 0x00, 0xae, 0xd3],
            [0xa5, 0xe1, 0x00, 0xa0, 0xd1, 0x2b, 0xe9, 0x31]
        ]
        algorithm = kupyna.Kupyna(256)
        algorithm._add_round_constant_p(state, 9)
        self.assertEqual(expected_state, state)

    def test_add_round_constant_q(self):
        state = [
            [0x61, 0x3a, 0x34, 0x8e, 0x2e, 0x0a, 0xd6, 0xc6],
            [0xc1, 0x67, 0xbd, 0x5c, 0xbf, 0x7c, 0x35, 0xcd],
            [0x3f, 0x0c, 0x39, 0x64, 0x0d, 0xf2, 0x8f, 0xeb],
            [0xcc, 0xdd, 0xc6, 0x6b, 0x1c, 0xad, 0xba, 0xd6],
            [0x0a, 0x5b, 0x58, 0x8d, 0x3d, 0xae, 0x1d, 0xef],
            [0xcd, 0x3f, 0x0f, 0xac, 0xf8, 0x10, 0x9b, 0x10],
            [0xd1, 0xf6, 0x23, 0xf7, 0x95, 0x7c, 0x9a, 0x96],
            [0xb5, 0xf6, 0x3a, 0x97, 0x98, 0x56, 0x2b, 0xfc]
        ]
        expected_state = [
            [0x54, 0x2b, 0x25, 0x7f, 0x1f, 0xfb, 0xc6, 0x3c],
            [0xb4, 0x58, 0xae, 0x4d, 0xb0, 0x6d, 0x26, 0x33],
            [0x32, 0xfd, 0x29, 0x55, 0xfe, 0xe2, 0x80, 0x41],
            [0xbf, 0xce, 0xb7, 0x5c, 0x0d, 0x9e, 0xab, 0x1c],
            [0xfd, 0x4b, 0x49, 0x7e, 0x2e, 0x9f, 0x0e, 0x25],
            [0xc0, 0x30, 0x00, 0x9d, 0xe9, 0x01, 0x8c, 0x36],
            [0xc4, 0xe7, 0x14, 0xe8, 0x86, 0x6d, 0x8b, 0xac],
            [0xa8, 0xe7, 0x2b, 0x88, 0x89, 0x47, 0x1c, 0x02]
        ]
        algorithm = kupyna.Kupyna(256)
        algorithm._add_round_constant_q(state, 5)
        self.assertEqual(expected_state, state)

    def test_sub_bytes(self):
        state = [
            [0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            [0x18, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            [0x30, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
            [0x28, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f],
            [0x60, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27],
            [0x78, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f],
            [0x50, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37],
            [0x48, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]
        ]
        expected_state = [
            [0xdc, 0xbb, 0x9a, 0x4d, 0x6b, 0xcb, 0x45, 0x2a],
            [0x79, 0x3a, 0xdf, 0xb3, 0x17, 0x90, 0x51, 0x1f],
            [0x92, 0x15, 0x2b, 0x3d, 0xc9, 0x1c, 0xbb, 0x83],
            [0x1f, 0x5c, 0x71, 0xd5, 0x6f, 0x57, 0x16, 0xbd],
            [0x34, 0xf6, 0xc0, 0x02, 0xb4, 0xf4, 0xad, 0x11],
            [0x8e, 0x0f, 0x7a, 0x5e, 0x49, 0x6d, 0xd1, 0x66],
            [0x2e, 0x26, 0xc4, 0x45, 0xd1, 0x5d, 0xb7, 0x94],
            [0x9c, 0x14, 0x0e, 0x1a, 0x58, 0x10, 0xb2, 0xdf]
        ]
        algorithm = kupyna.Kupyna(256)
        algorithm._sub_bytes(state)
        self.assertEqual(expected_state, state)

    def test_mix_columns(self):
        state = [
            [0xdc, 0x14, 0xc4, 0x5e, 0xb4, 0x57, 0xbb, 0x1f],
            [0x79, 0xbb, 0x0e, 0x45, 0x49, 0xf4, 0x16, 0x83],
            [0x92, 0x3a, 0x9a, 0x1a, 0xd1, 0x6d, 0xad, 0xbd],
            [0x1f, 0x15, 0xdf, 0x4d, 0x58, 0x5d, 0xd1, 0x11],
            [0x34, 0x5c, 0x2b, 0xb3, 0x6b, 0x10, 0xb7, 0x66],
            [0x8e, 0xf6, 0x71, 0x3d, 0x17, 0xcb, 0xb2, 0x94],
            [0x2e, 0x0f, 0xc0, 0xd5, 0xc9, 0x90, 0x45, 0xdf],
            [0x9c, 0x26, 0x7a, 0x02, 0x6f, 0x1c, 0x51, 0x2a]
        ]
        expected_state = [
            [0x39, 0x6a, 0x1e, 0x16, 0x44, 0x3c, 0xe6, 0x78],
            [0x95, 0x60, 0xf6, 0x40, 0x01, 0x44, 0x48, 0x8e],
            [0x65, 0xe3, 0xc6, 0x9c, 0xd3, 0xb2, 0x96, 0xfb],
            [0xa3, 0xf3, 0x43, 0x0a, 0x2e, 0x15, 0x4f, 0xe2],
            [0xe4, 0xb3, 0x2b, 0xb5, 0x03, 0xdf, 0xed, 0x48],
            [0x86, 0x0d, 0x18, 0xae, 0xbc, 0x3e, 0x13, 0x5c],
            [0xcf, 0x48, 0x53, 0xeb, 0x8c, 0xaf, 0xb6, 0xb6],
            [0x22, 0xbe, 0x8f, 0x75, 0x62, 0xd0, 0x10, 0x10]
        ]
        algorithm = kupyna.Kupyna(256)
        algorithm._mix_columns(state)
        self.assertEqual(expected_state, state)

    def test_shift_bytes(self):
        state1 = [
            [0xdc, 0xbb, 0x9a, 0x4d, 0x6b, 0xcb, 0x45, 0x2a],
            [0x79, 0x3a, 0xdf, 0xb3, 0x17, 0x90, 0x51, 0x1f],
            [0x92, 0x15, 0x2b, 0x3d, 0xc9, 0x1c, 0xbb, 0x83],
            [0x1f, 0x5c, 0x71, 0xd5, 0x6f, 0x57, 0x16, 0xbd],
            [0x34, 0xf6, 0xc0, 0x02, 0xb4, 0xf4, 0xad, 0x11],
            [0x8e, 0x0f, 0x7a, 0x5e, 0x49, 0x6d, 0xd1, 0x66],
            [0x2e, 0x26, 0xc4, 0x45, 0xd1, 0x5d, 0xb7, 0x94],
            [0x9c, 0x14, 0x0e, 0x1a, 0x58, 0x10, 0xb2, 0xdf]
        ]
        expected_state1 = [
            [0xdc, 0x14, 0xc4, 0x5e, 0xb4, 0x57, 0xbb, 0x1f],
            [0x79, 0xbb, 0x0e, 0x45, 0x49, 0xf4, 0x16, 0x83],
            [0x92, 0x3a, 0x9a, 0x1a, 0xd1, 0x6d, 0xad, 0xbd],
            [0x1f, 0x15, 0xdf, 0x4d, 0x58, 0x5d, 0xd1, 0x11],
            [0x34, 0x5c, 0x2b, 0xb3, 0x6b, 0x10, 0xb7, 0x66],
            [0x8e, 0xf6, 0x71, 0x3d, 0x17, 0xcb, 0xb2, 0x94],
            [0x2e, 0x0f, 0xc0, 0xd5, 0xc9, 0x90, 0x45, 0xdf],
            [0x9c, 0x26, 0x7a, 0x02, 0x6f, 0x1c, 0x51, 0x2a]
        ]
        algorithm1 = kupyna.Kupyna(256)
        algorithm1._shift_bytes(state1)
        self.assertEqual(expected_state1, state1)

        state2 = [
            [0x9b, 0xbb, 0x9a, 0x4d, 0x6b, 0xcb, 0x45, 0x2a],
            [0x79, 0x3a, 0xdf, 0xb3, 0x17, 0x90, 0x51, 0x1f],
            [0x92, 0x15, 0x2b, 0x3d, 0xc9, 0x1c, 0xbb, 0x83],
            [0x1f, 0x5c, 0x71, 0xd5, 0x6f, 0x57, 0x16, 0xbd],
            [0x34, 0xf6, 0xc0, 0x02, 0xb4, 0xf4, 0xad, 0x11],
            [0x8e, 0x0f, 0x7a, 0x5e, 0x49, 0x6d, 0xd1, 0x66],
            [0x2e, 0x26, 0xc4, 0x45, 0xd1, 0x5d, 0xb7, 0x94],
            [0x9c, 0x14, 0x0e, 0x1a, 0x58, 0x10, 0xb2, 0xdf],
            [0xa8, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x68],
            [0xeb, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x68],
            [0x78, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x68],
            [0xb3, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x68],
            [0x2f, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x68],
            [0xf7, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x68],
            [0xac, 0xce, 0x93, 0x68, 0xa8, 0xeb, 0x93, 0x68],
            [0x81, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x68]
        ]
        expected_state2 = [
            [0x9b, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x66],
            [0x79, 0xbb, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x94],
            [0x92, 0x3a, 0x9a, 0x68, 0xa8, 0xce, 0x93, 0xdf],
            [0x1f, 0x15, 0xdf, 0x4d, 0xa8, 0xeb, 0x93, 0x68],
            [0x34, 0x5c, 0x2b, 0xb3, 0x6b, 0xce, 0x93, 0x68],
            [0x8e, 0xf6, 0x71, 0x3d, 0x17, 0xcb, 0x93, 0x68],
            [0x2e, 0x0f, 0xc0, 0xd5, 0xc9, 0x90, 0x45, 0x68],
            [0x9c, 0x26, 0x7a, 0x02, 0x6f, 0x1c, 0x51, 0x68],
            [0xa8, 0x14, 0xc4, 0x5e, 0xb4, 0x57, 0xbb, 0x68],
            [0xeb, 0xce, 0x0e, 0x45, 0x49, 0xf4, 0x16, 0x68],
            [0x78, 0xce, 0x93, 0x1a, 0xd1, 0x6d, 0xad, 0x68],
            [0xb3, 0xce, 0x93, 0x68, 0x58, 0x5d, 0xd1, 0x2a],
            [0x2f, 0xce, 0x93, 0x68, 0xa8, 0x10, 0xb7, 0x1f],
            [0xf7, 0xce, 0x93, 0x68, 0xa8, 0xce, 0xb2, 0x83],
            [0xac, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0xbd],
            [0x81, 0xce, 0x93, 0x68, 0xa8, 0xce, 0x93, 0x11]
        ]
        algorithm2 = kupyna.Kupyna(512)
        algorithm2._shift_bytes(state2)
        self.assertEqual(expected_state2, state2)


if __name__ == '__main__':
    unittest.main()
