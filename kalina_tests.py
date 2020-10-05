import unittest
import kalyna


def _string_to_bytes(str: str):
    split = [str[i:i + 2] for i in range(0, len(str), 2)]
    print(''.join(list(map(lambda x: '\\x' + x, split))))


def _bytes_to_string(b: bytes):
    mapped = list(map(lambda x: '\\' + hex(x)[1:], b))
    print(''.join(mapped))


def _reverse_bytes(b: bytes) -> str:
    list_bytes = [byte for byte in b]
    reversed_list_bytes = reversed(list_bytes)
    reversed_bytes = list(map(lambda x: '\\' + hex(x)[1:], reversed_list_bytes))
    return ''.join(reversed_bytes)


def _reverse(b: bytes):
    first_part = b[:len(b) // 2]
    reversed_first_part = _reverse_bytes(first_part)
    second_part = b[len(b) // 2:]
    reversed_second_part = _reverse_bytes(second_part)
    print(''.join([reversed_first_part, reversed_second_part]))


def _default_key() -> bytes:
    return b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'


class KalinaEncryptionDecryptionTest(unittest.TestCase):
    def test_encrypt_decrypt(self):
        algorithm = kalyna.Kalyna(block_size=128, key=_default_key())

        plaintext1 = b'aaaaaaaaaaaaaaaaaaaa'
        plaintext2 = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        plaintext3 = b''
        plaintext4 = b'aaaaaaaaaaaaa'
        plaintext5 = b'F:SDF:Shf;Sg;JD;fJff;df'
        plaintext6 = b'The Advanced Encryption Standard Rijndael (AES), also known by its original name (Dutch pronunciation),[3] is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001'

        self.assertEqual(plaintext1, algorithm.decrypt(algorithm.encrypt(plaintext1)))
        self.assertEqual(plaintext2, algorithm.decrypt(algorithm.encrypt(plaintext2)))
        self.assertEqual(plaintext3, algorithm.decrypt(algorithm.encrypt(plaintext3)))
        self.assertEqual(plaintext4, algorithm.decrypt(algorithm.encrypt(plaintext4)))
        self.assertEqual(plaintext5, algorithm.decrypt(algorithm.encrypt(plaintext5)))
        self.assertEqual(plaintext6, algorithm.decrypt(algorithm.encrypt(plaintext6)))

    def test_encrypt_decrypt_loop(self):
        algorithm = kalyna.Kalyna(block_size=128, key=_default_key())
        for plaintext_length in range(1, 100):
            plaintext = b'a' * plaintext_length
            self.assertEqual(plaintext, algorithm.decrypt(algorithm.encrypt(plaintext)))


class KalinaEncryptorCipherTest(unittest.TestCase):
    def test_kalyna_cipher(self):
        self.helper_test_kalyna_cipher(
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F',
            b'\x81\xBF\x1C\x7D\x77\x9B\xAC\x20\xE1\xC9\xEA\x39\xB4\xD2\xAD\x06'
        )

    def helper_test_kalyna_cipher(self, _in, expected_out):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        self.assertEqual(expected_out, algorithm.cipher(_in))


class KalinaEncryptorInvCipherTest(unittest.TestCase):
    def test_kalyna_inv_cipher(self):
        self.helper_test_kalyna_inv_cipher(
            _default_key(),
            b'\x81\xBF\x1C\x7D\x77\x9B\xAC\x20\xE1\xC9\xEA\x39\xB4\xD2\xAD\x06',
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
        )
        self.helper_test_kalyna_inv_cipher(
            b'\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00',
            b'\x1F\x1E\x1D\x1C\x1B\x1A\x19\x18\x17\x16\x15\x14\x13\x12\x11\x10',
            b'\x72\x91\xEF\x2B\x47\x0C\xC7\x84\x6F\x09\xC2\x30\x39\x73\xDA\xD7'
        )

    def helper_test_kalyna_inv_cipher(self, key: bytes, _in: bytes, expected_out: bytes):
        algorithm = kalyna._KalynaEncryptor(128, key)
        self.assertEqual(expected_out, algorithm.inv_cipher(_in))


class KalinaEncryptorCipherInvCipherTest(unittest.TestCase):
    def test_cipher_inv_cipher(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        _in = b'Semen krasavchik'
        self.assertEqual(_in, algorithm.inv_cipher(algorithm.cipher(_in)))


class KalinaEncryptorUtilityTest(unittest.TestCase):
    def test_key_expansion(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())

        expected_keys = [
            b'\x16\x50\x5e\x6b\x9b\x3a\xb1\xe6\x86\x5b\x77\xdc\xe0\x82\xa0\xf4',
            b'\xE6\x86\x5B\x77\xDC\xE0\x82\xA0\xF4\x16\x50\x5E\x6B\x9B\x3A\xB1',
            b'\x7E\x70\x87\x6E\xAE\x49\x84\x76\x8A\xAA\xA0\x0A\x7C\x93\xEC\x42',
            b'\x76\x8A\xAA\xA0\x0A\x7C\x93\xEC\x42\x7E\x70\x87\x6E\xAE\x49\x84',
            b'\x45\xCE\xD4\xC5\x1E\x91\x40\xF5\x3E\x72\x76\x82\x0F\x0B\xD9\xFE',
            b'\xF5\x3E\x72\x76\x82\x0F\x0B\xD9\xFE\x45\xCE\xD4\xC5\x1E\x91\x40',
            b'\x8C\x77\xEE\x22\x79\x00\xC4\x62\x51\x5F\x66\x32\x05\x60\xC4\xB1',
            b'\x62\x51\x5F\x66\x32\x05\x60\xC4\xB1\x8C\x77\xEE\x22\x79\x00\xC4',
            b'\x0A\x98\x72\xE2\x5C\xD2\xB0\xB8\xAA\x87\x9A\x20\x86\xA6\x6D\xD8',
            b'\xB8\xAA\x87\x9A\x20\x86\xA6\x6D\xD8\x0A\x98\x72\xE2\x5C\xD2\xB0',
            b'\x57\x26\xB1\xA8\x94\xDB\xC4\x18\xF6\x0B\xF3\xD5\xE8\xD7\x48\x61'
        ]
        self.assertEqual(len(expected_keys), len(algorithm._round_keys))

        for key_index in range(len(expected_keys)):
            expected_key = kalyna._KalynaEncryptor._in_to_state(expected_keys[key_index])
            actual_key = algorithm._round_keys[key_index]
            if len(expected_key[0]) > 0:
                self.assertEqual(expected_key, actual_key)

    def test_round_key_expand(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())

        expected_kt = b'\x86\x2F\x1F\x65\x3B\x77\x5B\xA1\xD0\x5C\xBC\x2F\x38\xE2\xD8\x7D'
        actual_kt = algorithm._key_expand_kt(_default_key())

        self.assertEqual(expected_kt, algorithm._state_to_out(actual_kt))

    def test_rotate_left(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())

        _in = b'\x16\x50\x5e\x6b\x9b\x3a\xb1\xe6\x86\x5b\x77\xdc\xe0\x82\xa0\xf4'
        expected_out = b'\xe6\x86\x5b\x77\xdc\xe0\x82\xa0\xf4\x16\x50\x5e\x6b\x9b\x3a\xb1'
        state = algorithm._in_to_state(_in)
        out_state = algorithm._in_to_state(expected_out)
        algorithm._rotate_left(2, state)
        self.assertEqual(out_state, state)

    def test_state_to_int(self):
        state = [
            [0, 8],
            [1, 9],
            [2, 10],
            [3, 11],
            [4, 12],
            [5, 13],
            [6, 14],
            [7, 15]
        ]
        self.assertEqual(0x0f0e0d0c0b0a09080706050403020100, kalyna._KalynaEncryptor._state_to_int(state))

    def test_int_to_state(self):
        expected_state = [
            [0, 8],
            [1, 9],
            [2, 10],
            [3, 11],
            [4, 12],
            [5, 13],
            [6, 14],
            [7, 15]
        ]
        self.assertEqual(expected_state, kalyna._KalynaEncryptor._int_to_state(0x0f0e0d0c0b0a09080706050403020100, 2))

    def test_rotation_mask(self):
        self.assertEqual(kalyna._KalynaEncryptor._rotation_mask(1), 0xffffffffffffffff)
        self.assertEqual(kalyna._KalynaEncryptor._rotation_mask(2), 0xffffffffffffffffffffffffffffffff)
        self.assertEqual(kalyna._KalynaEncryptor._rotation_mask(3), 0xffffffffffffffffffffffffffffffffffffffffffffffff)
        self.assertEqual(kalyna._KalynaEncryptor._rotation_mask(4),
                         0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)

    def test_in_to_state(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        _in = b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
        expected_state = [
            [0x10, 0x18],
            [0x11, 0x19],
            [0x12, 0x1A],
            [0x13, 0x1B],
            [0x14, 0x1C],
            [0x15, 0x1D],
            [0x16, 0x1E],
            [0x17, 0x1F]
        ]
        self.assertEqual(expected_state, algorithm._in_to_state(_in))

    def test_state_to_out(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        state = [
            [0x10, 0x18],
            [0x11, 0x19],
            [0x12, 0x1A],
            [0x13, 0x1B],
            [0x14, 0x1C],
            [0x15, 0x1D],
            [0x16, 0x1E],
            [0x17, 0x1F]
        ]
        expected_out = b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'
        self.assertEqual(expected_out, algorithm._state_to_out(state))

    def test_add_round_key_modulo_2_64(self):
        self.helper_test_add_round_key_modulo_2_64(
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f',
            b'\x16\x50\x5e\x6b\x9b\x3a\xb1\xe6\x86\x5b\x77\xdc\xe0\x82\xa0\xf4',
            b'\x26\x61\x70\x7e\xaf\x4f\xc7\xfd\x9e\x74\x91\xf7\xfc\x9f\xbe\x13'
        )

    def helper_test_add_round_key_modulo_2_64(self,
                                              state_bytes: bytes,
                                              round_key_bytes: bytes,
                                              expected_out_bytes: bytes):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())

        state = algorithm._in_to_state(state_bytes)
        round_key = algorithm._in_to_state(round_key_bytes)

        algorithm._add_round_key_modulo_2_64(state, round_key)

        self.assertEqual(expected_out_bytes, algorithm._state_to_out(state))

    def test_subtract_round_key_modulo_2_64(self):
        self.helper_test_subtract_round_key_modulo_2_64(
            b'\x1f\x1e\x1d\x1c\x1b\x1a\x19\x18\x17\x16\x15\x14\x13\x12\x11\x10',
            b'\x45\xd3\x27\x64\xeb\x4b\x66\x9e\xd8\xa3\xb2\xe7\x38\x88\xcc\x77',
            b'\xda\x4a\xf5\xb7\x2f\xce\xb2\x79\x3f\x72\x62\x2c\xda\x89\x44\x98'
        )

    def helper_test_subtract_round_key_modulo_2_64(self,
                                                   state_bytes: bytes,
                                                   round_key_bytes: bytes,
                                                   expected_out_bytes: bytes):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())

        state = algorithm._in_to_state(state_bytes)
        round_key = algorithm._in_to_state(round_key_bytes)

        algorithm._subtract_round_key_modulo_2_64(state, round_key)

        self.assertEqual(expected_out_bytes, algorithm._state_to_out(state))

    def test_right_circular_shift(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        _in = b'\x9A\x2B\x1E\xAC\x76\xEE\x89\x1B\x91\x4A\xCF\x17\x7C\x98\xDD\x3D'
        _expected_out = b'\x9A\x2B\x1E\xAC\x7C\x98\xDD\x3D\x91\x4A\xCF\x17\x76\xEE\x89\x1B'
        state = algorithm._in_to_state(_in)
        algorithm._right_circular_shift(state)
        self.assertEqual(_expected_out, algorithm._state_to_out(state))

    def test_left_circular_shift(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        _in = b'\x9A\x2B\x1E\xAC\x7C\x98\xDD\x3D\x91\x4A\xCF\x17\x76\xEE\x89\x1B'
        _expected_out = b'\x9A\x2B\x1E\xAC\x76\xEE\x89\x1B\x91\x4A\xCF\x17\x7C\x98\xDD\x3D'
        state = algorithm._in_to_state(_in)
        algorithm._left_circular_shift(state)
        self.assertEqual(_expected_out, algorithm._state_to_out(state))

    def test_linear_transformation_over_finite_field(self):
        self.helper_test_linear_transformation_over_finite_field(
            b'\x75\xbb\x9a\x4d\x17\x90\x51\x1f\x71\x3a\xdf\xb3\x6b\xcb\x45\x2a',
            b'\x62\xc9\x7c\x6e\x6a\xbf\x41\x33\xed\x51\x31\xd6\x24\xc7\xc1\x82'
        )
        self.helper_test_linear_transformation_over_finite_field(
            b'\x9A\x2B\x1E\xAC\x7C\x98\xDD\x3D\x91\x4A\xCF\x17\x76\xEE\x89\x1B',
            b'\x16\xCE\xDE\xE8\xD9\x99\x0F\x9E\x25\xB5\x06\xF0\x42\xD3\xB3\x05'
        )

    def helper_test_linear_transformation_over_finite_field(self, _in: bytes, expected_out: bytes):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        state = algorithm._in_to_state(_in)
        algorithm._linear_transformation_over_finite_field(state)
        out = algorithm._state_to_out(state)
        self.assertEqual(expected_out, out)

    def test_inverse_linear_transformation_over_finite_field(self):
        self.helper_test_inverse_linear_transformation_over_finite_field(
            b'\x62\xc9\x7c\x6e\x6a\xbf\x41\x33\xed\x51\x31\xd6\x24\xc7\xc1\x82',
            b'\x75\xbb\x9a\x4d\x17\x90\x51\x1f\x71\x3a\xdf\xb3\x6b\xcb\x45\x2a'
        )
        self.helper_test_inverse_linear_transformation_over_finite_field(
            b'\x16\xCE\xDE\xE8\xD9\x99\x0F\x9E\x25\xB5\x06\xF0\x42\xD3\xB3\x05',
            b'\x9A\x2B\x1E\xAC\x7C\x98\xDD\x3D\x91\x4A\xCF\x17\x76\xEE\x89\x1B'
        )

    def helper_test_inverse_linear_transformation_over_finite_field(self, _in: bytes, expected_out: bytes):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        state = algorithm._in_to_state(_in)
        algorithm._inv_linear_transformation_over_finite_field(state)
        out = algorithm._state_to_out(state)
        self.assertEqual(expected_out, out)

    def test_state_indices(self):
        state = [[0, 0] for _ in range(8)]
        self.assertEqual((0, 0), kalyna._KalynaEncryptor._state_indices(state, 0, 0))
        self.assertEqual((0, 1), kalyna._KalynaEncryptor._state_indices(state, 1, 0))
        self.assertEqual((1, 0), kalyna._KalynaEncryptor._state_indices(state, 2, 0))
        self.assertEqual((1, 1), kalyna._KalynaEncryptor._state_indices(state, 3, 0))
        self.assertEqual((2, 0), kalyna._KalynaEncryptor._state_indices(state, 4, 0))
        self.assertEqual((2, 1), kalyna._KalynaEncryptor._state_indices(state, 5, 0))
        self.assertEqual((3, 0), kalyna._KalynaEncryptor._state_indices(state, 6, 0))
        self.assertEqual((3, 1), kalyna._KalynaEncryptor._state_indices(state, 7, 0))
        self.assertEqual((4, 0), kalyna._KalynaEncryptor._state_indices(state, 0, 1))
        self.assertEqual((4, 1), kalyna._KalynaEncryptor._state_indices(state, 1, 1))
        self.assertEqual((5, 0), kalyna._KalynaEncryptor._state_indices(state, 2, 1))
        self.assertEqual((5, 1), kalyna._KalynaEncryptor._state_indices(state, 3, 1))
        self.assertEqual((6, 0), kalyna._KalynaEncryptor._state_indices(state, 4, 1))
        self.assertEqual((6, 1), kalyna._KalynaEncryptor._state_indices(state, 5, 1))
        self.assertEqual((7, 0), kalyna._KalynaEncryptor._state_indices(state, 6, 1))
        self.assertEqual((7, 1), kalyna._KalynaEncryptor._state_indices(state, 7, 1))

    def test_non_linear_bijective_mapping(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        _in = b'\x26\x61\x70\x7E\xAF\x4F\xC7\xFD\x9E\x74\x91\xF7\xFC\x9F\xBE\x13'
        _expected_out = b'\x9A\x2B\x1E\xAC\x76\xEE\x89\x1B\x91\x4A\xCF\x17\x7C\x98\xDD\x3D'
        state = algorithm._in_to_state(_in)
        algorithm._non_linear_bijective_mapping(state)
        self.assertEqual(_expected_out, algorithm._state_to_out(state))

    def test_inv_non_linear_bijective_mapping(self):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        _in = b'\x9A\x2B\x1E\xAC\x76\xEE\x89\x1B\x91\x4A\xCF\x17\x7C\x98\xDD\x3D'
        _expected_out = b'\x26\x61\x70\x7E\xAF\x4F\xC7\xFD\x9E\x74\x91\xF7\xFC\x9F\xBE\x13'
        state = algorithm._in_to_state(_in)
        algorithm._inv_non_linear_bijective_mapping(state)
        self.assertEqual(_expected_out, algorithm._state_to_out(state))

    def test_add_round_key_modulo_2(self):
        self.helper_test_add_round_key_modulo_2(
            b'\x16\xCE\xDE\xE8\xD9\x99\x0F\x9E\x25\xB5\x06\xF0\x42\xD3\xB3\x05',
            b'\xE6\x86\x5B\x77\xDC\xE0\x82\xA0\xF4\x16\x50\x5E\x6B\x9B\x3A\xB1',
            b'\xF0\x48\x85\x9F\x05\x79\x8D\x3E\xD1\xA3\x56\xAE\x29\x48\x89\xB4'
        )
        self.helper_test_add_round_key_modulo_2(
            b'\x17\xaf\x69\xba\x9a\x05\x47\xeb\x25\x9b\xc2\x3a\x88\x13\xbd\xb0',
            b'\x24\x79\xf9\x50\xb5\x21\x87\xe2\xae\x8b\xd6\x5c\xcc\x74\x52\xd0',
            b'\x33\xd6\x90\xea\x2f\x24\xc0\x09\x8b\x10\x14\x66\x44\x67\xef\x60'
        )

    def helper_test_add_round_key_modulo_2(self, state_bytes: bytes, key_bytes: bytes, expected_out: bytes):
        algorithm = kalyna._KalynaEncryptor(128, _default_key())
        state = algorithm._in_to_state(state_bytes)
        key = algorithm._in_to_state(key_bytes)
        algorithm._add_round_key_modulo_2(state, key)
        self.assertEqual(expected_out, algorithm._state_to_out(state))


if __name__ == '__main__':
    unittest.main()
