import unittest
import aes


def _default_key() -> bytes:
    return b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'


def _default_iv() -> bytes:
    return b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'


class TestEncryptDecryptKeyLength(unittest.TestCase):
    _plaintext = b'The Advanced Encryption Standard Rijndael (AES), also known by its original name (Dutch pronunciation),[3] is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001'

    def test_128_bits(self):
        self._helper_test_key_length(128)

    def test_192_bits(self):
        self._helper_test_key_length(192)

    def test_256_bits(self):
        self._helper_test_key_length(256)

    def _helper_test_key_length(self, key_length):
        algorithm = aes.AES(key_length=key_length)
        ciphertext = algorithm.encrypt(TestEncryptDecryptKeyLength._plaintext)
        plaintext = algorithm.decrypt(ciphertext)
        self.assertEqual(TestEncryptDecryptKeyLength._plaintext, plaintext)


class TestAESEncryptDecrypt(unittest.TestCase):
    _tests = [
        b'',
        b'aaaaaaaaaaaaaaaa',
        b'The Advanced Encryption Standard Rijndael (AES), also known by its original name (Dutch pronunciation),'
        b'[3] is a specification for the encryption of electronic data established by the U.S. National Institute of '
        b'Standards and Technology (NIST) in 2001 '
    ]

    def test_encrypt_decrypt_cbc(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt(algorithm.encrypt_cbc, algorithm.decrypt_cbc, _default_iv())

    def test_encrypt_decrypt_loop_cbc(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt_loop(algorithm.encrypt_cbc, algorithm.decrypt_cbc, _default_iv())

    def test_encrypt_decrypt_pcbc(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt(algorithm.encrypt_pcbc, algorithm.decrypt_pcbc, _default_iv())

    def test_encrypt_decrypt_loop_pcbc(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt_loop(algorithm.encrypt_pcbc, algorithm.decrypt_pcbc, _default_iv())

    def test_encrypt_decrypt_cfb(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt(algorithm.encrypt_cfb, algorithm.decrypt_cfb, _default_iv())

    def test_encrypt_decrypt_loop_cfb(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt_loop(algorithm.encrypt_cfb, algorithm.decrypt_cfb, _default_iv())

    def test_encrypt_decrypt_ofb(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt(algorithm.encrypt_ofb, algorithm.decrypt_ofb, _default_iv())

    def test_encrypt_decrypt_loop_ofb(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt_loop(algorithm.encrypt_ofb, algorithm.decrypt_ofb, _default_iv())

    def test_encrypt_decrypt_ctr(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt(algorithm.encrypt_ctr, algorithm.decrypt_ctr, _default_iv())

    def test_encrypt_decrypt_loop_ctr(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt_loop(algorithm.encrypt_ctr, algorithm.decrypt_ctr, _default_iv())

    def test_encrypt_decrypt(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt(algorithm.encrypt, algorithm.decrypt)

    def test_encrypt_decrypt_loop(self):
        algorithm = aes.AES(key=_default_key())
        self._helper_test_encrypt_decrypt_loop(algorithm.encrypt, algorithm.decrypt)

    def _helper_test_encrypt_decrypt(self, encrypt_func, decrypt_func, iv=None):
        for plaintext in self._tests:
            if iv is None:
                self.assertEqual(plaintext, decrypt_func(encrypt_func(plaintext)))
            else:
                self.assertEqual(plaintext, decrypt_func(encrypt_func(plaintext, iv), iv))

    def _helper_test_encrypt_decrypt_loop(self, encrypt_func, decrypt_func, iv=None):
        for plaintext_length in range(1, 100):
            plaintext = b'a' * plaintext_length
            if iv is None:
                self.assertEqual(plaintext, decrypt_func(encrypt_func(plaintext)))
            else:
                self.assertEqual(plaintext, decrypt_func(encrypt_func(plaintext, iv), iv))


class TestAESUtility(unittest.TestCase):
    def test_pad(self):
        self.assertEqual(16, len(aes.AES._pad(b'')))
        self.assertEqual(16, len(aes.AES._pad(b'a')))
        self.assertEqual(16, len(aes.AES._pad(b'aaaaaaaaaaaaaaaa')))
        self.assertEqual(32, len(aes.AES._pad(b'aaaaaaaaaaaaaaaaa')))

    def test_unpad(self):
        self.assertEqual(b'', aes.AES._unpad(b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'))
        self.assertEqual(b'a', aes.AES._unpad(b'a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'))
        self.assertEqual(b'aaaaaaaaaaaaaaaa', aes.AES._unpad(b'aaaaaaaaaaaaaaaa'))
        with self.assertRaises(AssertionError):
            aes.AES._unpad(b'aaaaaaaaaaaaaaaaa')

    def test_split_blocks(self):
        self.assertEqual(1, len(aes.AES._split_blocks(b'aaaaaaaaaaaaaaaa')))
        self.assertEqual(16, len(aes.AES._split_blocks(b'aaaaaaaaaaaaaaaa')[0]))
        self.assertEqual(2, len(aes.AES._split_blocks(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')))
        self.assertEqual(16, len(aes.AES._split_blocks(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')[0]))
        self.assertEqual(16, len(aes.AES._split_blocks(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')[1]))
        with self.assertRaises(AssertionError):
            aes.AES._split_blocks(b'')
        with self.assertRaises(AssertionError):
            aes.AES._split_blocks(b'a')
        with self.assertRaises(AssertionError):
            aes.AES._split_blocks(b'aaaaaaaaaaaaaaaaa')


class TestAESEncryptorCipher(unittest.TestCase):

    def test_cipher(self):
        encryptor = aes._AESEncryptor(_default_key())

        _in = b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'
        out = b'\xb8\x22\xfe\x47\x6f\x13\xf2\xca\x82\x11\xed\x45\xe3\x37\x58\x82'

        self.assertEqual(out, encryptor.cipher(_in))

    def test_on_article_example(self):
        encryptor = aes._AESEncryptor(_default_key())

        _in = b'\x32\x88\x31\xe0\x43\x5a\x31\x37\xf6\x30\x98\x07\xa8\x8d\xa2\x34'
        out = b'\x39\x02\xdc\x19\x25\xdc\x11\x6a\x84\x09\x85\x0b\x1d\xfb\x97\x32'

        execution_data = [
            [
                [[0x32, 0x88, 0x31, 0xe0],
                 [0x43, 0x5a, 0x31, 0x37],
                 [0xf6, 0x30, 0x98, 0x07],
                 [0xa8, 0x8d, 0xa2, 0x34]],
                [[0x2b, 0x28, 0xab, 0x09],
                 [0x7e, 0xae, 0xf7, 0xcf],
                 [0x15, 0xd2, 0x15, 0x4f],
                 [0x16, 0xa6, 0x88, 0x3c]]
            ],
            [
                [[0x19, 0xa0, 0x9a, 0xe9],
                 [0x3d, 0xf4, 0xc6, 0xf8],
                 [0xe3, 0xe2, 0x8d, 0x48],
                 [0xbe, 0x2b, 0x2a, 0x08]],
                [[0xd4, 0xe0, 0xb8, 0x1e],
                 [0x27, 0xbf, 0xb4, 0x41],
                 [0x11, 0x98, 0x5d, 0x52],
                 [0xae, 0xf1, 0xe5, 0x30]],
                [[0xd4, 0xe0, 0xb8, 0x1e],
                 [0xbf, 0xb4, 0x41, 0x27],
                 [0x5d, 0x52, 0x11, 0x98],
                 [0x30, 0xae, 0xf1, 0xe5]],
                [[0x04, 0xe0, 0x48, 0x28],
                 [0x66, 0xcb, 0xf8, 0x06],
                 [0x81, 0x19, 0xd3, 0x26],
                 [0xe5, 0x9a, 0x7a, 0x4c]],
                [[0xa0, 0x88, 0x23, 0x2a],
                 [0xfa, 0x54, 0xa3, 0x6c],
                 [0xfe, 0x2c, 0x39, 0x76],
                 [0x17, 0xb1, 0x39, 0x05]]
            ],
            [
                [[0xa4, 0x68, 0x6b, 0x02],
                 [0x9c, 0x9f, 0x5b, 0x6a],
                 [0x7f, 0x35, 0xea, 0x50],
                 [0xf2, 0x2b, 0x43, 0x49]],
                [[0x49, 0x45, 0x7f, 0x77],
                 [0xde, 0xdb, 0x39, 0x02],
                 [0xd2, 0x96, 0x87, 0x53],
                 [0x89, 0xf1, 0x1a, 0x3b]],
                [[0x49, 0x45, 0x7f, 0x77],
                 [0xdb, 0x39, 0x02, 0xde],
                 [0x87, 0x53, 0xd2, 0x96],
                 [0x3b, 0x89, 0xf1, 0x1a]],
                [[0x58, 0x1b, 0xdb, 0x1b],
                 [0x4d, 0x4b, 0xe7, 0x6b],
                 [0xca, 0x5a, 0xca, 0xb0],
                 [0xf1, 0xac, 0xa8, 0xe5]],
                [[0xf2, 0x7a, 0x59, 0x73],
                 [0xc2, 0x96, 0x35, 0x59],
                 [0x95, 0xb9, 0x80, 0xf6],
                 [0xf2, 0x43, 0x7a, 0x7f]]
            ],
            [
                [[0xaa, 0x61, 0x82, 0x68],
                 [0x8f, 0xdd, 0xd2, 0x32],
                 [0x5f, 0xe3, 0x4a, 0x46],
                 [0x03, 0xef, 0xd2, 0x9a]],
                [[0xac, 0xef, 0x13, 0x45],
                 [0x73, 0xc1, 0xb5, 0x23],
                 [0xcf, 0x11, 0xd6, 0x5a],
                 [0x7b, 0xdf, 0xb5, 0xb8]],
                [[0xac, 0xef, 0x13, 0x45],
                 [0xc1, 0xb5, 0x23, 0x73],
                 [0xd6, 0x5a, 0xcf, 0x11],
                 [0xb8, 0x7b, 0xdf, 0xb5]],
                [[0x75, 0x20, 0x53, 0xbb],
                 [0xec, 0x0b, 0xc0, 0x25],
                 [0x09, 0x63, 0xcf, 0xd0],
                 [0x93, 0x33, 0x7c, 0xdc]],
                [[0x3d, 0x47, 0x1e, 0x6d],
                 [0x80, 0x16, 0x23, 0x7a],
                 [0x47, 0xfe, 0x7e, 0x88],
                 [0x7d, 0x3e, 0x44, 0x3b]]
            ],
            [
                [[0x48, 0x67, 0x4d, 0xd6],
                 [0x6c, 0x1d, 0xe3, 0x5f],
                 [0x4e, 0x9d, 0xb1, 0x58],
                 [0xee, 0x0d, 0x38, 0xe7]],
                [[0x52, 0x85, 0xe3, 0xf6],
                 [0x50, 0xa4, 0x11, 0xcf],
                 [0x2f, 0x5e, 0xc8, 0x6a],
                 [0x28, 0xd7, 0x07, 0x94]],
                [[0x52, 0x85, 0xe3, 0xf6],
                 [0xa4, 0x11, 0xcf, 0x50],
                 [0xc8, 0x6a, 0x2f, 0x5e],
                 [0x94, 0x28, 0xd7, 0x07]],
                [[0x0f, 0x60, 0x6f, 0x5e],
                 [0xd6, 0x31, 0xc0, 0xb3],
                 [0xda, 0x38, 0x10, 0x13],
                 [0xa9, 0xbf, 0x6b, 0x01]],
                [[0xef, 0xa8, 0xb6, 0xdb],
                 [0x44, 0x52, 0x71, 0x0b],
                 [0xa5, 0x5b, 0x25, 0xad],
                 [0x41, 0x7f, 0x3b, 0x00]]
            ],
            [
                [[0xe0, 0xc8, 0xd9, 0x85],
                 [0x92, 0x63, 0xb1, 0xb8],
                 [0x7f, 0x63, 0x35, 0xbe],
                 [0xe8, 0xc0, 0x50, 0x01]],
                [[0xe1, 0xe8, 0x35, 0x97],
                 [0x4f, 0xfb, 0xc8, 0x6c],
                 [0xd2, 0xfb, 0x96, 0xae],
                 [0x9b, 0xba, 0x53, 0x7c]],
                [[0xe1, 0xe8, 0x35, 0x97],
                 [0xfb, 0xc8, 0x6c, 0x4f],
                 [0x96, 0xae, 0xd2, 0xfb],
                 [0x7c, 0x9b, 0xba, 0x53]],
                [[0x25, 0xbd, 0xb6, 0x4c],
                 [0xd1, 0x11, 0x3a, 0x4c],
                 [0xa9, 0xd1, 0x33, 0xc0],
                 [0xad, 0x68, 0x8e, 0xb0]],
                [[0xd4, 0x7c, 0xca, 0x11],
                 [0xd1, 0x83, 0xf2, 0xf9],
                 [0xc6, 0x9d, 0xb8, 0x15],
                 [0xf8, 0x87, 0xbc, 0xbc]]
            ],
            [
                [[0xf1, 0xc1, 0x7c, 0x5d],
                 [0x00, 0x92, 0xc8, 0xb5],
                 [0x6f, 0x4c, 0x8b, 0xd5],
                 [0x55, 0xef, 0x32, 0x0c]],
                [[0xa1, 0x78, 0x10, 0x4c],
                 [0x63, 0x4f, 0xe8, 0xd5],
                 [0xa8, 0x29, 0x3d, 0x03],
                 [0xfc, 0xdf, 0x23, 0xfe]],
                [[0xa1, 0x78, 0x10, 0x4c],
                 [0x4f, 0xe8, 0xd5, 0x63],
                 [0x3d, 0x03, 0xa8, 0x29],
                 [0xfe, 0xfc, 0xdf, 0x23]],
                [[0x4b, 0x2c, 0x33, 0x37],
                 [0x86, 0x4a, 0x9d, 0xd2],
                 [0x8d, 0x89, 0xf4, 0x18],
                 [0x6d, 0x80, 0xe8, 0xd8]],
                [[0x6d, 0x11, 0xdb, 0xca],
                 [0x88, 0x0b, 0xf9, 0x00],
                 [0xa3, 0x3e, 0x86, 0x93],
                 [0x7a, 0xfd, 0x41, 0xfd]]
            ],
            [
                [[0x26, 0x3d, 0xe8, 0xfd],
                 [0x0e, 0x41, 0x64, 0xd2],
                 [0x2e, 0xb7, 0x72, 0x8b],
                 [0x17, 0x7d, 0xa9, 0x25]],
                [[0xf7, 0x27, 0x9b, 0x54],
                 [0xab, 0x83, 0x43, 0xb5],
                 [0x31, 0xa9, 0x40, 0x3d],
                 [0xf0, 0xff, 0xd3, 0x3f]],
                [[0xf7, 0x27, 0x9b, 0x54],
                 [0x83, 0x43, 0xb5, 0xab],
                 [0x40, 0x3d, 0x31, 0xa9],
                 [0x3f, 0xf0, 0xff, 0xd3]],
                [[0x14, 0x46, 0x27, 0x34],
                 [0x15, 0x16, 0x46, 0x2a],
                 [0xb5, 0x15, 0x56, 0xd8],
                 [0xbf, 0xec, 0xd7, 0x43]],
                [[0x4e, 0x5f, 0x84, 0x4e],
                 [0x54, 0x5f, 0xa6, 0xa6],
                 [0xf7, 0xc9, 0x4f, 0xdc],
                 [0x0e, 0xf3, 0xb2, 0x4f]]
            ],
            [
                [[0x5a, 0x19, 0xa3, 0x7a],
                 [0x41, 0x49, 0xe0, 0x8c],
                 [0x42, 0xdc, 0x19, 0x04],
                 [0xb1, 0x1f, 0x65, 0x0c]],
                [[0xbe, 0xd4, 0x0a, 0xda],
                 [0x83, 0x3b, 0xe1, 0x64],
                 [0x2c, 0x86, 0xd4, 0xf2],
                 [0xc8, 0xc0, 0x4d, 0xfe]],
                [[0xbe, 0xd4, 0x0a, 0xda],
                 [0x3b, 0xe1, 0x64, 0x83],
                 [0xd4, 0xf2, 0x2c, 0x86],
                 [0xfe, 0xc8, 0xc0, 0x4d]],
                [[0x00, 0xb1, 0x54, 0xfa],
                 [0x51, 0xc8, 0x76, 0x1b],
                 [0x2f, 0x89, 0x6d, 0x99],
                 [0xd1, 0xff, 0xcd, 0xea]],
                [[0xea, 0xb5, 0x31, 0x7f],
                 [0xd2, 0x8d, 0x2b, 0x8d],
                 [0x73, 0xba, 0xf5, 0x29],
                 [0x21, 0xd2, 0x60, 0x2f]]
            ],
            [
                [[0xea, 0x04, 0x65, 0x85],
                 [0x83, 0x45, 0x5d, 0x96],
                 [0x5c, 0x33, 0x98, 0xb0],
                 [0xf0, 0x2d, 0xad, 0xc5]],
                [[0x87, 0xf2, 0x4d, 0x97],
                 [0xec, 0x6e, 0x4c, 0x90],
                 [0x4a, 0xc3, 0x46, 0xe7],
                 [0x8c, 0xd8, 0x95, 0xa6]],
                [[0x87, 0xf2, 0x4d, 0x97],
                 [0x6e, 0x4c, 0x90, 0xec],
                 [0x46, 0xe7, 0x4a, 0xc3],
                 [0xa6, 0x8c, 0xd8, 0x95]],
                [[0x47, 0x40, 0xa3, 0x4c],
                 [0x37, 0xd4, 0x70, 0x9f],
                 [0x94, 0xe4, 0x3a, 0x42],
                 [0xed, 0xa5, 0xa6, 0xbc]],
                [[0xac, 0x19, 0x28, 0x57],
                 [0x77, 0xfa, 0xd1, 0x5c],
                 [0x66, 0xdc, 0x29, 0x00],
                 [0xf3, 0x21, 0x41, 0x6e]]
            ],
            [
                [[0xeb, 0x59, 0x8b, 0x1b],
                 [0x40, 0x2e, 0xa1, 0xc3],
                 [0xf2, 0x38, 0x13, 0x42],
                 [0x1e, 0x84, 0xe7, 0xd2]],
                [[0xe9, 0xcb, 0x3d, 0xaf],
                 [0x09, 0x31, 0x32, 0x2e],
                 [0x89, 0x07, 0x7d, 0x2c],
                 [0x72, 0x5f, 0x94, 0xb5]],
                [[0xe9, 0xcb, 0x3d, 0xaf],
                 [0x31, 0x32, 0x2e, 0x09],
                 [0x7d, 0x2c, 0x89, 0x07],
                 [0xb5, 0x72, 0x5f, 0x94]],
                [[0xd0, 0xc9, 0xe1, 0xb6],
                 [0x14, 0xee, 0x3f, 0x63],
                 [0xf9, 0x25, 0x0c, 0x0c],
                 [0xa8, 0x89, 0xc8, 0xa6]]
            ],
            [
                [[0x39, 0x02, 0xdc, 0x19],
                 [0x25, 0xdc, 0x11, 0x6a],
                 [0x84, 0x09, 0x85, 0x0b],
                 [0x1d, 0xfb, 0x97, 0x32]]
            ]
        ]
        self.assertEqual(execution_data[0][0], encryptor._in_to_state(_in))
        encryptor._add_round_key(execution_data[0][0], execution_data[0][1])
        self.assertEqual(execution_data[1][0], execution_data[0][0])

        for i, execution_datum in enumerate(execution_data):
            print(i)
            if len(execution_datum) == 5:
                print('mod 5')
                encryptor._sub_bytes(execution_datum[0])
                self.assertEqual(execution_datum[1], execution_datum[0])

                encryptor._shift_rows(execution_datum[1])
                self.assertEqual(execution_datum[2], execution_datum[1])

                encryptor._mix_columns(execution_datum[2], False)
                self.assertEqual(execution_datum[3], execution_datum[2])

                encryptor._add_round_key(execution_datum[3], execution_datum[4])
                self.assertEqual(execution_data[i + 1][0], execution_datum[3])
            elif len(execution_datum) == 4:
                print('mod 4')
                encryptor._sub_bytes(execution_datum[0])
                self.assertEqual(execution_datum[1], execution_datum[0])

                encryptor._shift_rows(execution_datum[1])
                self.assertEqual(execution_datum[2], execution_datum[1])

                encryptor._add_round_key(execution_datum[2], execution_datum[3])
                self.assertEqual(execution_data[i + 1][0], execution_datum[2])

        self.assertEqual(out, encryptor._state_to_out(execution_data[-1][0]))


class TestAESEncryptorInvCipher(unittest.TestCase):
    def test_inv_cipher(self):
        encryptor = aes._AESEncryptor(_default_key())

        _in = b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'
        out = b'\xb8\x22\xfe\x47\x6f\x13\xf2\xca\x82\x11\xed\x45\xe3\x37\x58\x82'

        self.assertEqual(_in, encryptor.inv_cipher(out))


class TestAESEncryptorUtility(unittest.TestCase):
    def test_key_expansion(self):
        print(aes._str_to_bytes('2b7e1516'))
        expected_round_keys = [
            [b'\x2b\x7e\x15\x16', b'\x28\xae\xd2\xa6', b'\xab\xf7\x15\x88', b'\x09\xcf\x4f\x3c'],
            [b'\xa0\xfa\xfe\x17', b'\x88\x54\x2c\xb1', b'\x23\xa3\x39\x39', b'\x2a\x6c\x76\x05'],
            [b'\xf2\xc2\x95\xf2', b'\x7a\x96\xb9\x43', b'\x59\x35\x80\x7a', b'\x73\x59\xf6\x7f'],
            [b'\x3d\x80\x47\x7d', b'\x47\x16\xfe\x3e', b'\x1e\x23\x7e\x44', b'\x6d\x7a\x88\x3b'],
            [b'\xef\x44\xa5\x41', b'\xa8\x52\x5b\x7f', b'\xb6\x71\x25\x3b', b'\xdb\x0b\xad\x00'],
            [b'\xd4\xd1\xc6\xf8', b'\x7c\x83\x9d\x87', b'\xca\xf2\xb8\xbc', b'\x11\xf9\x15\xbc'],
            [b'\x6d\x88\xa3\x7a', b'\x11\x0b\x3e\xfd', b'\xdb\xf9\x86\x41', b'\xca\x00\x93\xfd'],
            [b'\x4e\x54\xf7\x0e', b'\x5f\x5f\xc9\xf3', b'\x84\xa6\x4f\xb2', b'\x4e\xa6\xdc\x4f'],
            [b'\xea\xd2\x73\x21', b'\xb5\x8d\xba\xd2', b'\x31\x2b\xf5\x60', b'\x7f\x8d\x29\x2f'],
            [b'\xac\x77\x66\xf3', b'\x19\xfa\xdc\x21', b'\x28\xd1\x29\x41', b'\x57\x5c\x00\x6e'],
            [b'\xd0\x14\xf9\xa8', b'\xc9\xee\x25\x89', b'\xe1\x3f\x0c\xc8', b'\xb6\x63\x0c\xa6']
        ]
        encryptor = aes._AESEncryptor(_default_key())
        round_keys = encryptor._round_keys
        for i, round_key in enumerate(round_keys):
            for j, word in enumerate(round_key):
                print(f'{i} {j}')
                self.assertEqual(list(expected_round_keys[i][j]), word)

    def test_in_to_state(self):
        self.assertEqual(
            [[0x32, 0x43, 0xf6, 0xa8],
             [0x88, 0x5a, 0x30, 0x8d],
             [0x31, 0x31, 0x98, 0xa2],
             [0xe0, 0x37, 0x07, 0x34]],
            aes._AESEncryptor._in_to_state(b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34')
        )

    def test_state_to_out(self):
        self.assertEqual(
            b'\x39\x02\xdc\x19\x25\xdc\x11\x6a\x84\x09\x85\x0b\x1d\xfb\x97\x32',
            aes._AESEncryptor._state_to_out(
                [[0x39, 0x02, 0xdc, 0x19],
                 [0x25, 0xdc, 0x11, 0x6a],
                 [0x84, 0x09, 0x85, 0x0b],
                 [0x1d, 0xfb, 0x97, 0x32]])
        )

    def test_sub_bytes(self):
        state = [[0x19, 0xa0, 0x9a, 0xe9],
                 [0x3d, 0xf4, 0xc6, 0xf8],
                 [0xe3, 0xe2, 0x8d, 0x48],
                 [0xbe, 0x2b, 0x2a, 0x08]]
        expected_state = [[0xd4, 0xe0, 0xb8, 0x1e],
                          [0x27, 0xbf, 0xb4, 0x41],
                          [0x11, 0x98, 0x5d, 0x52],
                          [0xae, 0xf1, 0xe5, 0x30]]
        aes._AESEncryptor._sub_bytes(state)
        self.assertEqual(expected_state, state)

    def test_shift_rows(self):
        state = [[0xd4, 0xe0, 0xb8, 0x1e],
                 [0x27, 0xbf, 0xb4, 0x41],
                 [0x11, 0x98, 0x5d, 0x52],
                 [0xae, 0xf1, 0xe5, 0x30]]
        aes._AESEncryptor._shift_rows(state)
        self.assertEqual(
            [[0xd4, 0xe0, 0xb8, 0x1e],
             [0xbf, 0xb4, 0x41, 0x27],
             [0x5d, 0x52, 0x11, 0x98],
             [0x30, 0xae, 0xf1, 0xe5]],
            state
        )

    def test_mix_columns(self):
        state = [[0xd4, 0xe0, 0xb8, 0x1e],
                 [0xbf, 0xb4, 0x41, 0x27],
                 [0x5d, 0x52, 0x11, 0x98],
                 [0x30, 0xae, 0xf1, 0xe5]]
        aes._AESEncryptor._mix_columns(state, False)
        self.assertEqual(
            [[0x04, 0xe0, 0x48, 0x28],
             [0x66, 0xcb, 0xf8, 0x06],
             [0x81, 0x19, 0xd3, 0x26],
             [0xe5, 0x9a, 0x7a, 0x4c]],
            state
        )

    def test_add_round_key(self):
        state = [[0x32, 0x88, 0x31, 0xe0],
                 [0x43, 0x5a, 0x31, 0x37],
                 [0xf6, 0x30, 0x98, 0x07],
                 [0xa8, 0x8d, 0xa2, 0x34]]
        round_key = [[0x2b, 0x28, 0xab, 0x09],
                     [0x7e, 0xae, 0xf7, 0xcf],
                     [0x15, 0xd2, 0x15, 0x4f],
                     [0x16, 0xa6, 0x88, 0x3c]]
        aes._AESEncryptor._add_round_key(state, round_key)
        self.assertEqual([[0x19, 0xa0, 0x9a, 0xe9],
                          [0x3d, 0xf4, 0xc6, 0xf8],
                          [0xe3, 0xe2, 0x8d, 0x48],
                          [0xbe, 0x2b, 0x2a, 0x08]], state)

    def test_inv_sub_bytes(self):
        state = [[0x00, 0x01, 0x02, 0x03],
                 [0x10, 0x20, 0x30, 0x40],
                 [0xf8, 0xf9, 0xfa, 0xfb],
                 [0xfc, 0xfd, 0xfe, 0xff]]
        expected_state = [[0x52, 0x09, 0x6a, 0xd5],
                          [0x7c, 0x54, 0x08, 0x72],
                          [0xe1, 0x69, 0x14, 0x63],
                          [0x55, 0x21, 0x0c, 0x7d]]
        aes._AESEncryptor._inv_sub_bytes(state)
        self.assertEqual(expected_state, state)

    def test_inv_shift_rows(self):
        state = [[1, 2, 3, 4], [2, 3, 4, 1], [3, 4, 1, 2], [4, 1, 2, 3]]
        aes._AESEncryptor._inv_shift_rows(state)
        self.assertEqual(
            [[1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3, 4]],
            state
        )

    def test_inv_mix_columns(self):
        state = [[0x04, 0xe0, 0x48, 0x28],
                 [0x66, 0xcb, 0xf8, 0x06],
                 [0x81, 0x19, 0xd3, 0x26],
                 [0xe5, 0x9a, 0x7a, 0x4c]]
        aes._AESEncryptor._mix_columns(state, True)
        self.assertEqual(
            [[0xd4, 0xe0, 0xb8, 0x1e],
             [0xbf, 0xb4, 0x41, 0x27],
             [0x5d, 0x52, 0x11, 0x98],
             [0x30, 0xae, 0xf1, 0xe5]],
            state
        )

    def test_rot_word(self):
        self.assertEqual([2, 3, 4, 1], aes._AESEncryptor._rot_word([1, 2, 3, 4]))

    def test_sub_word(self):
        word = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]
        expected = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                    0xca, 0xb7, 0x04, 0x09, 0x53, 0xd0, 0x51, 0xcd,
                    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
        aes._AESEncryptor._sub_word(word)
        self.assertEqual(expected, word)

    def test_xor_list(self):
        self.assertEqual([5, 1, 1, 5], aes._AESEncryptor._xor_list([1, 2, 3, 4], [4, 3, 2, 1]))
        with self.assertRaises(AssertionError):
            aes._AESEncryptor._xor_list([1, 2, 3], [1, 2, 3])
        with self.assertRaises(AssertionError):
            aes._AESEncryptor._xor_list([1, 2, 3, 4], [1, 2, 3])


if __name__ == '__main__':
    unittest.main()
