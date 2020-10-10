import unittest
import rc4


class RC4Test(unittest.TestCase):
    def test_Key_Plaintext(self):
        self._helper_test_encrypt_decrypt(
            b'Key',
            b'\xEB\x9F\x77\x81\xB7\x34\xCA\x72\xA7\x19',
            b'Plaintext',
            b'\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3'
        )

    def test_Wiki_Pedia(self):
        self._helper_test_encrypt_decrypt(
            b'Wiki',
            b'\x60\x44\xDB\x6D\x41\xB7',
            b'pedia',
            b'\x10\x21\xBF\x04\x20'
        )

    def test_Secret_Attack_at_dawm(self):
        self._helper_test_encrypt_decrypt(
            b'Secret',
            b'\x04\xD4\x6B\x05\x3C\xA8\x7B\x59',
            b'Attack at dawn',
            b'\x45\xA0\x1F\x64\x5F\xC3\x5B\x38\x35\x52\x54\x4B\x9B\xF5'
        )

    def _helper_test_encrypt_decrypt(self,
                                     key: bytes,
                                     key_stream: bytes,
                                     plaintext: bytes,
                                     ciphertext: bytes):
        encryptor = rc4.RC4(key)
        decryptor = rc4.RC4(key)

        encrypted = encryptor.transform(plaintext)
        decrypted = decryptor.transform(encrypted)

        self.assertEqual(ciphertext, encrypted)
        self.assertEqual(plaintext, decrypted)
        print(f'\ndecrypted: {decrypted.decode("utf-8")}')
