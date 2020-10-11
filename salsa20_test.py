import unittest
import salsa20


def _salsa20_key() -> bytes:
    return b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'


def _salsa20_nonce():
    return bytes([3, 1, 4, 1, 5, 9, 2, 6])


def _salsa20_block_counter():
    return bytes([7, 0, 0, 0, 0, 0, 0, 0])


def _salsa20_rounds():
    return 20


class Salsa20Test(unittest.TestCase):
    def test_salsa20(self):
        self._helper_test_encrypt_decrypt(
            _salsa20_key(),
            _salsa20_nonce(),
            _salsa20_block_counter(),
            _salsa20_rounds(),
            b'plaintext',
            b'\xbe\xce\x70\x84\x35\x76\x77\xca\xfe'
        )

    def _helper_test_encrypt_decrypt(self,
                                     key: bytes,
                                     nonce: bytes,
                                     block_counter: bytes,
                                     rounds: int,
                                     plaintext: bytes,
                                     ciphertext: bytes):
        encryptor = salsa20.Salsa20(key, nonce, block_counter, rounds)
        decryptor = salsa20.Salsa20(key, nonce, block_counter, rounds)

        encrypted = encryptor.encrypt(plaintext)
        decrypted = decryptor.decrypt(encrypted)

        self.assertEqual(ciphertext, encrypted)
        self.assertEqual(plaintext, decrypted)
        print(f'\ndecrypted: {decrypted.decode("utf-8")}')
