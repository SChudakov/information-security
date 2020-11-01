import unittest
import sympy
from rsa import RSA, RSA_OAEP, _pad, _un_pad, _split_blocks


class RSATest(unittest.TestCase):
    def test_encrypt_block_decrypt_block(self):
        algorithm = RSA(512)
        self.helper_test_encrypt_block_decrypt_block(algorithm,
                                                     b'vp\x86\xfd\xbc\xbc\xa5[s;\xa7\xbf\xb0(\xf6!\x91\xe2\xb49\xd8\x06[\xf7Z+\xde\xd6\x1dI\xd5\xca\x9dt-6y\xd5\xb5cH\xe3ga\xf3\x00*^P\x9aB&\xd9ZAL\xf1SS\xe8\x8f<d\x94')
        self.helper_test_encrypt_block_decrypt_block(algorithm,
                                                     b"2\x80\x15P&\xac\xe3\xa7Y/48\x95J\xe6m\xf1,\xd2d\xc0\x0c\x15D\xf6\x93\xc1g*T\x1e'\xbe|W\x9e\x1cf?&H\xd5\xa1t\xd3\x12&\xbf\x82\x80(e?\x81\xdd\x97x\x0bk\x1a.\xca\xad\x1d")
        self.helper_test_encrypt_block_decrypt_block(algorithm, b'\x00\x00\x00\x00\x00')
        self.helper_test_encrypt_block_decrypt_block(algorithm, b'message')
        self.helper_test_encrypt_block_decrypt_block(algorithm,
                                                     b'RSA is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest.')

    def helper_test_encrypt_block_decrypt_block(self, algorithm, message):
        encrypted = algorithm.encrypt(message)
        decrypted = algorithm.decrypt(encrypted)
        print(f'encrypted: {encrypted}')
        print(f'decrypted: {decrypted}')
        self.assertEqual(message, decrypted)

    def test_large_prime(self):
        print()
        for i in range(5):
            large_prime = RSA._large_prime(128)
            print(f'large_prime: {large_prime}')
            self.assertTrue(sympy.isprime(large_prime))

    def test_gcd(self):
        self.assertEqual(1, RSA._gcd(1, 1))
        self.assertEqual(4, RSA._gcd(8, 12))
        self.assertEqual(11, RSA._gcd(33, 121))

    def test_lcm(self):
        self.assertEqual(1, RSA._lcm(1, 1))
        self.assertEqual(15, RSA._lcm(3, 5))
        self.assertEqual(24, RSA._lcm(8, 12))

    def test_inv_mod(self):
        self.assertEqual(989145189, RSA._inv_mod(1234567, 1000000007))


class RSA_OAEPTest(unittest.TestCase):

    def test_init(self):
        algorithm = RSA_OAEP(512)
        self.assertEqual(512 - 16, algorithm._block_length)
        self.assertEqual(512 - 8, algorithm._padded_block_length)
        algorithm = RSA_OAEP(1024)
        self.assertEqual(1024 - 512 - 8, algorithm._block_length)
        self.assertEqual(1024 - 512, algorithm._padded_block_length)
        with self.assertRaises(AssertionError):
            _ = RSA_OAEP(126)
            _ = RSA_OAEP(760)

    def test_encrypt_decrypt(self):
        algorithm1 = RSA_OAEP(512)
        self._helper_test_encrypt_decrypt(algorithm1, b'message')
        self._helper_test_encrypt_decrypt(algorithm1,
                                          b'RSA is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest.')

        algorithm2 = RSA_OAEP(1024)
        self._helper_test_encrypt_decrypt(algorithm2, b'message')
        self._helper_test_encrypt_decrypt(algorithm2,
                                          b'RSA is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest.')

    def _helper_test_encrypt_decrypt(self, algorithm, message):
        encrypted = algorithm.encrypt(message)
        decrypted = algorithm.decrypt(encrypted)
        print(f'encrypted: {encrypted}')
        print(f'decrypted1: {decrypted}')
        self.assertEqual(message, decrypted)

    def test_encrypt_block(self):
        algorithm1 = RSA_OAEP(512)
        message1 = b'\x00' * (algorithm1._block_length // 8)
        message2 = b'\x00' * ((algorithm1._block_length + 8) // 8)
        self.assertEqual(128, len(algorithm1._encrypt_block(message1)))
        with self.assertRaises(AssertionError):
            algorithm1._encrypt_block(message2)

        algorithm2 = RSA_OAEP(1024)
        message3 = b'\x00' * (algorithm2._block_length // 8)
        message4 = b'\x00' * (1024 // 8)
        self.assertEqual(256, len(algorithm2._encrypt_block(message3)))
        with self.assertRaises(AssertionError):
            algorithm2._encrypt_block(message4)

    def test_decrypt_block(self):
        algorithm1 = RSA_OAEP(512)
        encrypted1 = algorithm1._encrypt_block(b'\x00' * (algorithm1._block_length // 8))
        self.assertEqual(algorithm1._block_length // 8, len(algorithm1._decrypt_block(encrypted1)))

        algorithm2 = RSA_OAEP(1024)
        encrypted3 = algorithm2._encrypt_block(b'\x00' * (algorithm2._block_length // 8))
        self.assertEqual(algorithm2._block_length // 8, len(algorithm2._decrypt_block(encrypted3)))

    def test_encrypt_decrypt_block(self):
        algorithm1 = RSA_OAEP(512)
        self._helper_test_encrypt_decrypt_block(algorithm1, b'\x10' * (algorithm1._block_length // 8))
        self._helper_test_encrypt_decrypt_block(algorithm1, b'message' + b'7' * 55)

        algorithm2 = RSA_OAEP(1024)
        self._helper_test_encrypt_decrypt_block(algorithm2, b'\x10' * (algorithm2._block_length // 8))

    def _helper_test_encrypt_decrypt_block(self, algorithm, message):
        encrypted = algorithm._encrypt_block(message)
        decrypted = algorithm._decrypt_block(encrypted)
        print(f'encrypted: {encrypted}')
        print(f'decrypted: {decrypted}')
        self.assertEqual(message, decrypted)

    def test_pad_block(self):
        algorithm = RSA_OAEP(512)
        self.assertEqual(algorithm._padded_block_length // 8,
                         len(algorithm._pad_block(b'\x00' * (algorithm._block_length // 8))))

        algorithm = RSA_OAEP(1024)
        self.assertEqual(algorithm._padded_block_length // 8,
                         len(algorithm._pad_block(b'\x00' * (algorithm._block_length // 8))))

    def test_un_pad_block(self):
        algorithm = RSA_OAEP(512)
        self.assertEqual(algorithm._block_length // 8,
                         len(algorithm._un_pad_block(b'\x00' * (algorithm._padded_block_length // 8))))

        algorithm = RSA_OAEP(1024)
        self.assertEqual(algorithm._block_length // 8,
                         len(algorithm._un_pad_block(b'\x00' * (algorithm._padded_block_length // 8))))

    def test_pad(self):
        algorithm = RSA_OAEP(512)
        block_bytes = algorithm._block_length // 8
        self.assertEqual(block_bytes, len(_pad(b'', block_bytes)))
        self.assertEqual(block_bytes, len(_pad(b'\x00' * 10, block_bytes)))
        self.assertEqual(block_bytes * 2, len(_pad(b'\x00' * (block_bytes + 1), block_bytes)))

    def test_un_pad(self):
        algorithm = RSA_OAEP(512)
        block_bytes = algorithm._block_length // 8
        self.assertEqual(0, len(_un_pad(
            b'>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>',
            algorithm._block_length // 8)))
        self.assertEqual(10, len(_un_pad(
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x004444444444444444444444444444444444444444444444444444',
            algorithm._block_length // 8)))
        self.assertEqual(block_bytes + 1, len(_un_pad(
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00=============================================================',
            algorithm._block_length // 8)))

    def test_split_blocks(self):
        algorithm = RSA_OAEP(512)
        block_bytes = algorithm._block_length // 8
        blocks = _split_blocks(b'\x00' * (block_bytes * 4), 62)
        self.assertEqual(4, len(blocks))
        for block in blocks:
            self.assertEqual(len(block), block_bytes)

    def test_xor(self):
        self.assertEqual(b'\x01\x01', RSA_OAEP._xor(b'\x01\x00', b'\x00\x01'))
        with self.assertRaises(AssertionError):
            RSA_OAEP._xor(b'', b'\x00')


if __name__ == '__main__':
    unittest.main()
