import unittest
import sympy
from rsa import RSA


class RSATest(unittest.TestCase):

    def test_encrypt_decrypt(self):
        algorithm = RSA()
        self.helper_test_encrypt_decrypt(algorithm, b'message')
        self.helper_test_encrypt_decrypt(algorithm,
                                         b'RSA is a public-key cryptosystem that is widely used for secure data transmission.')

    def helper_test_encrypt_decrypt(self, algorithm, message):
        encrypted = algorithm.encrypt(message)
        decrypted = algorithm.decrypt(encrypted)
        print()
        print(f'encrypted: {encrypted}')
        print(f'decrypted: {decrypted}')
        self.assertEqual(decrypted, message)

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


if __name__ == '__main__':
    unittest.main()