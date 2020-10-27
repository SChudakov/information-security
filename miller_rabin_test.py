import unittest
from miller_rabin import MillerRabin

_default_k = 20


class MillerRabinTest(unittest.TestCase):
    def test_miller_rabin(self):
        self.assertFalse(MillerRabin.is_prime(1))
        self.assertFalse(MillerRabin.is_prime(9))
        self.assertFalse(MillerRabin.is_prime(121))
        self.assertFalse(MillerRabin.is_prime(255))
        self.assertFalse(MillerRabin.is_prime(33))

        self.assertTrue(MillerRabin.is_prime(2)),
        self.assertTrue(MillerRabin.is_prime(3))
        self.assertTrue(MillerRabin.is_prime(5))
        self.assertTrue(MillerRabin.is_prime(7))
        self.assertTrue(MillerRabin.is_prime(11))
        self.assertTrue(MillerRabin.is_prime(13))
        self.assertTrue(MillerRabin.is_prime(17))
