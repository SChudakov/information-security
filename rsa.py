import math
import random

from miller_rabin import MillerRabin


class RSA:
    _prime_bits = 1024

    def __init__(self):
        self._p = RSA._large_prime(RSA._prime_bits)
        self._q = RSA._large_prime(RSA._prime_bits)
        self._n = self._p * self._q
        self._key_length = self._n.bit_length()
        self._lambda_n = RSA._lcm(self._p - 1, self._q - 1)
        self._e = 2 ** 16 + 1
        self._d = RSA._inv_mod(self._e, self._lambda_n)

        self._d_p = self._d % (self._p - 1)
        self._d_q = self._d % (self._q - 1)
        self._q_inv = RSA._inv_mod(self._q, self._p)

    def encrypt(self, message: bytes) -> bytes:
        int_value = int.from_bytes(message, 'little')
        c = pow(int_value, self._e, self._n)

        c_byte_length = c.bit_length() // 8 if c.bit_length() % 8 == 0 else c.bit_length() // 8 + 1
        return c.to_bytes(c_byte_length, 'little')

    def decrypt(self, ciphertext: bytes) -> bytes:
        c = int.from_bytes(ciphertext, 'little')

        m1 = pow(c, self._d_p, self._p)
        m2 = pow(c, self._d_q, self._q)

        h = (self._q_inv * (m1 - m2)) % self._p
        m = m2 + h * self._q

        m_byte_length = m.bit_length() // 8 if m.bit_length() % 8 == 0 else m.bit_length() // 8 + 1
        return m.to_bytes(m_byte_length, 'little')

    @staticmethod
    def _inv_mod(value: int, mod: int):
        g, x, y = RSA._extended_gcd(value, mod)
        if g != 1:
            raise Exception(f'Modular inverse does not exist for value {value} and modulo {mod}')
        else:
            return x % mod

    @staticmethod
    def _extended_gcd(a: int, b: int):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = RSA._extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x

    @staticmethod
    def _large_prime(bits: int):
        attempts = int(1000 * (math.log(bits, 2) + 1))
        for _ in range(attempts):
            n = random.randrange(2 ** (bits - 1), 2 ** bits)
            if MillerRabin.is_prime(n):
                return n
        raise Exception(f'Failed to generate prime number of {bits} bits after {attempts} attempts')

    @staticmethod
    def _lcm(a: int, b: int):
        return abs(a * b) // RSA._gcd(a, b)

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        if a < b:
            return RSA._gcd(b, a)
        else:
            if a % b == 0:
                return b
            else:
                return RSA._gcd(b, a % b)
