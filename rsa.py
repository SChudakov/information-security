import os
import math
import random
import kupyna
import sympy

from typing import List
from miller_rabin import MillerRabin

_BITS_IN_BYTE = 8


def _pad(message: bytes, block_size: int) -> bytes:
    assert block_size < 255

    if len(message) > 0 and len(message) % block_size == 0:
        return message
    padding_len = block_size - (len(message) % block_size)
    padding = bytes([padding_len] * padding_len)
    return message + padding


def _un_pad(message: bytes, block_size: int) -> bytes:
    assert block_size < 255

    assert len(message) > 0 and len(message) % block_size == 0
    padding_len = message[-1]
    if padding_len > block_size:
        return message

    ciphertext, padding = message[:-padding_len], message[-padding_len:]
    if all(byte == padding_len for byte in padding):
        return ciphertext
    return message


def _split_blocks(message: bytes, block_size) -> List[bytes]:
    assert (len(message) > 0 and len(message) % block_size == 0)
    return [message[i:i + block_size] for i in range(0, len(message), block_size)]


class RSA:
    _prime_bits = 1024
    _max_prime_bits = 1024

    def __init__(self, key_length=_prime_bits):
        assert key_length in {512, 1024, 2048}

        self.key_length = key_length
        while True:
            self._p = RSA._large_prime(key_length // 2)
            self._q = RSA._large_prime(key_length // 2)
            self.n = self._p * self._q
            if self.n.bit_length() == key_length:
                break

        self._message_block_size = self.key_length // _BITS_IN_BYTE - 1
        self._cipher_block_size = self.key_length // _BITS_IN_BYTE
        self._lambda_n = RSA._lcm(self._p - 1, self._q - 1)
        self._e = 2 ** 16 + 1
        self._d = RSA._inv_mod(self._e, self._lambda_n)

        self._d_p = self._d % (self._p - 1)
        self._d_q = self._d % (self._q - 1)
        self._q_inv = RSA._inv_mod(self._q, self._p)

    def encrypt(self, message: bytes) -> bytes:
        plaintext = _pad(message, self._message_block_size)

        blocks = []
        for plaintext_block in _split_blocks(plaintext, self._message_block_size):
            blocks.append(self._encrypt_block(plaintext_block))

        return b''.join(blocks)

    def decrypt(self, message: bytes) -> bytes:
        blocks = list()
        for ciphertext_block in _split_blocks(message, self._cipher_block_size):
            blocks.append(self._decrypt_block(ciphertext_block))

        joined_blocks = b''.join(blocks)
        return _un_pad(joined_blocks, self._message_block_size)

    def _encrypt_block(self, block: bytes) -> bytes:
        m = int.from_bytes(block, 'little')
        c = pow(m, self._e, self.n)

        return c.to_bytes(self._cipher_block_size, 'little')

    def _decrypt_block(self, encrypted_block: bytes) -> bytes:
        c = int.from_bytes(encrypted_block, 'little')
        # m = pow(c, self._d, self.n)

        m1 = pow(c, self._d_p, self._p)
        m2 = pow(c, self._d_q, self._q)

        h = (self._q_inv * (m1 - m2)) % self._p
        m = m2 + h * self._q

        return m.to_bytes(self._message_block_size, 'little')

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
        if b == 0:
            return a
        else:
            return RSA._gcd(b, a % b)


class RSA_OAEP:
    _kupyna_max_bits = 512
    _prime_bit_length_to_k = {512: (8, 8), 1024: (512, 8)}

    def __init__(self, key_length):
        assert key_length in RSA_OAEP._prime_bit_length_to_k

        self._n = key_length
        self._rsa = RSA(key_length)
        self._k0, self._k1 = RSA_OAEP._prime_bit_length_to_k[key_length]
        self._block_length = self._n - self._k0 - self._k1
        self._padded_block_length = self._n - self._k0

        self._G = kupyna.Kupyna(self._padded_block_length)
        self._H = kupyna.Kupyna(self._k0)

    def encrypt(self, message: bytes) -> bytes:
        plaintext = _pad(message, self._block_length // _BITS_IN_BYTE)

        blocks = []
        for plaintext_block in _split_blocks(plaintext, self._block_length // _BITS_IN_BYTE):
            blocks.append(self._encrypt_block(plaintext_block))

        return b''.join(blocks)

    def decrypt(self, message: bytes) -> bytes:
        blocks = list()
        for ciphertext_block in _split_blocks(message, (self._n * 2) // _BITS_IN_BYTE):
            blocks.append(self._decrypt_block(ciphertext_block))

        joined_blocks = b''.join(blocks)
        return _un_pad(joined_blocks, self._block_length // _BITS_IN_BYTE)

    def _encrypt_block(self, block: bytes) -> bytes:
        assert len(block) == self._block_length // _BITS_IN_BYTE
        padded_block = self._pad_block(block)

        r = os.urandom(self._k0 // _BITS_IN_BYTE)
        r_hashed = self._G.hash(r)
        X = self._xor(padded_block, r_hashed)
        X_hashed = self._H.hash(X)
        Y = self._xor(r, X_hashed)
        XY = b''.join((X, Y))

        return self._rsa.encrypt(XY)

    def _decrypt_block(self, block: bytes) -> bytes:
        # assert len(block) == self._n // _BITS_IN_BYTE
        block = self._rsa.decrypt(block)

        X_byte_length = self._padded_block_length // _BITS_IN_BYTE
        X, Y = block[0:X_byte_length], block[X_byte_length:]
        X_hashed = self._H.hash(X)
        r = self._xor(Y, X_hashed)
        r_hashed = self._G.hash(r)
        padded_block = self._xor(X, r_hashed)

        return self._un_pad_block(padded_block)

    def _pad_block(self, block: bytes) -> bytes:
        assert len(block) == self._block_length // 8
        pad_bytes = self._k1 // _BITS_IN_BYTE
        return block + (b'\x00' * pad_bytes)

    def _un_pad_block(self, padded_block: bytes) -> bytes:
        assert len(padded_block) == self._padded_block_length // _BITS_IN_BYTE
        pad_bytes = self._k1 // _BITS_IN_BYTE
        return padded_block[:-pad_bytes]

    @staticmethod
    def _xor(a: bytes, b: bytes) -> bytes:
        assert len(a) == len(b)
        return bytes([b1 ^ b2 for b1, b2 in zip(a, b)])


if __name__ == '__main__':
    value = 7771896050098244257202839432925444989772522661541251252105145542259454635693527451910986045432100368018836965267672036415514870277213750572441900778156150
    print(value.bit_length())
