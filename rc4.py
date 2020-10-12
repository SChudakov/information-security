from typing import List


class RC4:
    def __init__(self, key):
        self._key = key
        self._S = RC4._key_scheduling_algorithm(key)
        self._encryptor = RC4._pseudo_random_generation_algorithm(self._S)

    def encrypt(self, text: bytes):
        return bytes([byte ^ next(self._encryptor) for byte in text])

    decrypt = encrypt

    @staticmethod
    def _key_scheduling_algorithm(key) -> List[int]:
        keylength = len(key)

        S = [0] * 256
        for i, _ in enumerate(S):
            S[i] = i

        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % keylength]) % 256
            S[i], S[j] = S[j], S[i]

        return S

    @staticmethod
    def _pseudo_random_generation_algorithm(S):
        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]

            K = S[(S[i] + S[j]) % 256]
            yield K
