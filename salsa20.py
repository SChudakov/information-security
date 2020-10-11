class Salsa20:
    def __init__(self, key: bytes, nonce: bytes, block_counter: bytes, rounds: int) -> None:
        assert len(key) == 32
        assert len(nonce) == 8
        assert len(block_counter) == 8
        assert rounds >= 0

        self._mask = 0xffffffff
        self._encryptor = self._byte_generator(key, nonce, block_counter, rounds)

    def encrypt(self, text):
        return bytes([byte ^ next(self._encryptor) for byte in text])

    decrypt = encrypt

    def _byte_generator(self, key: bytes, nonce: bytes, block_counter: bytes, rounds: int):
        kw = [self._byte_to_int_32(key[4 * i:4 * i + 4]) for i in range(8)]
        nw = [self._byte_to_int_32(nonce[4 * i:4 * i + 4]) for i in range(2)]
        bw = [self._byte_to_int_32(block_counter[4 * i:4 * i + 4]) for i in range(2)]
        cw = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

        s = [cw[0], kw[0], kw[1], kw[2],
             kw[3], cw[1], nw[0], nw[1],
             bw[0], bw[1], cw[2], kw[4],
             kw[5], kw[6], kw[7], cw[3]]

        while True:
            s_copy = s[:]

            for i in range(rounds):
                self._round(s_copy)

            s = [(s[i] + s_copy[i]) & self._mask for i in range(len(s))]
            for int_32 in s:
                for byte in self._int_32_to_byte(int_32):
                    yield byte

    def _round(self, S):
        rotate = self._rotate_left
        mask = self._mask

        S[4] ^= rotate((S[0] + S[12]) & mask, 7)
        S[8] ^= rotate((S[0] + S[4]) & mask, 9)
        S[12] ^= rotate((S[4] + S[8]) & mask, 13)
        S[0] ^= rotate((S[8] + S[12]) & mask, 18)

        S[9] ^= rotate((S[1] + S[5]) & mask, 7)
        S[13] ^= rotate((S[5] + S[9]) & mask, 9)
        S[1] ^= rotate((S[9] + S[13]) & mask, 13)
        S[5] ^= rotate((S[1] + S[13]) & mask, 18)

        S[14] ^= rotate((S[6] + S[10]) & mask, 7)
        S[2] ^= rotate((S[10] + S[14]) & mask, 9)
        S[6] ^= rotate((S[2] + S[14]) & mask, 13)
        S[10] ^= rotate((S[2] + S[6]) & mask, 18)

        S[3] ^= rotate((S[11] + S[15]) & mask, 7)
        S[7] ^= rotate((S[3] + S[15]) & mask, 9)
        S[11] ^= rotate((S[3] + S[7]) & mask, 13)
        S[15] ^= rotate((S[7] + S[11]) & mask, 18)

        S[0], S[1], S[2], S[3], \
        S[4], S[5], S[6], S[7], \
        S[8], S[9], S[10], S[11], \
        S[12], S[13], S[14], S[15] = S[0], S[4], S[8], S[12], \
                                     S[1], S[5], S[9], S[13], \
                                     S[2], S[6], S[10], S[14], \
                                     S[3], S[7], S[11], S[15]

    def _rotate_left(self, word, bits):
        return ((word << bits) & self._mask) | (word >> (32 - bits))

    @staticmethod
    def _byte_to_int_32(_bytes):
        assert len(_bytes) == 4
        return _bytes[0] ^ (_bytes[1] << 8) ^ (_bytes[2] << 16) ^ (_bytes[3] << 24)

    @staticmethod
    def _int_32_to_byte(int_32):
        return [(int_32 & 0xff000000) >> 24,
                (int_32 & 0x00ff0000) >> 16,
                (int_32 & 0x0000ff00) >> 8,
                int_32 & 0x000000ff]
