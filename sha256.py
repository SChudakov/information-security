from typing import List


class SHA256:
    _block_size = 512
    _word_size = 32
    _message_digest_size = 256
    _constants = (
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    )
    _H_0 = (0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19)

    @staticmethod
    def hash(message: bytes):
        assert len(message) * 8 < 2 ** 64
        message_blocks = SHA256._preprocessing(message)
        h0, h1, h2, h3, h4, h5, h6, h7 = SHA256._H_0

        for message_block in message_blocks:
            W = []
            for t in range(0, 64):
                if t <= 15:
                    W.append(int.from_bytes(message_block[t * 4:t * 4 + 4], 'big'))
                else:
                    summand1 = SHA256._sigma_1_256(W[t - 2])
                    summand2 = W[t - 7]
                    summand3 = SHA256._sigma_0_256(W[t - 15])
                    summand4 = W[t - 16]

                    schedule = (summand1 + summand2 + summand3 + summand4) % 2 ** 32
                    W.append(schedule)

            assert len(W) == 64

            a, b, c, d, e, f, g, h = (h0, h1, h2, h3, h4, h5, h6, h7)

            for t in range(64):
                t1 = (h + SHA256._sum_1_256(e) + SHA256._Ch(e, f, g)
                      + SHA256._constants[t] + W[t]) % 2 ** 32

                t2 = (SHA256._sum_0_256(a) + SHA256._Maj(a, b, c)) % 2 ** 32

                h = g
                g = f
                f = e
                e = (d + t1) % 2 ** 32
                d = c
                c = b
                b = a
                a = (t1 + t2) % 2 ** 32

            h0 = (h0 + a) % 2 ** 32
            h1 = (h1 + b) % 2 ** 32
            h2 = (h2 + c) % 2 ** 32
            h3 = (h3 + d) % 2 ** 32
            h4 = (h4 + e) % 2 ** 32
            h5 = (h5 + f) % 2 ** 32
            h6 = (h6 + g) % 2 ** 32
            h7 = (h7 + h) % 2 ** 32

        return (h0.to_bytes(4, 'big') + h1.to_bytes(4, 'big') +
                h2.to_bytes(4, 'big') + h3.to_bytes(4, 'big') +
                h4.to_bytes(4, 'big') + h5.to_bytes(4, 'big') +
                h6.to_bytes(4, 'big') + h7.to_bytes(4, 'big'))

    @staticmethod
    def _preprocessing(message) -> List[bytes]:
        padded = SHA256._pad_message(message)
        return SHA256._parse_message_into_blocks(padded)

    @staticmethod
    def _pad_message(message: bytes) -> bytes:
        if len(message) > 0 and (len(message) * 8) % 512 == 0:
            return message

        padded_message = [byte for byte in message]
        message_bits = (len(message) * 8) % 512

        if 0 <= message_bits <= 512 - 64 - 8:
            padded_message.append(0b10000000)
            padded_message.extend([0] * (((512 - 64 - 8) - message_bits) // 8))
        else:
            padded_message.append(0b10000000)
            padded_message.extend([0] * ((512 - message_bits) // 8))
            padded_message.extend([0] * ((512 - 64 - 8) // 8))
        padded_message.extend((len(message) * 8).to_bytes(8, 'big'))
        return bytes(padded_message)

    @staticmethod
    def _int_to_bytes(value: int, num_bytes: int) -> List[int]:
        result = list()
        for _ in range(num_bytes):
            result.append(value & 0xff)
            value >>= 8
        return result

    @staticmethod
    def _parse_message_into_blocks(message: bytes) -> List[bytes]:
        num_bytes = 512 // 8
        return [message[i:i + num_bytes] for i in range(0, len(message), num_bytes)]

    @staticmethod
    def _Ch(x: int, y: int, z: int):
        return (x & y) ^ ((~x) & z)

    @staticmethod
    def _Maj(x: int, y: int, z: int):
        return (x & y) ^ (x & z) ^ (y & z)

    @staticmethod
    def _sum_0_256(x: int):
        return SHA256._ROTR(x, 2) ^ SHA256._ROTR(x, 13) ^ SHA256._ROTR(x, 22)

    @staticmethod
    def _sum_1_256(x: int):
        return SHA256._ROTR(x, 6) ^ SHA256._ROTR(x, 11) ^ SHA256._ROTR(x, 25)

    @staticmethod
    def _sigma_0_256(x: int):
        return SHA256._ROTR(x, 7) ^ SHA256._ROTR(x, 18) ^ (x >> 3)

    @staticmethod
    def _sigma_1_256(x: int):
        return SHA256._ROTR(x, 17) ^ SHA256._ROTR(x, 19) ^ (x >> 10)

    @staticmethod
    def _ROTL(word: int, bits: int):
        return ((word << bits) & 0xffffffff) | (word >> (32 - bits))

    @staticmethod
    def _ROTR(word: int, bits: int):
        return ((word >> bits) & 0xffffffff) | (word << (32 - bits))


if __name__ == '__main__':
    message = b'Secret message'
    print(f'hashed message: {SHA256.hash(message)}')
