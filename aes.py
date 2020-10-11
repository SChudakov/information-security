import os
from typing import List, Any, Tuple

_State = List[List[int]]
_Word = List[int]
_SBox = Tuple[int]


def _str_to_bytes(s: str) -> bytes:
    split = [s[2 * i:2 * i + 2] for i in range(len(s) // 2)]
    mapped = list(map(lambda x: int(x, 16), split))
    return bytes(mapped)


def _print_state(state: _State):
    print('\n'.join(map(lambda x: ' '.join([hex(y) for y in x]), state)))


class AES:
    def __init__(self, **kwargs) -> None:
        if 'key_length' in kwargs:
            key_length = kwargs['key_length']
            assert key_length in (128, 192, 256)
            self._K = os.urandom(key_length // 8)
        else:
            assert 'key' in kwargs
            key = kwargs['key']
            assert len(key) in (128 // 8, 192 // 8, 256 // 8)
            self._K = key

        self._encryptor = _AESEncryptor(self._K)

    def encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        plaintext = self._pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in self._split_blocks(plaintext):
            block = self._encryptor.cipher(self._xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in self._split_blocks(ciphertext):
            blocks.append(self._xor_bytes(previous, self._encryptor.inv_cipher(ciphertext_block)))
            previous = ciphertext_block

        return self._unpad(b''.join(blocks))

    def encrypt_pcbc(self, plaintext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        plaintext = self._pad(plaintext)

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for plaintext_block in self._split_blocks(plaintext):
            ciphertext_block = self._encryptor.cipher(
                self._xor_bytes(plaintext_block, self._xor_bytes(prev_ciphertext, prev_plaintext))
            )
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return b''.join(blocks)

    def decrypt_pcbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for ciphertext_block in self._split_blocks(ciphertext):
            plaintext_block = self._xor_bytes(
                self._xor_bytes(prev_ciphertext, prev_plaintext), self._encryptor.inv_cipher(ciphertext_block)
            )
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return self._unpad(b''.join(blocks))

    def encrypt_cfb(self, plaintext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for plaintext_block in self._split_blocks(plaintext, require_padding=False):
            ciphertext_block = self._xor_bytes(plaintext_block, self._encryptor.cipher(prev_ciphertext))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def decrypt_cfb(self, ciphertext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        blocks = []
        prev_ciphertext = iv
        for ciphertext_block in self._split_blocks(ciphertext, require_padding=False):
            plaintext_block = self._xor_bytes(ciphertext_block, self._encryptor.cipher(prev_ciphertext))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def encrypt_ofb(self, plaintext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        blocks = []
        previous = iv
        for plaintext_block in self._split_blocks(plaintext, require_padding=False):
            block = self._encryptor.cipher(previous)
            ciphertext_block = self._xor_bytes(plaintext_block, block)
            blocks.append(ciphertext_block)
            previous = block

        return b''.join(blocks)

    def decrypt_ofb(self, ciphertext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        blocks = []
        previous = iv
        for ciphertext_block in self._split_blocks(ciphertext, require_padding=False):
            block = self._encryptor.cipher(previous)
            plaintext_block = self._xor_bytes(ciphertext_block, block)
            blocks.append(plaintext_block)
            previous = block

        return b''.join(blocks)

    def encrypt_ctr(self, plaintext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for plaintext_block in self._split_blocks(plaintext, require_padding=False):
            block = self._xor_bytes(plaintext_block, self._encryptor.cipher(nonce))
            blocks.append(block)
            nonce = self._inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext: bytes, iv: bytes) -> bytes:
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for ciphertext_block in self._split_blocks(ciphertext, require_padding=False):
            block = self._xor_bytes(ciphertext_block, self._encryptor.cipher(nonce))
            blocks.append(block)
            nonce = self._inc_bytes(nonce)

        return b''.join(blocks)

    def encrypt(self, plaintext: bytes) -> bytes:
        plaintext = self._pad(plaintext)

        blocks = []
        for plaintext_block in self._split_blocks(plaintext):
            blocks.append(self._encryptor.cipher(plaintext_block))

        return b''.join(blocks)

    def decrypt(self, ciphertext: bytes) -> bytes:
        blocks = list()
        for ciphertext_block in self._split_blocks(ciphertext):
            blocks.append(self._encryptor.inv_cipher(ciphertext_block))

        return self._unpad(b''.join(blocks))

    @staticmethod
    def _pad(plaintext: bytes) -> bytes:
        if len(plaintext) > 0 and len(plaintext) % 16 == 0:
            return plaintext
        padding_len = 16 - (len(plaintext) % 16)
        padding = bytes([padding_len] * padding_len)
        return plaintext + padding

    @staticmethod
    def _unpad(ciphertext: bytes) -> bytes:
        assert len(ciphertext) > 0 and len(ciphertext) % 16 == 0
        padding_len = ciphertext[-1]
        if padding_len > 16:
            return ciphertext

        ciphertext, padding = ciphertext[:-padding_len], ciphertext[-padding_len:]
        assert all(byte == padding_len for byte in padding)
        return ciphertext

    @staticmethod
    def _split_blocks(plaintext: bytes, require_padding=True) -> List[bytes]:
        block_size = 16
        assert (len(plaintext) > 0 and len(plaintext) % block_size == 0) or not require_padding
        return [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(i ^ j for i, j in zip(a, b))

    @staticmethod
    def _inc_bytes(a: bytes):
        out = list(a)
        for i in reversed(range(len(out))):
            if out[i] == 0xFF:
                out[i] = 0
            else:
                out[i] += 1
                break
        return bytes(out)


class _AESEncryptor:
    _key_length_to_Nr = {16: 10, 24: 12, 32: 14}
    _Nb = 4

    _S_box = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )
    _inv_S_box = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )
    _mix_columns_matrix = [
        b'\x02\x03\x01\x01',
        b'\x01\x02\x03\x01',
        b'\x01\x01\x02\x03',
        b'\x03\x01\x01\x02'
    ]
    _inv_mix_columns_matrix = [
        b'\x0e\x0b\x0d\x09',
        b'\x09\x0e\x0b\x0d',
        b'\x0d\x09\x0e\x0b',
        b'\x0b\x0d\x09\x0e'
    ]
    _Rcon = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    def __init__(self, key: bytes) -> None:
        self._Nr = _AESEncryptor._key_length_to_Nr[len(key)]
        self._Nk = len(key) // self._Nb
        self._key = key
        self._round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes) -> List[List[_Word]]:
        result = list()

        for i in range(self._Nk):
            result.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

        i = 1
        while len(result) < self._Nb * (self._Nr + 1):
            temp = list(result[-1])
            if (len(result) % self._Nk) == 0:
                temp = _AESEncryptor._rot_word(temp)
                self._sub_word(temp)
                temp[0] ^= self._Rcon[i]
                i += 1
            elif self._Nk > 6 and (len(result) % self._Nk) == 4:
                self._sub_word(temp)

            temp = self._xor_list(temp, result[-self._Nk])
            result.append(temp)

        return [result[4 * i: 4 * (i + 1)] for i in range(len(result) // 4)]

    def cipher(self, _in: bytes):
        assert len(_in) == self._Nb * self._Nb
        state = self._in_to_state(_in)

        self._add_round_key(state, self._round_keys[0])

        for round in range(1, self._Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state, False)
            self._add_round_key(state, self._round_keys[round])

        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self._round_keys[-1])

        return _AESEncryptor._state_to_out(state)

    def inv_cipher(self, _in: bytes):
        assert len(_in) == self._Nb * self._Nb

        state = self._in_to_state(_in)

        self._add_round_key(state, self._round_keys[-1])
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)

        for round in reversed(range(1, self._Nr)):
            self._add_round_key(state, self._round_keys[round])
            self._mix_columns(state, True)
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)

        self._add_round_key(state, self._round_keys[0])

        return _AESEncryptor._state_to_out(state)

    @staticmethod
    def _in_to_state(_in: bytes) -> _State:
        return [list(_in[i:i + 4]) for i in range(0, len(_in), 4)]

    @staticmethod
    def _state_to_out(state: _State) -> bytes:
        return bytes(sum(state, []))

    @staticmethod
    def _sub_bytes(state: _State) -> None:
        _AESEncryptor._do_sub_bytes(state, _AESEncryptor._S_box)

    @staticmethod
    def _shift_rows(state: _State) -> None:
        _AESEncryptor._do_shift_rows(state, [0, 1, 2, 3])

    @staticmethod
    def _mix_columns(state: _State, isInv: bool) -> None:
        for i in range(4):
            column = [row[i] for row in state]
            column = _AESEncryptor._mix_column(column, isInv)
            for j, row in enumerate(state):
                row[i] = column[j]

    @staticmethod
    def _mix_column(column, isInv):
        if isInv:
            mult = [14, 9, 13, 11]
        else:
            mult = [2, 1, 1, 3]
        cpy = list(column)
        g = _AESEncryptor._galois_multiplication

        column[0] = g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^ \
                    g(cpy[2], mult[2]) ^ g(cpy[1], mult[3])
        column[1] = g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^ \
                    g(cpy[3], mult[2]) ^ g(cpy[2], mult[3])
        column[2] = g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^ \
                    g(cpy[0], mult[2]) ^ g(cpy[3], mult[3])
        column[3] = g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^ \
                    g(cpy[1], mult[2]) ^ g(cpy[0], mult[3])
        return column

    @staticmethod
    def _galois_multiplication(a, b):
        p = 0
        for counter in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            a &= 0xff
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    @staticmethod
    def _add_round_key(state: _State, w: List[_Word]) -> None:
        for i in range(_AESEncryptor._Nb):
            for j in range(_AESEncryptor._Nb):
                state[i][j] ^= w[i][j]

    @staticmethod
    def _inv_sub_bytes(state: _State) -> None:
        _AESEncryptor._do_sub_bytes(state, _AESEncryptor._inv_S_box)

    @staticmethod
    def _inv_shift_rows(state: _State) -> None:
        _AESEncryptor._do_shift_rows(state, [0, 3, 2, 1])

    @staticmethod
    def _do_shift_rows(state: _State, shifts: List[int]):
        assert len(shifts) == 4
        for i in range(1, len(shifts)):
            state[i] = _AESEncryptor._do_shift(state[i], shifts[i])

    @staticmethod
    def _do_sub_bytes(state: _State, S_box: Tuple):
        for i in range(_AESEncryptor._Nb):
            for j in range(_AESEncryptor._Nb):
                state[i][j] = S_box[state[i][j]]

    @staticmethod
    def _do_shift(sequence: List[Any], shift: int) -> List[Any]:
        a = shift % len(sequence)
        return sequence[a:] + sequence[:a]

    @staticmethod
    def _rot_word(word: List[int]) -> List[int]:
        return _AESEncryptor._do_shift(word, 1)

    @staticmethod
    def _sub_word(word: _Word):
        for i, value in enumerate(word):
            word[i] = _AESEncryptor._S_box[value]

    @staticmethod
    def _xor_list(a: List[int], b: List[int]) -> List[int]:
        assert len(a) == len(b) == 4
        result = [0] * len(a)
        for i in range(len(a)):
            result[i] = a[i] ^ b[i]
        return result


if __name__ == '__main__':
    pass
