import os.path
import cProfile
import aes
import kalyna
import rc4
import salsa20

_data_dir = './data'
_iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
_key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
_salsa_key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'

_nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6])
_block_counter = bytes([7, 0, 0, 0, 0, 0, 0, 0])
_rounds = 20


def _load_file(file_name: str):
    with open(os.path.join(_data_dir, file_name), 'rb') as read_file:
        return read_file.read()


def _write_file(file_name: str, content: bytes):
    with open(os.path.join(_data_dir, file_name), 'wb') as write_file:
        write_file.write(content)


def benchmark_encrypt(content, algorithm, iv=None):
    if iv is None:
        _ = algorithm._encrypt_block(content)
    else:
        _ = algorithm._encrypt_block(content, iv)


def benchmark_decrypt(content, algorithm, iv=None):
    if iv is None:
        _ = algorithm._decrypt_block(content)
    else:
        _ = algorithm._decrypt_block(content, iv)


content_1kb = _load_file("1kb")
content_1mb = _load_file("1mb")


# content_1gb = _load_file("1gb")


def _benchmark_aes_ecb():
    cProfile.run('benchmark_encrypt(content_1kb, aes.AES(key_length=128))')
    cProfile.run('benchmark_encrypt(content_1mb, aes.AES(key_length=128))')
    cProfile.run('benchmark_encrypt(content_1gb, aes.AES(key_length=128))')

    cProfile.run('benchmark_decrypt(content_1kb, aes.AES(key_length=128))')
    cProfile.run('benchmark_decrypt(content_1mb, aes.AES(key_length=128))')
    cProfile.run('benchmark_decrypt(content_1gb, aes.AES(key_length=128))')


def _benchmark_aes_cbc():
    cProfile.run('benchmark_encrypt(content_1kb, aes.AES_CBC(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_encrypt(content_1mb, aes.AES_CBC(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_encrypt(content_1gb, aes.AES_CBC(block_size=128, key_length=128), _iv)')

    cProfile.run('benchmark_decrypt(content_1kb, aes.AES_CBC(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_decrypt(content_1mb, aes.AES_CBC(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_decrypt(content_1gb, aes.AES_CBC(block_size=128, key_length=128), _iv)')


def _benchmark_aes_pcbc():
    cProfile.run('benchmark_encrypt(content_1kb, aes.AES_PCBC(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_encrypt(content_1mb, aes.AES_PCBC(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_encrypt(content_1gb, aes.AES_PCBC(block_size=128, key_length=128), _iv)')

    cProfile.run('benchmark_decrypt(content_1kb, aes.AES_PCBC(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_decrypt(content_1mb, aes.AES_PCBC(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_decrypt(content_1gb, aes.AES_PCBC(block_size=128, key_length=128), _iv)')


def _benchmark_aes_cfb():
    cProfile.run('benchmark_encrypt(content_1kb, aes.AES_CFB(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_encrypt(content_1mb, aes.AES_CFB(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_encrypt(content_1gb, aes.AES_CFB(block_size=128, key_length=128), _iv)')

    cProfile.run('benchmark_decrypt(content_1kb, aes.AES_CFB(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_decrypt(content_1mb, aes.AES_CFB(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_decrypt(content_1gb, aes.AES_CFB(block_size=128, key_length=128), _iv)')


def _benchmark_aes_ofb():
    cProfile.run('benchmark_encrypt(content_1kb, aes.AES_OFB(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_encrypt(content_1mb, aes.AES_OFB(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_encrypt(content_1gb, aes.AES_OFB(block_size=128, key_length=128), _iv)')

    cProfile.run('benchmark_decrypt(content_1kb, aes.AES_OFB(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_decrypt(content_1mb, aes.AES_OFB(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_decrypt(content_1gb, aes.AES_OFB(block_size=128, key_length=128), _iv)')


def _benchmark_aes_ctr():
    cProfile.run('benchmark_encrypt(content_1kb, aes.AES_CTR(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_encrypt(content_1mb, aes.AES_CTR(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_encrypt(content_1gb, aes.AES_CTR(block_size=128, key_length=128), _iv)')

    cProfile.run('benchmark_decrypt(content_1kb, aes.AES_CTR(block_size=128, key_length=128), _iv)')
    cProfile.run('benchmark_decrypt(content_1mb, aes.AES_CTR(block_size=128, key_length=128), _iv)')
    # cProfile.run('benchmark_decrypt(content_1gb, aes.AES_CTR(block_size=128, key_length=128), _iv)')


def _benchmark_kalyna():
    cProfile.run('benchmark_encrypt(content_1kb, kalyna.Kalyna(block_size=128, key_length=128))')
    # cProfile.run('benchmark_encrypt(content_1mb, kalyna.Kalyna(block_size=128, key_length=128))')
    # cProfile.run('benchmark_encrypt(content_1gb, kalyna.Kalyna(block_size=128, key_length=128))')

    cProfile.run('benchmark_decrypt(content_1kb, kalyna.Kalyna(block_size=128, key_length=128))')
    # cProfile.run('benchmark_decrypt(content_1mb, kalyna.Kalyna(block_size=128, key_length=128))')
    # cProfile.run('benchmark_decrypt(content_1gb, kalyna.Kalyna(block_size=128, key_length=128))')


def _benchmark_rc4():
    cProfile.run('benchmark_encrypt(content_1kb, rc4.RC4(_key))')
    cProfile.run('benchmark_encrypt(content_1mb, rc4.RC4(_key))')
    # cProfile.run('benchmark_encrypt(content_1gb, rc4.RC4(_key))')


def _benchmark_salsa20():
    cProfile.run('benchmark_encrypt(content_1kb, salsa20.Salsa20(_salsa_key, _nonce, _block_counter, _rounds))')
    cProfile.run('benchmark_encrypt(content_1mb, salsa20.Salsa20(_salsa_key, _nonce, _block_counter, _rounds))')
    # cProfile.run('benchmark_encrypt(content_1gb, salsa20.Salsa20(_salsa_key, _nonce, _block_counter, _rounds))')


if __name__ == '__main__':
    _benchmark_aes_ecb()
    _benchmark_kalyna()
    _benchmark_aes_cbc()
    _benchmark_aes_pcbc()
    _benchmark_aes_cfb()
    _benchmark_aes_ofb()
    _benchmark_aes_ctr()
    _benchmark_rc4()
    _benchmark_salsa20()
