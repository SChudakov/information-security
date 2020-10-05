import os.path
import cProfile
import aes
import kalyna

_data_dir = './data'


def _load_file(file_name: str):
    with open(os.path.join(_data_dir, file_name), 'rb') as read_file:
        return read_file.read()


def _write_file(file_name: str, content: bytes):
    with open(os.path.join(_data_dir, file_name), 'wb') as write_file:
        write_file.write(content)


def benchmark_encrypt(content, algorithm):
    _ = algorithm.encrypt(content)


def benchmark_decrypt(content, algorithm):
    _ = algorithm.decrypt(content)


content_1kb = _load_file("1kb")
content_1mb = _load_file("1mb")


# content_1gb = _load_file("1gb")


def main():
    # ---------------    AES  -------------------------------------
    # cProfile.run('benchmark_encrypt(content_1kb, aes.AES(key_length=128))')
    # cProfile.run('benchmark_encrypt(content_1mb, aes.AES(key_length=128))')
    # cProfile.run('benchmark_encrypt(content_1gb, aes.AES(key_length=128))')

    # cProfile.run('benchmark_decrypt(content_1kb, aes.AES(key_length=128))')
    # cProfile.run('benchmark_decrypt(content_1mb, aes.AES(key_length=128))')
    # cProfile.run('benchmark_decrypt(content_1gb, aes.AES(key_length=128))')

    # ---------------    Kalyna  -----------------------------------

    cProfile.run('benchmark_encrypt(content_1kb, kalyna.Kalyna(block_size=128, key_length=128))')
    cProfile.run('benchmark_encrypt(content_1mb, kalyna.Kalyna(block_size=128, key_length=128))')
    # cProfile.run('benchmark_encrypt(content_1gb, kalyna.Kalyna(block_size=128, key_length=128))')

    cProfile.run('benchmark_decrypt(content_1kb, kalyna.Kalyna(block_size=128, key_length=128))')
    cProfile.run('benchmark_decrypt(content_1mb, kalyna.Kalyna(block_size=128, key_length=128))')
    # cProfile.run('benchmark_decrypt(content_1gb, kalyna.Kalyna(block_size=128, key_length=128))')


if __name__ == '__main__':
    main()
