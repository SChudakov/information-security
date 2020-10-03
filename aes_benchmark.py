import os.path
import cProfile
import aes

_data_dir = './data'


def _load_file(file_name: str):
    with open(os.path.join(_data_dir, file_name), 'rb') as read_file:
        return read_file.read()


def _write_file(file_name: str, content: bytes):
    with open(os.path.join(_data_dir, file_name), 'wb') as write_file:
        write_file.write(content)


def benchmark_encrypt(file_name: str, key_length: int):
    content = _load_file(file_name)
    algorithm = aes.AES(key_length=key_length)
    _ = algorithm.encrypt(content)


def benchmark_decrypt(file_name: str, key_length: int):
    content = _load_file(file_name)
    algorithm = aes.AES(key_length=key_length)
    _ = algorithm.decrypt(content)


def main():
    cProfile.run('benchmark_encrypt("1kb", 128)')
    cProfile.run('benchmark_encrypt("1mb", 128)')
    # cProfile.run('benchmark_encrypt("1gb", 128)')

    cProfile.run('benchmark_decrypt("1kb", 128)')
    cProfile.run('benchmark_decrypt("1mb", 128)')
    # cProfile.run('benchmark_decrypt("1gb", 128)')


if __name__ == '__main__':
    main()
