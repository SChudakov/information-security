import cProfile
import rsa
import random


def _get_random_message(message_length=32, number_of_message=32):
    return [bytes([random.randint(0, 255) for _ in range(message_length)]) for _ in range(number_of_message)]


_messages = _get_random_message()


def _helper_benchmark(algorithm):
    for message in _messages:
        encrypted = algorithm.encrypt(message)
        _ = algorithm.decrypt(encrypted)


def _benchmark_rsa(key_length):
    _helper_benchmark(rsa.RSA(key_length))


def _benchmark_rsa_oaep(key_length):
    _helper_benchmark(rsa.RSA_OAEP(key_length))


def main():
    cProfile.run('_benchmark_rsa(512)')
    cProfile.run('_benchmark_rsa(1024)')
    cProfile.run('_benchmark_rsa_oaep(512)')
    cProfile.run('_benchmark_rsa_oaep(1024)')


if __name__ == '__main__':
    main()
