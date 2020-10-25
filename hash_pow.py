from typing import List

import sha256
import kupyna

import cProfile


def _generate_messages_rec(length: int, stack: List[int], result: List[bytes]):
    if len(stack) == length:
        result.append(bytes(stack))
    else:
        for char in range(256):
            stack.append(char)
            _generate_messages_rec(length, stack, result)
            stack.pop()


def _generate_messages(length: int):
    result = []
    _generate_messages_rec(length, [], result)
    return result


def _helper_benchmark_hash(algorithm, message_bytes: int):
    for message in _generate_messages(message_bytes):
        algorithm.hash(message)


def _benchmark_sha256_hash(message_bytes: int):
    _helper_benchmark_hash(sha256.SHA256(), message_bytes)


def _benchmark_kupyna_hash(message_bytes: int, hash_bits: int):
    _helper_benchmark_hash(kupyna.Kupyna(hash_bits), message_bytes)


def _helper_benchmark_pow(algorithm, message_bytes: int, zero_bytes: int):
    tail_zeros = [0] * zero_bytes
    for i, message in enumerate(_generate_messages(message_bytes)):
        hash = algorithm.hash(message)
        if hash[-zero_bytes:] == bytes(tail_zeros):
            return message


def _benchmark_sha256_pow(message_bytes: int, zero_bytes: int):
    algorithm = sha256.SHA256()
    return _helper_benchmark_pow(algorithm, message_bytes, zero_bytes)


def _benchmark_kupyna_pow(message_bytes: int, zero_bytes: int, hash_bits:int):
    algorithm = kupyna.Kupyna(hash_bits)
    return _helper_benchmark_pow(algorithm, message_bytes, zero_bytes)


def main():
    cProfile.run('_benchmark_sha256_hash(1)')
    cProfile.run('_benchmark_kupyna_hash(1, 256)')
    cProfile.run('_benchmark_sha256_pow(2, 1)')
    cProfile.run('_benchmark_kupyna_pow(2, 1, 256)')


def _test_pow_correctness():
    print(_benchmark_sha256_pow(3, 2))
    print(sha256.SHA256().hash(b'\x01\xb1\x7f'))
    print(_benchmark_kupyna_pow(3, 2, 256))
    print(kupyna.Kupyna(256).hash(b'\x01\xb1\x7f'))


if __name__ == '__main__':
    main()
