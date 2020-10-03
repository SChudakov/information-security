import os.path

_data_dir = './data'


def _generate_file(file_name: str, file_size: int):
    print(f'generation {file_name} with {file_size} bytes')
    with open(os.path.join(_data_dir, file_name), 'wb') as write_stream:
        write_stream.write(os.urandom(file_size))


def main():
    kb1 = 2 ** 10
    _generate_file('1kb', kb1)
    mb1 = 2 ** 10 * 2 ** 10
    _generate_file('1mb', mb1)
    gb1 = 2 ** 10 * 2 ** 10 * 2 ** 10
    _generate_file('1gb', gb1)


if __name__ == '__main__':
    main()
