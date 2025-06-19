import subprocess

failed = False

def hex2bin(input_data):
    if isinstance(input_data, str):
        input_data = input_data.encode()
    process = subprocess.Popen(['./hex2bin'],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE)
    stdout, _ = process.communicate(input=input_data)
    if process.returncode != 0:
        raise RuntimeError(f'hex2bin returned {process.returncode}')
    return stdout

def check(input_data, output_hex):
    global failed
    result = hex2bin(input_data)
    expected = bytes.fromhex(output_hex)
    if result != expected:
        failed = True
        print('Check failed\n'
              f' Input:-\n{input_data}\n'
              f' Output:   {result.hex()}\n'
              f' Expected: {output_hex}\n')

def main():
    quest = '3f' # '?'
    check('0 5040', '4050')
    check('0 40 50', '4050')
    check('0 40 50\n', '4050')
    check('0 40 50\n2', '4050')
    check('0 40 50\n2 60', '405060')
    check('0 40 50|', '4050')
    check('0 40 50 |abcd\n2 60', '405060')
    check('0 40 50\n4 60', '4050' + quest * 2 + '60')
    check('0 40 50\n*\n4 60', '4050' * 2 + '60')
    check('0 40 50\n*\ne 60', '4050' * 7 + '60')
    check('3 40 50 \n6 60', quest * 3 + '4050' + quest + '60')
    check('1 40 50 |\n*\n7 60', quest + '4050' * 3 + '60')

if __name__ == '__main__':
    main()
    if failed:
        exit(1)
