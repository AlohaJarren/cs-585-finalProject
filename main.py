import des
from typing import List
import csv

def get_ddt(box: int) -> List[List[int]]:
    ddt = [[0 for y in range(16)] for x in range(64)]
    for x in range(64):
        for x_delta in range(64):
            x_ = x ^ x_delta
            y = des.S(x, box)
            y_ = des.S(x_, box)
            y_delta = y ^ y_
            ddt[x_delta][y_delta] += 1
    return ddt

def matrix_pretty_print(matrix):
    # see https://stackoverflow.com/questions/13214809/pretty-print-2d-python-list
    s = [[str(e) for e in row] for row in matrix]
    lens = [max(map(len, col)) for col in zip(*s)]
    fmt = '  '.join('{{:{}}}'.format(x) for x in lens)
    table = [fmt.format(*row) for row in s]
    print('\n'.join(table))

def demo_one_round():
    key = b"ABCDEFGH"
    plaintext = 0x0123456789ABCDEF
    subkeys = list(des.derive_keys(key))
    k1 = subkeys[0]
    print(f"Key bytes: {key!r}")
    print(f"First-round subkey K1: 0x{k1:012X}")
    c1 = des.encrypt_block_one_round(plaintext, key)
    print(f"Plaintext      : 0x{plaintext:016X}")
    print(f"1-round output : 0x{c1:016X}")

if __name__ == "__main__":
    ddt = get_ddt(1)
    with open('out.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(ddt)