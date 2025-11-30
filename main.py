import des
from typing import List, Tuple
import random
from bisect import insort

def get_ddt(box: int) -> List[List[int]]:
    ddt = [[0 for _ in range(16)] for _ in range(64)]
    for x in range(64):
        for x_diff in range(64):
            x_ = x ^ x_diff
            y = des.S(x, box)
            y_ = des.S(x_, box)
            y_diff = y ^ y_
            ddt[x_diff][y_diff] += 1
    return ddt

def get_likely_diff(ddt: List[List[int]]) -> Tuple[int, int]:
    ret = (-1, -1)
    max_prob = -1
    for x in range(1, 16):
        for y in range(16):
            if ddt[x << 1][y] > max_prob:
                ret = (x << 1, y)
                max_prob = ddt[x << 1][y]
    return ret

def get_best_characteristic(ddts: Tuple[List[List[int]]]) -> Tuple[int, int]:
    # Find differentials in each sbox with high probabilities
    print("Selecting likely XOR pairs for each s-box...")
    canidates = []
    for i in range(8):
        canidates.append(get_likely_diff(ddts[i]))
    print(f"Found {canidates}")
    # Of canidates find highest one with greatest probability
    idx = -1
    max = -1
    for i in range(8):
        if ddts[i][canidates[i][0]][canidates[i][1]] > max:
            idx = i
            max = ddts[i][canidates[i][0]][canidates[i][1]]
    print(f"Found best in sbox {idx} with probability {max}/64")
    return canidates[idx][0] << (42 - idx * 6), canidates[idx][1] << (42 - idx * 6)

def get_all_intermediate_pairs(in_diff: int, out_diff: int, box: int) -> List[Tuple[int, int]]:
    ret = []
    for x1 in range(64):
        x2 = x1 ^ in_diff
        if des.S(x1, box) ^ des.S(x2, box) == out_diff:
            ret.append((x1, x2))
    return ret

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
    # Generate the differential distribution table for each sbox
    print("Generating differential distribution tables...")
    ddts = tuple(get_ddt(i) for i in range(8))
    in_diff, out_diff = get_best_characteristic(ddts)
    print(f"in_diff={in_diff}, out_diff={out_diff}")
    '''
    for _ in range(100):
        L = random.randrange(0xffffffff)
        R1 = random.randrange(0xffffffff)
        R2 = R1 ^ 0x60000000
        Y1 = des.one_round_des(des.join_block(L, R1))
        Y2 = des.one_round_des(des.join_block(L, R2))
        output_diff = Y1 ^ Y2
    '''