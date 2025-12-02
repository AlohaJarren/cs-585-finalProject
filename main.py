import des
from typing import List, Tuple
import random

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

def get_best_characteristics(ddts: Tuple[List[List[int]]]) -> Tuple[int, int, int]:
    # Find differentials in each sbox with high probabilities
    print("Finding most likely XOR pair in each s-box...")
    diffs = []
    for i in range(8):
        diffs.append(get_likely_diff(ddts[i]))
    # Of canidates find highest one with greatest probability
    '''
    print("Selecting best XOR pair from canidates...")
    idx = -1
    max = -1
    for i in range(8):
        if ddts[i][canidates[i][0]][canidates[i][1]] > max:
            idx = i
            max = ddts[i][canidates[i][0]][canidates[i][1]]
    print(f"Found best in sbox {idx} with probability {max}/64")
    '''
    return diffs

def generate_plaintext_pairs(in_diff: int, n: int) -> List[Tuple[int, int]]:
    ret = []
    for _ in range(n):
        pt = random.randrange(2 ** 64)
        ret.append((pt, pt ^ in_diff))
    return ret

def get_probable_key(out_diff: int, in1: int, in2: int, box:int) -> List[int]:
    """
    Recover a 6-bit partial subkey candidate for one S-box characteristic.
    """
    candidates = []

    for k in range(64):
        y1 = des.S(in1 ^ k, box)
        y2 = des.S(in2 ^ k, box)
        if (y1 ^ y2) == out_diff:
            candidates.append(k)
    
    return candidates

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

def get_good_pairs(ct_pairs: List[Tuple[int, int]], expected_diff: int, box: int) -> List[Tuple[int, int]]:
    ret = []
    for ct1, ct2 in ct_pairs:
        _, r1 = des.split_block(ct1)
        _, r2 = des.split_block(ct2)
        f_diff = r1 ^ r2
        s_diff = des.P(f_diff, invert=True)
        if (s_diff >> (28 - (box * 4))) & 0xF == expected_diff:
            ret.append((ct1, ct2))
    return ret

def partial_subkey_canidates(ct_pairs: List[Tuple[int, int]], expected_diff: int, box: int) -> List[int]:
    votes = dict.fromkeys(range(2 ** 6), 0)
    for ct1, ct2 in ct_pairs:
        l1, _ = des.split_block(ct1)
        l2, _ = des.split_block(ct2)
        possible_keys = get_probable_key(expected_diff, des.get_i6(des.E(l1), box), des.get_i6(des.E(l2), box), box)
        for key_bits in possible_keys:
            votes[key_bits] += 1
    return [key for key in votes if votes[key] == max(votes.values())]

if __name__ == "__main__":
    # Generate the differential distribution table for each sbox
    print("Generating differential distribution tables...")
    ddts = tuple(get_ddt(i) for i in range(8))
    diffs = get_best_characteristics(ddts)
    print(f"characteristics: {diffs}")
    # Choose a random key and generate subkeys
    subkeys = list(des.subkeys((random.randbytes(8))))
    print(f"1 round subkey: {subkeys[0]}")
    print(f"subkey fragments: {[des.get_i6(subkeys[0], i) for i in range(8)]}")
    # Generate plaintext pairs for attack
    subkey = 0
    for i in range(8):
        pt_pairs = generate_plaintext_pairs(des.E(diffs[i][0] << 42 - i * 6, invert=True), 1000)
        ct_pairs = []
        for pt1, pt2 in pt_pairs:
            ct1 = des.encode_block_rounds(pt1, subkeys, encryption=True, rounds=1)
            ct2 = des.encode_block_rounds(pt2, subkeys, encryption=True, rounds=1)
            ct_pairs.append((ct1, ct2))
        ct_pairs = get_good_pairs(ct_pairs, diffs[i][1], i)
        print(f"for subkey pos {i} with characteristic {diffs[i]} filtered to {len(ct_pairs)} good ct pairs")
        canidates = partial_subkey_canidates(ct_pairs, diffs[i][1], i)
        print(f"Canidate partial subkeys for position {i}: {canidates}")