import des
from typing import List, Tuple
import random
from math import prod
import argparse

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

def get_best_characteristic(ddt: List[List[int]]) -> Tuple[int, int]:
    ret = (-1, -1)
    max_prob = -1
    for x in range(1, 4):
        for y in range(16):
            if ddt[x << 2][y] > max_prob:
                ret = (x << 2, y)
                max_prob = ddt[x << 2][y]
    return ret

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

def get_partial_subkeys(ct_pairs: List[Tuple[int, int]], expected_diff: int, box: int) -> List[int]:
    votes = dict.fromkeys(range(2 ** 6), 0)
    for ct1, ct2 in ct_pairs:
        l1, _ = des.split_block(ct1)
        l2, _ = des.split_block(ct2)
        possible_keys = get_probable_key(expected_diff, des.get_i6(des.E(l1), box), des.get_i6(des.E(l2), box), box)
        for key_bits in possible_keys:
            votes[key_bits] += 1
    return [key for key in votes if votes[key] == max(votes.values())]

oracle_calls = 0

def encryption_oracle(pt: int, subkeys: List[int]) -> int:
    global oracle_calls
    oracle_calls += 1
    return des.encode_block_rounds(pt, subkeys, encryption=True, rounds=1)


if __name__ == "__main__":
    # Parse command line arguments for attack settings
    parser = argparse.ArgumentParser()
    parser.add_argument('--pairs', type=int, default=200)
    args = parser.parse_args()
    PAIRS_PER_SBOX = args.pairs
    
    # Generate ddts and find best characteristic for the attack
    print("Generating differential distribution tables...")
    ddts = [get_ddt(i) for i in range(8)]
    print("Searching tables for best characteristics...")
    diffs = [get_best_characteristic(ddts[i]) for i in range(8)]
    print(f"Found the following characteristics: [{', '.join(f'({diffs[i][0]:02x}, {diffs[i][1]:01x})' for i in range(8))}]")
    print()

    # Choose a random key and generate subkeys
    print("Choosing a random key and generating subkeys...")
    subkeys = list(des.subkeys((random.randbytes(8))))
    print(f"First round subkey: {subkeys[0]:012x}")
    print(f"Subkey fragments: {' '.join(f'{des.get_i6(subkeys[0], i):02x}' for i in range(8))}")
    print()

    # Generate ciphertext pairs to use for the attack
    ct_pairs = []
    print(f"Generating {PAIRS_PER_SBOX} plaintext pairs for each sbox...")
    pt_pairs = [generate_plaintext_pairs(des.E(diffs[i][0] << 42 - i * 6, invert=True), PAIRS_PER_SBOX) for i in range(8)]
    print(f"Passing to encryption oracle to get ciphertext pairs...")
    ct_pairs = [[(encryption_oracle(pt1, subkeys), encryption_oracle(pt2, subkeys)) for pt1, pt2 in pt_pairs[i]] for i in range(8)]
    print(f"Total calls to encryption oracle: {oracle_calls}")
    print()

    # Filter ciphertext pairs and recover partial subkeys
    print(f"Filtering ciphertexts for only \"good pairs\"...")
    ct_pairs = [get_good_pairs(ct_pairs[i], diffs[i][1], i) for i in range(8)]
    print(f"Averaged {sum([len(ct_pairs[i]) for i in range(8)]) / 8:.02f}/{PAIRS_PER_SBOX} good ciphertexts for each sbox")
    print()

    # Calculate possible partial subkeys using good pairs
    print(f"Using ciphertexts to recover partial subkeys...")
    partial_subkeys = [get_partial_subkeys(ct_pairs[i], diffs[i][1], i) for i in range(8)]
    print(f"Reduced total key space to {prod([len(k) for k in partial_subkeys])}")

    # Brute force the remaining key space to recover full subkey