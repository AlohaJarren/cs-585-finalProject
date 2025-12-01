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

def get_best_characteristic(ddts: Tuple[List[List[int]]]) -> Tuple[int, int, int]:
    # Find differentials in each sbox with high probabilities
    print("Finding most likely XOR pair in each s-box...")
    canidates = []
    for i in range(8):
        canidates.append(get_likely_diff(ddts[i]))
    print(f"Found canidates: {canidates}")
    # Of canidates find highest one with greatest probability
    print("Selecting best XOR pair from canidates...")
    idx = -1
    max = -1
    for i in range(8):
        if ddts[i][canidates[i][0]][canidates[i][1]] > max:
            idx = i
            max = ddts[i][canidates[i][0]][canidates[i][1]]
    print(f"Found best in sbox {idx} with probability {max}/64")
    return idx, canidates[idx][0], canidates[idx][1]

def generate_plaintext_pairs(in_diff: int, n: int) -> List[Tuple[int, int]]:
    print(bin(in_diff))
    ret = []
    for _ in range(n):
        pt = int.from_bytes(random.randbytes(8))
        ret.append((pt, pt ^ in_diff))
    return ret

def get_probable_key(out_diff: int, in1: int, in2: int, box:int) -> int:
    """
    Recover a single 6-bit subkey candidate for one S-box in 1-round DES.
    """
    candidates = []

    for k in range(64):
        y1 = des.S(in1 ^ k, box)
        y2 = des.S(in2 ^ k, box)
        if (y1 ^ y2) == out_diff:
            candidates.append(k)
    
    # We only care about returning a single key.
    return candidates

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

def get_good_pairs(ct_pairs: List[Tuple[int, int]], out_diff: int, box: int) -> List[Tuple[int, int]]:
    ret = []
    for ct1, ct2 in ct_pairs:
        # 1. Split the ciphertexts into Left and Right halves (32-bits each)
        l1, r1 = des.split_block(ct1)
        l2, r2 = des.split_block(ct2)
        
        # 2. Calculate the difference in the Right Half
        # In a 1-round Feistel, R1 = L0 ^ F(R0, K).
        # Since we assume Delta L0 is 0, the difference in R1 is EXACTLY the F-function output diff.
        f_diff = r1 ^ r2
        
        # 3. Undo the P-Permutation 
        # The S-box outputs go through P before hitting the XOR. We must reverse this.
        sbox_outputs_diff = des.P(f_diff, invert=True)
        
        # 4. Extract the 4-bit difference for our specific S-box
        # We assume standard Big-Endian bit packing (Box 0 is MSB, Box 7 is LSB)
        # Shift amount: (7 - box) * 4 for Little Endian index, or (28 - box * 4) for Big Endian.
        # Standard DES usually treats Box 1 (idx 0) as the most significant nibble.
        shift = 28 - (box * 4)
        observed_nibble = (sbox_outputs_diff >> shift) & 0xF
        
        # 5. The Filter: Does the observed physics match our prediction?
        if observed_nibble == out_diff:
            ret.append((ct1, ct2))
    return ret

if __name__ == "__main__":
    # Generate the differential distribution table for each sbox
    print("Generating differential distribution tables...")
    ddts = tuple(get_ddt(i) for i in range(8))
    box, in_diff, out_diff = get_best_characteristic(ddts)
    # Generate plaintext pairs for attack
    pt_pairs = generate_plaintext_pairs(des.E(in_diff << 42 - box * 6, invert=True), 10000)
    # Generate random subkeys
    subkeys = list(des.subkeys((random.randbytes(8))))
    print(f"subkey: {subkeys[0]}")
    print(f"subkey fragment: {des.get_i6(subkeys[0], box)}")
    ct_pairs = []
    for pt1, pt2 in pt_pairs:
        ct1 = des.encode_block_rounds(pt1, subkeys, encryption=True, rounds=1)
        ct2 = des.encode_block_rounds(pt2, subkeys, encryption=True, rounds=1)
        ct_pairs.append((ct1, ct2))
    ct_pairs = get_good_pairs(ct_pairs, out_diff, box)
    votes = dict.fromkeys(range(2 ** 6), 0)
    for ct1, ct2 in ct_pairs:
        l1, r1 = des.split_block(ct1)
        l2, r2 = des.split_block(ct2)
        probable_key_bits = get_probable_key(out_diff, des.get_i6(des.E(l1), box), des.get_i6(des.E(l2), box), box)
        for key_bits in probable_key_bits:
            votes[key_bits] += 1
    print(votes)

    #print(max(votes, key=votes.get))
    max_value = max(votes.values())
    most_likely_keys = [key for key in votes if votes[key] == max_value]

    print(f"possible subkey fragments: {most_likely_keys}")