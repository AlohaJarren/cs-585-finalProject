import pandas as pd
import matplotlib.pyplot as plt
import des
from main import get_ddt, get_best_characteristic, generate_plaintext_pairs, get_good_pairs, get_partial_subkeys
import random
import math

ddts = [get_ddt(i) for i in range(8)]
diffs = [get_best_characteristic(ddts[i]) for i in range(8)]

def reduced_key_space(num_pairs, diffs):
    # Choose a random key and generate subkeys
    subkeys = list(des.subkeys((random.randbytes(8))))

    # Generate ciphertext pairs to use for the attack
    ct_pairs = []
    pt_pairs = [generate_plaintext_pairs(des.E(diffs[i][0] << 42 - i * 6, invert=True), num_pairs) for i in range(8)]
    ct_pairs = [[(des.encrypt_one_round(pt1, subkeys), des.encrypt_one_round(pt2, subkeys)) for pt1, pt2 in pt_pairs[i]] for i in range(8)]

    # Filter ciphertext pairs and recover partial subkeys
    good_ct_pairs = [get_good_pairs(ct_pairs[i], diffs[i][1], i) for i in range(8)]

    # Calculate possible partial subkeys using good pairs
    partial_subkeys = [get_partial_subkeys(good_ct_pairs[i], diffs[i][1], i) for i in range(8)]

    return math.log2(math.prod([len(k) for k in partial_subkeys]))

x = range(0,101,5)
y = []
TRIALS = 50

for n in x:
    k = 0
    for _ in range(TRIALS):
        k += reduced_key_space(n, diffs)
    k /= TRIALS
    y.append(k)

df = pd.DataFrame({
    'Pairs': x,
    'Key_Space_Bits': y
})

plt.figure(figsize=(6, 6))
plt.plot(df['Pairs'], df['Key_Space_Bits'], marker='o', linestyle='-', color='red')

plt.xlabel('Number of Plaintext Pairs', fontsize=12)
plt.ylabel(r'Reduced Key Space Size ($2^k$ bits)', fontsize=12) # Uses LaTeX for the exponent

plt.ylim(0, 48) 
plt.xlim(0, 100)

plt.grid(True, linestyle='--', alpha=0.7)

plt.tight_layout()
plt.show()