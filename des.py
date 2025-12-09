#!/usr/bin/env python
# encoding: utf-8

"""
   @author: Eric Wong
  @license: MIT Licence
  @contact: ericwong@zju.edu.cn
     @file: core.py
     @time: 2018-12-30 11:10
"""

from tables import IP, E, P, S, subkeys
from typing import Tuple, List

def get_i6(block: int, i: int) -> int:
    """
    Extract the i'th 6-bit chunk from a 48-bit block

    :param block: A 48-bit block of data
    :param i: The index of 6-bit chunk from MSB to LSB
    :ret: A 6-bit chunk from block
    """
    return (block >> (42 - i * 6)) & 0x3f

def get_i4(block: int, i: int) -> int:
    """
    Extract the i'th 6-bit chunk from a 48-bit block

    :param block: A 48-bit block of data
    :param i: The index of 6-bit chunk from MSB to LSB
    :ret: A 6-bit chunk from block
    """
    return (block >> (28 - i * 4)) & 0x0f

def split_block(block: int) -> Tuple[int, int]:
    """
    Split a 64-bit block into a pair of 32-bit halves (left, right).
    """
    return block >> 32, block & 0xffffffff

def join_block(left: int, right: int) -> int:
    """
    Join a pair of 32-bit halves back into a 64-bit block.
    """
    return (left << 32) | right

def f(block: int, key: int) -> int:
    """
    Implements the DES mangler function
    """
    block = E(block) ^ key
    ret = 0
    for i in range(8):
        ret = ret << 4 | S(get_i6(block, i), i)
    return P(ret)

def feistel_round(left: int, right: int, subkey: int) -> Tuple[int, int]:
    """
    Perform a single Feistel round of DES on 32-bit halves.

    This helper is useful for educational and cryptanalysis code where we
    want to explicitly see how one round updates the left and right halves.
    """
    new_left = right
    new_right = left ^ f(right, subkey)
    return new_left, new_right

def encode_block_rounds(block: int, derived_keys, encryption: bool, rounds: int = 16) -> int:
    """
    Encode a 64-bit block using a configurable number of DES rounds.

    This is similar to encode_block, but lets us stop after a smaller
    number of rounds such as 1, 2, or 6. This is especially handy for
    building reduced-round experiments and distinguishers.

    Parameters
    ----------
    block : int
        The 64-bit plaintext (when encryption is True) or ciphertext
        (when encryption is False).
    derived_keys : iterable
        A sequence or generator of the 16 DES round subkeys.
    encryption : bool
        True for encryption, False for decryption.
    rounds : int
        How many rounds of the Feistel structure to apply. Values larger
        than the number of available subkeys are clamped.

    Returns
    -------
    int
        The 64-bit block after applying the chosen number of rounds.
    """
    keys_list = list(derived_keys)
    if not keys_list:
        raise ValueError("derived_keys must contain at least one subkey")

    # Clamp rounds to the number of available subkeys.
    rounds = max(1, min(rounds, len(keys_list)))

    # Standard DES initial permutation.
    #permuted = IP(block)
    #left, right = split_block(permuted)
    left, right = split_block(block)

    if encryption:
        key_iter = keys_list[:rounds]
    else:
        # For decryption we use the subkeys in reverse order.
        key_iter = list(reversed(keys_list))[:rounds]

    for subkey in key_iter:
        left, right = feistel_round(left, right, subkey)

    # In DES the halves are swapped before the final permutation.
    #preoutput = join_block(right, left)
    #return IP(preoutput, invert=True)
    return join_block(left, right)

<<<<<<< HEAD
def encrypt_one_round(block: int, subkeys: bytes) -> int:
=======
def encrypt_one_round(block: int, subkeys: List[int]) -> int:
>>>>>>> 2ca63483c42bdcf022628cfa9e230db183b82f99
    """
    Convenience helper: encrypt a block using exactly one DES round.

    This derives the 16 DES subkeys from the user key, then calls
    encode_block_rounds with rounds=1. It is not meant for real security,
    but as a lab function for reduced-round experiments.
    """
    return encode_block_rounds(block, subkeys, encryption=True, rounds=1)