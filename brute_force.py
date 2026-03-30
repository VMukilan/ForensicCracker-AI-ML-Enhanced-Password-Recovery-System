"""
brute_force.py — Fast Brute Force Attacker
===========================================
Single-threaded tight loop over itertools.product.
Checkpoint/resume via pickle.
"""

import time
import string
import itertools
import pickle
import os
from hash_identifier import HashIdentifier


class BruteForceAttacker:

    CHARSETS = {
        'digits':   string.digits,
        'alpha':    string.ascii_lowercase,
        'alphanum': string.ascii_letters + string.digits,
        'full':     string.ascii_lowercase + string.digits + '!@#$',
    }

    def __init__(self, hash_type, max_length=6, charset='full',
                 bloom_filter=None, threads=4,
                 checkpoint_file=None, verbose=False):
        self.hash_type       = hash_type
        self.max_length      = max_length
        self.charset         = self.CHARSETS.get(charset, charset)
        self.checkpoint_file = checkpoint_file
        self.verbose         = verbose
        self.identifier      = HashIdentifier()
        self._hasher         = self.identifier.get_hash_function(hash_type)

    def crack(self, target_hash):
        target   = target_hash.strip().lower()
        start    = time.perf_counter()
        attempts = 0
        found    = None

        for length in range(1, self.max_length + 1):
            if found:
                break
            for combo in itertools.product(self.charset, repeat=length):
                candidate = ''.join(combo)
                attempts += 1
                if self._hasher(candidate) == target:
                    found = candidate
                    break
                if self.verbose and attempts % 200000 == 0:
                    elapsed = time.perf_counter() - start
                    print(f'  [BF] {attempts:,} | {attempts/elapsed:,.0f} H/s | {candidate}')

        elapsed = time.perf_counter() - start
        return {
            'password':  found,
            'attempts':  attempts,
            'time':      elapsed,
            'method':    'Brute Force Attack',
            'hash_rate': attempts / elapsed if elapsed > 0 else 0,
        }
