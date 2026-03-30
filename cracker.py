"""
cracker.py — Fast Dictionary Attacker
======================================
Single-threaded tight loop (fastest for I/O-bound wordlist attacks).
No queue deadlock. No bloom overhead on first pass.
"""

import time
import hashlib
from hash_identifier import HashIdentifier


class DictionaryAttacker:

    def __init__(self, wordlist_path, hash_type, bloom_filter=None,
                 threads=4, verbose=False, encoding_variants=False):
        self.wordlist_path = wordlist_path
        self.hash_type     = hash_type
        self.verbose       = verbose
        self.identifier    = HashIdentifier()
        self._hasher       = self.identifier.get_hash_function(hash_type)
        self._target_lower = None

    def crack(self, target_hash):
        target = target_hash.strip().lower()
        self._target_lower = target
        start    = time.perf_counter()
        attempts = 0
        found    = None

        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.rstrip('\r\n')
                    if not word:
                        continue

                    attempts += 1
                    if self._hasher(word) == target:
                        found = word
                        break

                    # Case variants inline — no function call overhead
                    low = word.lower()
                    if low != word:
                        attempts += 1
                        if self._hasher(low) == target:
                            found = low
                            break

                    cap = word.capitalize()
                    if cap != word and cap != low:
                        attempts += 1
                        if self._hasher(cap) == target:
                            found = cap
                            break

                    if self.verbose and attempts % 50000 == 0:
                        elapsed = time.perf_counter() - start
                        print(f'  [Dict] {attempts:,} attempts | {attempts/elapsed:,.0f} H/s')

        except FileNotFoundError:
            pass

        elapsed = time.perf_counter() - start
        return {
            'password':  found,
            'attempts':  attempts,
            'time':      elapsed,
            'method':    'Dictionary Attack',
            'hash_rate': attempts / elapsed if elapsed > 0 else 0,
        }
