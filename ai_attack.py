"""
ai_attack.py — AI-Based Attacker
==================================
Uses AIPasswordGenerator in a tight single-threaded loop.
No queue overhead. Immediate exit on match.
"""

import time
from hash_identifier import HashIdentifier
from ai_password_generator import AIPasswordGenerator


class AIAttacker:

    def __init__(self, hash_type, wordlist_path=None,
                 bloom_filter=None, threads=4, verbose=False):
        self.hash_type     = hash_type
        self.wordlist_path = wordlist_path
        self.verbose       = verbose
        self.identifier    = HashIdentifier()
        self._hasher       = self.identifier.get_hash_function(hash_type)

    def crack(self, target_hash):
        target   = target_hash.strip().lower()
        start    = time.perf_counter()
        attempts = 0
        found    = None
        seen     = set()

        gen = AIPasswordGenerator(wordlist_path=self.wordlist_path)

        for candidate in gen.generate(max_total=500_000):
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            attempts += 1

            if self._hasher(candidate) == target:
                found = candidate
                break

            if self.verbose and attempts % 50000 == 0:
                elapsed = time.perf_counter() - start
                print(f'  [AI] {attempts:,} | {attempts/elapsed:,.0f} H/s')

        elapsed = time.perf_counter() - start
        return {
            'password':  found,
            'attempts':  attempts,
            'time':      elapsed,
            'method':    'AI Attack',
            'hash_rate': attempts / elapsed if elapsed > 0 else 0,
        }
