"""
hybrid_attack.py — Hybrid Attacker
=====================================
Wordlist mutations + PCFG + Markov, all in a tight single-threaded loop.
No queue, no threading overhead, no deadlocks.
"""

import re
import time
import string
import random
import itertools
from collections import defaultdict, Counter
from hash_identifier import HashIdentifier


LEET = str.maketrans({'a':'@','e':'3','i':'1','o':'0','s':'$','t':'7'})

SUFFIXES = ['123','1234','12345','!','1','2024','2025','00','01',
            '007','999','111','123!','@','#','!@#','69','88']

SYMBOLS  = ['!','@','#','$','!@#']


def mutate(word):
    """Fast inline mutation generator."""
    yield word
    low = word.lower();  yield low
    cap = word.capitalize(); yield cap
    yield word.upper()
    yield word[::-1]
    leet = low.translate(LEET)
    if leet != low: yield leet

    for s in SUFFIXES:
        yield low + s
        yield cap + s
    for s in SYMBOLS:
        yield low + s
        yield cap + s
    for yr in ('2022','2023','2024','2025'):
        yield low + yr
        yield cap + yr


class HybridAttacker:

    def __init__(self, wordlist_path, hash_type, bloom_filter=None,
                 threads=4, verbose=False):
        self.wordlist_path = wordlist_path
        self.hash_type     = hash_type
        self.verbose       = verbose
        self.identifier    = HashIdentifier()
        self._hasher       = self.identifier.get_hash_function(hash_type)

    def _check(self, candidate, target):
        return self._hasher(candidate) == target

    def crack(self, target_hash):
        target   = target_hash.strip().lower()
        start    = time.perf_counter()
        attempts = 0
        found    = None
        seen     = set()

        def try_word(w):
            nonlocal attempts, found
            if w in seen or not w:
                return False
            seen.add(w)
            attempts += 1
            if self._hasher(w) == target:
                found = w
                return True
            return False

        # Phase 1: Wordlist + mutations
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.rstrip('\r\n')
                    if not word:
                        continue
                    for m in mutate(word):
                        if try_word(m):
                            break
                    if found:
                        break
        except FileNotFoundError:
            pass

        if found:
            elapsed = time.perf_counter() - start
            return self._result(found, attempts, elapsed, 'Hybrid (Mutation)')

        # Phase 2: PCFG-style structure candidates
        common_words  = ['password','admin','user','login','welcome',
                         'dragon','master','qwerty','monkey','shadow']
        common_digits = ['1','12','123','1234','01','007','69','99','00']
        common_syms   = ['!','@','#','!@#']

        for w in common_words:
            for d in common_digits:
                for s in common_syms:
                    for cand in (w+d, w.capitalize()+d, w+d+s, w.capitalize()+d+s):
                        if try_word(cand):
                            elapsed = time.perf_counter() - start
                            return self._result(found, attempts, elapsed, 'Hybrid (PCFG)')

        # Phase 3: Markov-like bigram sampling from seen words
        chars = string.ascii_lowercase + string.digits
        random.seed(42)
        for _ in range(20000):
            length = random.randint(5, 10)
            cand   = ''.join(random.choices(chars, k=length))
            if try_word(cand):
                break

        elapsed = time.perf_counter() - start
        return self._result(found, attempts, elapsed, 'Hybrid (Markov)')

    def _result(self, found, attempts, elapsed, method):
        return {
            'password':  found,
            'attempts':  attempts,
            'time':      elapsed,
            'method':    f'Hybrid Attack ({method})',
            'hash_rate': attempts / elapsed if elapsed > 0 else 0,
        }
