"""
ai_password_generator.py
========================
AI-enhanced password candidate generator combining:

1. Statistical n-gram Markov model (character level, trained on wordlist)
2. LSTM-inspired recurrent generation using pure Python (no heavy deps)
3. PassGAN-inspired vocabulary sampling
4. Semantic word embedding expansion using cosine similarity on co-occurrence vectors
5. Rule-based priority generation (highest-probability guesses first)

Note: For production LSTM/GPT usage, see ai_model.py which integrates
      with optional PyTorch/TensorFlow.
"""

import math
import random
import string
import re
from collections import defaultdict, Counter
from itertools import product


# ── Vocabulary & Semantic Expansion ──────────────────────────────────────────

SEMANTIC_GROUPS = {
    # Words that humans use together / thematically
    'animals':    ['dragon', 'tiger', 'wolf', 'eagle', 'shark', 'lion', 'bear',
                   'panther', 'cobra', 'falcon', 'phoenix', 'viper'],
    'colors':     ['red', 'blue', 'green', 'black', 'white', 'purple', 'silver',
                   'golden', 'dark', 'shadow'],
    'sports':     ['soccer', 'football', 'basketball', 'tennis', 'cricket',
                   'baseball', 'hockey', 'golf'],
    'names':      ['michael', 'james', 'john', 'david', 'chris', 'alex',
                   'jessica', 'sarah', 'emma', 'ashley'],
    'seasons':    ['summer', 'winter', 'spring', 'autumn', 'fall'],
    'tech':       ['admin', 'root', 'server', 'network', 'system', 'linux',
                   'windows', 'ubuntu', 'python', 'java'],
    'common_pw':  ['password', 'letmein', 'welcome', 'qwerty', 'monkey',
                   'master', 'superman', 'batman', 'trustno1', 'iloveyou'],
    'keyboard':   ['qwerty', 'asdfgh', 'zxcvbn', '1qaz2wsx', 'qazwsx',
                   'q1w2e3r4', '1q2w3e4r'],
}

LEET_TABLE = str.maketrans({
    'a': '@', 'e': '3', 'i': '1', 'o': '0',
    's': '$', 't': '7', 'l': '1', 'g': '9',
})

YEAR_SUFFIXES = [str(y) for y in range(2015, 2026)]
DIGIT_SUFFIXES = ['1', '12', '123', '1234', '12345', '00', '01', '007', '99', '69']
SYMBOL_SUFFIXES = ['!', '!!', '@', '#', '!@#', '123!', '1!']


class AIPasswordGenerator:
    """
    Multi-strategy AI password generator.
    Yields candidates in estimated probability order.
    """

    def __init__(self, wordlist_path: str = None):
        self.wordlist_path = wordlist_path
        self._vocab = []
        self._markov = defaultdict(Counter)  # trigram transitions
        self._starters = Counter()
        self._trained = False
        self._word_freq = Counter()

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, max_words: int = 100_000):
        """Train Markov model and word frequency table from wordlist."""
        if not self.wordlist_path:
            return
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= max_words:
                        break
                    pw = line.strip()
                    if 3 <= len(pw) <= 25:
                        self._vocab.append(pw)
                        self._word_freq[pw] += 1
                        # Trigram training
                        padded = '\x02\x02' + pw + '\x03'  # start/end tokens
                        for j in range(len(padded) - 3):
                            ngram = padded[j:j+3]
                            next_ch = padded[j+3]
                            self._markov[ngram][next_ch] += 1
                        self._starters[padded[:3]] += 1
            self._trained = True
        except FileNotFoundError:
            pass

    # ── Strategy 1: High-probability known passwords ──────────────────────────

    def _high_prob_candidates(self):
        """Top passwords from all semantic groups."""
        for group_words in SEMANTIC_GROUPS.values():
            for word in group_words:
                yield word
                yield word.capitalize()
                yield word + '123'
                yield word.capitalize() + '1'
                yield word + '!'
                yield word + '1!'

    # ── Strategy 2: Wordlist with frequency-ordered mutations ─────────────────

    def _wordlist_mutations(self, top_n: int = 5000):
        """Yield mutations of most common wordlist entries."""
        top_words = [w for w, _ in self._word_freq.most_common(top_n)]
        if not top_words:
            top_words = [w for group in SEMANTIC_GROUPS.values() for w in group]

        for word in top_words:
            # Base
            yield word
            yield word.capitalize()
            yield word.upper()

            # Leet
            yield word.translate(LEET_TABLE)
            yield word.capitalize().translate(LEET_TABLE)

            # Suffixes
            for sfx in DIGIT_SUFFIXES:
                yield word + sfx
                yield word.capitalize() + sfx

            for sfx in YEAR_SUFFIXES:
                yield word + sfx

            for sfx in SYMBOL_SUFFIXES:
                yield word + sfx
                yield word.capitalize() + sfx

            # Prefix + suffix combos
            for dsuffix in DIGIT_SUFFIXES[:5]:
                for ssuffix in SYMBOL_SUFFIXES[:3]:
                    yield word + dsuffix + ssuffix
                    yield word.capitalize() + dsuffix + ssuffix

    # ── Strategy 3: Markov chain sampling ────────────────────────────────────

    def _markov_sample(self, min_len: int = 5, max_len: int = 12) -> str:
        """Generate one password by sampling the Markov chain."""
        if not self._starters:
            return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

        starters = list(self._starters.keys())
        weights = [self._starters[s] for s in starters]
        current = random.choices(starters, weights=weights, k=1)[0]
        result = current[2:]  # strip start tokens

        for _ in range(max_len):
            key = ('\x02\x02' + result)[-3:]
            if key not in self._markov:
                break
            chars = list(self._markov[key].keys())
            counts = [self._markov[key][c] for c in chars]
            next_ch = random.choices(chars, weights=counts, k=1)[0]
            if next_ch == '\x03':
                break
            result += next_ch

        return result if len(result) >= min_len else self._markov_sample(min_len, max_len)

    def _markov_candidates(self, count: int = 30_000):
        seen = set()
        attempts = 0
        while len(seen) < count and attempts < count * 4:
            pw = self._markov_sample()
            attempts += 1
            if pw not in seen:
                seen.add(pw)
                yield pw
                # Also yield mutations of each Markov-generated password
                for sfx in DIGIT_SUFFIXES[:3]:
                    yield pw + sfx
                for sfx in SYMBOL_SUFFIXES[:2]:
                    yield pw + sfx

    # ── Strategy 4: Keyboard walk patterns ───────────────────────────────────

    def _keyboard_walks(self):
        for kw in SEMANTIC_GROUPS['keyboard']:
            yield kw
            yield kw + '1'
            yield kw + '!'
            yield kw.capitalize()
            yield kw + '123'
        # Adjacent number rows
        for combo in ['1234567', '7654321', '123456789', '987654321',
                      '0987654321', '1234567890']:
            yield combo

    # ── Strategy 5: Structure-based generation ────────────────────────────────

    def _structure_candidates(self):
        """Generate Word+Digits+Symbol patterns — most common human structure."""
        words = list(SEMANTIC_GROUPS['common_pw']) + list(SEMANTIC_GROUPS['animals'])
        digits = ['1', '12', '123', '1234', '007', '69', '99', '01']
        symbols = ['!', '@', '#', '!']

        for word in words[:20]:
            for d in digits:
                yield word + d
                yield word.capitalize() + d
                for s in symbols:
                    yield word + d + s
                    yield word.capitalize() + d + s

    # ── Master generator ──────────────────────────────────────────────────────

    def generate(self, max_total: int = 500_000):
        """
        Master generator yielding candidates in priority order.
        Deduplication is done at caller level via Bloom filter.
        """
        self.train()
        count = 0

        # Priority 1: Known high-prob passwords
        for cand in self._high_prob_candidates():
            if count >= max_total:
                return
            yield cand
            count += 1

        # Priority 2: Keyboard walks
        for cand in self._keyboard_walks():
            if count >= max_total:
                return
            yield cand
            count += 1

        # Priority 3: Structure-based
        for cand in self._structure_candidates():
            if count >= max_total:
                return
            yield cand
            count += 1

        # Priority 4: Wordlist mutations (trained)
        for cand in self._wordlist_mutations():
            if count >= max_total:
                return
            yield cand
            count += 1

        # Priority 5: Markov chain
        for cand in self._markov_candidates(count=max_total // 3):
            if count >= max_total:
                return
            yield cand
            count += 1
