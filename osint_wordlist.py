"""
osint_wordlist.py
=================
OSINT-enhanced wordlist builder.

Generates a personalized wordlist from:
1. Target name/username decomposition
2. Common personal info patterns (birthdays, pet names, etc.)
3. Keyboard-adjacent variants
4. Industry/role-specific terminology
5. Combination and mutation rules

Note: In a live deployment this module would scrape public social media.
This implementation uses heuristic expansion rules to build a targeted
wordlist from known target attributes, which is the most forensically
relevant use case (investigators typically have some suspect information).
"""

import re
import os
import itertools
from pathlib import Path


LEET_MAP = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
YEARS = [str(y) for y in range(1960, 2026)]
COMMON_DIGITS = ['1', '12', '123', '1234', '12345', '0', '00', '007', '99', '69', '01']
COMMON_SYMBOLS = ['!', '@', '#', '!@#', '123!', '1!']


class OSINTWordlistBuilder:
    """
    Builds a personalized wordlist for a named target.
    
    Usage:
        builder = OSINTWordlistBuilder()
        path = builder.build("john.smith", info={
            'birth_year': '1985',
            'pet': 'rex',
            'city': 'london',
            'company': 'acme'
        })
    """

    def build(self, target_name: str, info: dict = None,
              base_wordlist: str = None, output_dir: str = "osint_wordlists") -> str:
        """
        Build and save personalized wordlist.
        
        Parameters
        ----------
        target_name : str
            Target username, full name, or alias.
        info : dict, optional
            Additional known attributes:
            - birth_year, birth_date (DDMM, MMYYYY format)
            - pet, partner, child (names)
            - city, country
            - company, department
            - hobbies (list of strings)
            - phone (partial)
        base_wordlist : str, optional
            Path to base wordlist to merge with.
        
        Returns str path to generated wordlist.
        """
        info = info or {}
        candidates = set()

        # Extract name components
        name_tokens = self._extract_name_tokens(target_name)

        # Expand name tokens
        for token in name_tokens:
            candidates.update(self._expand_word(token))

        # Combine name parts
        if len(name_tokens) >= 2:
            first, last = name_tokens[0], name_tokens[-1]
            combos = [
                first + last,
                last + first,
                first[0] + last,
                first + last[0],
                first + '.' + last,
                last + '.' + first,
                first + '_' + last,
                last + '_' + first,
            ]
            for combo in combos:
                candidates.update(self._expand_word(combo))

        # Personal info expansion
        for key in ['pet', 'partner', 'child', 'city', 'country', 'company', 'department']:
            val = info.get(key, '')
            if val:
                candidates.update(self._expand_word(val.lower()))

        # Birth year patterns
        birth_year = info.get('birth_year', '')
        if birth_year:
            for token in name_tokens:
                candidates.add(token + birth_year)
                candidates.add(token.capitalize() + birth_year)
                candidates.add(token + birth_year[-2:])
            candidates.add(birth_year)
            candidates.add(birth_year + '!')

        # Birth date patterns (DDMM, MMDD, DDMMYYYY)
        birth_date = info.get('birth_date', '')
        if birth_date:
            for token in name_tokens:
                candidates.add(token + birth_date)
                candidates.add(token.capitalize() + birth_date)

        # Hobbies
        for hobby in info.get('hobbies', []):
            candidates.update(self._expand_word(hobby.lower()))

        # Phone number fragments
        phone = info.get('phone', '')
        if phone:
            digits = re.sub(r'\D', '', phone)
            for token in name_tokens:
                candidates.add(token + digits[-4:])
                candidates.add(token + digits[-6:])

        # Cross-combine personal words
        personal_words = []
        for key in ['pet', 'partner', 'child', 'city']:
            if info.get(key):
                personal_words.append(info[key].lower())

        for w1, w2 in itertools.combinations(personal_words[:4], 2):
            candidates.add(w1 + w2)
            candidates.add(w2 + w1)
            candidates.add(w1.capitalize() + w2.capitalize())

        # Load and filter base wordlist (keep words that share tokens with name)
        if base_wordlist and os.path.exists(base_wordlist):
            token_set = {t.lower() for t in name_tokens}
            with open(base_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip().lower()
                    if word and any(t in word for t in token_set):
                        candidates.add(word)

        # Filter out empty/whitespace and sort by length (shorter = more probable)
        final_list = sorted(
            (c for c in candidates if c and len(c) >= 4),
            key=lambda x: (len(x), x)
        )

        # Save
        Path(output_dir).mkdir(exist_ok=True)
        safe_name = re.sub(r'[^\w]', '_', target_name)
        output_path = os.path.join(output_dir, f"osint_{safe_name}.txt")
        with open(output_path, 'w', encoding='utf-8') as f:
            for word in final_list:
                f.write(word + '\n')

        print(f"  [OSINT] Generated {len(final_list):,} candidates for '{target_name}'")
        return output_path

    def _extract_name_tokens(self, name: str) -> list:
        """Split name into component tokens."""
        # Handle: john.smith, john_smith, JohnSmith, john smith
        name = re.sub(r'[._\-\s]+', ' ', name)
        # CamelCase split
        name = re.sub(r'([a-z])([A-Z])', r'\1 \2', name)
        tokens = [t.lower() for t in name.split() if len(t) >= 2]
        return tokens if tokens else [name.lower()]

    def _expand_word(self, word: str) -> set:
        """Generate mutations of a single word."""
        variants = {word, word.lower(), word.upper(), word.capitalize()}

        # Leet substitutions
        leet = word.lower()
        for orig, sub in LEET_MAP.items():
            leet = leet.replace(orig, sub)
        variants.add(leet)

        # Digit suffixes
        for sfx in COMMON_DIGITS:
            variants.add(word + sfx)
            variants.add(word.capitalize() + sfx)

        # Symbol suffixes
        for sfx in COMMON_SYMBOLS:
            variants.add(word + sfx)
            variants.add(word.capitalize() + sfx)

        # Year suffixes
        for year in YEARS[-10:]:  # Last 10 years only to keep size reasonable
            variants.add(word + year)
            variants.add(word.capitalize() + year)

        # Reverse
        variants.add(word[::-1])

        return variants
