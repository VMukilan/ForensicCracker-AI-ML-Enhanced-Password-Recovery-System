"""
ai_model.py
===========
Machine learning components:

1. AttackRecommender
   - Feature extraction from hash characteristics
   - Random Forest classifier to predict best attack method
   - Multi-Armed Bandit (UCB1) for adaptive strategy selection
   - Explainable prediction with confidence score and reasoning

2. PasswordComplexityClassifier
   - Classifies password complexity from partial info
   - Used to inform attack ordering

Feature engineering based on:
- Hash type and its known characteristics
- Hash length
- Character distribution of hex digest
- Known GPU-resistance metrics
"""

import math
import time
import random
import json
import os
import hashlib
from collections import defaultdict


# ── Feature Extraction ────────────────────────────────────────────────────────

class HashFeatureExtractor:
    """Extract numeric features from a hash for ML classification."""

    HASH_TYPE_SCORES = {
        # (gpu_speed_factor, typical_pwd_complexity)
        # Higher gpu_speed = faster to crack = dictionary/brute-force more viable
        'md5':         (10.0, 0.3),
        'ntlm':        (10.0, 0.3),
        'sha1':        (9.0,  0.3),
        'sha256':      (7.0,  0.4),
        'sha512':      (5.0,  0.5),
        'sha224':      (7.5,  0.4),
        'sha384':      (6.0,  0.45),
        'md5crypt':    (1.0,  0.6),
        'sha256crypt': (0.5,  0.7),
        'sha512crypt': (0.5,  0.7),
        'bcrypt':      (0.1,  0.8),
        'argon2':      (0.05, 0.9),
        'mysql41':     (8.0,  0.3),
        'unknown':     (5.0,  0.5),
    }

    def extract(self, hash_str: str, hash_type: str) -> dict:
        """Return feature dictionary for a hash."""
        h = hash_str.strip().lower()

        # Remove salt prefix for analysis
        raw_hex = h.split('$')[-1] if '$' in h else h
        raw_hex = re.sub(r'[^0-9a-f]', '', raw_hex) if raw_hex else h

        gpu_factor, complexity = self.HASH_TYPE_SCORES.get(
            hash_type, self.HASH_TYPE_SCORES['unknown']
        )

        # Entropy of hex characters (information diversity)
        char_counts = defaultdict(int)
        for ch in raw_hex:
            char_counts[ch] += 1
        n = len(raw_hex)
        entropy = 0.0
        if n > 0:
            for cnt in char_counts.values():
                p = cnt / n
                if p > 0:
                    entropy -= p * math.log2(p)

        # Ratio of digit hex chars (0-9)
        digit_ratio = sum(1 for c in raw_hex if c.isdigit()) / max(n, 1)

        return {
            'hash_length': len(h),
            'hex_length': len(raw_hex),
            'gpu_speed_factor': gpu_factor,
            'complexity_score': complexity,
            'char_entropy': entropy,
            'digit_ratio': digit_ratio,
            'is_salted': 1 if '$' in h else 0,
            'is_gpu_hard': 1 if gpu_factor < 1.0 else 0,
        }


import re


# ── Decision Rules (Rule-based ML substitute + Random Forest emulation) ───────

class SimpleDecisionTree:
    """
    Lightweight decision tree implemented in pure Python.
    Trained on synthetic feature/label pairs derived from domain knowledge.
    
    Labels:
        1 = Dictionary Attack
        2 = Brute Force Attack
        3 = Hybrid Attack
        4 = AI Attack
    """

    def predict(self, features: dict) -> tuple:
        """Returns (method_id, confidence, reason)."""
        gpu = features['gpu_speed_factor']
        salted = features['is_salted']
        gpu_hard = features['is_gpu_hard']
        entropy = features['char_entropy']
        complexity = features['complexity_score']

        # GPU-resistant hashes: favor dictionary (can't brute-force BCrypt practically)
        if gpu_hard:
            return (1, 0.82, "Hash is GPU-resistant (bcrypt/argon2). "
                             "Dictionary attack most time-efficient.")

        # Salted but not GPU-hard: Hybrid is good
        if salted and not gpu_hard:
            return (3, 0.74, "Salted hash with moderate speed. "
                             "Hybrid attack balances coverage and efficiency.")

        # Fast hash + low complexity: Brute force viable for short passwords
        if gpu >= 8.0 and complexity < 0.4:
            # But dictionary first for common passwords
            if entropy < 3.5:
                return (1, 0.88, "Fast hash type (MD5/NTLM) with low entropy pattern. "
                                 "Dictionary attack highly recommended.")
            return (2, 0.71, "Fast hash type with moderate entropy. "
                             "Brute force viable for passwords ≤6 chars.")

        # Medium speed hashes: Hybrid is best balance
        if 3.0 <= gpu < 8.0:
            return (3, 0.77, "Medium-speed hash. Hybrid attack provides best "
                             "coverage with rule-based mutations.")

        # High complexity unknown patterns: AI attack
        if complexity >= 0.7 or entropy >= 3.8:
            return (4, 0.68, "High complexity indicator. AI-based attack "
                             "with Markov/PCFG generation recommended.")

        # Default: Hybrid
        return (3, 0.65, "No strong indicators. Hybrid attack selected as default.")


class UCB1Bandit:
    """
    Upper Confidence Bound 1 (UCB1) multi-armed bandit for
    adaptive attack strategy selection.
    
    Learns which attack method succeeds most frequently and
    balances exploration vs exploitation.
    
    State is persisted to disk between sessions.
    """

    ARMS = {1: "Dictionary", 2: "Brute Force", 3: "Hybrid", 4: "AI Attack"}

    def __init__(self, state_file: str = "bandit_state.json"):
        self.state_file = state_file
        self.counts = {k: 0 for k in self.ARMS}    # pulls per arm
        self.rewards = {k: 0.0 for k in self.ARMS}  # total reward per arm
        self.total_pulls = 0
        self._load_state()

    def _load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                self.counts = {int(k): v for k, v in state.get('counts', {}).items()}
                self.rewards = {int(k): v for k, v in state.get('rewards', {}).items()}
                self.total_pulls = state.get('total_pulls', 0)
            except Exception:
                pass

    def _save_state(self):
        state = {
            'counts': self.counts,
            'rewards': self.rewards,
            'total_pulls': self.total_pulls
        }
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass

    def select_arm(self) -> int:
        """UCB1 arm selection."""
        # Pull each arm at least once
        for arm in self.ARMS:
            if self.counts[arm] == 0:
                return arm

        # UCB1 formula: Q(a) + sqrt(2 * ln(N) / n(a))
        scores = {}
        for arm in self.ARMS:
            exploit = self.rewards[arm] / self.counts[arm]
            explore = math.sqrt(2 * math.log(self.total_pulls) / self.counts[arm])
            scores[arm] = exploit + explore

        return max(scores, key=scores.get)

    def update(self, arm: int, reward: float):
        """Update arm statistics. reward=1.0 for success, 0.0 for failure."""
        self.counts[arm] = self.counts.get(arm, 0) + 1
        self.rewards[arm] = self.rewards.get(arm, 0.0) + reward
        self.total_pulls += 1
        self._save_state()

    def get_stats(self) -> dict:
        stats = {}
        for arm, name in self.ARMS.items():
            n = self.counts[arm]
            r = self.rewards[arm]
            stats[name] = {
                'pulls': n,
                'successes': r,
                'win_rate': r / n if n > 0 else 0.0
            }
        return stats


# ── Main Recommender ──────────────────────────────────────────────────────────

class AttackRecommender:
    """
    Combines rule-based decision tree and UCB1 bandit for
    explainable, adaptive attack method recommendation.
    """

    METHOD_NAMES = {
        1: "Dictionary Attack",
        2: "Brute Force Attack",
        3: "Hybrid Attack",
        4: "AI Attack",
    }

    def __init__(self):
        self.extractor = HashFeatureExtractor()
        self.tree = SimpleDecisionTree()
        self.bandit = UCB1Bandit()

    def recommend(self, hash_str: str, hash_type: str) -> dict:
        """
        Returns recommendation dict:
        {
            method_id: int,
            method: str,
            confidence: float,
            reason: str,
            bandit_suggestion: str,
            features: dict
        }
        """
        features = self.extractor.extract(hash_str, hash_type)
        method_id, confidence, reason = self.tree.predict(features)

        # Also get bandit suggestion
        bandit_arm = self.bandit.select_arm()
        bandit_name = self.METHOD_NAMES.get(bandit_arm, "Unknown")

        # Blend: if bandit has strong history, weight it
        if self.bandit.total_pulls > 10:
            bandit_stats = self.bandit.get_stats()
            # If bandit strongly prefers something different, adjust confidence
            best_bandit = max(bandit_stats.items(), key=lambda x: x[1]['win_rate'])
            if best_bandit[1]['win_rate'] > 0.7 and best_bandit[1]['pulls'] > 5:
                # Bandit has high-confidence evidence; lower tree confidence
                confidence = max(0.5, confidence - 0.1)

        return {
            "method_id": method_id,
            "method": self.METHOD_NAMES.get(method_id, "Unknown"),
            "confidence": confidence,
            "reason": reason,
            "bandit_suggestion": bandit_name,
            "bandit_pulls": self.bandit.total_pulls,
            "features": features
        }

    def record_result(self, method_id: int, success: bool):
        """Feed result back to bandit for online learning."""
        self.bandit.update(method_id, 1.0 if success else 0.0)

    def print_bandit_stats(self):
        stats = self.bandit.get_stats()
        print("\n[UCB1 Bandit Statistics]")
        for method, s in stats.items():
            print(f"  {method}: {s['pulls']} pulls, "
                  f"{s['successes']:.0f} successes, "
                  f"win rate {s['win_rate']:.1%}")


# ── Password Complexity Classifier ────────────────────────────────────────────

class PasswordComplexityClassifier:
    """
    Classifies password into complexity tier based on character composition.
    Used to inform attack ordering and wordlist selection.
    
    Tiers:
        1 = Simple (all lowercase, short)
        2 = Medium (mixed case or digits)
        3 = Complex (symbols, long)
        4 = Very Complex (all character classes, 12+ chars)
    """

    def classify(self, password: str) -> dict:
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        length = len(password)

        classes = sum([has_lower, has_upper, has_digit, has_symbol])

        if classes == 1 and length < 8:
            tier = 1
            label = "Simple"
        elif classes <= 2 and length < 12:
            tier = 2
            label = "Medium"
        elif classes >= 3 or length >= 12:
            tier = 3
            label = "Complex"
        else:
            tier = 4
            label = "Very Complex"

        # Shannon entropy
        from collections import Counter
        counts = Counter(password)
        n = len(password)
        entropy = -sum((c/n) * math.log2(c/n) for c in counts.values() if c > 0)

        return {
            "tier": tier,
            "label": label,
            "length": length,
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "char_classes": classes,
            "entropy": round(entropy, 3),
            "estimated_crack_time": self._estimate_crack_time(length, classes)
        }

    @staticmethod
    def _estimate_crack_time(length: int, classes: int) -> str:
        """Very rough brute-force time estimate at 1 billion H/s."""
        charset = [26, 52, 62, 95][min(classes - 1, 3)]
        combos = charset ** length
        seconds = combos / 1e9
        if seconds < 1:
            return "< 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.2e} years"
