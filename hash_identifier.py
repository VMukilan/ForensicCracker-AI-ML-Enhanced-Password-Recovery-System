"""
hash_identifier.py
==================
Identifies hash type from length, prefix patterns, and character sets.
Supports: MD5, SHA1, SHA224, SHA256, SHA384, SHA512, bcrypt, NTLM,
          sha512crypt ($6$), sha256crypt ($5$), MD5crypt ($1$), argon2.
"""

import re
import hashlib


class HashIdentifier:
    """Identify cryptographic hash type from hash string."""

    HASH_PATTERNS = [
        # (name, regex_pattern, description)
        ("bcrypt",       r"^\$2[aby]\$\d{2}\$.{53}$",        "bcrypt (Blowfish)"),
        ("argon2",       r"^\$argon2(i|d|id)\$",              "Argon2"),
        ("sha512crypt",  r"^\$6\$.+\$.+$",                    "SHA-512 crypt ($6$)"),
        ("sha256crypt",  r"^\$5\$.+\$.+$",                    "SHA-256 crypt ($5$)"),
        ("md5crypt",     r"^\$1\$.+\$.+$",                    "MD5 crypt ($1$)"),
        ("apr1",         r"^\$apr1\$.+\$.+$",                 "Apache MD5 ($apr1$)"),
        ("sha1",         r"^[0-9a-fA-F]{40}$",               "SHA-1"),
        ("sha224",       r"^[0-9a-fA-F]{56}$",               "SHA-224"),
        ("sha256",       r"^[0-9a-fA-F]{64}$",               "SHA-256"),
        ("sha384",       r"^[0-9a-fA-F]{96}$",               "SHA-384"),
        ("sha512",       r"^[0-9a-fA-F]{128}$",              "SHA-512"),
        ("md5",          r"^[0-9a-fA-F]{32}$",               "MD5"),
        ("ntlm",         r"^[0-9a-fA-F]{32}$",               "NTLM (same len as MD5)"),
        ("mysql41",      r"^\*[0-9a-fA-F]{40}$",             "MySQL 4.1+"),
        ("sha3_256",     r"^[0-9a-fA-F]{64}$",               "SHA3-256 (same as SHA-256)"),
        ("sha3_512",     r"^[0-9a-fA-F]{128}$",              "SHA3-512 (same as SHA-512)"),
    ]

    LENGTH_MAP = {
        32:  ["md5", "ntlm"],
        40:  ["sha1"],
        56:  ["sha224"],
        64:  ["sha256", "sha3_256"],
        96:  ["sha384"],
        128: ["sha512", "sha3_512"],
    }

    def identify(self, hash_str: str) -> str:
        """
        Returns the most likely hash type as a string.
        For ambiguous cases (MD5 vs NTLM, SHA256 vs SHA3-256),
        returns the most common one (MD5, SHA256).
        """
        hash_str = hash_str.strip()

        # Check prefix-based patterns first (most specific)
        for name, pattern, desc in self.HASH_PATTERNS:
            if name in ("bcrypt", "argon2", "sha512crypt", "sha256crypt",
                        "md5crypt", "apr1", "mysql41"):
                if re.match(pattern, hash_str):
                    return name

        # Length-based identification
        length = len(hash_str)
        candidates = self.LENGTH_MAP.get(length, [])

        if not candidates:
            return "unknown"

        # Return the primary candidate
        return candidates[0]

    def identify_verbose(self, hash_str: str) -> dict:
        """Returns detailed identification info."""
        hash_str = hash_str.strip()
        hash_type = self.identify(hash_str)
        length = len(hash_str)
        candidates = self.LENGTH_MAP.get(length, [hash_type])

        salted = hash_type in ("bcrypt", "argon2", "sha512crypt",
                               "sha256crypt", "md5crypt", "apr1")
        gpu_hard = hash_type in ("bcrypt", "argon2")

        return {
            "hash": hash_str[:16] + "...",
            "identified_type": hash_type,
            "candidates": candidates,
            "length": length,
            "salted": salted,
            "gpu_resistant": gpu_hard,
            "crack_difficulty": "Very High" if gpu_hard else
                               "High" if salted else
                               "Medium" if hash_type in ("sha256", "sha512") else "Low"
        }

    def get_hash_function(self, hash_type: str):
        """
        Returns a callable that hashes a plaintext string.
        Handles salted hashes by returning a passthrough for external verification.
        """
        hashers = {
            "md5":     lambda p: hashlib.md5(p.encode()).hexdigest(),
            "sha1":    lambda p: hashlib.sha1(p.encode()).hexdigest(),
            "sha224":  lambda p: hashlib.sha224(p.encode()).hexdigest(),
            "sha256":  lambda p: hashlib.sha256(p.encode()).hexdigest(),
            "sha384":  lambda p: hashlib.sha384(p.encode()).hexdigest(),
            "sha512":  lambda p: hashlib.sha512(p.encode()).hexdigest(),
            "sha3_256": lambda p: hashlib.sha3_256(p.encode()).hexdigest(),
            "sha3_512": lambda p: hashlib.sha3_512(p.encode()).hexdigest(),
            "ntlm":    self._ntlm_hash,
            "mysql41": self._mysql41_hash,
        }
        return hashers.get(hash_type, hashlib.md5)

    def verify_hash(self, plaintext: str, target_hash: str, hash_type: str) -> bool:
        """
        Unified verification. Handles salted hashes (bcrypt, sha512crypt)
        and plain hashes alike.
        """
        try:
            if hash_type == "bcrypt":
                import bcrypt
                return bcrypt.checkpw(plaintext.encode(), target_hash.encode())

            elif hash_type in ("sha512crypt", "sha256crypt", "md5crypt", "apr1"):
                import crypt
                return crypt.crypt(plaintext, target_hash) == target_hash

            elif hash_type == "argon2":
                from argon2 import PasswordHasher
                ph = PasswordHasher()
                try:
                    return ph.verify(target_hash, plaintext)
                except Exception:
                    return False

            else:
                hasher = self.get_hash_function(hash_type)
                return hasher(plaintext) == target_hash.lower()

        except ImportError as e:
            # Fallback if optional library not installed
            hasher = self.get_hash_function(hash_type)
            return hasher(plaintext) == target_hash.lower()

    @staticmethod
    def _ntlm_hash(plaintext: str) -> str:
        import hashlib
        return hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()

    @staticmethod
    def _mysql41_hash(plaintext: str) -> str:
        stage1 = hashlib.sha1(plaintext.encode()).digest()
        return '*' + hashlib.sha1(stage1).hexdigest().upper()
