"""
evidence_parser.py
==================
Parses real forensic evidence files to extract password hashes.

Supported formats:
- /etc/shadow  (Linux shadow password file)
- /etc/passwd  (old-style passwd with hashes)
- Windows SAM/NTLM hash dumps (pwdump format)
- SQLite databases (common in mobile/app forensics)
- CSV/text dumps with hash columns
- Firefox/Chrome saved password databases (key4.db, Login Data)
- KeePass hash extraction (wrapper for hashcat extraction)
- Raw hash files (one hash per line, optionally username:hash)
"""

import re
import os
import csv
import json
import sqlite3
from pathlib import Path
from typing import List, Dict


class EvidenceParser:
    """
    Multi-format evidence parser that extracts (username, hash) pairs
    from various forensic artifact types.
    """

    def parse(self, file_path: str) -> List[Dict]:
        """
        Auto-detect file format and extract hashes.
        Returns list of dicts: [{username, hash, source, format}]
        """
        path = Path(file_path)
        if not path.exists():
            print(f"  [!] Evidence file not found: {file_path}")
            return []

        fname = path.name.lower()
        suffix = path.suffix.lower()

        # Auto-detect by filename/extension
        if fname in ('shadow', 'shadow.bak', 'gshadow'):
            return self._parse_shadow(file_path)
        elif fname in ('passwd',):
            return self._parse_passwd(file_path)
        elif fname in ('sam', 'ntds.dit') or 'pwdump' in fname:
            return self._parse_pwdump(file_path)
        elif suffix == '.db' or suffix == '.sqlite' or suffix == '.sqlite3':
            return self._parse_sqlite(file_path)
        elif suffix == '.csv':
            return self._parse_csv(file_path)
        elif fname == 'login data':
            return self._parse_chrome_login_data(file_path)
        else:
            # Try raw hash file (one per line, optionally user:hash)
            return self._parse_raw(file_path)

    # ── Format: /etc/shadow ───────────────────────────────────────────────────

    def _parse_shadow(self, path: str) -> List[Dict]:
        """
        Parse Linux /etc/shadow format.
        Format: username:$type$salt$hash:last_change:...
        """
        results = []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                if len(parts) < 2:
                    continue
                username = parts[0]
                hash_field = parts[1]

                # Skip locked/empty accounts
                if hash_field in ('*', '!', '!!', 'x', ''):
                    continue

                # Detect hash type from prefix
                hash_type = self._detect_shadow_type(hash_field)
                results.append({
                    'username': username,
                    'hash': hash_field,
                    'hash_type': hash_type,
                    'source': path,
                    'format': 'shadow'
                })
        print(f"  [*] shadow: extracted {len(results)} hashes")
        return results

    # ── Format: /etc/passwd (legacy) ─────────────────────────────────────────

    def _parse_passwd(self, path: str) -> List[Dict]:
        results = []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    pw_field = parts[1]
                    if pw_field and pw_field not in ('x', '*', '!', ''):
                        results.append({
                            'username': username,
                            'hash': pw_field,
                            'hash_type': self._detect_shadow_type(pw_field),
                            'source': path,
                            'format': 'passwd'
                        })
        print(f"  [*] passwd: extracted {len(results)} hashes")
        return results

    # ── Format: pwdump / NTLM dump ────────────────────────────────────────────

    def _parse_pwdump(self, path: str) -> List[Dict]:
        """
        Parse pwdump format: username:RID:LM_hash:NTLM_hash:::
        """
        results = []
        ntlm_pattern = re.compile(r'^[0-9a-fA-F]{32}$')
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                parts = line.split(':')
                if len(parts) >= 4:
                    username = parts[0]
                    # LM hash at index 2, NTLM at index 3
                    ntlm_hash = parts[3]
                    if ntlm_pattern.match(ntlm_hash):
                        # Skip empty NT hash (aad3b435...)
                        if ntlm_hash.lower() != 'aad3b435b51404eeaad3b435b51404ee':
                            results.append({
                                'username': username,
                                'hash': ntlm_hash.lower(),
                                'hash_type': 'ntlm',
                                'source': path,
                                'format': 'pwdump'
                            })
        print(f"  [*] pwdump: extracted {len(results)} NTLM hashes")
        return results

    # ── Format: SQLite database ───────────────────────────────────────────────

    def _parse_sqlite(self, path: str) -> List[Dict]:
        """
        Search all SQLite tables for columns that look like password hashes.
        Common in mobile app databases and web app databases.
        """
        results = []
        hash_patterns = [
            re.compile(r'^[0-9a-fA-F]{32}$'),   # MD5/NTLM
            re.compile(r'^[0-9a-fA-F]{40}$'),   # SHA1
            re.compile(r'^[0-9a-fA-F]{64}$'),   # SHA256
            re.compile(r'^\$2[aby]\$.+'),         # bcrypt
            re.compile(r'^\$6\$.+'),              # sha512crypt
        ]
        username_col_names = {'username', 'user', 'email', 'login', 'name', 'user_name'}
        hash_col_names = {'password', 'passwd', 'pwd', 'pass', 'hash', 'password_hash',
                          'hashed_password', 'pw_hash', 'pw'}

        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                try:
                    cursor.execute(f'PRAGMA table_info("{table}")')
                    columns = [(row[1].lower(), row[1]) for row in cursor.fetchall()]
                    col_names_lower = [c[0] for c in columns]

                    # Find username and hash columns
                    user_col = next((c[1] for c in columns if c[0] in username_col_names), None)
                    hash_col = next((c[1] for c in columns if c[0] in hash_col_names), None)

                    if hash_col:
                        select_cols = f'"{hash_col}"'
                        if user_col:
                            select_cols = f'"{user_col}", {select_cols}'

                        cursor.execute(f'SELECT {select_cols} FROM "{table}" LIMIT 10000')
                        rows = cursor.fetchall()

                        for row in rows:
                            if user_col:
                                username, hash_val = str(row[0]), str(row[1])
                            else:
                                username, hash_val = table, str(row[0])

                            hash_val = hash_val.strip() if hash_val else ''
                            if hash_val and any(p.match(hash_val) for p in hash_patterns):
                                results.append({
                                    'username': username,
                                    'hash': hash_val,
                                    'hash_type': 'unknown',
                                    'source': f"{path}:{table}",
                                    'format': 'sqlite'
                                })
                except Exception:
                    pass

            conn.close()
        except Exception as e:
            print(f"  [!] SQLite parse error: {e}")

        print(f"  [*] SQLite: extracted {len(results)} hashes from {path}")
        return results

    # ── Format: CSV ──────────────────────────────────────────────────────────

    def _parse_csv(self, path: str) -> List[Dict]:
        """Parse CSV files with username/hash columns."""
        results = []
        hash_col_names = {'password', 'passwd', 'hash', 'password_hash', 'pw', 'md5', 'sha1'}
        user_col_names = {'username', 'user', 'email', 'login'}

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return results

            headers_lower = {h.lower(): h for h in reader.fieldnames}
            hash_col = next((headers_lower[h] for h in headers_lower if h in hash_col_names), None)
            user_col = next((headers_lower[h] for h in headers_lower if h in user_col_names), None)

            if not hash_col:
                return results

            for row in reader:
                hash_val = row.get(hash_col, '').strip()
                username = row.get(user_col, 'csv_user').strip() if user_col else 'csv_user'
                if hash_val:
                    results.append({
                        'username': username,
                        'hash': hash_val,
                        'hash_type': 'unknown',
                        'source': path,
                        'format': 'csv'
                    })

        print(f"  [*] CSV: extracted {len(results)} hashes")
        return results

    # ── Format: Chrome Login Data ─────────────────────────────────────────────

    def _parse_chrome_login_data(self, path: str) -> List[Dict]:
        """
        Parse Chrome's Login Data SQLite database.
        Note: passwords are encrypted with DPAPI/Keyring in real browsers.
        This extracts the origin_url + username for OSINT wordlist building.
        """
        results = []
        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT origin_url, username_value, password_value
                FROM logins
            """)
            for url, username, pw_blob in cursor.fetchall():
                if username:
                    results.append({
                        'username': username,
                        'hash': pw_blob.hex() if pw_blob else '',
                        'hash_type': 'chrome_encrypted',
                        'source': path,
                        'format': 'chrome_login_data',
                        'url': url
                    })
            conn.close()
        except Exception as e:
            print(f"  [!] Chrome Login Data parse error: {e}")
        print(f"  [*] Chrome Login Data: extracted {len(results)} entries")
        return results

    # ── Format: Raw hash file ─────────────────────────────────────────────────

    def _parse_raw(self, path: str) -> List[Dict]:
        """
        Parse raw hash file.
        Accepts: hash_value or username:hash_value per line.
        """
        results = []
        hash_re = re.compile(r'^[0-9a-fA-F]{32,128}$|^\$[0-9a-z]+\$.+')

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    parts = line.split(':', 1)
                    username, hash_val = parts[0], parts[1]
                else:
                    username, hash_val = 'unknown', line

                hash_val = hash_val.strip()
                if hash_re.match(hash_val):
                    results.append({
                        'username': username,
                        'hash': hash_val,
                        'hash_type': 'unknown',
                        'source': path,
                        'format': 'raw'
                    })

        print(f"  [*] Raw file: extracted {len(results)} hashes")
        return results

    # ── Helper ────────────────────────────────────────────────────────────────

    @staticmethod
    def _detect_shadow_type(hash_str: str) -> str:
        if hash_str.startswith('$6$'):
            return 'sha512crypt'
        elif hash_str.startswith('$5$'):
            return 'sha256crypt'
        elif hash_str.startswith('$1$'):
            return 'md5crypt'
        elif hash_str.startswith('$2') and hash_str[2] in 'aby':
            return 'bcrypt'
        elif hash_str.startswith('$argon2'):
            return 'argon2'
        elif hash_str.startswith('$apr1$'):
            return 'apr1'
        elif re.match(r'^[0-9a-fA-F]{32}$', hash_str):
            return 'md5'
        elif re.match(r'^[0-9a-fA-F]{40}$', hash_str):
            return 'sha1'
        elif re.match(r'^[0-9a-fA-F]{64}$', hash_str):
            return 'sha256'
        return 'unknown'
