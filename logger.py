"""
logger.py
=========
Forensic-grade logging with:
- HMAC-SHA256 chain signing (each log entry includes MAC of previous entry)
- Tamper detection on log file integrity
- Structured JSON log format
- Chain of custody metadata
- Timestamped entries with examiner attribution
"""

import os
import json
import hmac
import hashlib
import datetime
import secrets
from pathlib import Path


class ForensicLogger:
    """
    HMAC-chained forensic logger.
    
    Each log entry is signed with HMAC-SHA256 using a session key,
    forming a hash chain. Any tampering with previous entries breaks
    the chain, which can be detected on audit.
    
    Log file: forensic_logs/CASE-ID_TIMESTAMP.json
    """

    def __init__(self, case_id: str = "CASE-001", examiner: str = "Unknown",
                 log_dir: str = "forensic_logs"):
        self.case_id = case_id
        self.examiner = examiner
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

        # Generate session signing key (store alongside log for verification)
        self._session_key = secrets.token_bytes(32)
        self._prev_hash = "GENESIS"  # Initial chain anchor
        self._entry_count = 0
        self._session_start = datetime.datetime.utcnow().isoformat() + "Z"

        # Create log file
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.log_path = self.log_dir / f"{case_id}_{ts}.jsonl"
        self._key_path = self.log_dir / f"{case_id}_{ts}.key"

        # Write session key (in real deployment: store on separate secure media)
        with open(self._key_path, 'wb') as f:
            f.write(self._session_key)

        # Write header
        self._write_entry("SESSION_START", {
            "case_id": case_id,
            "examiner": examiner,
            "session_start": self._session_start,
            "tool": "ForensicCracker v2.0",
            "chain_anchor": self._prev_hash
        })

    def _compute_mac(self, data: str) -> str:
        """Compute HMAC-SHA256 of data using session key."""
        return hmac.new(self._session_key, data.encode('utf-8'), hashlib.sha256).hexdigest()

    def _write_entry(self, event_type: str, data: dict):
        """Write a signed, chained log entry."""
        self._entry_count += 1
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"

        entry = {
            "seq": self._entry_count,
            "timestamp": timestamp,
            "event": event_type,
            "case_id": self.case_id,
            "examiner": self.examiner,
            "prev_hash": self._prev_hash,
            "data": data
        }

        # Serialize for signing (deterministic)
        entry_str = json.dumps(entry, sort_keys=True)
        mac = self._compute_mac(entry_str)
        entry["mac"] = mac

        # Update chain
        self._prev_hash = hashlib.sha256(entry_str.encode()).hexdigest()

        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')

    def log_attempt(self, case_id: str, examiner: str, target_hash: str,
                    hash_type: str, result: dict):
        """Log a cracking attempt (success or failure)."""
        data = {
            "target_hash": target_hash,
            "hash_type": hash_type,
            "attack_method": result.get("method", "Unknown") if result else "Unknown",
            "attempts": result.get("attempts", 0) if result else 0,
            "time_seconds": round(result.get("time", 0), 4) if result else 0,
            "hash_rate": round(result.get("hash_rate", 0), 2) if result else 0,
            "success": bool(result and result.get("password")),
            "recovered_password": result.get("password") if result else None,
        }
        self._write_entry("CRACK_ATTEMPT", data)

    def log_evidence_parsed(self, source_file: str, hash_count: int, hash_types: list):
        """Log evidence file parsing."""
        self._write_entry("EVIDENCE_PARSED", {
            "source_file": source_file,
            "hashes_extracted": hash_count,
            "hash_types_found": hash_types
        })

    def log_wordlist_generated(self, source: str, word_count: int):
        """Log OSINT wordlist generation."""
        self._write_entry("WORDLIST_GENERATED", {
            "source": source,
            "word_count": word_count
        })

    def finalize(self):
        """Write session end entry and compute final chain hash."""
        self._write_entry("SESSION_END", {
            "total_entries": self._entry_count + 1,
            "final_chain_hash": self._prev_hash,
            "session_start": self._session_start,
            "session_end": datetime.datetime.utcnow().isoformat() + "Z"
        })
        print(f"\n[*] Forensic log: {self.log_path}")
        print(f"[*] Chain key: {self._key_path}")
        print(f"[*] Final chain hash: {self._prev_hash[:16]}...")

    def verify_integrity(self) -> bool:
        """
        Re-read the log file and verify the HMAC chain.
        Returns True if untampered, False if tampering detected.
        """
        try:
            with open(self._key_path, 'rb') as f:
                key = f.read()

            entries = []
            with open(self.log_path, 'r') as f:
                for line in f:
                    entries.append(json.loads(line.strip()))

            prev_hash = "GENESIS"
            for entry in entries:
                stored_mac = entry.pop("mac", None)
                entry_str = json.dumps(entry, sort_keys=True)
                expected_mac = hmac.new(key, entry_str.encode(), hashlib.sha256).hexdigest()

                if stored_mac != expected_mac:
                    print(f"[!] TAMPER DETECTED at entry seq={entry.get('seq')}")
                    return False

                if entry.get("prev_hash") != prev_hash:
                    print(f"[!] CHAIN BREAK at entry seq={entry.get('seq')}")
                    return False

                prev_hash = hashlib.sha256(entry_str.encode()).hexdigest()

            print("[✓] Log integrity verified. No tampering detected.")
            return True

        except Exception as e:
            print(f"[!] Integrity check failed: {e}")
            return False
