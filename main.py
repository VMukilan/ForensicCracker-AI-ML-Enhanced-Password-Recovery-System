"""
ForensicCracker v2.0 - Simple Menu-Driven Interface
====================================================
Run:  python main.py
No arguments needed. Follow the on-screen menu.
"""

import os
import sys
from hash_identifier import HashIdentifier
from cracker import DictionaryAttacker
from brute_force import BruteForceAttacker
from hybrid_attack import HybridAttacker
from ai_attack import AIAttacker
from ai_model import AttackRecommender
from evaluation import EvaluationEngine
from logger import ForensicLogger
from report_generator import ReportGenerator
from evidence_parser import EvidenceParser
from osint_wordlist import OSINTWordlistBuilder
from bloom_filter import BloomFilter

BANNER = """
╔══════════════════════════════════════════════════╗
║       FORENSIC PASSWORD RECOVERY v2.0            ║
║     AI/ML-Enhanced  |  Research Use Only         ║
╚══════════════════════════════════════════════════╝
"""

WORDLIST = "wordlist.txt"


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def ask(prompt, default=""):
    val = input(f"  {prompt}: ").strip()
    return val if val else default


def header(title):
    print(f"\n{'─'*50}")
    print(f"  {title}")
    print(f"{'─'*50}")


# ── Step 1: Session Setup ─────────────────────────────────────────────────────

def setup_session():
    header("STEP 1 — Session Setup")
    case_id  = ask("Case ID", "CASE-001")
    examiner = ask("Examiner name", "Unknown")
    return case_id, examiner


# ── Step 2: Get Target Hash(es) ───────────────────────────────────────────────

def get_hashes():
    header("STEP 2 — Target Hash Input")
    print("  [1] Enter a single hash")
    print("  [2] Load from file  (username:hash  or  hash per line)")
    print("  [3] Parse evidence file  (shadow / pwdump / SQLite / CSV)")
    choice = ask("Choose", "1")

    hashes = []

    if choice == "1":
        h = ask("Paste hash")
        if h:
            hashes.append({"hash": h, "username": "target"})

    elif choice == "2":
        path = ask("File path")
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if ':' in line:
                        parts = line.split(':', 1)
                        hashes.append({"username": parts[0], "hash": parts[1]})
                    else:
                        hashes.append({"username": "unknown", "hash": line})
            print(f"  Loaded {len(hashes)} hash(es).")
        else:
            print("  File not found.")

    elif choice == "3":
        path = ask("Evidence file path")
        if os.path.exists(path):
            parser = EvidenceParser()
            hashes = parser.parse(path)
            print(f"  Extracted {len(hashes)} hash(es).")
        else:
            print("  File not found.")

    return hashes


# ── Step 3: Wordlist ──────────────────────────────────────────────────────────

def get_wordlist():
    header("STEP 3 — Wordlist")
    print(f"  [1] Use default wordlist  ({WORDLIST})")
    print("  [2] Use custom wordlist path")
    print("  [3] Build OSINT wordlist from target name")
    choice = ask("Choose", "1")

    if choice == "2":
        path = ask("Wordlist path")
        return path if os.path.exists(path) else WORDLIST

    elif choice == "3":
        name = ask("Target name / username")
        builder = OSINTWordlistBuilder()
        path = builder.build(name, base_wordlist=WORDLIST)
        print(f"  OSINT wordlist saved: {path}")
        return path

    return WORDLIST


# ── Step 4: Attack Method ─────────────────────────────────────────────────────

def choose_attack(target_hash, hash_type, recommender):
    header("STEP 4 — Attack Method")
    print("  [1] Dictionary Attack")
    print("  [2] Brute Force Attack")
    print("  [3] Hybrid Attack  (Mutations + PCFG + Markov)")
    print("  [4] AI Attack      (Semantic + Markov + Structure)")
    print("  [5] Ensemble       (All methods, fastest wins)")
    print("  [6] Auto-Recommend (AI picks best method)  [default]")
    method = ask("Choose", "6")

    if method == "6":
        rec = recommender.recommend(target_hash, hash_type)
        print(f"\n  AI Recommendation : {rec['method']}")
        print(f"  Confidence        : {rec['confidence']:.0%}")
        print(f"  Reason            : {rec['reason']}")
        method = str(rec['method_id'])

    return method


# ── Run Attack ────────────────────────────────────────────────────────────────

def run_attack(method, target_hash, hash_type, wordlist):
    bloom     = BloomFilter(capacity=2_000_000, error_rate=0.001)
    evaluator = EvaluationEngine()
    threads   = 4

    if method == "1":
        a = DictionaryAttacker(wordlist, hash_type, bloom_filter=bloom, threads=threads)
        return evaluator.run("Dictionary Attack", a, target_hash)

    elif method == "2":
        max_len = ask("Max password length (default 6)", "6")
        a = BruteForceAttacker(hash_type, max_length=int(max_len),
                               bloom_filter=bloom, threads=threads)
        return evaluator.run("Brute Force Attack", a, target_hash)

    elif method == "3":
        a = HybridAttacker(wordlist, hash_type, bloom_filter=bloom, threads=threads)
        return evaluator.run("Hybrid Attack", a, target_hash)

    elif method == "4":
        a = AIAttacker(hash_type, wordlist, bloom_filter=bloom, threads=threads)
        return evaluator.run("AI Attack", a, target_hash)

    elif method == "5":
        return evaluator.run_ensemble(target_hash, hash_type, wordlist,
                                      bloom, threads, verbose=False)

    # fallback
    a = DictionaryAttacker(wordlist, hash_type, bloom_filter=bloom, threads=threads)
    return evaluator.run("Dictionary Attack", a, target_hash)


# ── Show Result ───────────────────────────────────────────────────────────────

def show_result(result, hash_type):
    header("RESULT")
    if result and result.get("password"):
        print(f"  ✓ PASSWORD FOUND  : {result['password']}")
        print(f"  ✓ Hash Type       : {hash_type}")
        print(f"  ✓ Method Used     : {result['method']}")
        print(f"  ✓ Attempts        : {result['attempts']:,}")
        print(f"  ✓ Time Taken      : {result['time']:.4f}s")
        print(f"  ✓ Speed           : {result.get('hash_rate', 0):,.0f} H/s")
    else:
        print("  ✗ Password NOT recovered.")
        print("  Tip: Try a different attack or use a larger wordlist.")


# ── Report ────────────────────────────────────────────────────────────────────

def maybe_report(case_id, examiner, results, log_path):
    header("STEP 5 — Forensic Report")
    choice = ask("Generate PDF report? (y/n)", "n")
    if choice.lower() == 'y':
        gen  = ReportGenerator()
        path = gen.generate(case_id=case_id, examiner=examiner,
                            results=results, log_file=log_path)
        print(f"  Report saved: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    clear()
    print(BANNER)

    case_id, examiner = setup_session()
    logger      = ForensicLogger(case_id=case_id, examiner=examiner)
    recommender = AttackRecommender()
    identifier  = HashIdentifier()

    hashes = get_hashes()
    if not hashes:
        print("\n  No hashes to process. Exiting.")
        sys.exit(0)

    wordlist    = get_wordlist()
    all_results = []

    for entry in hashes:
        target_hash = entry["hash"].strip()
        username    = entry.get("username", "unknown")
        hash_type   = identifier.identify(target_hash)
        info        = identifier.identify_verbose(target_hash)

        header(f"Processing: {username}")
        print(f"  Hash       : {target_hash[:40]}...")
        print(f"  Type       : {hash_type}  |  Difficulty: {info['crack_difficulty']}")
        if info['salted']:
            print("  ⚠  Salted hash — brute force not recommended.")

        method = choose_attack(target_hash, hash_type, recommender)
        result = run_attack(method, target_hash, hash_type, wordlist)

        if result:
            result["username"]  = username
            result["hash_type"] = hash_type

        show_result(result, hash_type)
        logger.log_attempt(case_id, examiner, target_hash, hash_type, result)
        recommender.record_result(int(method), bool(result and result.get("password")))
        all_results.append(result or {})

        if len(hashes) > 1:
            if ask("Continue to next hash? (y/n)", "y").lower() != 'y':
                break

    EvaluationEngine().print_summary(all_results)
    logger.finalize()
    maybe_report(case_id, examiner, all_results, logger.log_path)

    print("\n  Session complete.\n")


if __name__ == "__main__":
    main()
