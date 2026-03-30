"""
evaluation.py — Evaluation Engine
===================================
Runs attacks and measures performance.
Ensemble: runs all methods, first result wins.
"""

import time
import threading
import math
from hash_identifier import HashIdentifier


class EvaluationEngine:

    def __init__(self, logger=None):
        self.logger   = logger
        self._results = []

    def run(self, method_name, attacker, target_hash):
        print(f'\n[*] Starting: {method_name}')
        result  = attacker.crack(target_hash)
        result['method'] = result.get('method', method_name)
        self._results.append(result)

        if result.get('password'):
            print(f"    Cracked: {result['password']} | "
                  f"{result['attempts']:,} attempts | "
                  f"{result['time']:.3f}s | "
                  f"{result.get('hash_rate',0):,.0f} H/s")
        else:
            print(f"    Not found | {result['attempts']:,} attempts | {result['time']:.3f}s")
        return result

    def run_ensemble(self, target_hash, hash_type, wordlist_path,
                     bloom, threads, verbose):
        """All 4 methods race. First to crack wins."""
        from cracker       import DictionaryAttacker
        from brute_force   import BruteForceAttacker
        from hybrid_attack import HybridAttacker
        from ai_attack     import AIAttacker

        print('\n[*] Ensemble Mode — all attacks racing')
        winner      = [None]
        winner_lock = threading.Lock()
        done_event  = threading.Event()
        start       = time.perf_counter()

        attackers = [
            ('Dictionary',  DictionaryAttacker(wordlist_path, hash_type)),
            ('Hybrid',      HybridAttacker(wordlist_path, hash_type)),
            ('AI',          AIAttacker(hash_type, wordlist_path)),
            ('Brute Force', BruteForceAttacker(hash_type, max_length=5)),
        ]

        def run_one(name, attacker):
            result = attacker.crack(target_hash)
            if result.get('password'):
                with winner_lock:
                    if winner[0] is None:
                        winner[0] = result
                        winner[0]['method'] = f'Ensemble ({name} won)'
                        print(f'  [Ensemble] {name} cracked first: {result["password"]}')
                done_event.set()

        threads_list = [threading.Thread(target=run_one, args=(n, a), daemon=True)
                        for n, a in attackers]
        for t in threads_list:
            t.start()

        done_event.wait(timeout=120)  # max 2 min
        elapsed = time.perf_counter() - start

        result = winner[0] or {
            'password':  None,
            'attempts':  0,
            'time':      elapsed,
            'method':    'Ensemble (all failed)',
            'hash_rate': 0,
        }
        result['time'] = elapsed
        self._results.append(result)
        return result

    def print_summary(self, results=None):
        results = results or self._results
        if not results:
            return
        print('\n' + '='*65)
        print('  PERFORMANCE SUMMARY')
        print('='*65)
        print(f"  {'Method':<28} {'Attempts':>10} {'Time':>8} {'H/s':>12} {'Result':>10}")
        print('-'*65)
        for r in results:
            m      = (r.get('method') or '')[:26]
            found  = 'CRACKED' if r.get('password') else 'FAILED'
            print(f"  {m:<28} {r.get('attempts',0):>10,} "
                  f"{r.get('time',0):>8.3f} "
                  f"{r.get('hash_rate',0):>12,.0f} {found:>10}")
        print('='*65)
