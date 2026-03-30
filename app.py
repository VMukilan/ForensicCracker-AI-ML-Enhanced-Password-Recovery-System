"""
app.py - ForensicCracker Flask Backend
=======================================
Run: python app.py
Opens at: http://127.0.0.1:5000
"""

import os, sys, json, threading, time, uuid
from flask import Flask, render_template, request, jsonify, send_file

sys.path.insert(0, os.path.dirname(__file__))

from hash_identifier      import HashIdentifier
from cracker              import DictionaryAttacker
from brute_force          import BruteForceAttacker
from hybrid_attack        import HybridAttacker
from ai_attack            import AIAttacker
from ai_model             import AttackRecommender, PasswordComplexityClassifier
from evaluation           import EvaluationEngine
from logger               import ForensicLogger
from report_generator     import ReportGenerator
from evidence_parser      import EvidenceParser
from osint_wordlist       import OSINTWordlistBuilder
from bloom_filter         import BloomFilter

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

WORDLIST    = os.path.join(os.path.dirname(__file__), 'wordlist.txt')
sessions    = {}   # session_id -> {case_id, examiner, logger, results}
job_status  = {}   # job_id    -> {status, message, result, log}

identifier  = HashIdentifier()
recommender = AttackRecommender()
complexity  = PasswordComplexityClassifier()


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_session(sid):
    if sid not in sessions:
        sessions[sid] = {'case_id': 'CASE-001', 'examiner': 'Analyst',
                         'logger': None, 'results': []}
    return sessions[sid]


def new_job():
    jid = str(uuid.uuid4())[:8]
    job_status[jid] = {'status': 'pending', 'message': 'Initializing...',
                       'result': None, 'log': []}
    return jid


def jlog(jid, msg):
    if jid in job_status:
        job_status[jid]['log'].append(msg)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/session', methods=['POST'])
def create_session():
    data = request.json or {}
    sid  = str(uuid.uuid4())[:12]
    sess = get_session(sid)
    sess['case_id']  = data.get('case_id',  'CASE-001')
    sess['examiner'] = data.get('examiner', 'Analyst')
    sess['logger']   = ForensicLogger(case_id=sess['case_id'], examiner=sess['examiner'])
    return jsonify({'session_id': sid, 'case_id': sess['case_id'], 'examiner': sess['examiner']})


@app.route('/api/identify', methods=['POST'])
def identify_hash():
    data     = request.json or {}
    hash_str = data.get('hash', '').strip()
    if not hash_str:
        return jsonify({'error': 'No hash provided'}), 400
    hash_type = identifier.identify(hash_str)
    info      = identifier.identify_verbose(hash_str)
    rec       = recommender.recommend(hash_str, hash_type)
    return jsonify({
        'hash':               hash_str,
        'hash_type':          hash_type,
        'length':             len(hash_str),
        'salted':             info['salted'],
        'difficulty':         info['crack_difficulty'],
        'gpu_resistant':      info['gpu_resistant'],
        'recommended_method': rec['method'],
        'recommended_id':     rec['method_id'],
        'confidence':         round(rec['confidence'] * 100),
        'reason':             rec['reason'],
    })


@app.route('/api/crack', methods=['POST'])
def crack_hash():
    data      = request.json or {}
    hash_str  = data.get('hash', '').strip()
    method_id = str(data.get('method', '1'))
    sid       = data.get('session_id', '')
    max_len   = int(data.get('max_len', 6))
    wl        = data.get('wordlist') or WORDLIST
    if not os.path.exists(wl):
        wl = WORDLIST
    if not hash_str:
        return jsonify({'error': 'No hash provided'}), 400

    jid       = new_job()
    hash_type = identifier.identify(hash_str)

    def run():
        try:
            job_status[jid]['status']  = 'running'
            job_status[jid]['message'] = 'Attack running...'
            jlog(jid, f'Hash type: {hash_type}')
            jlog(jid, f'Method ID: {method_id}')
            jlog(jid, f'Wordlist:  {wl}')

            result = None

            if method_id == '1':
                jlog(jid, 'Running Dictionary Attack...')
                a = DictionaryAttacker(wl, hash_type)
                result = EvaluationEngine().run('Dictionary Attack', a, hash_str)

            elif method_id == '2':
                jlog(jid, f'Running Brute Force (max len {max_len})...')
                a = BruteForceAttacker(hash_type, max_length=max_len)
                result = EvaluationEngine().run('Brute Force Attack', a, hash_str)

            elif method_id == '3':
                jlog(jid, 'Running Hybrid Attack...')
                a = HybridAttacker(wl, hash_type)
                result = EvaluationEngine().run('Hybrid Attack', a, hash_str)

            elif method_id == '4':
                jlog(jid, 'Running AI Attack...')
                a = AIAttacker(hash_type, wl)
                result = EvaluationEngine().run('AI Attack', a, hash_str)

            elif method_id == '5':
                jlog(jid, 'Running Ensemble (all methods)...')
                result = EvaluationEngine().run_ensemble(
                    hash_str, hash_type, wl, None, 4, False)
            else:
                jlog(jid, 'Running Dictionary Attack (default)...')
                a = DictionaryAttacker(wl, hash_type)
                result = EvaluationEngine().run('Dictionary Attack', a, hash_str)

            # Log to forensic session
            if sid in sessions:
                sess = sessions[sid]
                if sess.get('logger'):
                    sess['logger'].log_attempt(
                        sess['case_id'], sess['examiner'], hash_str, hash_type, result)
                if result:
                    r = dict(result)
                    r['hash_type'] = hash_type
                    r['username']  = data.get('username', 'target')
                    sess['results'].append(r)

            recommender.record_result(int(method_id),
                                      bool(result and result.get('password')))

            if result and result.get('password'):
                jlog(jid, f"Recovered: {result['password']}")
                job_status[jid]['status']  = 'success'
                job_status[jid]['message'] = 'Password recovered.'
            else:
                jlog(jid, 'Password not found.')
                job_status[jid]['status']  = 'failed'
                job_status[jid]['message'] = 'Password not recovered.'

            job_status[jid]['result'] = result

        except Exception as e:
            import traceback; traceback.print_exc()
            job_status[jid]['status']  = 'error'
            job_status[jid]['message'] = str(e)
            jlog(jid, f'Error: {e}')

    threading.Thread(target=run, daemon=True).start()
    return jsonify({'job_id': jid, 'hash_type': hash_type})


@app.route('/api/job/<jid>', methods=['GET'])
def job_route(jid):
    if jid not in job_status:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(job_status[jid])


@app.route('/api/parse_evidence', methods=['POST'])
def parse_evidence():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f    = request.files['file']
    path = f'/tmp/ev_{uuid.uuid4().hex[:8]}_{f.filename}'
    f.save(path)
    try:
        hashes = EvidenceParser().parse(path)
        os.remove(path)
        return jsonify({'hashes': hashes, 'count': len(hashes)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/osint', methods=['POST'])
def build_osint():
    data   = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target name provided'}), 400
    path  = OSINTWordlistBuilder().build(target, base_wordlist=WORDLIST)
    count = sum(1 for _ in open(path, encoding='utf-8', errors='ignore'))
    return jsonify({'path': path, 'word_count': count, 'target': target})


@app.route('/api/report', methods=['POST'])
def generate_report():
    data = request.json or {}
    sid  = data.get('session_id', '')
    if sid not in sessions:
        return jsonify({'error': 'Session not found'}), 404
    sess    = sessions[sid]
    results = sess.get('results', [])
    if not results:
        return jsonify({'error': 'No results to report'}), 400
    log_path = str(sess['logger'].log_path) if sess.get('logger') else None
    path = ReportGenerator().generate(
        case_id=sess['case_id'], examiner=sess['examiner'],
        results=results, log_file=log_path)
    return send_file(path, as_attachment=True,
                     download_name=f"{sess['case_id']}_report.pdf")


@app.route('/api/bandit_stats', methods=['GET'])
def bandit_stats():
    return jsonify(recommender.bandit.get_stats())


@app.route('/api/complexity', methods=['POST'])
def check_complexity():
    pw = (request.json or {}).get('password', '')
    if not pw:
        return jsonify({'error': 'No password'}), 400
    return jsonify(complexity.classify(pw))


# ── Error handlers — always return JSON, never HTML ───────────────────────────

@app.errorhandler(400)
def e400(e): return jsonify({'error': str(e)}), 400

@app.errorhandler(404)
def e404(e): return jsonify({'error': 'Not found'}), 404

@app.errorhandler(405)
def e405(e): return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def e500(e): return jsonify({'error': str(e)}), 500

@app.errorhandler(Exception)
def eAll(e):
    import traceback; traceback.print_exc()
    return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print('\n  ForensicCracker v2.0')
    print('  Server: http://127.0.0.1:5000')
    print('  Press Ctrl+C to stop\n')
    app.run(debug=False, host='127.0.0.1', port=5000, threaded=True)
