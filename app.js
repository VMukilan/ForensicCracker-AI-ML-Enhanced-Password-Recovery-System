/* ═══════════════════════════════════════════════════════════
   ForensicCracker v2.0 — Frontend Application Logic
   ═══════════════════════════════════════════════════════════ */

'use strict';

/* ── State ──────────────────────────────────────────────── */

const state = {
  sessionId:      null,
  caseId:         'CASE-001',
  examiner:       'Analyst',
  currentJob:     null,
  pollInterval:   null,
  osintPath:      null,
  results:        [],
  evidenceHashes: [],
  batchQueue:     [],
  batchIndex:     0,
  batchRunning:   false,
};

/* ── Init ────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  initMethodCards();
  attachHashInputListener();
  setStatus('idle', 'Idle');
  // Auto-create a default session on page load so user can start immediately
  await autoSession();
});

/* ── Auto Session ────────────────────────────────────────── */

async function autoSession() {
  try {
    const res = await apiJson('/api/session', 'POST', {
      case_id:  state.caseId,
      examiner: state.examiner,
    });
    state.sessionId = res.session_id;
    state.caseId    = res.case_id;
    state.examiner  = res.examiner;
    updateSessionBadge();
  } catch (e) {
    // server not yet ready, silently ignore
  }
}

/* ── Panel Navigation ────────────────────────────────────── */

function showPanel(panelId, navEl) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(panelId).classList.add('active');
  if (navEl) navEl.classList.add('active');

  if (panelId === 'panel-model')   loadModelStats();
  if (panelId === 'panel-results') renderResultsTable();
  if (panelId === 'panel-log')     renderForensicLog();
}

/* ── Session Modal ───────────────────────────────────────── */

function openSessionModal()  { document.getElementById('sessionModal').classList.remove('hidden'); }
function closeSessionModal() { document.getElementById('sessionModal').classList.add('hidden'); }

async function createSession() {
  const caseId   = document.getElementById('modalCaseId').value.trim()   || 'CASE-001';
  const examiner = document.getElementById('modalExaminer').value.trim() || 'Analyst';

  try {
    const res = await apiJson('/api/session', 'POST', { case_id: caseId, examiner });
    state.sessionId = res.session_id;
    state.caseId    = res.case_id;
    state.examiner  = res.examiner;
    state.results   = [];
    updateSessionBadge();
    closeSessionModal();
    appendLog('logBox', `Session opened: ${res.case_id} / ${res.examiner}`, 'info');
  } catch (e) {
    showError('Failed to create session: ' + e.message);
  }
}

function updateSessionBadge() {
  document.getElementById('sessionBadge').textContent =
    `${state.caseId}  —  ${state.examiner}`;
}

/* ── Hash Input & Identification ─────────────────────────── */

let identifyTimer = null;

function attachHashInputListener() {
  document.getElementById('hashInput').addEventListener('input', () => {
    clearTimeout(identifyTimer);
    const val = document.getElementById('hashInput').value.trim();
    if (val.length >= 16) {
      identifyTimer = setTimeout(() => identifyHash(val), 500);
    } else {
      document.getElementById('hashInfo').classList.add('hidden');
      resetRecommendBox();
    }
  });
}

async function identifyHash(hash) {
  try {
    const res = await apiJson('/api/identify', 'POST', { hash });
    document.getElementById('hashInfo').classList.remove('hidden');
    document.getElementById('infoType').textContent   = res.hash_type.toUpperCase();
    document.getElementById('infoDiff').textContent   = res.difficulty;
    document.getElementById('infoSalted').textContent = res.salted ? 'Yes' : 'No';
    document.getElementById('infoGpu').textContent    = res.gpu_resistant ? 'Yes' : 'No';

    const box = document.getElementById('recommendBox');
    box.classList.add('has-rec');
    box.innerHTML =
      `<strong>${res.recommended_method}</strong> &mdash; ${res.confidence}% confidence<br>
       <span style="font-size:11px;opacity:.8">${res.reason}</span>`;

    selectMethod(String(res.recommended_id));
  } catch (e) {
    // silent — identification is non-critical
  }
}

function resetRecommendBox() {
  const box = document.getElementById('recommendBox');
  box.classList.remove('has-rec');
  box.textContent = 'Paste a hash above to get an AI recommendation.';
}

/* ── Method Cards ────────────────────────────────────────── */

function initMethodCards() {
  document.querySelectorAll('.method-card').forEach(card => {
    card.addEventListener('click', () => selectMethod(card.dataset.method));
  });
}

function selectMethod(methodId) {
  document.querySelectorAll('.method-card').forEach(c => c.classList.remove('selected'));
  const target = document.querySelector(`.method-card[data-method="${methodId}"]`);
  if (target) {
    target.classList.add('selected');
    const radio = target.querySelector('input[type=radio]');
    if (radio) radio.checked = true;
  }
  document.getElementById('bfOptions').style.display = methodId === '2' ? 'flex' : 'none';
}

/* ── Crack Attack ────────────────────────────────────────── */

async function startCrack() {
  const hash = document.getElementById('hashInput').value.trim();
  if (!hash) { showError('Please enter a hash value.'); return; }

  // Ensure we have a session (auto-create if needed)
  if (!state.sessionId) {
    await autoSession();
    if (!state.sessionId) { showError('Could not connect to server. Is app.py running?'); return; }
  }

  const methodEl = document.querySelector('.method-card.selected');
  const method   = methodEl ? methodEl.dataset.method : '1';
  const maxLen   = parseInt(document.getElementById('maxLen').value || '6', 10);

  document.getElementById('crackBtn').disabled = true;
  resetProgressArea();
  clearLogBox();
  setStatus('running', 'Running...');
  appendLog('logBox', `Attack initiated — method: ${method}, hash length: ${hash.length}`, 'info');

  try {
    const res = await apiJson('/api/crack', 'POST', {
      hash,
      method,
      max_len:    maxLen,
      session_id: state.sessionId,
      wordlist:   state.osintPath || null,
      username:   'target',
    });

    state.currentJob = res.job_id;
    appendLog('logBox', `Job ID: ${res.job_id} | Hash type: ${res.hash_type}`, 'info');
    startPolling(res.job_id);

  } catch (e) {
    document.getElementById('crackBtn').disabled = false;
    setStatus('failed', 'Error');
    showError('Attack failed to start: ' + e.message);
    appendLog('logBox', 'Attack failed to start: ' + e.message, 'error');
  }
}

function startPolling(jobId) {
  clearInterval(state.pollInterval);
  state.pollInterval = setInterval(async () => {
    try {
      const job = await apiJson(`/api/job/${jobId}`, 'GET');

      // Append any new log lines
      if (Array.isArray(job.log) && job.log.length) {
        const box = document.getElementById('logBox');
        const existing = box.querySelectorAll('.log-line').length;
        job.log.slice(existing).forEach(msg => appendLog('logBox', msg, 'info'));
      }

      if (['success', 'failed', 'error'].includes(job.status)) {
        clearInterval(state.pollInterval);
        document.getElementById('crackBtn').disabled = false;
        finalizeResult(job);
      }
    } catch (e) {
      // network blip — keep polling
    }
  }, 900);
}

function resetProgressArea() {
  document.getElementById('progressArea').innerHTML = `
    <div class="progress-bar-wrap">
      <div class="progress-label">
        <span>Attack in progress...</span>
      </div>
      <div class="progress-bar"><div class="progress-fill"></div></div>
    </div>`;
  document.getElementById('resultBlock').classList.add('hidden');
}

function clearLogBox() {
  document.getElementById('logBox').innerHTML = '';
}

function finalizeResult(job) {
  const result = job.result || {};

  // Collapse progress bar
  document.getElementById('progressArea').innerHTML =
    '<div class="progress-idle"><p>Attack complete.</p></div>';

  const block    = document.getElementById('resultBlock');
  const statusEl = document.getElementById('resultStatus');
  const gridEl   = document.getElementById('resultGrid');
  block.classList.remove('hidden');

  if (result.password) {
    setStatus('success', 'Cracked');
    statusEl.className   = 'result-status success';
    statusEl.textContent = 'Password recovered successfully.';
    appendLog('logBox', 'Recovered: ' + result.password, 'success');

    gridEl.innerHTML = `
      <div class="result-item highlight" style="grid-column:1/-1">
        <div class="result-key">Recovered Password</div>
        <div class="result-val">${esc(result.password)}</div>
      </div>
      <div class="result-item">
        <div class="result-key">Method</div>
        <div class="result-val">${esc(result.method || '—')}</div>
      </div>
      <div class="result-item">
        <div class="result-key">Attempts</div>
        <div class="result-val">${(result.attempts || 0).toLocaleString()}</div>
      </div>
      <div class="result-item">
        <div class="result-key">Time</div>
        <div class="result-val">${(result.time || 0).toFixed(4)}s</div>
      </div>
      <div class="result-item">
        <div class="result-key">Speed</div>
        <div class="result-val">${Math.round(result.hash_rate || 0).toLocaleString()} H/s</div>
      </div>`;

    state.results.push(result);

  } else {
    setStatus('failed', 'Not Recovered');
    statusEl.className   = 'result-status failed';
    statusEl.textContent = job.status === 'error'
      ? 'Error: ' + (job.message || 'Unknown error.')
      : 'Password not recovered. Try a different attack method or a larger wordlist.';
    appendLog('logBox', 'Password not found.', 'warn');

    gridEl.innerHTML = `
      <div class="result-item">
        <div class="result-key">Attempts</div>
        <div class="result-val">${(result.attempts || 0).toLocaleString()}</div>
      </div>
      <div class="result-item">
        <div class="result-key">Time</div>
        <div class="result-val">${(result.time || 0).toFixed(4)}s</div>
      </div>`;
  }
}

function clearCrack() {
  clearInterval(state.pollInterval);
  document.getElementById('hashInput').value = '';
  document.getElementById('hashInfo').classList.add('hidden');
  document.getElementById('resultBlock').classList.add('hidden');
  resetRecommendBox();
  document.getElementById('progressArea').innerHTML = `
    <div class="progress-idle">
      <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
        <circle cx="20" cy="20" r="18" stroke="#c8d4e0" stroke-width="1.5"/>
        <path d="M20 12v8l5 3" stroke="#c8d4e0" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <p>No attack running.</p>
    </div>`;
  clearLogBox();
  document.getElementById('crackBtn').disabled = false;
  setStatus('idle', 'Idle');
}

/* ── Evidence Parser ─────────────────────────────────────── */

function handleEvidenceUpload(input) {
  const file = input.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('file', file);
  appendLog('logBox', 'Parsing evidence file: ' + file.name, 'info');

  fetch('/api/parse_evidence', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      if (data.error) { showError(data.error); return; }
      state.evidenceHashes = data.hashes || [];
      renderEvidenceTable(state.evidenceHashes);
    })
    .catch(e => showError('Upload failed: ' + e.message));
}

function renderEvidenceTable(hashes) {
  const body = document.getElementById('evidenceBody');
  body.innerHTML = '';
  hashes.forEach((h, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${esc(h.username || '—')}</td>
      <td class="mono">${esc((h.hash || '').slice(0, 32))}${(h.hash || '').length > 32 ? '...' : ''}</td>
      <td>${esc(h.hash_type || 'unknown')}</td>
      <td class="mono">${esc(h.format || '—')}</td>
      <td><button class="btn-secondary" style="height:28px;font-size:11px;padding:0 10px"
          onclick="crackEvidenceHash(${i})">Crack</button></td>`;
    body.appendChild(tr);
  });
  document.getElementById('evidenceResults').classList.remove('hidden');
}

function crackEvidenceHash(index) {
  const entry = state.evidenceHashes[index];
  if (!entry) return;
  document.getElementById('hashInput').value = entry.hash;
  showPanel('panel-crack', document.querySelector('[data-panel="panel-crack"]'));
  identifyHash(entry.hash);
}

function sendHashesToCracker() {
  if (!state.evidenceHashes.length) return;
  document.getElementById('batchInput').value =
    state.evidenceHashes.map(h => `${h.username}:${h.hash}`).join('\n');
  showPanel('panel-batch', document.querySelector('[data-panel="panel-batch"]'));
}

/* ── OSINT Wordlist ──────────────────────────────────────── */

async function buildOsint() {
  const name = document.getElementById('osintName').value.trim();
  if (!name) { showError('Please enter a target name.'); return; }

  try {
    const res = await apiJson('/api/osint', 'POST', {
      target:     name,
      birth_year: document.getElementById('osintYear').value,
      city:       document.getElementById('osintCity').value,
      pet:        document.getElementById('osintPet').value,
      company:    document.getElementById('osintCompany').value,
    });
    state.osintPath = res.path;
    document.getElementById('osintCount').textContent  = res.word_count.toLocaleString();
    document.getElementById('osintTarget').textContent = res.target;
    document.getElementById('osintPath').textContent   = res.path;
    document.getElementById('osintOutput').classList.add('hidden');
    document.getElementById('osintResult').classList.remove('hidden');
  } catch (e) {
    showError('OSINT build failed: ' + e.message);
  }
}

function useOsintWordlist() {
  if (!state.osintPath) return;
  showPanel('panel-crack', document.querySelector('[data-panel="panel-crack"]'));
  appendLog('logBox', 'OSINT wordlist active: ' + state.osintPath, 'info');
}

/* ── Batch Analysis ──────────────────────────────────────── */

async function runBatch() {
  const raw    = document.getElementById('batchInput').value.trim();
  const method = document.getElementById('batchMethod').value;
  if (!raw) { showError('Paste hashes into the input.'); return; }

  if (!state.sessionId) {
    await autoSession();
    if (!state.sessionId) { showError('Cannot connect to server.'); return; }
  }

  const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);
  state.batchQueue = lines.map(l => {
    if (l.includes(':')) {
      const idx  = l.indexOf(':');
      return { username: l.slice(0, idx), hash: l.slice(idx + 1) };
    }
    return { username: 'unknown', hash: l };
  });
  state.batchIndex   = 0;
  state.batchRunning = true;

  document.getElementById('batchProgress').classList.add('hidden');
  document.getElementById('batchResults').classList.remove('hidden');
  document.getElementById('batchBody').innerHTML = '';

  state.batchQueue.forEach((item, i) => {
    const tr = document.createElement('tr');
    tr.id = `brow-${i}`;
    tr.innerHTML = `
      <td>${i + 1}</td>
      <td class="mono">${esc(item.hash.slice(0, 24))}...</td>
      <td id="btype-${i}">—</td>
      <td id="bpass-${i}">—</td>
      <td id="btime-${i}">—</td>
      <td><span class="badge badge-info" id="bstat-${i}">Queued</span></td>`;
    document.getElementById('batchBody').appendChild(tr);
  });

  processBatchItem(method);
}

async function processBatchItem(method) {
  if (state.batchIndex >= state.batchQueue.length) {
    state.batchRunning = false;
    return;
  }
  const i    = state.batchIndex;
  const item = state.batchQueue[i];

  document.getElementById(`bstat-${i}`).textContent = 'Running';
  document.getElementById(`bstat-${i}`).className   = 'badge badge-info';

  try {
    const idRes = await apiJson('/api/identify', 'POST', { hash: item.hash });
    document.getElementById(`btype-${i}`).textContent = idRes.hash_type.toUpperCase();

    const crackRes = await apiJson('/api/crack', 'POST', {
      hash: item.hash, method, session_id: state.sessionId, username: item.username
    });
    await pollUntilDone(crackRes.job_id, i);
  } catch (e) {
    document.getElementById(`bstat-${i}`).textContent = 'Error';
    document.getElementById(`bstat-${i}`).className   = 'badge badge-failed';
  }

  state.batchIndex++;
  setTimeout(() => processBatchItem(method), 300);
}

function pollUntilDone(jobId, rowIndex) {
  return new Promise(resolve => {
    const iv = setInterval(async () => {
      try {
        const job = await apiJson(`/api/job/${jobId}`, 'GET');
        if (['success', 'failed', 'error'].includes(job.status)) {
          clearInterval(iv);
          const r = job.result || {};
          document.getElementById(`bpass-${rowIndex}`).textContent = r.password || '—';
          document.getElementById(`btime-${rowIndex}`).textContent = `${(r.time || 0).toFixed(3)}s`;
          if (r.password) {
            document.getElementById(`bstat-${rowIndex}`).textContent = 'Cracked';
            document.getElementById(`bstat-${rowIndex}`).className   = 'badge badge-success';
            state.results.push(r);
          } else {
            document.getElementById(`bstat-${rowIndex}`).textContent = 'Not Found';
            document.getElementById(`bstat-${rowIndex}`).className   = 'badge badge-failed';
          }
          resolve();
        }
      } catch (e) { clearInterval(iv); resolve(); }
    }, 900);
  });
}

/* ── AI Model Stats ──────────────────────────────────────── */

async function loadModelStats() {
  try {
    const stats = await apiJson('/api/bandit_stats', 'GET');
    const map = {
      'Dictionary':  { v: 's1', s: 's1sub' },
      'Brute Force': { v: 's2', s: 's2sub' },
      'Hybrid':      { v: 's3', s: 's3sub' },
      'AI Attack':   { v: 's4', s: 's4sub' },
    };
    Object.entries(stats).forEach(([name, data]) => {
      const ids = map[name];
      if (!ids) return;
      const pct = data.pulls > 0 ? (data.win_rate * 100).toFixed(0) + '%' : '—';
      document.getElementById(ids.v).textContent = pct;
      document.getElementById(ids.s).textContent = `${data.pulls} pulls / ${data.successes} wins`;
    });
  } catch (e) { /* silent */ }
}

/* ── Forensic Log Panel ──────────────────────────────────── */

function renderForensicLog() {
  const box = document.getElementById('forensicLog');
  box.innerHTML = '';
  appendLog('forensicLog', `Session: ${state.caseId} | Examiner: ${state.examiner}`, 'info');
  appendLog('forensicLog', 'HMAC-SHA256 chain signing active. Each entry cryptographically linked.', 'info');
  if (!state.results.length) {
    appendLog('forensicLog', 'No results yet this session.', 'warn');
    return;
  }
  state.results.forEach((r, i) => {
    const pw  = r.password ? `RECOVERED: ${r.password}` : 'NOT FOUND';
    const msg = `[${i+1}] ${(r.hash_type||'—').toUpperCase()} | ${r.method||'—'} | ${pw} | ${(r.attempts||0).toLocaleString()} attempts`;
    appendLog('forensicLog', msg, r.password ? 'success' : 'warn');
  });
}

/* ── Results Table ───────────────────────────────────────── */

function renderResultsTable() {
  const body = document.getElementById('resultsBody');
  body.innerHTML = '';
  if (!state.results.length) {
    document.getElementById('resultsEmpty').classList.remove('hidden');
    document.getElementById('resultsTable').classList.add('hidden');
    return;
  }
  document.getElementById('resultsEmpty').classList.add('hidden');
  document.getElementById('resultsTable').classList.remove('hidden');
  state.results.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${esc(r.username || '—')}</td>
      <td>${esc((r.hash_type || '—').toUpperCase())}</td>
      <td>${esc(r.method || '—')}</td>
      <td>${(r.attempts || 0).toLocaleString()}</td>
      <td>${(r.time || 0).toFixed(4)}s</td>
      <td>${Math.round(r.hash_rate || 0).toLocaleString()} H/s</td>
      <td><strong>${r.password ? esc(r.password) : '—'}</strong></td>`;
    body.appendChild(tr);
  });
}

/* ── Report Download ─────────────────────────────────────── */

async function downloadReport() {
  if (!state.sessionId) { showError('Open a session first.'); return; }
  if (!state.results.length) { showError('Run at least one attack first.'); return; }

  try {
    const res = await fetch('/api/report', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ session_id: state.sessionId }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Report generation failed.' }));
      showError(err.error || 'Report generation failed.');
      return;
    }

    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `${state.caseId}_report.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    showError('Report download failed: ' + e.message);
  }
}

/* ── Core API Helper ─────────────────────────────────────── */

async function apiJson(url, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(url, opts);

  // Guard: server may return HTML on 404/500 — always parse safely
  const contentType = res.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    const text = await res.text();
    throw new Error(`Server error (${res.status}): ${text.slice(0, 120)}`);
  }

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

/* ── UI Helpers ──────────────────────────────────────────── */

function appendLog(boxId, message, type = 'info') {
  const box = document.getElementById(boxId);
  if (!box) return;
  const line = document.createElement('div');
  line.className   = `log-line log-${type}`;
  line.textContent = `[${ts()}]  ${message}`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

function ts() {
  return new Date().toTimeString().slice(0, 8);
}

function esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function setStatus(type, text) {
  document.getElementById('statusDot').className  = 'status-dot ' + (type === 'idle' ? '' : type);
  document.getElementById('statusText').textContent = text;
}

function showError(msg) {
  alert(msg);
}
