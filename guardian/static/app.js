const ui = {
  runButton: document.querySelector('#runButton'),
  stopButton: document.querySelector('#stopButton'),
  systemState: document.querySelector('#systemState'),
  stateDot: document.querySelector('#stateDot'),
  runId: document.querySelector('#runId'),
  terminal: document.querySelector('#terminal'),
  logStatus: document.querySelector('#logStatus'),
  generated: document.querySelector('#generated'),
  grounded: document.querySelector('#grounded'),
  executed: document.querySelector('#executed'),
  observed: document.querySelector('#observed'),
  gateInterventions: document.querySelector('#gateInterventions'),
  gateMetric: document.querySelector('#gateMetric'),
  resultBadge: document.querySelector('#resultBadge'),
  emptyResult: document.querySelector('#emptyResult'),
  resultContent: document.querySelector('#resultContent'),
  flowName: document.querySelector('#flowName'),
  categoryList: document.querySelector('#categoryList'),
  reportLinks: document.querySelector('#reportLinks'),
  toast: document.querySelector('#toast'),
  modelSelect: document.querySelector('#modelSelect'),
  deepseekRow: document.querySelector('#deepseekRow'),
  apiKeyInput: document.querySelector('#apiKeyInput'),
  modelNameInput: document.querySelector('#modelNameInput'),
  modelHint: document.querySelector('#modelHint'),
  runHistorySelect: document.querySelector('#runHistorySelect'),
  runHistoryHint: document.querySelector('#runHistoryHint'),
};

let viewingRunId = null;

function updateModelPicker() {
  const isDeepseek = ui.modelSelect && ui.modelSelect.value === 'deepseek';
  if (ui.deepseekRow) ui.deepseekRow.style.display = isDeepseek ? 'flex' : 'none';
  if (ui.modelHint) {
    ui.modelHint.textContent = isDeepseek
      ? 'DeepSeek will act as the guardian agent for this run. Key is used only for this run and is not saved.'
      : 'Using the fine-tuned Guardian model served from Colab.';
  }
}

function modelPayload() {
  if (!ui.modelSelect || ui.modelSelect.value !== 'deepseek') return { provider: 'local' };
  return {
    provider: 'deepseek',
    api_key: (ui.apiKeyInput && ui.apiKeyInput.value.trim()) || '',
    model_name: (ui.modelNameInput && ui.modelNameInput.value.trim()) || '',
  };
}

let previousLogCount = 0;
let polling = false;

function showToast(message) {
  ui.toast.textContent = message;
  ui.toast.classList.add('show');
  window.setTimeout(() => ui.toast.classList.remove('show'), 3200);
}

async function post(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'The request failed.');
  return data;
}

if (ui.modelSelect) {
  ui.modelSelect.addEventListener('change', updateModelPicker);
  updateModelPicker();
}

ui.runButton.addEventListener('click', async () => {
  try {
    const config = modelPayload();
    if (config.provider === 'deepseek' && !config.api_key) {
      showToast('Paste a DeepSeek API key first.');
      return;
    }
    const data = await post('/api/run', config);
    showToast(data.message);
    previousLogCount = 0;
    await refresh();
  } catch (error) { showToast(error.message); }
});

ui.stopButton.addEventListener('click', async () => {
  try {
    const data = await post('/api/stop');
    showToast(data.message);
    await refresh();
  } catch (error) { showToast(error.message); }
});

const rejudgeButton = document.querySelector('#rejudgeButton');
if (rejudgeButton) {
  rejudgeButton.addEventListener('click', async () => {
    try {
      const data = await post('/api/rejudge');
      showToast(data.message);
      previousLogCount = 0;
      await refresh();
    } catch (error) { showToast(error.message); }
  });
}

let remediationItems = [];
let remediationRunId = '';

function formatRunSummary(run) {
  const when = run.created_at ? new Date(run.created_at).toLocaleString() : '';
  const found = Number(run.vulnerabilities_observed || 0);
  const bits = [run.flow_name, `${run.executed ?? 0} executed`, found ? `${found} found` : 'no findings'];
  return `${run.run_id}${when ? ' — ' + when : ''} (${bits.filter(Boolean).join(', ')})`;
}

async function loadRunsList() {
  if (!ui.runHistorySelect) return;
  try {
    const res = await fetch('/api/runs', { cache: 'no-store' });
    const data = await res.json();
    const runs = data.runs || [];
    const current = ui.runHistorySelect.value;
    ui.runHistorySelect.innerHTML = '<option value="">Live (current run)</option>' +
      runs.map(run => `<option value="${escapeHtml(run.run_id)}">${escapeHtml(formatRunSummary(run))}</option>`).join('');
    if (current && runs.some(run => run.run_id === current)) ui.runHistorySelect.value = current;
  } catch (error) { }
}

async function viewRun(runId) {
  try {
    const res = await fetch(`/api/runs/${encodeURIComponent(runId)}`, { cache: 'no-store' });
    if (!res.ok) throw new Error('Could not load that run.');
    const state = await res.json();
    render(state);
    previousLogCount = 0;
    ui.terminal.textContent = `Viewing stored results for run ${runId}. No live log for past runs -- see the report links or remediation panel below.`;
    ui.logStatus.textContent = 'Archived';
    if (ui.runHistoryHint) ui.runHistoryHint.textContent = `Viewing past run ${runId}. Nothing is running.`;
    await refreshRemediation();
  } catch (error) { showToast(error.message); }
}

if (ui.runHistorySelect) {
  ui.runHistorySelect.addEventListener('change', async () => {
    viewingRunId = ui.runHistorySelect.value || null;
    if (viewingRunId) {
      await viewRun(viewingRunId);
    } else {
      if (ui.runHistoryHint) ui.runHistoryHint.textContent = 'Showing the live run. Pick a past run to view its results without running anything.';
      await refresh();
      await refreshRemediation();
    }
  });
}

async function refreshRemediation() {
  try {
    const url = viewingRunId ? `/api/remediation?run=${encodeURIComponent(viewingRunId)}` : '/api/remediation';
    const res = await fetch(url, { cache: 'no-store' });
    const data = await res.json();
    remediationItems = data.items || [];
    remediationRunId = data.run_id || '';
    const list = document.querySelector('#remediationList');
    const empty = document.querySelector('#remediationEmpty');
    const pdfBtn = document.querySelector('#exportPdfButton');
    if (!list) return;
    if (!remediationItems.length) {
      list.innerHTML = '';
      if (empty) empty.style.display = '';
      if (pdfBtn) pdfBtn.disabled = true;
      return;
    }
    if (empty) empty.style.display = 'none';
    if (pdfBtn) pdfBtn.disabled = false;
    list.innerHTML = remediationItems.map((it, i) => `
      <div class="rem-item">
        <div class="rem-head"><span class="rem-num">${i + 1}</span>
          <span class="rem-cat">${escapeHtml(it.category)}</span>
          <span class="rem-title">${escapeHtml(it.title)}</span></div>
        <div class="rem-row"><span class="rem-label">What happened</span>
          <span class="rem-text">${escapeHtml(it.what_happened)}</span></div>
        <div class="rem-row"><span class="rem-label rem-fix">Fix</span>
          <span class="rem-text">${escapeHtml(it.fix)}</span></div>
        ${it.note ? `<div class="rem-row"><span class="rem-label">Model note</span>
          <span class="rem-text rem-note">${escapeHtml(it.note)}</span></div>` : ''}
      </div>`).join('');
  } catch (error) { }
}

function exportRemediationPdf() {
  if (!remediationItems.length) return;
  const a = document.createElement('a');
  a.href = viewingRunId ? `/api/remediation.pdf?run=${encodeURIComponent(viewingRunId)}` : '/api/remediation.pdf';
  a.download = `guardian_remediation_${remediationRunId || 'latest'}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

const exportPdfButton = document.querySelector('#exportPdfButton');
if (exportPdfButton) exportPdfButton.addEventListener('click', exportRemediationPdf);

const explainButton = document.querySelector('#explainButton');
if (explainButton) {
  explainButton.addEventListener('click', async () => {
    try {
      const data = await post('/api/remediate');
      showToast(data.message);
      previousLogCount = 0;
      await refresh();
    } catch (error) { showToast(error.message); }
  });
}

function setStageProgress(state) {
  let progress = 0;
  const text = (state.logs || []).join(' ').toLowerCase();
  if (['starting', 'running', 'stopping'].includes(state.status)) progress = 1;
  if (text.includes('scenario') || text.includes('generation')) progress = 2;
  if (text.includes('ground') || text.includes('static')) progress = 3;
  if (text.includes('execution') || text.includes('transcript') || text.includes('langflow')) progress = Math.max(progress, 4);
  if (['completed', 'failed', 'stopped'].includes(state.status)) progress = 5;
  document.querySelectorAll('.stage').forEach((node, index) => {
    node.classList.toggle('done', index + 1 < progress || state.status === 'completed');
    node.classList.toggle('active', index + 1 === progress && state.status !== 'completed');
  });
  document.querySelectorAll('.connector').forEach((node, index) => node.classList.toggle('done', index + 1 < progress));
}

function renderResult(state) {
  const hasResult = Boolean(state.run_id && state.report_urls);
  ui.emptyResult.classList.toggle('hidden', hasResult);
  ui.resultContent.classList.toggle('hidden', !hasResult);
  if (!hasResult) return;

  ui.flowName.textContent = state.flow?.name || state.flow?.id || 'Unnamed flow';
  ui.categoryList.innerHTML = (state.categories || []).map(category => `
    <div class="category-row">
      <strong title="${escapeHtml(category.category)}">${escapeHtml(category.category)}</strong>
      <span>${category.executed || 0} run</span>
      <span class="${category.vulnerabilities_observed ? 'bad' : ''}">${category.vulnerabilities_observed || 0} found</span>
    </div>`).join('') || '<div class="category-row"><strong>No category results</strong></div>';
  ui.reportLinks.innerHTML = `
    <a href="${state.report_urls.markdown}" target="_blank" rel="noopener">Open report</a>
    <a href="${state.report_urls.json}">Download JSON</a>`;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
}

function render(state) {
  const running = ['starting', 'running', 'stopping'].includes(state.status);
  ui.runButton.disabled = running || Boolean(viewingRunId);
  ui.stopButton.disabled = !running || state.status === 'stopping';
  if (rejudgeButton) rejudgeButton.disabled = running || Boolean(viewingRunId);
  if (explainButton) explainButton.disabled = running || Boolean(viewingRunId);
  ui.systemState.textContent = ({
    idle: 'System ready', starting: 'Starting evaluation', running: 'Evaluation running',
    stopping: 'Stopping evaluation', completed: 'Evaluation complete', failed: 'Evaluation failed', stopped: 'Evaluation stopped'
  })[state.status] || state.status;
  ui.stateDot.className = `state-dot ${running ? 'running' : ''} ${state.status === 'failed' ? 'failed' : ''}`;
  ui.runId.textContent = state.run_id ? `RUN ${state.run_id}` : (running ? 'RUN IN PROGRESS' : 'NO ACTIVE RUN');
  ui.logStatus.textContent = running ? 'Streaming' : state.status;

  const logs = state.logs || [];
  if (logs.length) {
    ui.terminal.textContent = logs.join('\n');
    if (logs.length !== previousLogCount) ui.terminal.scrollTop = ui.terminal.scrollHeight;
  }
  previousLogCount = logs.length;

  const summary = state.summary || {};
  ui.generated.textContent = summary.unique_scenarios ?? summary.generation_calls ?? '—';
  ui.grounded.textContent = summary.grounded_candidates ?? '—';
  ui.executed.textContent = summary.executed ?? '—';
  ui.observed.textContent = summary.vulnerabilities_observed ?? '—';

  const gateCount = state.gate_interventions;
  ui.gateInterventions.textContent = gateCount === null || gateCount === undefined ? '—' : gateCount;
  ui.gateMetric.classList.toggle('gate-clear', !gateCount);

  let badge = ['idle', 'starting', 'running', 'stopping'].includes(state.status) ? 'neutral' : 'warning';
  let badgeText = running ? 'In progress' : 'Not run';
  if (state.status === 'completed') {
    const observed = Number(summary.vulnerabilities_observed || 0);
    badge = observed ? 'danger' : 'success';
    badgeText = observed ? `${observed} observed` : 'No finding observed';
  } else if (state.status === 'failed') { badge = 'danger'; badgeText = 'Run failed'; }
  else if (state.status === 'stopped') { badgeText = 'Stopped'; }
  ui.resultBadge.className = `badge ${badge}`;
  ui.resultBadge.textContent = badgeText;
  setStageProgress(state);
  renderResult(state);
}

async function refresh() {
  if (polling || viewingRunId) return;
  polling = true;
  try {
    const response = await fetch('/api/status', { cache: 'no-store' });
    if (!response.ok) throw new Error('Status unavailable');
    const state = await response.json();
    render(state);
    if (['completed', 'failed', 'stopped'].includes(state.status)) loadRunsList();
  } catch (error) {
    ui.systemState.textContent = 'UI disconnected';
    ui.stateDot.className = 'state-dot failed';
  } finally { polling = false; }
}

refresh();
refreshRemediation();
loadRunsList();
window.setInterval(refresh, 1200);
window.setInterval(refreshRemediation, 3000);
window.setInterval(loadRunsList, 5000);
