/* ============================================================
   NetShield Research Workbench
   Vanilla JS. No build step, no framework, no decorative icons.
   ============================================================ */

'use strict';

(function () {
  const researchNode = document.getElementById('research-data');
  const research = researchNode ? JSON.parse(researchNode.textContent) : {};

  const $ = (id) => document.getElementById(id);
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
  }

  function formatInt(value) {
    return Number(value || 0).toLocaleString('en-US');
  }

  function formatPct(value, digits = 2) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return 'n/a';
    return `${(Number(value) * 100).toFixed(digits)}%`;
  }

  function formatDecimal(value, digits = 4) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return 'n/a';
    return Number(value).toFixed(digits);
  }

  function apiFetch(resource, options = {}) {
    const headers = new Headers(options.headers || {});
    const method = String(options.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) {
      headers.set('X-CSRF-Token', csrfToken);
    }
    return fetch(resource, { ...options, headers, credentials: 'same-origin' });
  }

  /* ---------- Theme label ---------- */

  const themeLabel = $('themeLabel');
  function updateThemeLabel() {
    if (!themeLabel) return;
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    themeLabel.textContent = theme === 'light' ? 'Theme: light' : 'Theme: dark';
  }
  updateThemeLabel();
  window.addEventListener('themeChanged', updateThemeLabel);

  /* ---------- View switching ---------- */

  const views = Array.from(document.querySelectorAll('.view'));
  const railButtons = Array.from(document.querySelectorAll('.rail-item[data-view]'));

  function showView(viewId) {
    const target = document.getElementById(viewId);
    if (!target) return;
    views.forEach((view) => { view.hidden = view.id !== viewId; });
    railButtons.forEach((button) => {
      if (button.dataset.view === viewId) {
        button.setAttribute('aria-current', 'page');
      } else {
        button.removeAttribute('aria-current');
      }
    });
    if (window.location.hash !== `#${viewId.replace('view-', '')}`) {
      history.replaceState(null, '', `#${viewId.replace('view-', '')}`);
    }
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  railButtons.forEach((button) => {
    button.addEventListener('click', () => showView(button.dataset.view));
  });

  const VIEW_KEYS = {
    '1': 'view-overview',
    '2': 'view-analyze',
    '3': 'view-protocol',
    '4': 'view-budget',
    '5': 'view-prevalence',
    '6': 'view-provenance',
    '7': 'view-limitations'
  };

  document.addEventListener('keydown', (event) => {
    const tag = document.activeElement ? document.activeElement.tagName : '';
    const typing = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
    if (event.ctrlKey || event.metaKey || event.altKey) return;

    if (event.key === 'Escape') {
      const split = $('flowSplit');
      if (split && split.classList.contains('has-detail')) {
        split.classList.remove('has-detail');
      }
      return;
    }

    if (event.key === '/' && !typing) {
      const search = $('flowSearchInput');
      if (search && !$('resultsSection')?.hidden) {
        event.preventDefault();
        search.focus();
      }
      return;
    }

    if (!typing && VIEW_KEYS[event.key]) {
      showView(VIEW_KEYS[event.key]);
    }
  });

  const hashView = window.location.hash.replace('#', '');
  if (hashView && document.getElementById(`view-${hashView}`)) {
    showView(`view-${hashView}`);
  }

  window.addEventListener('hashchange', () => {
    const next = window.location.hash.replace('#', '');
    if (next && document.getElementById(`view-${next}`)) {
      showView(`view-${next}`);
    }
  });

  /* ---------- Alert budget selector ---------- */

  const budgets = research.budgets || [];
  const budgetList = $('budgetList');
  if (budgetList && budgets.length) {
    const fields = {
      title: $('budgetTitle'),
      kind: $('budgetKind'),
      k: $('budgetK'),
      threshold: $('budgetThreshold'),
      precision: $('budgetPrecision'),
      recall: $('budgetRecall'),
      explain: $('budgetExplain'),
      bot: $('budgetBot'),
      ddos: $('budgetDdos'),
      portscan: $('budgetPortscan'),
      fp: $('budgetFp')
    };

    function selectBudget(index) {
      const budget = budgets[index];
      if (!budget) return;
      budgetList.querySelectorAll('.budget-option').forEach((button) => {
        button.setAttribute('aria-pressed', String(Number(button.dataset.budgetIndex) === index));
      });
      fields.title.textContent = budget.label;
      fields.kind.textContent = budget.kind;
      fields.k.textContent = formatInt(budget.k);
      fields.threshold.textContent = formatDecimal(budget.threshold, 4);
      fields.precision.textContent = formatPct(budget.precision);
      fields.recall.textContent = formatPct(budget.recall, 3);
      fields.bot.textContent = formatPct(budget.families?.Bot ?? 0);
      fields.ddos.textContent = formatPct(budget.families?.DDoS ?? 0);
      fields.portscan.textContent = formatPct(budget.families?.PortScan ?? 0);
      fields.fp.textContent = formatDecimal(budget.fp_per_10k, 2);
      fields.explain.textContent = `${formatInt(budget.k)} highest-scoring flows are reviewed. Of those, ${formatPct(budget.precision)} are attacks. The queue captures ${formatPct(budget.recall, 3)} of all Friday attacks.`;
    }

    budgetList.querySelectorAll('.budget-option').forEach((button) => {
      button.addEventListener('click', () => selectBudget(Number(button.dataset.budgetIndex)));
    });
  }

  /* ---------- Upload and sample ---------- */

  const dropZone = $('dropZone');
  const fileInput = $('fileInput');
  const analyzeBtn = $('analyzeBtn');
  const btnText = $('btnText');
  const btnLoadSample = $('btnLoadSample');
  const sampleSelect = $('sampleSelect');
  const uploadFilename = $('uploadFilename');
  const progress = $('progress');
  const errorCard = $('errorCard');
  const errorText = $('errorText');
  const resultsSection = $('resultsSection');

  let currentPayload = null;
  let currentFlows = [];
  let filteredFlows = [];
  let selectedIndex = null;

  const SUPPORTED = ['.csv', '.pcap', '.pcapng'];
  const MAX_SIZE = 50 * 1024 * 1024;

  function showError(message) {
    if (!errorCard || !errorText) return;
    errorText.textContent = message;
    errorCard.hidden = false;
    errorCard.scrollIntoView({ block: 'nearest' });
  }

  function hideError() {
    if (errorCard) errorCard.hidden = true;
  }

  function setProgress(step) {
    if (!progress) return;
    progress.hidden = false;
    for (let index = 1; index <= 4; index += 1) {
      const item = $(`progressStep${index}`);
      if (!item) continue;
      item.classList.toggle('active', index === step);
      item.classList.toggle('done', index < step);
    }
  }

  function clearProgress() {
    if (!progress) return;
    progress.hidden = true;
    for (let index = 1; index <= 4; index += 1) {
      const item = $(`progressStep${index}`);
      if (item) item.classList.remove('active', 'done');
    }
  }

  function setLoading(loading) {
    if (!analyzeBtn || !btnText) return;
    analyzeBtn.disabled = loading;
    btnText.textContent = loading ? 'Scoring rows...' : 'Run flow classification';
  }

  function selectFile(file) {
    hideError();
    const name = file.name.toLowerCase();
    const extension = SUPPORTED.find((suffix) => name.endsWith(suffix));
    if (!extension) {
      showError('Unsupported format. Use a CSV, PCAP, or PCAPNG file.');
      return;
    }
    if (file.size > MAX_SIZE) {
      showError(`File is larger than 50 MB (${(file.size / (1024 * 1024)).toFixed(1)} MB).`);
      return;
    }
    if (uploadFilename) {
      uploadFilename.textContent = `${file.name} (${(file.size / 1024).toFixed(0)} KB)`;
    }
    if (analyzeBtn) analyzeBtn.disabled = false;
  }

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files[0]) selectFile(fileInput.files[0]);
    });
  }

  if (dropZone) {
    ['dragenter', 'dragover'].forEach((eventName) => {
      dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.add('is-dragging');
      });
    });
    ['dragleave', 'drop'].forEach((eventName) => {
      dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.remove('is-dragging');
      });
    });
    dropZone.addEventListener('drop', (event) => {
      const file = event.dataTransfer?.files?.[0];
      if (!file || !fileInput) return;
      const transfer = new DataTransfer();
      transfer.items.add(file);
      fileInput.files = transfer.files;
      selectFile(file);
    });
  }

  async function runPrediction(url, options) {
    hideError();
    setLoading(true);
    if (resultsSection) resultsSection.hidden = true;
    setProgress(1);

    try {
      await new Promise((resolve) => setTimeout(resolve, 160));
      setProgress(2);
      const responsePromise = apiFetch(url, options);
      await new Promise((resolve) => setTimeout(resolve, 220));
      setProgress(3);
      const response = await responsePromise;
      const payload = await response.json();
      if (!response.ok || payload.error) {
        throw new Error(payload.error || `Server returned ${response.status}`);
      }
      setProgress(4);
      await new Promise((resolve) => setTimeout(resolve, 160));
      currentPayload = payload;
      renderResults(payload);
      clearProgress();
    } catch (error) {
      clearProgress();
      showError(error.message || 'The analysis could not be completed.');
    } finally {
      setLoading(false);
    }
  }

  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', () => {
      const file = fileInput?.files?.[0];
      if (!file) {
        showError('Choose a file first, or load a built-in sample.');
        return;
      }
      const formData = new FormData();
      formData.append('file', file);
      runPrediction('/predict', { method: 'POST', body: formData });
    });
  }

  if (btnLoadSample) {
    btnLoadSample.addEventListener('click', () => {
      const kind = sampleSelect?.value || 'heldout';
      if (uploadFilename) uploadFilename.textContent = '';
      runPrediction(`/predict?sample=${encodeURIComponent(kind)}`, { method: 'POST' });
    });
  }

  // One-click demo: ingest the bundled 500-flow fixture into the console and
  // let a real host/window incident open. No dataset download required.
  const btnBundledSample = $('btnBundledSample');
  const bundledSampleStatus = $('bundledSampleStatus');
  if (btnBundledSample) {
    btnBundledSample.addEventListener('click', async () => {
      if (btnBundledSample.dataset.busy === 'true') return;
      btnBundledSample.dataset.busy = 'true';
      btnBundledSample.disabled = true;
      if (bundledSampleStatus) bundledSampleStatus.textContent = 'Scoring the bundled sample…';
      try {
        const response = await apiFetch('/api/load-sample', { method: 'POST' });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || `Sample load failed (${response.status})`);
        const incidents = Number(data.incidents || 0);
        if (bundledSampleStatus) {
          bundledSampleStatus.innerHTML = `Stored ${formatInt(data.accepted)} flows with ${formatInt(data.alerts)} flow alerts. ${formatInt(incidents)} host/window incident${incidents === 1 ? '' : 's'} opened — <a href="/">open the console</a>.`;
        }
      } catch (error) {
        if (bundledSampleStatus) {
          bundledSampleStatus.textContent = error.message || 'The bundled sample could not be loaded.';
        }
      } finally {
        btnBundledSample.disabled = false;
        btnBundledSample.dataset.busy = 'false';
      }
    });
  }

  /* ---------- Results rendering ---------- */

  function ingestionText(payload) {
    const ingestion = payload.ingestion || {};
    if (ingestion.sample) {
      const display = ingestion.sample.display_rows
        ? ` ${formatInt(ingestion.sample.display_rows)} rows are shown: all predicted non-benign rows first, then evenly spaced benign rows.`
        : '';
      return `Sample: ${ingestion.sample.file}, first ${formatInt(ingestion.sample.rows_evaluated)} of ${formatInt(ingestion.sample.rows_available)} rows scored.${display} Predictions only; labels are not used for scoring.`;
    }
    if (ingestion.packets_dissected !== null && ingestion.packets_dissected !== undefined) {
      return `PCAP: ${ingestion.filename || 'uploaded capture'}, ${formatInt(ingestion.packets_dissected)} packets dissected, ${formatInt(ingestion.flows_extracted)} flows extracted. Predictions only.`;
    }
    return `CSV: ${ingestion.filename || 'uploaded file'}, ${formatInt(payload.total)} rows scored. Predictions only.`;
  }

  function renderResults(payload) {
    const total = Number(payload.total || 0);
    const benign = Number(payload.benign || 0);
    const attack = Number(payload.attack || 0);
    const labels = payload.attack_types || {};

    $('statTotal').textContent = formatInt(total);
    $('statBenign').textContent = formatInt(benign);
    $('statAttack').textContent = formatInt(attack);
    $('statClasses').textContent = formatInt(Object.keys(labels).length);
    $('statBenignPct').textContent = `${total ? ((benign / total) * 100).toFixed(1) : '0.0'}% of batch`;
    $('statAttackPct').textContent = `${total ? ((attack / total) * 100).toFixed(1) : '0.0'}% of batch`;
    $('ingestionSummary').textContent = ingestionText(payload);

    renderDistribution(labels, total);

    currentFlows = Array.isArray(payload.sample_flows) ? payload.sample_flows : [];
    filteredFlows = currentFlows.slice();
    selectedIndex = null;
    renderFlowTable();

    if (resultsSection) {
      resultsSection.hidden = false;
      resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function renderDistribution(labels, total) {
    const tbody = $('attackTableBody');
    if (!tbody) return;
    const entries = Object.entries(labels).sort((a, b) => b[1] - a[1]);
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="small">No predictions were returned.</td></tr>';
      return;
    }
    const max = Math.max(...entries.map(([, count]) => Number(count)), 1);
    tbody.innerHTML = entries.map(([label, count]) => {
      const share = total ? (Number(count) / total) * 100 : 0;
      const width = (Number(count) / max) * 100;
      const isBenign = label === 'BENIGN';
      return `
        <tr>
          <td class="name">${escapeHtml(label)}</td>
          <td class="num">${formatInt(count)}</td>
          <td class="num">${share.toFixed(2)}%</td>
          <td>
            <div class="bar-track" aria-hidden="true">
              <div class="bar-fill ${isBenign ? 'benign' : ''}" style="width:${width.toFixed(2)}%"></div>
            </div>
          </td>
        </tr>`;
    }).join('');
  }

  function renderFlowTable() {
    const tbody = $('flowSampleTableBody');
    const foot = $('flowTableFoot');
    if (!tbody) return;

    if (!filteredFlows.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="small">No rows match the current filter.</td></tr>';
      if (foot) foot.textContent = `0 of ${formatInt(currentFlows.length)} returned rows shown.`;
      return;
    }

    tbody.innerHTML = filteredFlows.map((flow) => {
      const index = currentFlows.indexOf(flow);
      const selected = index === selectedIndex;
      const isBenign = !flow.is_attack;
      return `
        <tr data-flow-index="${index}" tabindex="0"${selected ? ' class="is-selected"' : ''}>
          <td class="num">${flow.row_index || index + 1}</td>
          <td class="mono">${escapeHtml(flow.src_ip || 'not present')}${flow.src_port ? `:${escapeHtml(flow.src_port)}` : ''}</td>
          <td class="mono">${escapeHtml(flow.dst_ip || 'not present')}${flow.dst_port ? `:${escapeHtml(flow.dst_port)}` : ''}</td>
          <td>${escapeHtml(flow.protocol || 'unknown')}</td>
          <td class="name">${escapeHtml(flow.predicted_label || 'unknown')} ${isBenign ? '<span class="badge ok">Benign</span>' : '<span class="badge bad">Non-benign</span>'}</td>
        </tr>`;
    }).join('');

    if (foot) foot.textContent = `${formatInt(filteredFlows.length)} of ${formatInt(currentFlows.length)} returned rows shown. Select a row for details.`;

    tbody.querySelectorAll('tr[data-flow-index]').forEach((row) => {
      const index = Number(row.dataset.flowIndex);
      row.addEventListener('click', () => selectFlow(index));
      row.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          selectFlow(index);
        }
      });
    });
  }

  function selectFlow(index) {
    const flow = currentFlows[index];
    if (!flow) return;
    selectedIndex = index;
    renderFlowTable();

    const split = $('flowSplit');
    if (split) split.classList.add('has-detail');

    $('detailTitle').textContent = `Row ${flow.row_index || index + 1}`;
    $('detailLabel').textContent = flow.predicted_label || 'unknown';
    $('detailRoute').textContent = `${flow.src_ip || 'not present'}${flow.src_port ? `:${flow.src_port}` : ''} to ${flow.dst_ip || 'not present'}${flow.dst_port ? `:${flow.dst_port}` : ''} (${flow.protocol || 'unknown'})`;
    $('detailSource').textContent = flow.interface === 'pcap'
      ? 'Uploaded PCAP. Predicted label, not ground truth.'
      : 'Uploaded or sampled CSV. Predicted label, not ground truth.';
    $('detailDuration').textContent = `${flow.duration_us || '0'} us`;
    $('detailBytes').textContent = `${flow.bytes_s || '0'} B/s`;
    $('detailPkts').textContent = `${flow.pkts_s || '0'} pkt/s`;
    $('detailRatio').textContent = `${flow.fwd_pkts || 0} fwd / ${flow.bwd_pkts || 0} bwd`;

    const flags = flow.flags || {};
    const flagMap = [
      ['detailSyn', 'SYN', flags.syn],
      ['detailAck', 'ACK', flags.ack],
      ['detailRst', 'RST', flags.rst],
      ['detailFin', 'FIN', flags.fin]
    ];
    flagMap.forEach(([id, label, value]) => {
      const node = $(id);
      if (!node) return;
      node.textContent = `${label} ${value || 0}`;
      node.classList.toggle('on', Number(value) > 0);
    });
  }

  const closeDetail = $('btnCloseDetail');
  if (closeDetail) {
    closeDetail.addEventListener('click', () => {
      $('flowSplit')?.classList.remove('has-detail');
      selectedIndex = null;
      renderFlowTable();
    });
  }

  const copyJson = $('btnCopyJson');
  if (copyJson) {
    copyJson.addEventListener('click', async () => {
      if (selectedIndex === null || !currentFlows[selectedIndex]) return;
      try {
        await navigator.clipboard.writeText(JSON.stringify(currentFlows[selectedIndex], null, 2));
        copyJson.textContent = 'Copied';
        setTimeout(() => { copyJson.textContent = 'Copy row JSON'; }, 1600);
      } catch (error) {
        copyJson.textContent = 'Copy failed';
        setTimeout(() => { copyJson.textContent = 'Copy row JSON'; }, 1600);
      }
    });
  }

  /* ---------- Filters, density, export ---------- */

  function applyFilters() {
    const term = ($('flowSearchInput')?.value || '').toLowerCase().trim();
    const mode = $('flowFilterSelect')?.value || 'all';
    filteredFlows = currentFlows.filter((flow) => {
      if (mode === 'attacks' && !flow.is_attack) return false;
      if (mode === 'benign' && flow.is_attack) return false;
      if (!term) return true;
      return [
        flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
        flow.protocol, flow.predicted_label
      ].some((value) => String(value || '').toLowerCase().includes(term));
    });
    renderFlowTable();
  }

  $('flowSearchInput')?.addEventListener('input', applyFilters);
  $('flowFilterSelect')?.addEventListener('change', applyFilters);

  const densityStandard = $('btnDensityStandard');
  const densityCompact = $('btnDensityCompact');
  function setDensity(mode) {
    const table = $('flowTableCard');
    if (table) table.dataset.density = mode;
    densityStandard?.setAttribute('aria-pressed', String(mode === 'standard'));
    densityCompact?.setAttribute('aria-pressed', String(mode === 'compact'));
  }
  densityStandard?.addEventListener('click', () => setDensity('standard'));
  densityCompact?.addEventListener('click', () => setDensity('compact'));

  function downloadFile(name, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  $('btnExportCSV')?.addEventListener('click', () => {
    if (!filteredFlows.length) {
      showError('There are no rows to export.');
      return;
    }
    const header = ['row', 'source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol', 'predicted_label', 'is_attack'];
    const lines = filteredFlows.map((flow) => [
      flow.row_index || currentFlows.indexOf(flow) + 1,
      flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
      flow.protocol, `"${String(flow.predicted_label || '').replace(/"/g, '""')}"`,
      flow.is_attack
    ].join(','));
    downloadFile(`netshield_predictions_${Date.now()}.csv`, [header.join(','), ...lines].join('\n'), 'text/csv;charset=utf-8');
  });

  $('btnExportJSON')?.addEventListener('click', () => {
    if (!currentPayload) {
      showError('There is no result payload to export.');
      return;
    }
    downloadFile(`netshield_predictions_${Date.now()}.json`, JSON.stringify(currentPayload, null, 2), 'application/json');
  });
})();
