/* ============================================================
   NETSHIELD AI: Enterprise SOC Batch Traffic & Telemetry Engine
   Architectural Pillars:
   1. Compact Operational Hierarchy & Telemetry Header
   2. SHAP Explainability & Flow Inspector SideSheet Drawer
   3. Table Ergonomics, Cross-Filtering & Custom Density
   4. Multi-Stage Pipeline Progress UX
   5. Power-User Command Palette (Cmd+K / Ctrl+K)
   ============================================================ */

'use strict';
function apiFetch(resource, options = {}) {
  const headers = new Headers(options.headers || {});
  const method = String(options.method || 'GET').toUpperCase();
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrf) headers.set('X-CSRF-Token', csrf);
  return fetch(resource, { ...options, headers, credentials: 'same-origin' });
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}


function getSeverity(type) {
  return type === 'BENIGN'
    ? { label: 'Predicted benign', cls: 'badge-safe' }
    : { label: 'Predicted non-benign', cls: 'badge-medium' };
}

// ── DOM References ──
const dropZone            = document.getElementById('dropZone');
const fileInput           = document.getElementById('fileInput');
const analyzeBtn          = document.getElementById('analyzeBtn');
const btnSampleDemo       = document.getElementById('btnSampleDemo');
const btnText             = document.getElementById('btnText');
const btnIcon             = document.getElementById('btnIcon');
const errorCard           = document.getElementById('errorCard');
const errorText           = document.getElementById('errorText');
const resultsSection      = document.getElementById('resultsSection');
const uploadFilename      = document.getElementById('uploadFilename');
const flowSearchInput     = document.getElementById('flowSearchInput');
const flowFilterSelect    = document.getElementById('flowFilterSelect');
const pipelineProgress    = document.getElementById('pipelineProgress');

// Table Tools & Filter Chips
const flowSampleTable     = document.getElementById('flowSampleTable');
const activeFilterChips   = document.getElementById('activeFilterChips');
const filterChipsList     = document.getElementById('filterChipsList');
const btnClearAllFilters  = document.getElementById('btnClearAllFilters');
const btnDensityStandard  = document.getElementById('btnDensityStandard');
const btnDensityCompact   = document.getElementById('btnDensityCompact');
const btnExportCSV        = document.getElementById('btnExportCSV');
const btnExportJSON       = document.getElementById('btnExportJSON');

// Inspector Drawer DOM
const flowDrawer          = document.getElementById('flowDrawer');
const drawerBackdrop      = document.getElementById('drawerBackdrop');
const btnCloseDrawer      = document.getElementById('btnCloseDrawer');
const drawerFlowId        = document.getElementById('drawerFlowId');
const drawerThreatBadge   = document.getElementById('drawerThreatBadge');
const drawerCvssBadge     = document.getElementById('drawerCvssBadge');
const drawerRouteText     = document.getElementById('drawerRouteText');
const drawerMitre         = document.getElementById('drawerMitre');

// Incident & Threat Intel DOM
const drawerTriageStatus  = document.getElementById('drawerTriageStatus');
const drawerReviewNote    = document.getElementById('drawerReviewNote');
const reviewControls      = document.getElementById('reviewControls');
const reviewUnavailable   = document.getElementById('reviewUnavailable');
const reviewUpdatedMeta   = document.getElementById('reviewUpdatedMeta');
const reviewAuditList     = document.getElementById('reviewAuditList');
const btnSaveFlowReview   = document.getElementById('btnSaveFlowReview');
const drawerThreatAsn     = document.getElementById('drawerThreatAsn');
const drawerThreatGeo     = document.getElementById('drawerThreatGeo');
const drawerAbuseScore    = document.getElementById('drawerAbuseScore');
const drawerThreatTag     = document.getElementById('drawerThreatTag');
const packetDissectorSection = document.getElementById('packetDissectorSection');
const packetDissectorSummary = document.getElementById('packetDissectorSummary');
const packetDissectorLayers = document.getElementById('packetDissectorLayers');
const packetDissectorFields = document.getElementById('packetDissectorFields');

// Layer-2 Hardware DOM
const drawerL2Interface   = document.getElementById('drawerL2Interface');
const drawerL2Vector      = document.getElementById('drawerL2Vector');
const drawerL2Port        = document.getElementById('drawerL2Port');
const drawerL2Signal      = document.getElementById('drawerL2Signal');
const drawerL2Health      = document.getElementById('drawerL2Health');

// Raw Telemetry & Flags
const drawerShapList      = document.getElementById('drawerShapList');
const drawerTelDuration   = document.getElementById('drawerTelDuration');
const drawerTelBytes      = document.getElementById('drawerTelBytes');
const drawerTelPkts       = document.getElementById('drawerTelPkts');
const drawerTelPacketRatio = document.getElementById('drawerTelPacketRatio');
const flagSYN             = document.getElementById('flagSYN');
const flagACK             = document.getElementById('flagACK');
const flagRST             = document.getElementById('flagRST');
const flagFIN             = document.getElementById('flagFIN');
const btnDrawerCopyJson   = document.getElementById('btnDrawerCopyJson');
const btnDrawerFlagFP     = document.getElementById('btnDrawerFlagFP');

// SOAR Playbook DOM
const btnSoarIptables     = document.getElementById('btnSoarIptables');
const btnSoarCloudflare   = document.getElementById('btnSoarCloudflare');
const btnSoarAwsSg        = document.getElementById('btnSoarAwsSg');
const btnSoarStix         = document.getElementById('btnSoarStix');
const btnSoarSlack        = document.getElementById('btnSoarSlack');
const btnSoarPagerDuty    = document.getElementById('btnSoarPagerDuty');
const soarTerminalOutput  = document.getElementById('soarTerminalOutput');

// Command Palette DOM
const btnOpenCmdPalette   = document.getElementById('btnOpenCmdPalette');
const cmdModal            = document.getElementById('cmdModal');
const cmdBackdrop         = document.getElementById('cmdBackdrop');
const cmdInput            = document.getElementById('cmdInput');
const cmdList             = document.getElementById('cmdList');
const toastContainer      = document.getElementById('toastContainer');

// Topology Metadata & Ingestion Vectors
const TOPOLOGY_META = {
  'all': {
    tag: 'ALL UPLOADED FLOWS',
    desc: 'All rows in the current uploaded capture or CSV analysis'
  },
  'pcap': {
    tag: 'PCAP UPLOAD',
    desc: 'Rows reconstructed from the uploaded packet capture'
  },
  'batch': {
    tag: 'CSV UPLOAD',
    desc: 'Rows from the current uploaded CSV file'
  }
};

// State Store
let donutChart = null;
let barChart   = null;
let currentResultsPayload = null;
let currentSampleFlows = [];
let activeChartFilter = null; // e.g., 'PortScan' or 'Threats'
let activeTopologyFilter = 'all';
let activeInspectedFlow = null;

// ============================================================
// 1. TOAST NOTIFICATION SYSTEM
// ============================================================
function showToast(message, type = 'info') {
  if (!toastContainer) return;
  const toast = document.createElement('div');
  toast.className = `toast-message ${type === 'success' ? 'toast-success' : type === 'danger' ? 'toast-danger' : ''}`;
  
  const icon = type === 'success' ? '✓' : type === 'danger' ? '!' : 'ℹ';
  const iconNode = document.createElement('span');
  iconNode.style.fontWeight = '700';
  iconNode.textContent = icon;
  const messageNode = document.createElement('span');
  messageNode.textContent = message;
  toast.replaceChildren(iconNode, document.createTextNode(' '), messageNode);
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px) scale(0.95)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => toast.remove(), 250);
  }, 3200);
}

// ============================================================
// 2. FILE SELECTION & DRAG-AND-DROP
// ============================================================
if (fileInput) {
  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (file) selectFile(file);
  });
}

const SUPPORTED_EXTENSIONS = ['.csv', '.pcap', '.pcapng'];
const EXTENSION_LABELS = {
  '.csv':    'NetFlow / IPFIX / CIC-IDS Export',
  '.pcap':   'Wireshark / tcpdump PCAP Capture',
  '.pcapng': 'Wireshark PCAPNG Wire Trace',
};

function selectFile(file) {
  hideError();
  const MAX_SIZE = 50 * 1024 * 1024; // 50MB
  const lowerName = file.name.toLowerCase();
  const ext = SUPPORTED_EXTENSIONS.find(e => lowerName.endsWith(e));
  if (!ext) {
    return showError('Unsupported format. Accepted: PCAP/PCAPNG captures and NetFlow CSV exports.');
  }
  if (file.size > MAX_SIZE) {
    return showError(`File size exceeds 50 MB limit (${(file.size / (1024 * 1024)).toFixed(1)} MB).`);
  }
  const typeLabel = EXTENSION_LABELS[ext] || 'Network Capture';
  if (uploadFilename) {
    uploadFilename.textContent = `FILE ${file.name}  ·  ${typeLabel}  ·  ${(file.size / 1024).toFixed(0)} KB`;
    uploadFilename.classList.add('show');
  }
  if (analyzeBtn) analyzeBtn.disabled = false;
  showToast(`Ingested: ${typeLabel}: ${file.name}`, 'info');
}

if (dropZone) {
  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files[0];
    if (file) {
      const dt = new DataTransfer();
      dt.items.add(file);
      fileInput.files = dt.files;
      selectFile(file);
    }
  });
}

// ============================================================
// 3. MULTI-STAGE PROCESSING PIPELINE (PILLAR 4)
// ============================================================
const PIPELINE_STEP_LABELS = [
  'Frame Dissection & Flow Export',
  'Feature Engineering (78 Metrics)',
  'Hybrid Ensemble Inference',
  'SHAP Attribution & Threat Intel'
];

function advancePipeline(stepNum) {
  if (!pipelineProgress) return;
  pipelineProgress.hidden = false;

  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById(`pipeStep${i}`);
    if (!el) continue;
    const textEl = el.querySelector('.step-text');
    if (textEl && PIPELINE_STEP_LABELS[i - 1]) {
      textEl.textContent = PIPELINE_STEP_LABELS[i - 1];
    }
    if (i < stepNum) {
      el.className = 'pipeline-step completed';
      el.querySelector('.step-num').textContent = '✓';
    } else if (i === stepNum) {
      el.className = 'pipeline-step active';
      el.querySelector('.step-num').textContent = i;
    } else {
      el.className = 'pipeline-step';
      el.querySelector('.step-num').textContent = i;
    }
  }
}

function resetPipeline() {
  if (pipelineProgress) pipelineProgress.hidden = true;
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById(`pipeStep${i}`);
    if (el) {
      el.className = 'pipeline-step';
      el.querySelector('.step-num').textContent = i;
    }
  }
}

async function executePrediction(url, options) {
  setLoading(true);
  hideError();
  if (resultsSection) resultsSection.classList.remove('show');

  advancePipeline(1);
  await new Promise(r => setTimeout(r, 220));

  try {
    advancePipeline(2);
    const fetchPromise = apiFetch(url, options);

    await new Promise(r => setTimeout(r, 350));
    advancePipeline(3);

    const res = await fetchPromise;
    const data = await res.json();

    if (!res.ok || data.error) {
      showError(data.error || `Server returned error status ${res.status}`);
      resetPipeline();
    } else {
      advancePipeline(4);
      await new Promise(r => setTimeout(r, 280));
      currentResultsPayload = data;
      renderResults(data);
      showToast(`Classified ${data.total.toLocaleString()} flows successfully`, 'success');
    }
  } catch (err) {
    showError(`Network connection failure: ${err.message || 'Ensure backend server is running.'}`);
    resetPipeline();
  } finally {
    setLoading(false);
  }
}

if (analyzeBtn) {
  analyzeBtn.addEventListener('click', async () => {
    const file = fileInput?.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    await executePrediction('/predict', { method: 'POST', body: formData });
  });
}

if (btnSampleDemo) {
  btnSampleDemo.addEventListener('click', async () => {
    if (uploadFilename) {
      uploadFilename.textContent = 'Built-in Test Dataset (1,500 CIC-IDS-2017 Flows)';
      uploadFilename.classList.add('show');
    }
    await executePrediction('/predict?sample=true', { method: 'POST' });
  });
}

function setLoading(loading) {
  if (!analyzeBtn) return;
  analyzeBtn.disabled = loading;
  if (loading) {
    btnIcon.innerHTML = '<div class="spinner"></div>';
    btnText.textContent = 'Executing Pipeline Inference...';
  } else {
    btnIcon.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>`;
    btnText.textContent = 'Run flow classification';
  }
}

function showError(msg) {
  if (errorText) errorText.textContent = msg;
  if (errorCard) {
    errorCard.classList.add('show');
    errorCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

function hideError() {
  if (errorCard) errorCard.classList.remove('show');
}

// ============================================================
// 4. RENDER RESULTS & DATA VISUALIZATION
// ============================================================
function renderResults(data) {
  const { total, benign, attack, attack_types, sample_flows } = data;

  const elTotal = document.getElementById('statTotal');
  const elBenign = document.getElementById('statBenign');
  const elAttack = document.getElementById('statAttack');
  const elClasses = document.getElementById('statClassesCount');
  const elBenignPct = document.getElementById('statBenignPct');
  const elAttackPct = document.getElementById('statAttackPct');
  const elTableCount = document.getElementById('tableCountBadge');
  const ingestionSummary = document.getElementById('ingestionSummary');

  if (elTotal) elTotal.textContent = total.toLocaleString();
  if (elBenign) elBenign.textContent = benign.toLocaleString();
  if (elAttack) elAttack.textContent = attack.toLocaleString();

  const classCount = Object.keys(attack_types || {}).length;
  if (elClasses) elClasses.textContent = classCount.toLocaleString();

  if (elBenignPct) {
    elBenignPct.textContent = `${((benign / Math.max(1, total)) * 100).toFixed(1)}% predicted benign`;
  }
  if (elAttackPct) {
    elAttackPct.textContent = `${((attack / Math.max(1, total)) * 100).toFixed(1)}% predicted non-benign`;
  }
  if (elTableCount) {
    elTableCount.textContent = `${classCount} predicted non-benign labels`;
  }
  if (ingestionSummary && data.ingestion) {
    const ingestion = data.ingestion;
    ingestionSummary.hidden = false;
    ingestionSummary.textContent = ingestion.packets_dissected === null
      ? `${ingestion.type} · ${total.toLocaleString()} flows`
      : `${ingestion.filename} · ${ingestion.packets_dissected.toLocaleString()} packets dissected · ${ingestion.flows_extracted.toLocaleString()} flows extracted`;
  }

  // Render Charts with Cross-Filter Click Handlers
  renderDonutChart(benign, attack);
  renderBarChart(attack_types, total);

  renderAttackTable(attack_types, total);

  currentSampleFlows = sample_flows || [];
  renderFlowSamples(currentSampleFlows);

  // Reveal results
  if (resultsSection) {
    resultsSection.classList.add('show');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// ── Interactive Donut Chart ──
function renderDonutChart(benign, attack) {
  if (donutChart) donutChart.destroy();
  const canvas = document.getElementById('donutChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const legendColor = isLight ? '#5e4f45' : '#cec4b8';

  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Predicted benign', 'Predicted non-benign'],
      datasets: [{
        data: [benign, attack],
        backgroundColor: ['rgba(72, 187, 120, 0.85)', 'rgba(245, 101, 101, 0.85)'],
        borderColor: ['#48bb78', '#f56565'],
        borderWidth: 2,
        hoverOffset: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      onClick: (evt, elements) => {
        if (!elements || elements.length === 0) return;
        const index = elements[0].index;
        if (index === 0) setChartCrossFilter('benign', 'Traffic: Benign Only');
        else if (index === 1) setChartCrossFilter('attacks', 'Traffic: Threats Only');
      },
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: legendColor,
            font: { family: 'IBM Plex Sans', size: 12 },
            padding: 16,
            usePointStyle: true
          }
        },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.parsed.toLocaleString()} flows (Click to filter table)`
          }
        }
      }
    }
  });
}

// ── Interactive Bar Chart ──
function renderBarChart(attackTypes, total) {
  if (barChart) barChart.destroy();
  const canvas = document.getElementById('barChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const sorted = Object.entries(attackTypes || {}).sort((a, b) => b[1] - a[1]);
  const labels = sorted.map(([k]) => k);
  const values = sorted.map(([, v]) => v);

  const colors = labels.map(l => l === 'BENIGN' ? 'rgba(72, 187, 120, 0.85)' : 'rgba(245, 101, 101, 0.85)');
  const borders = labels.map(l => l === 'BENIGN' ? '#48bb78' : '#f56565');

  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const textColor = isLight ? '#5e4f45' : '#cec4b8';
  const gridColor = isLight ? 'rgba(214, 203, 190, 0.5)' : 'rgba(61, 50, 45, 0.5)';

  barChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Flow Count',
        data: values,
        backgroundColor: colors,
        borderColor: borders,
        borderWidth: 1.5,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      onClick: (evt, elements) => {
        if (!elements || elements.length === 0) return;
        const index = elements[0].index;
        const selectedLabel = labels[index];
        setChartCrossFilter(selectedLabel, `Vector: ${selectedLabel}`);
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => {
              const pct = total > 0 ? ((ctx.parsed.x / total) * 100).toFixed(1) : '0';
              return ` ${ctx.parsed.x.toLocaleString()} flows (${pct}%): Click to filter table`;
            }
          }
        }
      },
      scales: {
        x: {
          ticks: { color: textColor, font: { family: 'JetBrains Mono', size: 11 } },
          grid: { color: gridColor },
          border: { display: false }
        },
        y: {
          ticks: { color: textColor, font: { family: 'IBM Plex Sans', size: 11 } },
          grid: { display: false },
          border: { display: false }
        }
      }
    }
  });
}

function renderAttackTable(attackTypes, total) {
  const tbody = document.getElementById('attackTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const sorted = Object.entries(attackTypes || {}).sort((a, b) => b[1] - a[1]);
  if (sorted.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px;">No non-benign predictions in this analysis.</td></tr>';
    return;
  }

  sorted.forEach(([type, count]) => {
    const pct = total > 0 ? ((count / total) * 100).toFixed(2) : '0.00';
    const sev = getSeverity(type);
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.title = `Click to filter flows for ${type}`;
    tr.innerHTML = `
      <td><strong>${escapeHtml(type)}</strong></td>
      <td class="mono">${count.toLocaleString()}</td>
      <td class="mono">${pct}%</td>
      <td><span class="badge ${sev.cls}">${sev.label}</span></td>
    `;
    tr.addEventListener('click', () => setChartCrossFilter(type, `Vector: ${type}`));
    tbody.appendChild(tr);
  });
}

// ============================================================
// 5. FLOW SAMPLES TABLE & ROW INSPECTION (PILLAR 2 - P0)
// ============================================================
function renderFlowSamples(flows) {
  const tbody = document.getElementById('flowSampleTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!flows || flows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--text-lo);">No flow records match the current filter or topology criteria.</td></tr>';
    return;
  }

  flows.forEach((flow) => {
    const tr = document.createElement('tr');
    tr.setAttribute('data-flow-id', flow.id);
    
    // Ingress vector chip
    const ifaceKey = (flow.interface || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '');
    const ifaceBadge = `<span class="vector-chip ${ifaceKey}">${ifaceKey}</span>`;

    // Threat intelligence enrichment
    const asn = flow.threat_intel?.asn || 'Not enriched';
    const geo = flow.threat_intel?.geo || 'Not available';
    const geoParts = geo.split(' ');
    const flagIcon = geoParts[0] || 'INTL';

    // Incident triage status
    const status = flow.review?.status || 'Unreviewed';
    const statusColor = status === 'New' ? 'var(--red)' : status === 'Investigating' ? 'var(--orange)' : 'var(--text-med)';

    tr.innerHTML = `
      <td class="mono">#${escapeHtml(flow.id)}</td>
      <td>${ifaceBadge}</td>
      <td>
        <div class="host-cell">
          <span class="host-ip ip-clickable" data-ip="${escapeHtml(flow.src_ip)}" title="Click to copy IP">${escapeHtml(flow.src_ip)}${flow.src_port ? `:${escapeHtml(flow.src_port)}` : ''}</span>
          <span class="asn-sub"><span class="geo-flag">${escapeHtml(flagIcon)}</span> ${escapeHtml(asn)}</span>
        </div>
      </td>
      <td class="mono"><span class="ip-clickable" data-ip="${escapeHtml(flow.dst_ip)}" title="Click to copy IP">${escapeHtml(flow.dst_ip)}</span>${flow.dst_port ? `:${escapeHtml(flow.dst_port)}` : ''}</td>
      <td><span class="live-pill" style="font-size:0.65rem;">${escapeHtml(flow.protocol)}</span></td>
      <td>
        <div style="display:flex; flex-direction:column; gap:3px;">
          <strong>${escapeHtml(flow.predicted_label)}</strong>
          <span class="cvss-pill">No risk score calculated</span>
        </div>
      </td>
      <td>
        <span class="badge" style="background:transparent; border:1px solid ${statusColor}; color:${statusColor}; font-size:0.68rem;">
          ● ${escapeHtml(status)}
        </span>
      </td>
      <td><button type="button" class="btn-inspect-pill">Inspect ➔</button></td>
    `;

    // Row click opens inspection drawer
    tr.addEventListener('click', (e) => {
      // If user clicked directly on copyable IP, don't open drawer
      if (e.target.classList.contains('ip-clickable')) {
        const ip = e.target.getAttribute('data-ip');
        navigator.clipboard.writeText(ip);
        showToast(`Copied ${ip} to clipboard`, 'success');
        return;
      }
      openFlowInspector(flow, tr);
    });

    tbody.appendChild(tr);
  });
}

// ── Open Inspection Drawer (Pillar 2) ──
function openFlowInspector(flow, trElement) {
  activeInspectedFlow = flow;

  // Highlight selected row in table
  document.querySelectorAll('.flow-records-table tr.selected-row').forEach(r => r.classList.remove('selected-row'));
  if (trElement) trElement.classList.add('selected-row');

  // Fill Header
  if (drawerFlowId) drawerFlowId.textContent = `Flow Record #${flow.id}`;
  if (drawerRouteText) drawerRouteText.textContent = `${flow.src_ip}:${flow.src_port} ➔ ${flow.dst_ip}:${flow.dst_port} (${flow.protocol})`;
  if (drawerMitre) drawerMitre.textContent = flow.mitre || 'No technique mapping available';

  if (drawerThreatBadge) {
    const sev = getSeverity(flow.predicted_label);
    drawerThreatBadge.className = `badge ${sev.cls}`;
    drawerThreatBadge.textContent = `${sev.label}: ${flow.predicted_label}`;
  }

  // Fill CVSS Rating Pill
  if (drawerCvssBadge) {
    drawerCvssBadge.className = 'cvss-pill';
    drawerCvssBadge.textContent = 'No risk score calculated';
  }

  // Persistent review is available only for records loaded from flow storage.
  const reviewable = flow.persisted === true && Number.isSafeInteger(Number(flow.id));
  if (reviewControls) reviewControls.hidden = !reviewable;
  if (reviewUnavailable) reviewUnavailable.hidden = reviewable;
  if (btnDrawerFlagFP) btnDrawerFlagFP.hidden = !reviewable;
  if (drawerTriageStatus) drawerTriageStatus.value = flow.review?.status || 'Unreviewed';
  if (drawerReviewNote) drawerReviewNote.value = flow.review?.note || '';
  if (reviewUpdatedMeta) {
    reviewUpdatedMeta.textContent = flow.review?.updated_at
      ? `Saved by ${flow.review.updated_by || 'unknown'} at ${new Date(flow.review.updated_at).toLocaleString()}`
      : 'No review saved';
  }
  if (reviewable) loadFlowReviewAudit(flow.id);
  else if (reviewAuditList) reviewAuditList.replaceChildren(Object.assign(document.createElement('li'), { textContent: 'No persistent review history for this record.' }));

  // Fill optional public-IP reputation-provider fields
  if (drawerThreatAsn) drawerThreatAsn.textContent = flow.threat_intel?.asn || 'Not enriched';
  if (drawerThreatGeo) drawerThreatGeo.textContent = flow.threat_intel?.geo || 'Not available';
  if (drawerAbuseScore) {
    const score = flow.threat_intel?.abuse_score;
    const providerStatus = flow.threat_intel?.provider_status;
    drawerAbuseScore.textContent = Number.isFinite(score)
      ? `${score}% confidence · ${flow.threat_intel.total_reports ?? 0} reports`
      : providerStatus === 'private_address' ? 'Private IP · lookup skipped'
        : providerStatus === 'not_configured' ? 'API key not configured'
          : providerStatus === 'unavailable' ? 'Provider unavailable' : 'Not queried';
    drawerAbuseScore.className = `abuse-badge ${Number.isFinite(score) && score <= 50 ? 'badge-safe' : ''}`;
  }
  if (drawerThreatTag) drawerThreatTag.textContent = flow.threat_intel?.tag || 'No reputation tag available';

  // Fill Layer-2 Ingress Hardware Telemetry
  if (drawerL2Interface) drawerL2Interface.textContent = flow.interface || 'Not provided';
  if (drawerL2Vector) drawerL2Vector.textContent = flow.l2_meta?.vector || 'Not available from flow data';
  if (drawerL2Port) {
    drawerL2Port.textContent = flow.l2_meta?.switch_port || flow.l2_meta?.ssid || flow.l2_meta?.apn || flow.l2_meta?.peer || 'Not provided';
  }
  if (drawerL2Signal) {
    drawerL2Signal.textContent = flow.l2_meta?.duplex || flow.l2_meta?.rssi || flow.l2_meta?.rsrp || flow.l2_meta?.mtls || 'Not provided';
  }
  if (drawerL2Health) {
    drawerL2Health.textContent = flow.l2_meta?.l2_health || 'Not measured';
  }

  renderPacketDissector(flow.packet_dissector);

  // Reset SOAR Terminal prompt
  if (soarTerminalOutput) {
    renderSoarTerminal([`Target host: ${flow.src_ip} (${flow.predicted_label}). Select a playbook or mock webhook.`]);
  }

  // Fill Raw Telemetry
  if (drawerTelDuration) drawerTelDuration.textContent = `${flow.duration_us || '0'} µs`;
  if (drawerTelBytes) drawerTelBytes.textContent = `${flow.bytes_s || '0'} B/s`;
  if (drawerTelPkts) drawerTelPkts.textContent = `${flow.pkts_s || '0'} pkts/s`;
  if (drawerTelPacketRatio) drawerTelPacketRatio.textContent = `${flow.fwd_pkts || 0} fwd / ${flow.bwd_pkts || 0} bwd`;

  // Fill TCP Flags
  const flags = flow.flags || { syn: 0, ack: 0, rst: 0, fin: 0 };
  if (flagSYN) { flagSYN.textContent = `SYN: ${flags.syn}`; flagSYN.className = `flag-chip ${flags.syn > 0 ? 'active' : ''}`; }
  if (flagACK) { flagACK.textContent = `ACK: ${flags.ack}`; flagACK.className = `flag-chip ${flags.ack > 0 ? 'active' : ''}`; }
  if (flagRST) { flagRST.textContent = `RST: ${flags.rst}`; flagRST.className = `flag-chip ${flags.rst > 0 ? 'active' : ''}`; }
  if (flagFIN) { flagFIN.textContent = `FIN: ${flags.fin}`; flagFIN.className = `flag-chip ${flags.fin > 0 ? 'active' : ''}`; }

  // Render SHAP Waterfall mini-bars
  if (drawerShapList) {
    drawerShapList.innerHTML = '';
    const shapItems = Array.isArray(flow.shap) ? flow.shap : [];
    if (shapItems.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'table-sub';
      empty.textContent = 'Per-flow explanations are unavailable for this model artifact.';
      drawerShapList.appendChild(empty);
    }

    shapItems.forEach(item => {
      const row = document.createElement('div');
      row.className = 'shap-row';
      const isPos = item.direction === '+';
      const impact = Math.max(0, Math.min(100, Number(item.impact) || 0));
      row.innerHTML = `
        <div class="shap-row-header">
          <span class="shap-feat-name">${escapeHtml(item.feature)} (${escapeHtml(item.value)})</span>
          <span class="shap-feat-val" style="color:${isPos ? 'var(--red)' : 'var(--green)'}; font-weight:700;">
            ${escapeHtml(item.direction)}${impact}% contribution
          </span>
        </div>
        <div class="shap-bar-track">
          <div class="shap-bar-fill ${isPos ? 'positive' : 'negative'}" style="width: ${impact}%;"></div>
        </div>
      `;
      drawerShapList.appendChild(row);
    });
  }

  // Slide open drawer (mobile / full-screen mode)
  if (flowDrawer) {
    flowDrawer.classList.add('open');
    flowDrawer.setAttribute('aria-hidden', 'false');
  }
  if (drawerBackdrop) drawerBackdrop.classList.add('open');

  // Sync the docked inline inspector panel (desktop workbench layout)
  if (typeof window.syncDockedInspector === 'function') {
    window.syncDockedInspector(flow);
  }
  // Expose the active flow for the docked inspector to reference
  window.activeInspectedFlow = flow;
}

function renderPacketDissector(header) {
  if (!packetDissectorSection) return;
  packetDissectorSection.hidden = !header;
  if (!header) return;

  if (packetDissectorSummary) packetDissectorSummary.textContent = header.summary || 'Decoded packet header';
  if (packetDissectorLayers) {
    packetDissectorLayers.replaceChildren();
    (header.layers || []).forEach((layer) => {
      const tag = document.createElement('span');
      tag.className = 'dissector-layer';
      tag.textContent = layer;
      packetDissectorLayers.appendChild(tag);
    });
  }
  if (packetDissectorFields) {
    const fields = [
      ['IP version', header.ip_version], ['Source', header.source], ['Destination', header.destination],
      ['Protocol', header.protocol], ['Source port', header.source_port], ['Destination port', header.destination_port],
      ['TTL / Hop limit', header.ttl], ['IP header length', header.ip_header_length],
      ['IP total length', header.ip_total_length], ['IP ID', header.ip_id], ['IP flags', header.ip_flags],
      ['TCP flags', header.tcp_flags], ['TCP window', header.tcp_window], ['UDP length', header.udp_length],
      ['ICMP type', header.icmp_type], ['ICMP code', header.icmp_code]
    ].filter(([, value]) => value !== null && value !== undefined && value !== '');
    packetDissectorFields.replaceChildren();
    fields.forEach(([label, value]) => {
      const cell = document.createElement('div');
      const term = document.createElement('dt');
      const detail = document.createElement('dd');
      cell.className = 'dissector-field';
      term.textContent = label;
      detail.textContent = String(value);
      cell.append(term, detail);
      packetDissectorFields.appendChild(cell);
    });
  }
}

function renderSoarTerminal(lines) {
  if (!soarTerminalOutput) return;
  soarTerminalOutput.replaceChildren();
  lines.forEach((text, index) => {
    const line = document.createElement('div');
    line.className = 'terminal-line';
    if (index === 0) {
      const prompt = document.createElement('span');
      prompt.className = 'term-prompt';
      prompt.textContent = 'soar@netshield:~$ ';
      line.appendChild(prompt);
    }
    line.appendChild(document.createTextNode(text));
    soarTerminalOutput.appendChild(line);
  });
}

function closeFlowInspector() {
  if (flowDrawer) {
    flowDrawer.classList.remove('open');
    flowDrawer.setAttribute('aria-hidden', 'true');
  }
  if (drawerBackdrop) drawerBackdrop.classList.remove('open');
  document.querySelectorAll('.flow-records-table tr.selected-row').forEach(r => r.classList.remove('selected-row'));
  activeInspectedFlow = null;
}

if (btnCloseDrawer) btnCloseDrawer.addEventListener('click', closeFlowInspector);
if (drawerBackdrop) drawerBackdrop.addEventListener('click', closeFlowInspector);

// Drawer Triage Actions
if (btnDrawerCopyJson) {
  btnDrawerCopyJson.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    navigator.clipboard.writeText(JSON.stringify(activeInspectedFlow, null, 2));
    showToast(`Copied Flow #${activeInspectedFlow.id} JSON telemetry to clipboard`, 'success');
  });
}

if (btnDrawerFlagFP) {
  btnDrawerFlagFP.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    if (drawerTriageStatus) drawerTriageStatus.value = 'Suppressed';
    saveFlowReview();
  });
}

async function loadFlowReviewAudit(flowId) {
  if (!reviewAuditList) return;
  try {
    const response = await apiFetch(`/api/flows/${encodeURIComponent(flowId)}/review/audit`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    reviewAuditList.replaceChildren();
    if (!payload.events?.length) {
      reviewAuditList.appendChild(Object.assign(document.createElement('li'), { textContent: 'No review events' }));
      return;
    }
    payload.events.forEach((event) => {
      const item = document.createElement('li');
      const noteChange = event.note_changed ? ' · note updated' : '';
      item.textContent = `${event.changed_at} · ${event.actor}: ${event.previous_status} → ${event.new_status}${noteChange}`;
      reviewAuditList.appendChild(item);
    });
  } catch (error) {
    reviewAuditList.replaceChildren(Object.assign(document.createElement('li'), { textContent: 'Review history could not be loaded.' }));
  }
}

async function saveFlowReview() {
  if (!activeInspectedFlow || activeInspectedFlow.persisted !== true) return;
  if (!drawerTriageStatus || !drawerReviewNote || !btnSaveFlowReview) return;
  const flowId = activeInspectedFlow.id;
  btnSaveFlowReview.disabled = true;
  const originalText = btnSaveFlowReview.textContent;
  btnSaveFlowReview.textContent = 'Saving…';
  try {
    const response = await apiFetch(`/api/flows/${encodeURIComponent(flowId)}/review`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: drawerTriageStatus.value, note: drawerReviewNote.value })
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    if (activeInspectedFlow?.id !== flowId) return;
    activeInspectedFlow.review = payload.review;
    if (reviewUpdatedMeta) {
      reviewUpdatedMeta.textContent = `Saved by ${payload.review.updated_by || 'unknown'} at ${new Date(payload.review.updated_at).toLocaleString()}`;
    }
    filterFlowTable();
    await loadFlowReviewAudit(flowId);
    showToast(payload.changed ? 'Review saved with audit history' : 'Review is unchanged', 'success');
  } catch (error) {
    showToast(`Review could not be saved: ${error.message}`, 'danger');
  } finally {
    btnSaveFlowReview.disabled = false;
    btnSaveFlowReview.textContent = originalText;
  }
}

if (btnSaveFlowReview) btnSaveFlowReview.addEventListener('click', saveFlowReview);

// ============================================================
// AUTOMATED SOAR PLAYBOOK EXECUTION TERMINAL
// ============================================================
function dispatchSoarPlaybook(actionType, commandText, successMsg) {
  if (!activeInspectedFlow || !soarTerminalOutput) return;
  renderSoarTerminal([
    `[DISPATCHING ${actionType.toUpperCase()} PLAYBOOK]`,
    `[EXEC] ${commandText}`,
    `[SIMULATED OK] ${successMsg}`,
    '[INFO] Local preview only · no external enforcement performed.'
  ]);

  showToast(successMsg, 'danger');
}

async function dispatchMockWebhook(channel) {
  if (!activeInspectedFlow || !soarTerminalOutput) return;
  const flow = activeInspectedFlow;
  const message = `${flow.predicted_label} alert for ${flow.src_ip} → ${flow.dst_ip}:${flow.dst_port}`;
  renderSoarTerminal([`[POST] Mock ${channel} webhook · Flow #${flow.id}`, '[WAIT] Awaiting local simulation response']);
  try {
    const response = await apiFetch('/api/soar/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, message, flow_id: flow.id })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    renderSoarTerminal([
      `[POST] Mock ${channel} webhook accepted`,
      `[202 SIMULATED] Destination: ${result.destination}`,
      `[MESSAGE] ${result.message}`,
      `[AUDIT] Event ${result.event_id} · external_delivery=${result.external_delivery}`
    ]);
    showToast(`${channel} webhook simulated`, 'success');
  } catch (error) {
    renderSoarTerminal([`[ERROR] ${channel} simulation failed: ${error.message}`]);
    showToast(`${channel} webhook simulation failed`, 'danger');
  }
}

if (btnSoarSlack) btnSoarSlack.addEventListener('click', () => dispatchMockWebhook('slack'));
if (btnSoarPagerDuty) btnSoarPagerDuty.addEventListener('click', () => dispatchMockWebhook('pagerduty'));

if (btnSoarIptables) {
  btnSoarIptables.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    const cmd = activeInspectedFlow.soar?.iptables || `sudo iptables -I INPUT -s ${activeInspectedFlow.src_ip} -j DROP`;
    dispatchSoarPlaybook('iptables', cmd, 'Preview only. No host firewall action was performed.');
  });
}

if (btnSoarCloudflare) {
  btnSoarCloudflare.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    const cmd = activeInspectedFlow.soar?.waf_cmd || `cloudflare-cli waf rule create --action block --ip ${activeInspectedFlow.src_ip}`;
    dispatchSoarPlaybook('cloudflare', cmd, 'Preview only. No Cloudflare request was sent.');
  });
}

if (btnSoarAwsSg) {
  btnSoarAwsSg.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    const cmd = activeInspectedFlow.soar?.aws_sg_cmd || `aws ec2 revoke-security-group-ingress --group-id sg-prod --cidr ${activeInspectedFlow.src_ip}/32`;
    dispatchSoarPlaybook('aws', cmd, 'Preview only. No AWS request was sent.');
  });
}

if (btnSoarStix) {
  btnSoarStix.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    const stixId = activeInspectedFlow.soar?.stix_id || `indicator--${Date.now()}`;
    const cmd = `export_stix_bundle --indicator-id "${stixId}" --threat-pattern "[network-traffic:src_ref.value = '${activeInspectedFlow.src_ip}']"`;
    dispatchSoarPlaybook('stix', cmd, 'Preview only. No STIX bundle was exported or published.');
  });
}

// ============================================================
// 6. FILTER CHIPS & CHART CROSS-FILTERING (PILLAR 3)
// ============================================================
function setChartCrossFilter(filterValue, labelText) {
  activeChartFilter = filterValue;
  if (activeFilterChips && filterChipsList) {
    activeFilterChips.hidden = false;
    filterChipsList.innerHTML = `
      <div class="filter-chip">
        <span>${escapeHtml(labelText)}</span>
        <button type="button" class="filter-chip-remove" id="btnRemoveChip">✕</button>
      </div>
    `;

    document.getElementById('btnRemoveChip')?.addEventListener('click', clearCrossFilter);
  }

  filterFlowTable();
  const sampleCard = document.getElementById('flowSampleCard');
  if (sampleCard) sampleCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function clearCrossFilter() {
  activeChartFilter = null;
  if (activeFilterChips) activeFilterChips.hidden = true;
  if (filterChipsList) filterChipsList.innerHTML = '';
  filterFlowTable();
}

if (btnClearAllFilters) btnClearAllFilters.addEventListener('click', clearCrossFilter);

function filterFlowTable() {
  const searchTerm = (flowSearchInput?.value || '').toLowerCase().trim();
  const selectFilter = flowFilterSelect?.value || 'all';

  const filtered = currentSampleFlows.filter((flow) => {
    // 1. Ingestion Vector (Topology) filter
    let matchesVector = true;
    if (activeTopologyFilter !== 'all') {
      matchesVector = (flow.interface || 'unknown').toLowerCase() === activeTopologyFilter.toLowerCase();
    }

    // 2. Search filter
    const matchesSearch =
      (flow.src_ip || '').toLowerCase().includes(searchTerm) ||
      (flow.dst_ip || '').toLowerCase().includes(searchTerm) ||
      (flow.predicted_label || '').toLowerCase().includes(searchTerm) ||
      (flow.protocol || '').toLowerCase().includes(searchTerm) ||
      (flow.threat_intel?.asn || '').toLowerCase().includes(searchTerm);

    // 3. Select dropdown filter
    let matchesSelect = true;
    if (selectFilter === 'attacks') matchesSelect = flow.is_attack;
    else if (selectFilter === 'benign') matchesSelect = !flow.is_attack;

    // 4. Active chart cross-filter
    let matchesChart = true;
    if (activeChartFilter) {
      if (activeChartFilter === 'benign') matchesChart = !flow.is_attack;
      else if (activeChartFilter === 'attacks') matchesChart = flow.is_attack;
      else matchesChart = (flow.predicted_label || '').toLowerCase() === activeChartFilter.toLowerCase();
    }

    return matchesVector && matchesSearch && matchesSelect && matchesChart;
  });

  renderFlowSamples(filtered);
}

if (flowSearchInput) flowSearchInput.addEventListener('input', filterFlowTable);
if (flowFilterSelect) flowFilterSelect.addEventListener('change', filterFlowTable);

// ── Network Topology Vector Tab Strip Listeners ──
const topologyTabs = document.querySelectorAll('.topology-tab');

const TOPOLOGY_BANNER = {
  'all': {
    iface: 'All uploaded inputs',
    link: 'Interface metadata is not available unless included in the upload',
    health: 'Link-layer inspection is not implemented'
  },
  'pcap': {
    iface: 'Uploaded packet capture',
    link: 'Packet capture file processed locally by the configured parser',
    health: 'No live interface health data is collected'
  },
  'batch': {
    iface: 'Uploaded CSV file',
    link: 'Flow rows processed by the model pipeline',
    health: 'No live interface health data is collected'
  }
};

if (topologyTabs && topologyTabs.length > 0) {
  topologyTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      topologyTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeTopologyFilter = tab.getAttribute('data-vector') || 'all';

      const banner = TOPOLOGY_BANNER[activeTopologyFilter] || TOPOLOGY_BANNER['all'];
      const ifaceEl = document.getElementById('topActiveIface');
      const linkEl  = document.getElementById('topActiveLink');
      const hlthEl  = document.getElementById('topActiveHealth');
      if (ifaceEl) ifaceEl.textContent = banner.iface;
      if (linkEl)  linkEl.textContent  = banner.link;
      if (hlthEl)  hlthEl.textContent  = banner.health;

      filterFlowTable();
      const meta = TOPOLOGY_META[activeTopologyFilter] || TOPOLOGY_META['all'];
      showToast(`Interface filter: ${meta.tag}`, 'info');
    });
  });
}


// ============================================================
// 7. TABLE DENSITY & EXPORT DATA
// ============================================================
if (btnDensityStandard && btnDensityCompact) {
  btnDensityStandard.addEventListener('click', () => {
    flowSampleTable?.removeAttribute('data-density');
    btnDensityStandard.classList.add('active');
    btnDensityCompact.classList.remove('active');
  });

  btnDensityCompact.addEventListener('click', () => {
    flowSampleTable?.setAttribute('data-density', 'compact');
    btnDensityCompact.classList.add('active');
    btnDensityStandard.classList.remove('active');
  });
}

if (btnExportCSV) {
  btnExportCSV.addEventListener('click', () => {
    if (!currentSampleFlows || currentSampleFlows.length === 0) {
      return showToast('No flow records available to export', 'danger');
    }
    const headers = ['ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Classification', 'Is Threat', 'MITRE'];
    const rows = currentSampleFlows.map(f => [
      f.id, f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.protocol, `"${f.predicted_label}"`, f.is_attack, `"${f.mitre || ''}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const link = document.createElement('a');
    link.href = encodeURI(csvContent);
    link.download = `netshield_flows_${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast('Exported flows to CSV file', 'success');
  });
}

if (btnExportJSON) {
  btnExportJSON.addEventListener('click', () => {
    if (!currentResultsPayload) {
      return showToast('No analysis report available to export', 'danger');
    }
    const jsonStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentResultsPayload, null, 2));
    const link = document.createElement('a');
    link.href = jsonStr;
    link.download = `netshield_report_${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast('Exported full telemetry report to JSON', 'success');
  });
}

// ============================================================
// 8. POWER-USER COMMAND PALETTE (PILLAR 5 - P4)
// ============================================================
function openCommandPalette() {
  if (cmdModal && cmdBackdrop) {
    cmdModal.classList.add('open');
    cmdBackdrop.classList.add('open');
    cmdInput.value = '';
    filterCommandItems('');
    setTimeout(() => cmdInput?.focus(), 50);
  }
}

function closeCommandPalette() {
  if (cmdModal && cmdBackdrop) {
    cmdModal.classList.remove('open');
    cmdBackdrop.classList.remove('open');
  }
}

if (btnOpenCmdPalette) btnOpenCmdPalette.addEventListener('click', openCommandPalette);
if (cmdBackdrop) cmdBackdrop.addEventListener('click', closeCommandPalette);

function filterCommandItems(query) {
  const q = (query || '').toLowerCase().trim();
  const items = document.querySelectorAll('.cmd-item');
  items.forEach(item => {
    const text = item.textContent.toLowerCase();
    item.style.display = text.includes(q) ? 'flex' : 'none';
  });
}

if (cmdInput) {
  cmdInput.addEventListener('input', (e) => filterCommandItems(e.target.value));
  cmdInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeCommandPalette();
    if (e.key === 'Enter') {
      const visible = Array.from(document.querySelectorAll('.cmd-item')).filter(i => i.style.display !== 'none');
      if (visible.length > 0) executeCommandAction(visible[0].getAttribute('data-action'));
    }
  });
}

document.querySelectorAll('.cmd-item').forEach(item => {
  item.addEventListener('click', () => {
    const action = item.getAttribute('data-action');
    executeCommandAction(action);
  });
});

function executeCommandAction(action) {
  closeCommandPalette();
  switch (action) {
    case 'load-demo':
      btnSampleDemo?.click();
      break;
    case 'goto-dashboard':
      window.location.href = '/dashboard';
      break;
    case 'focus-search':
      flowSearchInput?.focus();
      break;
    case 'export-csv':
      btnExportCSV?.click();
      break;
    case 'export-json':
      btnExportJSON?.click();
      break;
    case 'toggle-theme':
      document.getElementById('themeToggle')?.click();
      showToast('Theme switched', 'info');
      break;
    default:
      break;
  }
}

// Global Keyboard Shortcut Listeners
window.addEventListener('keydown', (e) => {
  // Cmd+K or Ctrl+K
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (cmdModal?.classList.contains('open')) closeCommandPalette();
    else openCommandPalette();
    return;
  }

  // Escape closes active modals/drawers
  if (e.key === 'Escape') {
    if (cmdModal?.classList.contains('open')) {
      closeCommandPalette();
      return;
    }
    if (flowDrawer?.classList.contains('open')) {
      closeFlowInspector();
      return;
    }
  }

  // / key focuses table search box when not inside an input
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
    e.preventDefault();
    flowSearchInput?.focus();
  }
});

// ── Theme Switch Listener for Charts ──
window.addEventListener('themeChanged', () => {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const textColor = isLight ? '#5e4f45' : '#cec4b8';
  const gridColor = isLight ? 'rgba(214, 203, 190, 0.5)' : 'rgba(61, 50, 45, 0.5)';

  if (donutChart) {
    donutChart.options.plugins.legend.labels.color = textColor;
    donutChart.update();
  }
  if (barChart) {
    barChart.options.scales.x.ticks.color = textColor;
    barChart.options.scales.x.grid.color = gridColor;
    barChart.options.scales.y.ticks.color = textColor;
    barChart.update();
  }
});
