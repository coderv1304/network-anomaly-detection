/* ============================================================
   NETSHIELD AI: Flow Review Dashboard
   Polls stored flow records and labels optional demo fixtures.
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


// ── DOM References ──
const statusEl          = document.getElementById('status-dot');
const statusLabel       = statusEl ? statusEl.querySelector('.status-label') : null;
const totalEl           = document.getElementById('stat-total');
const benignEl          = document.getElementById('stat-benign');
const attackEl          = document.getElementById('stat-attack');
const benignPctEl       = document.getElementById('stat-benign-pct');
const attackPctEl       = document.getElementById('stat-attack-pct');
const fpsEl             = document.getElementById('stat-fps');
const tableBody         = document.getElementById('flow-table-body');
const systemBanner      = document.getElementById('systemBanner');
const bannerTitle       = document.getElementById('bannerStatusTitle');
const bannerSub         = document.getElementById('bannerStatusSub');
const threatIndexVal    = document.getElementById('threatIndexVal');
const threatGaugeFill   = document.getElementById('threatGaugeFill');

const searchInput       = document.getElementById('searchInput');
const filterAllBtn       = document.getElementById('filterAllBtn');
const filterAttacksBtn   = document.getElementById('filterAttacksBtn');
const filterBenignBtn    = document.getElementById('filterBenignBtn');
const btnClearLog        = document.getElementById('btnClearLog');
const btnSimulate        = document.getElementById('btnSimulate');
const btnBurst           = document.getElementById('btnBurst');

// ── Breakdown Widget Elements ──
const bBenignCount  = document.getElementById('b-benign-count');
const bBenignFill   = document.getElementById('b-benign-fill');
const bDdosCount    = document.getElementById('b-ddos-count');
const bDdosFill     = document.getElementById('b-ddos-fill');
const bPortscanCount= document.getElementById('b-portscan-count');
const bPortscanFill = document.getElementById('b-portscan-fill');
const bWebCount     = document.getElementById('b-web-count');
const bWebFill      = document.getElementById('b-web-fill');
const bHulkCount    = document.getElementById('b-hulk-count');
const bHulkFill     = document.getElementById('b-hulk-fill');

// ── State Variables ──
let totalCount = 0;
let benignCount = 0;
let attackCount = 0;
let flowsLastSec = 0;
let lastSecTimestamp = Date.now();

const breakdownMap = {
  BENIGN: 0,
  DDoS: 0,
  PortScan: 0,
  "Web Attack – Brute Force": 0,
  "DoS Hulk": 0,
  "FTP-Patator": 0,
};

const MAX_ROWS = 100;
let currentFilter = 'all'; // 'all' | 'attacks' | 'benign'
let searchQuery = '';
let allFlowRecords = [];
let seenFlowKeys = new Set();
let simulationTimer = null;
let flowHistoryLoaded = false;
let syncInProgress = false;

// ── Oscilloscope Canvas (Pulse Strip) ──
const canvas = document.getElementById('pulseCanvas');
const ctx = canvas ? canvas.getContext('2d') : null;
const pulseData = []; // { attack: boolean }
const BAR_WIDTH = 6;
const BAR_GAP = 3;

function resizeCanvas() {
  if (!canvas || !ctx) return;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * (window.devicePixelRatio || 1);
  canvas.height = rect.height * (window.devicePixelRatio || 1);
  ctx.setTransform(window.devicePixelRatio || 1, 0, 0, window.devicePixelRatio || 1, 0, 0);
  drawPulse();
}

if (canvas) {
  window.addEventListener('resize', resizeCanvas);
  setTimeout(resizeCanvas, 0);
}

function drawPulse() {
  if (!canvas || !ctx) return;
  const rect = canvas.getBoundingClientRect();
  const w = rect.width;
  const h = rect.height || 130;
  ctx.clearRect(0, 0, w, h);

  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const cyanColor = isLight ? '#0284c7' : '#00d4ff';
  const redColor = isLight ? '#dc2626' : '#ff4757';
  const baselineColor = isLight ? 'rgba(100, 116, 139, 0.25)' : 'rgba(163, 178, 207, 0.2)';

  const maxBars = Math.floor(w / (BAR_WIDTH + BAR_GAP));

  // Ambient idle wave when pulse data is empty
  if (pulseData.length === 0) {
    ctx.strokeStyle = baselineColor;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(0, h / 2);
    for (let x = 0; x < w; x += 12) {
      const yOffset = Math.sin(x * 0.04 + Date.now() * 0.003) * 4;
      ctx.lineTo(x, h / 2 + yOffset);
    }
    ctx.stroke();
    return;
  }

  const visible = pulseData.slice(-maxBars);

  // Baseline
  ctx.strokeStyle = baselineColor;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, h / 2);
  ctx.lineTo(w, h / 2);
  ctx.stroke();

  // Vertical Frequency Bars
  visible.forEach((entry, i) => {
    const x = w - (visible.length - i) * (BAR_WIDTH + BAR_GAP);
    const barHeight = entry.attack ? h * 0.62 : h * 0.30;
    const color = entry.attack ? redColor : cyanColor;

    ctx.fillStyle = color;
    ctx.shadowColor = color;
    ctx.shadowBlur = entry.attack ? 12 : 5;
    ctx.fillRect(x, h / 2 - barHeight / 2, BAR_WIDTH, barHeight);
  });
  ctx.shadowBlur = 0;
}

function pushPulse(isAttack) {
  pulseData.push({ attack: isAttack });
  if (pulseData.length > 400) pulseData.shift();
  drawPulse();
}

// ── Stored Prediction Metrics ──
function updateMetricsUI() {
  if (totalEl) totalEl.textContent = totalCount.toLocaleString();
  if (benignEl) benignEl.textContent = benignCount.toLocaleString();
  if (attackEl) attackEl.textContent = attackCount.toLocaleString();

  const totalSafe = Math.max(1, totalCount);
  const benignPct = ((benignCount / totalSafe) * 100).toFixed(1);
  const attackPct = ((attackCount / totalSafe) * 100).toFixed(1);

  if (benignPctEl) benignPctEl.textContent = `${benignPct}% predicted benign`;
  if (attackPctEl) attackPctEl.textContent = `${attackPct}% classified non-benign`;

  // Descriptive share of stored records predicted as non-benign.
  const predictionShare = Math.min(100, Math.round((attackCount / totalSafe) * 100));
  if (threatIndexVal) threatIndexVal.textContent = `${predictionShare}%`;
  if (threatGaugeFill) threatGaugeFill.style.width = `${predictionShare}%`;

  // Update Status Banner
  if (systemBanner) {
    if (predictionShare >= 25 || attackCount > 0) {
      systemBanner.className = 'system-banner alert';
      if (bannerTitle) bannerTitle.textContent = `NON-BENIGN PREDICTIONS PRESENT (${predictionShare}%)`;
      if (bannerSub) bannerSub.textContent = `${attackCount} flow records classified as non-benign · this is not a verified incident count`;
    } else {
      systemBanner.className = 'system-banner';
      if (bannerTitle) bannerTitle.textContent = 'NO NON-BENIGN PREDICTIONS IN STORED DATA';
      if (bannerSub) bannerSub.textContent = `${totalCount.toLocaleString()} flow records processed · this result does not establish network security`;
    }
  }

  // Update Distribution Breakdown Matrix
  updateBreakdownMatrix();
}

function updateBreakdownMatrix() {
  const totalSafe = Math.max(1, totalCount);

  if (bBenignCount) bBenignCount.textContent = (breakdownMap.BENIGN || 0).toLocaleString();
  if (bBenignFill) bBenignFill.style.width = `${((breakdownMap.BENIGN || 0) / totalSafe * 100).toFixed(0)}%`;

  if (bDdosCount) bDdosCount.textContent = (breakdownMap.DDoS || 0).toLocaleString();
  if (bDdosFill) bDdosFill.style.width = `${((breakdownMap.DDoS || 0) / totalSafe * 100).toFixed(0)}%`;

  if (bPortscanCount) bPortscanCount.textContent = (breakdownMap.PortScan || 0).toLocaleString();
  if (bPortscanFill) bPortscanFill.style.width = `${((breakdownMap.PortScan || 0) / totalSafe * 100).toFixed(0)}%`;

  if (bWebCount) bWebCount.textContent = (breakdownMap["Web Attack – Brute Force"] || 0).toLocaleString();
  if (bWebFill) bWebFill.style.width = `${((breakdownMap["Web Attack – Brute Force"] || 0) / totalSafe * 100).toFixed(0)}%`;

  if (bHulkCount) bHulkCount.textContent = (breakdownMap["DoS Hulk"] || 0).toLocaleString();
  if (bHulkFill) bHulkFill.style.width = `${((breakdownMap["DoS Hulk"] || 0) / totalSafe * 100).toFixed(0)}%`;
}

// ── Flow Table Rendering ──
function clearEmptyRow() {
  if (!tableBody) return;
  const empty = tableBody.querySelector('.empty-row');
  if (empty) empty.remove();
}

function createRowElement(flow) {
  const row = document.createElement('tr');
  row.className = flow.is_attack ? 'attack-row' : '';

  const timeStr = flow.timestamp
    ? new Date(flow.timestamp).toLocaleTimeString('en-GB', { hour12: false })
    : new Date().toLocaleTimeString('en-GB', { hour12: false });

  const srcPort = flow.src_port ? `:${escapeHtml(flow.src_port)}` : '';
  const dstPort = flow.dst_port ? `:${escapeHtml(flow.dst_port)}` : '';
  const proto = (flow.protocol || 'TCP').toUpperCase();

  const intel = flow.threat_intel || {};
  const iface = String(flow.interface || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'unknown';
  const ifaceChip = `<span class="vector-chip ${iface}">${escapeHtml(iface)}</span>`;

  const severityBadge = flow.is_attack
    ? `<span class="badge badge-critical">THREAT</span>`
    : `<span class="badge badge-safe">BENIGN</span>`;

  const abuseScore = Number.isFinite(Number(intel.abuse_score)) && intel.abuse_score !== null && intel.abuse_score !== '' ? Number(intel.abuse_score) : null;
  const abuseColor = Number.isFinite(abuseScore) && abuseScore > 50 ? 'var(--red)' : 'var(--text-med)';
  const asnHtml = `<div class="host-cell">
      <span class="mono" style="font-size:0.8rem;font-weight:600">${escapeHtml(flow.src_ip || 'Not provided')}${srcPort}</span>
      <span class="asn-sub">${escapeHtml(intel.asn || 'Not enriched')}${Number.isFinite(abuseScore) ? ` <span style="color:${abuseColor};font-size:0.65rem;">${abuseScore}% abuse score</span>` : ''}</span>
    </div>`;
  const simulationBadge = flow.simulation ? '<span class="badge badge-medium">SIMULATED</span>' : '';

  row.innerHTML = `
    <td>${escapeHtml(timeStr)}</td>
    <td>${ifaceChip}</td>
    <td>${asnHtml}</td>
    <td class="mono" style="font-size:0.8rem">${escapeHtml(flow.dst_ip || 'Not provided')}${dstPort}</td>
    <td><span class="live-pill" style="font-size:0.65rem">${escapeHtml(proto)}</span></td>
    <td><strong>${escapeHtml(flow.predicted_label || 'Unknown')}</strong></td>
    <td>${simulationBadge || severityBadge}</td>
  `;
  return row;
}

function addFlowToDOM(flow, isLive = true) {
  if (!flow) return;

  const flowKey = (flow.id !== undefined && flow.id !== null)
    ? `id-${flow.id}`
    : `${flow.timestamp}-${flow.src_ip}-${flow.src_port}-${Math.random()}`;

  if (seenFlowKeys.has(flowKey)) return;
  seenFlowKeys.add(flowKey);

  if (isLive) {
    flowsLastSec++;
    pushPulse(Boolean(flow.is_attack));
  }

  allFlowRecords.unshift(flow);
  if (allFlowRecords.length > MAX_ROWS) {
    const popped = allFlowRecords.pop();
    if (popped && popped.id) seenFlowKeys.delete(`id-${popped.id}`);
  }

  if (!matchesFilterAndSearch(flow)) return;

  if (tableBody) {
    clearEmptyRow();
    const row = createRowElement(flow);
    tableBody.prepend(row);
    while (tableBody.rows.length > MAX_ROWS) {
      tableBody.deleteRow(-1);
    }
  }
}

function matchesFilterAndSearch(flow) {
  if (currentFilter === 'attacks' && !flow.is_attack) return false;
  if (currentFilter === 'benign' && flow.is_attack) return false;

  if (searchQuery) {
    const text = `${flow.src_ip} ${flow.dst_ip} ${flow.src_port} ${flow.dst_port} ${flow.protocol} ${flow.predicted_label}`.toLowerCase();
    if (!text.includes(searchQuery)) return false;
  }

  return true;
}

function renderFilteredTable() {
  if (!tableBody) return;
  tableBody.innerHTML = '';

  const flowsToDisplay = allFlowRecords.filter(matchesFilterAndSearch);

  if (flowsToDisplay.length === 0) {
    tableBody.innerHTML = `<tr class="empty-row"><td colspan="6"><div class="empty-state-box">No matching network flow records found.</div></td></tr>`;
    return;
  }

  flowsToDisplay.forEach((flow) => {
    tableBody.appendChild(createRowElement(flow));
  });
}

// ── Backend Connection Status ──
function markOnline() {
  if (statusEl) {
    statusEl.classList.remove('offline');
    statusEl.classList.add('online');
  }
  if (statusLabel) statusLabel.textContent = 'BACKEND CONNECTED';
}

function markOffline() {
  if (statusEl) {
    statusEl.classList.remove('online');
    statusEl.classList.add('offline');
  }
  if (statusLabel) statusLabel.textContent = 'BACKEND UNAVAILABLE';
}

function updateCaptureStatus(capture) {
  if (!bannerSub || !capture) return;
  const interfaceName = capture.interface || 'configured interface';
  if (capture.state === 'not_started') {
    bannerSub.textContent = 'Packet capture not started. Run python app.py; flask run serves the dashboard only.';
  } else if (capture.state === 'starting') {
    bannerSub.textContent = `Starting packet capture on ${interfaceName}...`;
  } else if (capture.state === 'listening' && capture.flows_received === 0) {
    bannerSub.textContent = `Listening on ${interfaceName}; no flows received yet. Capture sees this PC’s traffic, not the phone’s full 5G session.`;
  } else if (capture.state === 'listening') {
    bannerSub.textContent = `Capturing on ${interfaceName} · ${capture.flows_received.toLocaleString()} flows received since startup`;
  } else {
    bannerSub.textContent = capture.message || `Packet capture ${capture.state}`;
  }
}

// Periodic HTTP Sync Fallback (Syncs both database stats & flow records every 1.5s)
async function syncFlowsFromBackend() {
  if (syncInProgress) return;
  syncInProgress = true;
  try {
    const [statsResponse, flowsResponse, captureResponse] = await Promise.all([
      apiFetch('/api/stats'),
      apiFetch('/api/flows?limit=40'),
      apiFetch('/api/capture-status')
    ]);
    if (!statsResponse.ok || !flowsResponse.ok || !captureResponse.ok) throw new Error('Backend request failed');

    const [data, flowData, capture] = await Promise.all([
      statsResponse.json(), flowsResponse.json(), captureResponse.json()
    ]);
    totalCount = data.total || 0;
    benignCount = data.benign || 0;
    attackCount = data.attack || 0;
    if (data.attack_types) Object.assign(breakdownMap, data.attack_types);
    updateMetricsUI();
    updateCaptureStatus(capture);
    markOnline();

    if (flowData.flows && flowData.flows.length > 0) {
      [...flowData.flows].reverse().forEach((flow) => addFlowToDOM(flow, flowHistoryLoaded));
    }
    flowHistoryLoaded = true;
  } catch (error) {
    markOffline();
  } finally {
    syncInProgress = false;
  }
}

setInterval(syncFlowsFromBackend, 1500);
syncFlowsFromBackend();

// Flows-Per-Second Metric Updater
setInterval(() => {
  const now = Date.now();
  const dt = (now - lastSecTimestamp) / 1000;
  const fps = (flowsLastSec / dt).toFixed(1);
  if (fpsEl) fpsEl.textContent = `${fps} new records / sec`;
  flowsLastSec = 0;
  lastSecTimestamp = now;
}, 1000);

// ── Simulation Controls ──
function sendSimulatedFlow() {
  apiFetch('/api/simulate-flow', { method: 'POST' })
    .then((r) => { if (!r.ok) throw new Error('Demo stream is unavailable'); return r.json(); })
    .then((flow) => addFlowToDOM(flow))
    .catch(() => {});
}

function toggleSimulation() {
  if (simulationTimer) {
    clearInterval(simulationTimer);
    simulationTimer = null;
    if (btnSimulate) {
      btnSimulate.classList.remove('active');
      btnSimulate.textContent = 'Demo Stream';
    }
  } else {
    sendSimulatedFlow();
    simulationTimer = setInterval(sendSimulatedFlow, 750);
    if (btnSimulate) {
      btnSimulate.classList.add('active');
      btnSimulate.textContent = 'Pause Demo';
    }
  }
}

function triggerAttackBurst() {
  for (let i = 0; i < 15; i++) {
    setTimeout(sendSimulatedFlow, i * 110);
  }
}

if (btnSimulate) btnSimulate.addEventListener('click', toggleSimulation);
if (btnBurst) btnBurst.addEventListener('click', triggerAttackBurst);

// ── Filter Controls ──
if (searchInput) {
  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    renderFilteredTable();
  });
}

if (filterAllBtn) {
  filterAllBtn.addEventListener('click', () => {
    currentFilter = 'all';
    filterAllBtn.classList.add('active');
    if (filterAttacksBtn) filterAttacksBtn.classList.remove('active');
    if (filterBenignBtn) filterBenignBtn.classList.remove('active');
    renderFilteredTable();
  });
}

if (filterAttacksBtn) {
  filterAttacksBtn.addEventListener('click', () => {
    currentFilter = 'attacks';
    filterAttacksBtn.classList.add('active');
    if (filterAllBtn) filterAllBtn.classList.remove('active');
    if (filterBenignBtn) filterBenignBtn.classList.remove('active');
    renderFilteredTable();
  });
}

if (filterBenignBtn) {
  filterBenignBtn.addEventListener('click', () => {
    currentFilter = 'benign';
    filterBenignBtn.classList.add('active');
    if (filterAllBtn) filterAllBtn.classList.remove('active');
    if (filterAttacksBtn) filterAttacksBtn.classList.remove('active');
    renderFilteredTable();
  });
}

if (btnClearLog) {
  btnClearLog.addEventListener('click', () => {
    allFlowRecords = [];
    seenFlowKeys.clear();
    if (tableBody) {
      tableBody.innerHTML = '<tr class="empty-row"><td colspan="6"><div class="empty-state-box">Log table cleared by user.</div></td></tr>';
    }
  });
}

// Idle Canvas Animation Tick
setInterval(() => {
  if (pulseData.length === 0) {
    drawPulse();
  }
}, 400);

// Re-draw canvas on theme change
window.addEventListener('themeChanged', () => {
  drawPulse();
});

// ── Dashboard: Ingestion Topology Tab Filter ──
let dashActiveIface = 'all';
const dashTopoTabs = document.querySelectorAll('#dashTopoStrip .topology-tab');

if (dashTopoTabs && dashTopoTabs.length > 0) {
  dashTopoTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      dashTopoTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      dashActiveIface = tab.getAttribute('data-iface') || 'all';

      // Re-render table with the selected interface filter
      const filtered = allFlowRecords.filter(f => {
        if (dashActiveIface === 'all') return true;
        const fi = f.interface || 'unknown';
        return fi === dashActiveIface;
      });

      if (tableBody) {
        tableBody.innerHTML = '';
        if (filtered.length === 0) {
          tableBody.innerHTML = `<tr class="empty-row"><td colspan="7"><div class="empty-state-box">No flows captured on ${dashActiveIface} interface yet.</div></td></tr>`;
        } else {
          filtered.forEach(f => tableBody.appendChild(createRowElement(f)));
        }
      }

    });
  });
}
