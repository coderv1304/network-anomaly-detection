/* ============================================================
   NETSHIELD AI — SOC Sentinel Real-Time Threat Engine
   High-Reliability Dual Transport (WebSocket + HTTP Sync Fallback)
   ============================================================ */

'use strict';

const socket = io({
  transports: ['polling', 'websocket'],
  reconnection: true,
  reconnectionDelay: 1000,
  timeout: 5000,
});

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

// ── Metrics & Threat Index Updater ──
function updateMetricsUI() {
  if (totalEl) totalEl.textContent = totalCount.toLocaleString();
  if (benignEl) benignEl.textContent = benignCount.toLocaleString();
  if (attackEl) attackEl.textContent = attackCount.toLocaleString();

  const totalSafe = Math.max(1, totalCount);
  const benignPct = ((benignCount / totalSafe) * 100).toFixed(1);
  const attackPct = ((attackCount / totalSafe) * 100).toFixed(1);

  if (benignPctEl) benignPctEl.textContent = `${benignPct}% normal network activity`;
  if (attackPctEl) attackPctEl.textContent = `${attackPct}% intrusion attempts`;

  // Calculate Threat Index Gauge (0-100)
  const threatIndex = Math.min(100, Math.round((attackCount / totalSafe) * 100));
  if (threatIndexVal) threatIndexVal.textContent = `${threatIndex} / 100`;
  if (threatGaugeFill) threatGaugeFill.style.width = `${threatIndex}%`;

  // Update Status Banner
  if (systemBanner) {
    if (threatIndex >= 25 || attackCount > 0) {
      systemBanner.className = 'system-banner alert';
      if (bannerTitle) bannerTitle.textContent = `SYSTEM STATUS: ELEVATED THREAT DETECTED (${threatIndex}/100)`;
      if (bannerSub) bannerSub.textContent = `${attackCount} malicious anomalies flagged by Random Forest model`;
    } else {
      systemBanner.className = 'system-banner secure';
      if (bannerTitle) bannerTitle.textContent = 'SYSTEM STATUS: NOMINAL (SECURE)';
      if (bannerSub) bannerSub.textContent = 'Real-time packet sniffing active · 0 threat anomalies detected';
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

  const srcPort = flow.src_port ? `:${flow.src_port}` : '';
  const dstPort = flow.dst_port ? `:${flow.dst_port}` : '';
  const proto = (flow.protocol || 'TCP').toUpperCase();
  const severityBadge = flow.is_attack
    ? '<span class="badge badge-critical">THREAT</span>'
    : '<span class="badge badge-safe">BENIGN</span>';

  row.innerHTML = `
    <td>${timeStr}</td>
    <td class="mono">${flow.src_ip || '192.168.1.x'}${srcPort}</td>
    <td class="mono">${flow.dst_ip || '10.0.0.x'}${dstPort}</td>
    <td><span class="proto-pill">${proto}</span></td>
    <td><strong>${flow.predicted_label || 'BENIGN'}</strong></td>
    <td>${severityBadge}</td>
  `;
  return row;
}

function addFlowToDOM(flow) {
  if (!flow) return;

  const flowKey = (flow.id !== undefined && flow.id !== null)
    ? `id-${flow.id}`
    : `${flow.timestamp}-${flow.src_ip}-${flow.src_port}-${Math.random()}`;

  if (seenFlowKeys.has(flowKey)) return;
  seenFlowKeys.add(flowKey);

  flowsLastSec++;

  totalCount++;
  if (flow.is_attack) attackCount++;
  else benignCount++;

  const labelKey = flow.predicted_label || 'BENIGN';
  breakdownMap[labelKey] = (breakdownMap[labelKey] || 0) + 1;

  allFlowRecords.unshift(flow);
  if (allFlowRecords.length > MAX_ROWS) {
    const popped = allFlowRecords.pop();
    if (popped && popped.id) seenFlowKeys.delete(`id-${popped.id}`);
  }

  updateMetricsUI();
  pushPulse(Boolean(flow.is_attack));

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

// ── Socket & HTTP Polling Dual Engine ──
function markOnline() {
  if (statusEl) {
    statusEl.classList.remove('offline');
    statusEl.classList.add('online');
  }
  if (statusLabel) statusLabel.textContent = 'LIVE SENTINEL CONNECTED';
}

function markOffline() {
  if (statusEl) {
    statusEl.classList.remove('online');
    statusEl.classList.add('offline');
  }
  if (statusLabel) statusLabel.textContent = 'RECONNECTING...';
}

socket.on('connect', markOnline);
socket.on('reconnect', markOnline);
socket.on('disconnect', markOffline);
socket.on('connect_error', markOnline);

socket.on('new_flow', (flow) => {
  addFlowToDOM(flow);
});

// Periodic HTTP Sync Fallback (Syncs both database stats & flow records every 1.5s)
function syncFlowsFromBackend() {
  fetch('/api/stats')
    .then((r) => r.json())
    .then((data) => {
      if (data) {
        if (data.total > totalCount) totalCount = data.total;
        if (data.benign > benignCount) benignCount = data.benign;
        if (data.attack > attackCount) attackCount = data.attack;
        if (data.attack_types) {
          Object.assign(breakdownMap, data.attack_types);
        }
        updateMetricsUI();
      }
    })
    .catch(() => {});

  fetch('/api/flows?limit=40')
    .then((r) => r.json())
    .then((data) => {
      if (data && data.flows && data.flows.length > 0) {
        const flows = [...data.flows].reverse();
        flows.forEach((f) => addFlowToDOM(f));
      }
    })
    .catch(() => {});
}

setInterval(syncFlowsFromBackend, 1500);

// Flows-Per-Second Metric Updater
setInterval(() => {
  const now = Date.now();
  const dt = (now - lastSecTimestamp) / 1000;
  const fps = (flowsLastSec / dt).toFixed(1);
  if (fpsEl) fpsEl.textContent = `${fps} flows / sec`;
  flowsLastSec = 0;
  lastSecTimestamp = now;
}, 1000);

// ── Simulation Controls ──
function sendSimulatedFlow() {
  fetch('/api/simulate-flow', { method: 'POST' })
    .then((r) => r.json())
    .then((flow) => addFlowToDOM(flow))
    .catch(() => {});
}

function toggleSimulation() {
  if (simulationTimer) {
    clearInterval(simulationTimer);
    simulationTimer = null;
    if (btnSimulate) {
      btnSimulate.classList.remove('active');
      btnSimulate.textContent = '⚡ Auto Stream';
    }
  } else {
    sendSimulatedFlow();
    simulationTimer = setInterval(sendSimulatedFlow, 750);
    if (btnSimulate) {
      btnSimulate.classList.add('active');
      btnSimulate.textContent = '⏸ Pause Stream';
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

// Initial Sync & Auto Simulation trigger if empty
syncFlowsFromBackend();
setTimeout(() => {
  if (totalCount === 0) {
    triggerAttackBurst();
  }
}, 800);

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