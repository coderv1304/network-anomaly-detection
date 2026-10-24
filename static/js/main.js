/* ============================================================
   NETSHIELD AI — Enterprise SOC Batch Traffic & Telemetry Engine
   Architectural Pillars:
   1. Compact Operational Hierarchy & Telemetry Header
   2. SHAP Explainability & Flow Inspector SideSheet Drawer
   3. Table Ergonomics, Cross-Filtering & Custom Density
   4. Multi-Stage Pipeline Progress UX
   5. Power-User Command Palette (Cmd+K / Ctrl+K)
   ============================================================ */

'use strict';

// ── Threat Severity Classifier & Rules ──
const SEVERITY_RULES = {
  'BENIGN':                          { label: 'Safe',     cls: 'badge-safe' },
  'DDoS':                            { label: 'Critical', cls: 'badge-critical' },
  'DoS slowloris':                   { label: 'Critical', cls: 'badge-critical' },
  'DoS Slowhttptest':                { label: 'Critical', cls: 'badge-critical' },
  'DoS Hulk':                        { label: 'Critical', cls: 'badge-critical' },
  'DoS GoldenEye':                   { label: 'Critical', cls: 'badge-critical' },
  'Heartbleed':                      { label: 'Critical', cls: 'badge-critical' },
  'Infiltration':                    { label: 'Critical', cls: 'badge-critical' },
  'Bot':                             { label: 'Critical', cls: 'badge-critical' },
  'Web Attack – Brute Force':        { label: 'High',     cls: 'badge-high' },
  'Web Attack – XSS':                { label: 'High',     cls: 'badge-high' },
  'Web Attack – Sql Injection':      { label: 'High',     cls: 'badge-high' },
  'FTP-Patator':                     { label: 'High',     cls: 'badge-high' },
  'SSH-Patator':                     { label: 'High',     cls: 'badge-high' },
  'PortScan':                        { label: 'Medium',   cls: 'badge-medium' },
};

function getSeverity(type) {
  if (SEVERITY_RULES[type]) return SEVERITY_RULES[type];
  if (type.includes('DoS') || type.includes('DDoS')) return { label: 'Critical', cls: 'badge-critical' };
  if (type.includes('Web Attack') || type.includes('Patator')) return { label: 'High', cls: 'badge-high' };
  if (type === 'BENIGN') return { label: 'Safe', cls: 'badge-safe' };
  return { label: 'Medium', cls: 'badge-medium' };
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
const drawerSlaBadge      = document.getElementById('drawerSlaBadge');
const drawerAnalystName   = document.getElementById('drawerAnalystName');
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
    tag: 'ALL INGRESS VECTORS',
    desc: 'Monitoring enterprise ingress across all physical & virtual taps simultaneously'
  },
  'eth0': {
    tag: 'ETH0 · 10GbE CORE BACKBONE',
    desc: 'SPAN/TAP mirror on Core Catalyst 9500 (VLAN 10, 20, 50) · Full Duplex 10 Gbps'
  },
  'wlan0': {
    tag: 'WLAN0 · 802.11AX AIRSPACE',
    desc: 'Corp-Secure-WPA3 Wi-Fi Controller · 0 Rogue APs / Evil Twins detected'
  },
  'wwan0': {
    tag: 'WWAN0 · 5G REMOTE EDGE',
    desc: 'Verizon Private 5G NR Gateway · SIM auth valid · Latency: 18ms'
  },
  'wg0': {
    tag: 'WG0 · ZERO-TRUST VPC MESH',
    desc: 'WireGuard / Cilium eBPF mesh overlay · Mutual TLS (SPIFFE ID verified)'
  }
};

// State Store
let donutChart = null;
let barChart   = null;
let currentResultsPayload = null;
let currentSampleFlows = [];
let activeChartFilter = null; // e.g., 'PortScan' or 'Threats'
let activeTopologyFilter = 'all'; // 'all', 'eth0', 'wlan0', 'wwan0', 'wg0'
let activeInspectedFlow = null;
let slaTimer = null;

// ============================================================
// 1. TOAST NOTIFICATION SYSTEM
// ============================================================
function showToast(message, type = 'info') {
  if (!toastContainer) return;
  const toast = document.createElement('div');
  toast.className = `toast-message ${type === 'success' ? 'toast-success' : type === 'danger' ? 'toast-danger' : ''}`;
  
  const icon = type === 'success' ? '✓' : type === 'danger' ? '🛡' : 'ℹ';
  toast.innerHTML = `<span style="font-weight:700;">${icon}</span> <span>${message}</span>`;
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
    uploadFilename.textContent = `📦 ${file.name}  ·  ${typeLabel}  ·  ${(file.size / 1024).toFixed(0)} KB`;
    uploadFilename.classList.add('show');
  }
  if (analyzeBtn) analyzeBtn.disabled = false;
  showToast(`Ingested: ${typeLabel} — ${file.name}`, 'info');
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
    const fetchPromise = fetch(url, options);

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
      uploadFilename.textContent = '⚡ Built-in Test Dataset (1,500 CIC-IDS-2017 Flows)';
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
    btnText.textContent = 'Execute AI Classification';
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
    elBenignPct.textContent = total > 0 ? `${((benign / total) * 100).toFixed(1)}% safe traffic` : '0% safe';
  }
  if (elAttackPct) {
    elAttackPct.textContent = total > 0 ? `${((attack / total) * 100).toFixed(1)}% anomaly threats` : '0% anomalies';
  }
  if (elTableCount) {
    elTableCount.textContent = `${classCount} vector types identified`;
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
      labels: ['Benign Traffic', 'Malicious Threats'],
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
            font: { family: 'Inter', size: 12 },
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
              return ` ${ctx.parsed.x.toLocaleString()} flows (${pct}%) — Click to filter table`;
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
          ticks: { color: textColor, font: { family: 'Inter', size: 11 } },
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
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px;">No attack vectors identified.</td></tr>';
    return;
  }

  sorted.forEach(([type, count]) => {
    const pct = total > 0 ? ((count / total) * 100).toFixed(2) : '0.00';
    const sev = getSeverity(type);
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.title = `Click to filter flows for ${type}`;
    tr.innerHTML = `
      <td><strong>${type}</strong></td>
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
    const ifaceKey = (flow.interface || 'eth0').toLowerCase();
    const ifaceBadge = `<span class="vector-chip ${ifaceKey}">${ifaceKey}</span>`;

    // CVSS severity badge
    const cvss = flow.incident?.cvss || (flow.is_attack ? 'CVSS 8.4 · High' : 'CVSS 0.0 · Benign');
    let cvssCls = 'cvss-benign';
    if (cvss.includes('Critical') || cvss.includes('9.')) cvssCls = 'cvss-critical';
    else if (cvss.includes('High') || cvss.includes('7.')) cvssCls = 'cvss-high';
    else if (cvss.includes('Medium') || cvss.includes('5.')) cvssCls = 'cvss-medium';

    // Threat intelligence enrichment
    const asn = flow.threat_intel?.asn || 'Internal Enterprise Subnet';
    const geo = flow.threat_intel?.geo || 'US 🇺🇸 Local VPC';
    const geoParts = geo.split(' ');
    const flagIcon = geoParts[1] || '🌐';

    // Incident triage status
    const status = flow.incident?.status || (flow.is_attack ? 'New' : 'Verified');
    const statusColor = status === 'New' ? 'var(--red)' : status === 'Investigating' ? 'var(--orange)' : 'var(--green)';

    tr.innerHTML = `
      <td class="mono">#${flow.id}</td>
      <td>${ifaceBadge}</td>
      <td>
        <div class="host-cell">
          <span class="host-ip ip-clickable" data-ip="${flow.src_ip}" title="Click to copy IP">${flow.src_ip}:${flow.src_port}</span>
          <span class="asn-sub"><span class="geo-flag">${flagIcon}</span> ${asn}</span>
        </div>
      </td>
      <td class="mono"><span class="ip-clickable" data-ip="${flow.dst_ip}" title="Click to copy IP">${flow.dst_ip}</span>:${flow.dst_port}</td>
      <td><span class="live-pill" style="font-size:0.65rem;">${flow.protocol}</span></td>
      <td>
        <div style="display:flex; flex-direction:column; gap:3px;">
          <strong>${flow.predicted_label}</strong>
          <span class="cvss-pill ${cvssCls}">${cvss.split('·')[0].trim()}</span>
        </div>
      </td>
      <td>
        <span class="badge" style="background:transparent; border:1px solid ${statusColor}; color:${statusColor}; font-size:0.68rem;">
          ● ${status}
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
  if (drawerMitre) drawerMitre.textContent = flow.mitre || 'MITRE ATT&CK: T1046 · Network Service Discovery';

  if (drawerThreatBadge) {
    const sev = getSeverity(flow.predicted_label);
    drawerThreatBadge.className = `badge ${sev.cls}`;
    drawerThreatBadge.textContent = `${flow.predicted_label} (${sev.label})`;
  }

  // Fill CVSS Rating Pill
  if (drawerCvssBadge) {
    const cvss = flow.incident?.cvss || (flow.is_attack ? 'CVSS 8.4' : 'CVSS 0.0');
    let cvssCls = 'cvss-benign';
    if (cvss.includes('Critical') || cvss.includes('9.')) cvssCls = 'cvss-critical';
    else if (cvss.includes('High') || cvss.includes('7.')) cvssCls = 'cvss-high';
    else if (cvss.includes('Medium') || cvss.includes('5.')) cvssCls = 'cvss-medium';
    drawerCvssBadge.className = `cvss-pill ${cvssCls}`;
    drawerCvssBadge.textContent = cvss;
  }

  // Fill Incident Lifecycle Triage Bar
  if (drawerTriageStatus) {
    drawerTriageStatus.value = flow.incident?.status || (flow.is_attack ? 'New' : 'Mitigated');
  }
  if (drawerSlaBadge) {
    updateSlaCountdown();
    if (slaTimer) clearInterval(slaTimer);
    slaTimer = window.setInterval(updateSlaCountdown, 1000);
  }
  if (drawerAnalystName) {
    drawerAnalystName.textContent = flow.incident?.analyst || 'SecOps Tier-2 (On-Call)';
  }

  // Fill Threat Intelligence Attribution
  if (drawerThreatAsn) drawerThreatAsn.textContent = flow.threat_intel?.asn || 'Internal Enterprise Fabric';
  if (drawerThreatGeo) drawerThreatGeo.textContent = flow.threat_intel?.geo || 'US 🇺🇸 Local VPC Subnet';
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
  if (drawerThreatTag) drawerThreatTag.textContent = flow.threat_intel?.tag || (flow.is_attack ? 'Automated Attack Tool' : 'Legitimate Traffic');

  // Fill Layer-2 Ingress Hardware Telemetry
  if (drawerL2Interface) drawerL2Interface.textContent = flow.interface || 'eth0';
  if (drawerL2Vector) drawerL2Vector.textContent = flow.l2_meta?.vector || 'Ethernet 802.3';
  if (drawerL2Port) {
    drawerL2Port.textContent = flow.l2_meta?.switch_port || flow.l2_meta?.ssid || flow.l2_meta?.apn || flow.l2_meta?.peer || 'Trunk Gi0/1 (VLAN 10)';
  }
  if (drawerL2Signal) {
    drawerL2Signal.textContent = flow.l2_meta?.duplex || flow.l2_meta?.rssi || flow.l2_meta?.rsrp || flow.l2_meta?.mtls || 'Full Duplex 10 Gbps';
  }
  if (drawerL2Health) {
    drawerL2Health.textContent = flow.l2_meta?.l2_health || 'ARP Table Clean · 0 Broadcast Storms';
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
    const shapItems = flow.shap || [
      { feature: 'Flow Packets/s', value: 'Elevated', impact: 42, direction: '+' },
      { feature: 'Subflow Fwd Bytes', value: 'High', impact: 26, direction: '+' },
      { feature: 'Flow Duration', value: 'Short Burst', impact: 18, direction: '+' },
      { feature: 'SYN Flag Count', value: '1', impact: 9, direction: '+' },
      { feature: 'RST Anomaly', value: '0', impact: 5, direction: '+' },
    ];

    shapItems.forEach(item => {
      const row = document.createElement('div');
      row.className = 'shap-row';
      const isPos = item.direction === '+';
      row.innerHTML = `
        <div class="shap-row-header">
          <span class="shap-feat-name">${item.feature} (${item.value})</span>
          <span class="shap-feat-val" style="color:${isPos ? 'var(--red)' : 'var(--green)'}; font-weight:700;">
            ${item.direction}${item.impact}% contribution
          </span>
        </div>
        <div class="shap-bar-track">
          <div class="shap-bar-fill ${isPos ? 'positive' : 'negative'}" style="width: ${item.impact}%;"></div>
        </div>
      `;
      drawerShapList.appendChild(row);
    });
  }

  // Slide open drawer
  if (flowDrawer) {
    flowDrawer.classList.add('open');
    flowDrawer.setAttribute('aria-hidden', 'false');
  }
  if (drawerBackdrop) drawerBackdrop.classList.add('open');
}

function updateSlaCountdown() {
  if (!drawerSlaBadge || !activeInspectedFlow) return;
  const incident = activeInspectedFlow.incident || {};
  const deadline = Number(incident.sla_deadline);
  if (!Number.isFinite(deadline)) {
    drawerSlaBadge.textContent = 'No active SLA';
    drawerSlaBadge.classList.remove('sla-breached');
    return;
  }

  const isActive = ['New', 'Investigating'].includes(incident.status);
  const remaining = Math.max(0, Math.ceil(
    isActive || !Number.isFinite(incident.sla_remaining_at_stop)
      ? deadline - Date.now() / 1000
      : incident.sla_remaining_at_stop
  ));
  const minutes = String(Math.floor(remaining / 60)).padStart(2, '0');
  const seconds = String(remaining % 60).padStart(2, '0');
  drawerSlaBadge.textContent = remaining === 0
    ? 'SLA BREACHED · 00:00'
    : `${isActive ? 'SLA' : 'SLA stopped'} · ${minutes}:${seconds}`;
  drawerSlaBadge.classList.toggle('sla-breached', remaining === 0);
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
  if (slaTimer) clearInterval(slaTimer);
  slaTimer = null;
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
    if (activeInspectedFlow.incident) {
      const incident = activeInspectedFlow.incident;
      if (['New', 'Investigating'].includes(incident.status)) {
        incident.sla_remaining_at_stop = Math.max(0, Number(incident.sla_deadline) - Date.now() / 1000);
      }
      incident.status = 'Suppressed';
      updateSlaCountdown();
    }
    filterFlowTable();
    showToast(`Flow #${activeInspectedFlow.id} marked as Suppressed / False Positive`, 'info');
  });
}

// Drawer Triage Status Change Dropdown
if (drawerTriageStatus) {
  drawerTriageStatus.addEventListener('change', () => {
    if (!activeInspectedFlow) return;
    const newStatus = drawerTriageStatus.value;
    if (!activeInspectedFlow.incident) activeInspectedFlow.incident = {};
    const incident = activeInspectedFlow.incident;
    if (['New', 'Investigating'].includes(incident.status) && !['New', 'Investigating'].includes(newStatus)) {
      incident.sla_remaining_at_stop = Math.max(0, Number(incident.sla_deadline) - Date.now() / 1000);
    } else if (['New', 'Investigating'].includes(newStatus)) {
      if (!['New', 'Investigating'].includes(incident.status) && Number.isFinite(incident.sla_remaining_at_stop)) {
        incident.sla_deadline = Date.now() / 1000 + incident.sla_remaining_at_stop;
      }
      delete incident.sla_remaining_at_stop;
    }
    incident.status = newStatus;
    updateSlaCountdown();
    filterFlowTable();
    showToast(`Incident #${activeInspectedFlow.id} state updated to: ${newStatus}`, 'success');
  });
}

// ============================================================
// AUTOMATED SOAR PLAYBOOK EXECUTION TERMINAL
// ============================================================
function dispatchSoarPlaybook(actionType, commandText, successMsg) {
  if (!activeInspectedFlow || !soarTerminalOutput) return;
  renderSoarTerminal([
    `[DISPATCHING ${actionType.toUpperCase()} PLAYBOOK]`,
    `[EXEC] ${commandText}`,
    `[SIMULATED OK] ${successMsg}`,
    `[AUDIT] Dispatched by SecOps Tier-2 · no external enforcement performed.`
  ]);

  showToast(successMsg, 'danger');
}

async function dispatchMockWebhook(channel) {
  if (!activeInspectedFlow || !soarTerminalOutput) return;
  const flow = activeInspectedFlow;
  const message = `${flow.predicted_label} alert for ${flow.src_ip} → ${flow.dst_ip}:${flow.dst_port}`;
  renderSoarTerminal([`[POST] Mock ${channel} webhook · Flow #${flow.id}`, '[WAIT] Awaiting local simulation response']);
  try {
    const response = await fetch('/api/soar/webhook', {
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
    dispatchSoarPlaybook('iptables', cmd, `Host ${activeInspectedFlow.src_ip} null-routed in kernel netfilter`);
  });
}

if (btnSoarCloudflare) {
  btnSoarCloudflare.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    const cmd = activeInspectedFlow.soar?.waf_cmd || `cloudflare-cli waf rule create --action block --ip ${activeInspectedFlow.src_ip}`;
    dispatchSoarPlaybook('cloudflare', cmd, `Cloudflare Edge WAF block rule synchronized for ${activeInspectedFlow.src_ip}`);
  });
}

if (btnSoarAwsSg) {
  btnSoarAwsSg.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    const cmd = activeInspectedFlow.soar?.aws_sg_cmd || `aws ec2 revoke-security-group-ingress --group-id sg-prod --cidr ${activeInspectedFlow.src_ip}/32`;
    dispatchSoarPlaybook('aws', cmd, `AWS VPC Security Group ingress revoked for CIDR ${activeInspectedFlow.src_ip}/32`);
  });
}

if (btnSoarStix) {
  btnSoarStix.addEventListener('click', () => {
    if (!activeInspectedFlow) return;
    const stixId = activeInspectedFlow.soar?.stix_id || `indicator--${Date.now()}`;
    const cmd = `export_stix_bundle --indicator-id "${stixId}" --threat-pattern "[network-traffic:src_ref.value = '${activeInspectedFlow.src_ip}']"`;
    dispatchSoarPlaybook('stix', cmd, `STIX 2.1 Threat Indicator ${stixId} published to TAXII server`);
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
        <span>${labelText}</span>
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
      matchesVector = (flow.interface || 'eth0').toLowerCase() === activeTopologyFilter.toLowerCase();
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
    iface: 'Global Multi-Vector Ingestion (All Interfaces)',
    link: 'eth0 + wlan0 + wwan0 + wg0 aggregated · 4.34 Gbps total wire rate',
    health: 'ARP Cache Clean · Airspace Monitored · Zero-Trust Active · eBPF Ring Buffers Online'
  },
  'eth0': {
    iface: 'eth0 · Enterprise 10GbE Fiber Backbone',
    link: 'Trunk Gi0/1 (VLAN 10, 20, 50) · Full Duplex 10 Gbps · Cisco Catalyst 9500 SPAN',
    health: 'ARP Cache Clean · MAC Table Stable · 0 Broadcast Storms Detected'
  },
  'wlan0': {
    iface: 'wlan0 · Corporate 802.11ax Wi-Fi 6 Controller',
    link: 'SSID: Corp-Secure-WPA3 · BSSID: 00:14:22:01:FA:0C · RSSI: -58 dBm',
    health: '0 Rogue APs / Evil Twins · 0 Deauth Floods · Airspace Health: CLEAN'
  },
  'wwan0': {
    iface: 'wwan0 · 5G NR Cellular / Remote Edge IoT Gateway',
    link: 'Carrier: Verizon Private 5G · APN: iot.edge.internal · RSRP: -84 dBm · Latency: 18ms',
    health: 'SIM Verified · eNodeB Stable · 0 Abnormal Handoff Events Detected'
  },
  'wg0': {
    iface: 'wg0 · WireGuard Zero-Trust VPN / Kubernetes CNI Mesh',
    link: 'Cilium eBPF Overlay · Mutual TLS (SPIFFE ID enforced) · 8 Active Peers',
    health: 'Zero-Trust Policy Enforced · 0 Lateral Movement Alerts · SPIRE Attestation Valid'
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