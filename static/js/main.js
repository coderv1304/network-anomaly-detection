/* ============================================================
   NETSHIELD AI — Batch Traffic Classification & Analytics
   ============================================================ */

'use strict';

// ── Threat Severity Classifier ──
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
  'Web Attack \u2013 Brute Force':   { label: 'High',     cls: 'badge-high' },
  'Web Attack \u2013 XSS':           { label: 'High',     cls: 'badge-high' },
  'Web Attack \u2013 Sql Injection': { label: 'High',     cls: 'badge-high' },
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
const dropZone           = document.getElementById('dropZone');
const fileInput          = document.getElementById('fileInput');
const analyzeBtn         = document.getElementById('analyzeBtn');
const btnSampleDemo      = document.getElementById('btnSampleDemo');
const btnText            = document.getElementById('btnText');
const btnIcon            = document.getElementById('btnIcon');
const errorCard          = document.getElementById('errorCard');
const errorText          = document.getElementById('errorText');
const resultsSection     = document.getElementById('resultsSection');
const uploadFilename     = document.getElementById('uploadFilename');
const flowSearchInput    = document.getElementById('flowSearchInput');
const flowFilterSelect   = document.getElementById('flowFilterSelect');

let donutChart = null;
let barChart   = null;
let currentSampleFlows = [];

// ── File Selection Handlers ──
if (fileInput) {
  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (file) selectFile(file);
  });
}

function selectFile(file) {
  hideError();
  const MAX_SIZE = 50 * 1024 * 1024; // 50MB
  if (!file.name.toLowerCase().endsWith('.csv')) {
    return showError('Invalid file format. Please upload a .csv file.');
  }
  if (file.size > MAX_SIZE) {
    return showError(`File size exceeds 50 MB limit (${(file.size / (1024 * 1024)).toFixed(1)} MB).`);
  }
  if (uploadFilename) {
    uploadFilename.textContent = `📎 ${file.name} (${(file.size / 1024).toFixed(0)} KB)`;
    uploadFilename.classList.add('show');
  }
  if (analyzeBtn) analyzeBtn.disabled = false;
}

// ── Drag & Drop Events ──
if (dropZone) {
  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
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

// ── Analyze Button Click ──
if (analyzeBtn) {
  analyzeBtn.addEventListener('click', async () => {
    const file = fileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    await executePrediction('/predict', { method: 'POST', body: formData });
  });
}

// ── Quick Demo Sample Button ──
if (btnSampleDemo) {
  btnSampleDemo.addEventListener('click', async () => {
    if (uploadFilename) {
      uploadFilename.textContent = '⚡ Built-in Test Dataset (CIC-IDS-2017 Sample)';
      uploadFilename.classList.add('show');
    }
    await executePrediction('/predict?sample=true', { method: 'POST' });
  });
}

// ── Prediction Executor ──
async function executePrediction(url, options) {
  setLoading(true);
  hideError();
  if (resultsSection) resultsSection.classList.remove('show');

  try {
    const res = await fetch(url, options);
    const data = await res.json();

    if (!res.ok || data.error) {
      showError(data.error || `Server returned error status ${res.status}`);
    } else {
      renderResults(data);
    }
  } catch (err) {
    showError(`Network connection failure: ${err.message || 'Ensure backend server is running.'}`);
  } finally {
    setLoading(false);
  }
}

// ── Loading State ──
function setLoading(loading) {
  if (!analyzeBtn) return;
  analyzeBtn.disabled = loading;
  if (loading) {
    btnIcon.innerHTML = '<div class="spinner"></div>';
    btnText.textContent = 'Running Machine Learning Classification...';
  } else {
    btnIcon.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>`;
    btnText.textContent = 'Execute AI Classification';
  }
}

// ── Error Helpers ──
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

// ── Render Results Payload ──
function renderResults(data) {
  const { total, benign, attack, attack_types, sample_flows } = data;

  // Stat KPI cards
  const elTotal = document.getElementById('statTotal');
  const elBenign = document.getElementById('statBenign');
  const elAttack = document.getElementById('statAttack');
  const elClasses = document.getElementById('statClassesCount');
  const elBenignPct = document.getElementById('statBenignPct');
  const elAttackPct = document.getElementById('statAttackPct');
  const elTableCount = document.getElementById('tableCountBadge');

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
    elTableCount.textContent = `${classCount} vector types detected`;
  }

  // Render Charts
  renderDonutChart(benign, attack);
  renderBarChart(attack_types, total);

  // Render Tables
  renderAttackTable(attack_types, total);

  currentSampleFlows = sample_flows || [];
  renderFlowSamples(currentSampleFlows);

  // Reveal results section
  if (resultsSection) {
    resultsSection.classList.add('show');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// ── Donut Chart ──
function renderDonutChart(benign, attack) {
  if (donutChart) donutChart.destroy();
  const canvas = document.getElementById('donutChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const legendColor = isLight ? '#475569' : '#a3b2cf';

  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Benign Traffic', 'Malicious Threats'],
      datasets: [{
        data: [benign, attack],
        backgroundColor: ['rgba(46, 213, 115, 0.85)', 'rgba(255, 71, 87, 0.85)'],
        borderColor: ['#2ed573', '#ff4757'],
        borderWidth: 2,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: legendColor,
            font: { family: 'Inter', size: 12 },
            padding: 18,
            usePointStyle: true
          }
        },
        tooltip: {
          callbacks: {
            label: (context) => ` ${context.label}: ${context.parsed.toLocaleString()} flows`
          }
        }
      }
    }
  });
}

// ── Bar Chart ──
function renderBarChart(attackTypes, total) {
  if (barChart) barChart.destroy();
  const canvas = document.getElementById('barChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const sorted = Object.entries(attackTypes || {}).sort((a, b) => b[1] - a[1]);
  const labels = sorted.map(([k]) => k);
  const values = sorted.map(([, v]) => v);

  const colors = labels.map(l => l === 'BENIGN' ? 'rgba(46, 213, 115, 0.85)' : 'rgba(255, 71, 87, 0.85)');
  const borders = labels.map(l => l === 'BENIGN' ? '#2ed573' : '#ff4757');

  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const textColor = isLight ? '#475569' : '#a3b2cf';
  const gridColor = isLight ? 'rgba(212, 220, 235, 0.6)' : 'rgba(41, 52, 78, 0.5)';

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
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (context) => {
              const pct = total > 0 ? ((context.parsed.x / total) * 100).toFixed(1) : '0';
              return ` ${context.parsed.x.toLocaleString()} flows (${pct}%)`;
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

// ── Attack Vector Table ──
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
    tr.innerHTML = `
      <td><strong>${type}</strong></td>
      <td class="mono">${count.toLocaleString()}</td>
      <td class="mono">${pct}%</td>
      <td><span class="badge ${sev.cls}">${sev.label}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// ── Flow Samples Log Table ──
function renderFlowSamples(flows) {
  const tbody = document.getElementById('flowSampleTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (!flows || flows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px;">No flow sample records available.</td></tr>';
    return;
  }

  flows.forEach((flow) => {
    const tr = document.createElement('tr');
    const statusBadge = flow.is_attack
      ? '<span class="badge badge-critical">Threat Flagged</span>'
      : '<span class="badge badge-safe">Benign</span>';

    tr.innerHTML = `
      <td class="mono">${flow.id}</td>
      <td class="mono">${flow.src_ip}:${flow.src_port}</td>
      <td class="mono">${flow.dst_ip}:${flow.dst_port}</td>
      <td><span class="proto-pill">${flow.protocol}</span></td>
      <td><strong>${flow.predicted_label}</strong></td>
      <td>${statusBadge}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ── Table Search & Filter Listeners ──
function filterFlowTable() {
  const searchTerm = (flowSearchInput?.value || '').toLowerCase().trim();
  const filterType = flowFilterSelect?.value || 'all';

  const filtered = currentSampleFlows.filter((flow) => {
    const matchesSearch =
      flow.src_ip.toLowerCase().includes(searchTerm) ||
      flow.dst_ip.toLowerCase().includes(searchTerm) ||
      flow.predicted_label.toLowerCase().includes(searchTerm) ||
      flow.protocol.toLowerCase().includes(searchTerm);

    let matchesFilter = true;
    if (filterType === 'attacks') matchesFilter = flow.is_attack;
    else if (filterType === 'benign') matchesFilter = !flow.is_attack;

    return matchesSearch && matchesFilter;
  });

  renderFlowSamples(filtered);
}

if (flowSearchInput) flowSearchInput.addEventListener('input', filterFlowTable);
if (flowFilterSelect) flowFilterSelect.addEventListener('change', filterFlowTable);

// ── Theme Switch Listener for Charts ──
window.addEventListener('themeChanged', () => {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const textColor = isLight ? '#475569' : '#a3b2cf';
  const gridColor = isLight ? 'rgba(212, 220, 235, 0.6)' : 'rgba(41, 52, 78, 0.5)';

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