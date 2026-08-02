/* ── main.js — NetShield AI Upload & Results ── */

'use strict';

// ── Severity classification ──────────────────────────────────────────────
const SEVERITY = {
  'BENIGN':                      { label: 'Safe',     cls: 'badge-safe' },
  'DDoS':                        { label: 'Critical', cls: 'badge-critical' },
  'DoS slowloris':               { label: 'Critical', cls: 'badge-critical' },
  'DoS Slowhttptest':            { label: 'Critical', cls: 'badge-critical' },
  'DoS Hulk':                    { label: 'Critical', cls: 'badge-critical' },
  'DoS GoldenEye':               { label: 'Critical', cls: 'badge-critical' },
  'Heartbleed':                  { label: 'Critical', cls: 'badge-critical' },
  'Infiltration':                { label: 'Critical', cls: 'badge-critical' },
  'Bot':                         { label: 'Critical', cls: 'badge-critical' },
  'Web Attack \u2013 Brute Force':   { label: 'High',     cls: 'badge-high' },
  'Web Attack \u2013 XSS':           { label: 'High',     cls: 'badge-high' },
  'Web Attack \u2013 Sql Injection': { label: 'High',     cls: 'badge-high' },
  'FTP-Patator':                 { label: 'High',     cls: 'badge-high' },
  'SSH-Patator':                 { label: 'High',     cls: 'badge-high' },
  'PortScan':                    { label: 'Medium',   cls: 'badge-medium' },
};

function getSeverity(type) {
  if (SEVERITY[type]) return SEVERITY[type];
  if (type.startsWith('DoS') || type.startsWith('DDoS')) return { label: 'Critical', cls: 'badge-critical' };
  if (type.startsWith('Web Attack')) return { label: 'High', cls: 'badge-high' };
  return { label: 'Medium', cls: 'badge-medium' };
}

// ── DOM refs ─────────────────────────────────────────────────────────────
const dropZone      = document.getElementById('dropZone');
const fileInput     = document.getElementById('fileInput');
const analyzeBtn    = document.getElementById('analyzeBtn');
const btnText       = document.getElementById('btnText');
const btnIcon       = document.getElementById('btnIcon');
const errorCard     = document.getElementById('errorCard');
const errorText     = document.getElementById('errorText');
const resultsSection= document.getElementById('resultsSection');
const uploadFilename= document.getElementById('uploadFilename');

let donutChart = null;
let barChart   = null;

// ── File selection ────────────────────────────────────────────────────────
fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];
  if (file) selectFile(file);
});

function selectFile(file) {
  hideError();
  const MAX = 16 * 1024 * 1024;
  if (!file.name.toLowerCase().endsWith('.csv')) {
    return showError('Invalid file type. Please upload a .csv file.');
  }
  if (file.size > MAX) {
    return showError(`File too large (${(file.size/1024/1024).toFixed(1)} MB). Maximum is 16 MB.`);
  }
  uploadFilename.textContent = '📎 ' + file.name;
  uploadFilename.classList.add('show');
  analyzeBtn.disabled = false;
}

// ── Drag & drop ───────────────────────────────────────────────────────────
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) {
    // Create a DataTransfer to assign to input
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;
    selectFile(file);
  }
});

// ── Form submit ───────────────────────────────────────────────────────────
analyzeBtn.addEventListener('click', async () => {
  const file = fileInput.files[0];
  if (!file) return;

  setLoading(true);
  hideError();
  resultsSection.classList.remove('show');

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res  = await fetch('/predict', { method: 'POST', body: formData });
    const data = await res.json();

    if (!res.ok || data.error) {
      showError(data.error || `Server error (HTTP ${res.status})`);
    } else {
      renderResults(data);
    }
  } catch (err) {
    showError('Network error — ensure the Flask server is running on localhost:5000.');
  } finally {
    setLoading(false);
  }
});

// ── Loading state ─────────────────────────────────────────────────────────
function setLoading(on) {
  analyzeBtn.disabled = on;
  if (on) {
    btnIcon.outerHTML = '<div class="spinner" id="btnIcon"></div>';
    btnText.textContent = 'Analyzing…';
  } else {
    document.querySelector('.spinner, #btnIcon').outerHTML =
      `<svg id="btnIcon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>`;
    btnText.textContent = 'Analyze Traffic';
  }
}

// ── Error helpers ─────────────────────────────────────────────────────────
function showError(msg) {
  errorText.textContent = msg;
  errorCard.classList.add('show');
  errorCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function hideError() { errorCard.classList.remove('show'); }

// ── Render results ────────────────────────────────────────────────────────
function renderResults(data) {
  const { total, benign, attack, attack_types } = data;

  // Stat cards
  document.getElementById('statTotal').textContent  = total.toLocaleString();
  document.getElementById('statBenign').textContent = benign.toLocaleString();
  document.getElementById('statAttack').textContent = attack.toLocaleString();
  document.getElementById('statBenignPct').textContent =
    total > 0 ? `${((benign/total)*100).toFixed(1)}% of total` : 'Safe traffic';
  document.getElementById('statAttackPct').textContent =
    total > 0 ? `${((attack/total)*100).toFixed(1)}% of total` : 'Threats detected';

  // Charts
  renderDonut(benign, attack);
  renderBar(attack_types, total);

  // Table
  renderTable(attack_types, total);

  // Show
  resultsSection.classList.add('show');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── Donut chart ───────────────────────────────────────────────────────────
function renderDonut(benign, attack) {
  if (donutChart) donutChart.destroy();
  const ctx = document.getElementById('donutChart').getContext('2d');
  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Benign', 'Attacks'],
      datasets: [{
        data: [benign, attack],
        backgroundColor: ['rgba(46,213,115,0.85)', 'rgba(255,71,87,0.85)'],
        borderColor: ['#2ed573', '#ff4757'],
        borderWidth: 2,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: document.documentElement.getAttribute('data-theme') === 'light' ? '#475569' : '#bbc9cf', font: { family: 'Inter', size: 12 }, padding: 16, boxWidth: 12, boxHeight: 12 },
        },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed.toLocaleString()}` } },
      },
    },
  });
}

// ── Bar chart ─────────────────────────────────────────────────────────────
function renderBar(attack_types, total) {
  if (barChart) barChart.destroy();

  // Sort by count descending, exclude benign
  const entries = Object.entries(attack_types)
    .sort((a, b) => b[1] - a[1]);

  const labels = entries.map(([k]) => k);
  const values = entries.map(([, v]) => v);
  const colors = labels.map(l =>
    l === 'BENIGN' ? 'rgba(46,213,115,0.85)' : 'rgba(255,71,87,0.85)'
  );
  const borders = labels.map(l =>
    l === 'BENIGN' ? '#2ed573' : '#ff4757'
  );

  const ctx = document.getElementById('barChart').getContext('2d');
  barChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Count',
        data: values,
        backgroundColor: colors,
        borderColor: borders,
        borderWidth: 1.5,
        borderRadius: 4,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => {
              const pct = total > 0 ? ((ctx.parsed.x/total)*100).toFixed(1) : '0';
              return ` ${ctx.parsed.x.toLocaleString()} (${pct}%)`;
            },
          },
        },
      },
      scales: {
        x: {
          ticks: { color: document.documentElement.getAttribute('data-theme') === 'light' ? '#475569' : '#bbc9cf', font: { family: 'JetBrains Mono', size: 11 } },
          grid: { color: document.documentElement.getAttribute('data-theme') === 'light' ? 'rgba(203,213,225,0.8)' : 'rgba(60,73,78,0.4)' },
          border: { color: document.documentElement.getAttribute('data-theme') === 'light' ? 'rgba(203,213,225,1)' : 'rgba(60,73,78,0.6)' },
        },
        y: {
          ticks: { color: document.documentElement.getAttribute('data-theme') === 'light' ? '#0f172a' : '#dfe2f3', font: { family: 'Inter', size: 11 }, maxRotation: 0 },
          grid: { display: false },
          border: { display: false },
        },
      },
    },
  });
}

// ── Attack table ──────────────────────────────────────────────────────────
function renderTable(attack_types, total) {
  const tbody = document.getElementById('attackTableBody');
  tbody.innerHTML = '';

  const sorted = Object.entries(attack_types).sort((a, b) => b[1] - a[1]);

  sorted.forEach(([type, count]) => {
    const pct = total > 0 ? ((count / total) * 100).toFixed(2) : '0.00';
    const sev = getSeverity(type);
    const tr  = document.createElement('tr');
    tr.innerHTML = `
      <td>${type}</td>
      <td class="mono">${count.toLocaleString()}</td>
      <td class="mono">${pct}%</td>
      <td><span class="badge ${sev.cls}">${sev.label}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// ── Theme toggle chart update ─────────────────────────────────────────────
window.addEventListener('themeChanged', () => {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const textColor = isLight ? '#475569' : '#bbc9cf';
  const yTextColor = isLight ? '#0f172a' : '#dfe2f3';
  const gridColor = isLight ? 'rgba(203,213,225,0.8)' : 'rgba(60,73,78,0.4)';
  const borderColor = isLight ? 'rgba(203,213,225,1)' : 'rgba(60,73,78,0.6)';

  if (donutChart) {
    donutChart.options.plugins.legend.labels.color = textColor;
    donutChart.update();
  }
  if (barChart) {
    barChart.options.scales.x.ticks.color = textColor;
    barChart.options.scales.x.grid.color = gridColor;
    barChart.options.scales.x.border.color = borderColor;
    barChart.options.scales.y.ticks.color = yTextColor;
    barChart.update();
  }
});