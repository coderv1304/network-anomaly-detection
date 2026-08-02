/* ── dashboard.js — NetShield AI Live Monitor ── */

'use strict';

// ── Known attack labels from CIC-IDS-2017 ────────────────────────────────
const ALL_LABELS = [
  'BENIGN', 'FTP-Patator', 'SSH-Patator',
  'DoS slowloris', 'DoS Slowhttptest', 'DoS Hulk', 'DoS GoldenEye',
  'Heartbleed', 'Web Attack \u2013 Brute Force', 'Web Attack \u2013 XSS',
  'Web Attack \u2013 Sql Injection', 'Infiltration', 'Bot', 'PortScan', 'DDoS',
];

const ATTACK_LABELS = ALL_LABELS.filter(l => l !== 'BENIGN');

const SEVERITY_MAP = {
  'BENIGN': { label: 'Safe',     cls: 'safe',     dotCls: '' },
  'DDoS':                        { label: 'Critical', cls: 'critical', dotCls: 'critical' },
  'DoS slowloris':               { label: 'Critical', cls: 'critical', dotCls: 'critical' },
  'DoS Slowhttptest':            { label: 'Critical', cls: 'critical', dotCls: 'critical' },
  'DoS Hulk':                    { label: 'Critical', cls: 'critical', dotCls: 'critical' },
  'DoS GoldenEye':               { label: 'Critical', cls: 'critical', dotCls: 'critical' },
  'Heartbleed':                  { label: 'Critical', cls: 'critical', dotCls: 'critical' },
  'Infiltration':                { label: 'Critical', cls: 'critical', dotCls: 'critical' },
  'Bot':                         { label: 'Critical', cls: 'critical', dotCls: 'critical' },
  'FTP-Patator':                 { label: 'High',     cls: 'high',     dotCls: 'high' },
  'SSH-Patator':                 { label: 'High',     cls: 'high',     dotCls: 'high' },
  'Web Attack \u2013 Brute Force':   { label: 'High',     cls: 'high',     dotCls: 'high' },
  'Web Attack \u2013 XSS':           { label: 'High',     cls: 'high',     dotCls: 'high' },
  'Web Attack \u2013 Sql Injection': { label: 'High',     cls: 'high',     dotCls: 'high' },
  'PortScan':                    { label: 'Medium',   cls: 'medium',   dotCls: 'medium' },
};

// ── State ─────────────────────────────────────────────────────────────────
let totalAnalyzed   = 0;
let totalBenign     = 0;
let totalAttack     = 0;
const alerts        = [];   // max 10
let barChart        = null;
let donutChart      = null;
let secondsAgo      = 0;

// ── DOM refs ──────────────────────────────────────────────────────────────
const liveTotalEl   = document.getElementById('liveTotalVal');
const liveBenignEl  = document.getElementById('liveBenignVal');
const liveAttackEl  = document.getElementById('liveAttackVal');
const threatLevelEl = document.getElementById('liveThreatLevel');
const threatSubEl   = document.getElementById('liveThreatSub');
const alertsList    = document.getElementById('alertsList');
const alertsEmpty   = document.getElementById('alertsEmpty');
const alertsCount   = document.getElementById('alertsCount');
const lastUpdated   = document.getElementById('lastUpdated');

// ── Simulate one cycle of data ────────────────────────────────────────────
function simulateCycle() {
  // Realistic CIC-IDS-2017 distribution: ~85% benign
  const batchSize  = Math.floor(Math.random() * 120) + 80;  // 80-200 flows per tick
  const attackRate = Math.random() < 0.6                    // 60% chance of some attack
    ? (Math.random() * 0.25)                                // 0-25% attack rate
    : 0;

  const attackCount  = Math.round(batchSize * attackRate);
  const benignCount  = batchSize - attackCount;

  totalAnalyzed += batchSize;
  totalBenign   += benignCount;
  totalAttack   += attackCount;

  // Pick 1-3 random attack types for this tick
  const attackTypes = {};
  if (attackCount > 0) {
    const numTypes = Math.min(attackCount, Math.floor(Math.random() * 3) + 1);
    const shuffled = [...ATTACK_LABELS].sort(() => Math.random() - 0.5).slice(0, numTypes);
    let remaining  = attackCount;
    shuffled.forEach((type, i) => {
      const cnt = i === shuffled.length - 1
        ? remaining
        : Math.floor(Math.random() * remaining * 0.8) + 1;
      attackTypes[type] = cnt;
      remaining -= cnt;
    });
  }

  // Compute threat level
  const overallRate = totalAnalyzed > 0 ? (totalAttack / totalAnalyzed) * 100 : 0;
  const threat = getThreatLevel(overallRate);

  // Update DOM
  updateStats(threat, overallRate);
  updateCharts(benignCount, attackTypes);
  if (Object.keys(attackTypes).length > 0) addAlerts(attackTypes);
  updateTimer();
}

// ── Threat level ──────────────────────────────────────────────────────────
function getThreatLevel(pct) {
  if (pct === 0)      return { label: 'SECURE',   cls: 'threat-secure' };
  if (pct <= 10)      return { label: 'LOW',       cls: 'threat-low' };
  if (pct <= 30)      return { label: 'ELEVATED',  cls: 'threat-elevated' };
  return               { label: 'CRITICAL',  cls: 'threat-critical' };
}

// ── Update stat cards ─────────────────────────────────────────────────────
function updateStats(threat, rate) {
  liveTotalEl.textContent  = totalAnalyzed.toLocaleString();
  liveBenignEl.textContent = totalBenign.toLocaleString();
  liveAttackEl.textContent = totalAttack.toLocaleString();

  threatLevelEl.textContent = threat.label;
  threatLevelEl.className   = `threat-level ${threat.cls}`;
  threatSubEl.textContent   = `${rate.toFixed(1)}% attack rate`;
}

// ── Bar chart ─────────────────────────────────────────────────────────────
const barColors = {
  'BENIGN': 'rgba(46,213,115,0.85)',
};
ATTACK_LABELS.forEach(l => { barColors[l] = 'rgba(255,71,87,0.8)'; });

function buildBarData() {
  return {
    labels: ALL_LABELS.map(l => l.length > 18 ? l.slice(0, 16) + '…' : l),
    fullLabels: ALL_LABELS,
    values: ALL_LABELS.map(l =>
      l === 'BENIGN' ? Math.round(totalBenign / 10) : 0  // normalize
    ),
    colors: ALL_LABELS.map(l => barColors[l] || 'rgba(255,71,87,0.8)'),
    borders: ALL_LABELS.map(l => l === 'BENIGN' ? '#2ed573' : '#ff4757'),
  };
}

// Store per-label running totals for the bar chart
const labelTotals = {};
ALL_LABELS.forEach(l => { labelTotals[l] = 0; });

function updateCharts(benignCount, attackTypes) {
  labelTotals['BENIGN'] += benignCount;
  Object.entries(attackTypes).forEach(([t, c]) => {
    if (labelTotals[t] !== undefined) labelTotals[t] += c;
  });

  const barLabels = ALL_LABELS.map(l => l.length > 14 ? l.slice(0, 12) + '…' : l);
  const barValues = ALL_LABELS.map(l => labelTotals[l]);
  const bgColors  = ALL_LABELS.map(l => l === 'BENIGN' ? 'rgba(46,213,115,0.85)' : 'rgba(255,71,87,0.8)');
  const bdColors  = ALL_LABELS.map(l => l === 'BENIGN' ? '#2ed573' : '#ff4757');

  if (!barChart) {
    const ctx = document.getElementById('liveBarChart').getContext('2d');
    barChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: barLabels,
        datasets: [{
          label: 'Flow Count',
          data: barValues,
          backgroundColor: bgColors,
          borderColor: bdColors,
          borderWidth: 1.5,
          borderRadius: 3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 600, easing: 'easeInOutQuart' },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: {
            title: (items) => ALL_LABELS[items[0].dataIndex],
            label: (ctx) => ` ${ctx.parsed.y.toLocaleString()} flows`,
          }},
        },
        scales: {
          x: {
            ticks: { color: document.documentElement.getAttribute('data-theme') === 'light' ? '#475569' : '#bbc9cf', font: { family: 'Inter', size: 9 }, maxRotation: 45, minRotation: 30 },
            grid: { color: document.documentElement.getAttribute('data-theme') === 'light' ? 'rgba(203,213,225,0.8)' : 'rgba(60,73,78,0.3)' },
            border: { color: document.documentElement.getAttribute('data-theme') === 'light' ? 'rgba(203,213,225,1)' : 'rgba(60,73,78,0.5)' },
          },
          y: {
            ticks: { color: document.documentElement.getAttribute('data-theme') === 'light' ? '#475569' : '#bbc9cf', font: { family: 'JetBrains Mono', size: 10 } },
            grid: { color: document.documentElement.getAttribute('data-theme') === 'light' ? 'rgba(203,213,225,0.8)' : 'rgba(60,73,78,0.3)' },
            border: { color: document.documentElement.getAttribute('data-theme') === 'light' ? 'rgba(203,213,225,1)' : 'rgba(60,73,78,0.5)' },
          },
        },
      },
    });
  } else {
    barChart.data.datasets[0].data = barValues;
    barChart.update('active');
  }

  // Donut
  const totalA = Object.values(labelTotals).filter((_, i) => ALL_LABELS[i] !== 'BENIGN').reduce((a, b) => a + b, 0);
  const totalB = labelTotals['BENIGN'];

  if (!donutChart) {
    const ctx2 = document.getElementById('liveDonutChart').getContext('2d');
    donutChart = new Chart(ctx2, {
      type: 'doughnut',
      data: {
        labels: ['Benign', 'Attacks'],
        datasets: [{
          data: [totalB, totalA],
          backgroundColor: ['rgba(46,213,115,0.85)', 'rgba(255,71,87,0.85)'],
          borderColor: ['#2ed573', '#ff4757'],
          borderWidth: 2,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        animation: { duration: 500 },
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: document.documentElement.getAttribute('data-theme') === 'light' ? '#475569' : '#bbc9cf', font: { family: 'Inter', size: 11 }, padding: 12, boxWidth: 10, boxHeight: 10 },
          },
        },
      },
    });
  } else {
    donutChart.data.datasets[0].data = [totalB, totalA];
    donutChart.update('active');
  }
}

// ── Alerts panel ──────────────────────────────────────────────────────────
function addAlerts(attackTypes) {
  const now = new Date();
  const ts  = now.toTimeString().slice(0, 8);

  Object.entries(attackTypes).forEach(([type, count]) => {
    const sev   = SEVERITY_MAP[type] || { label: 'Medium', cls: 'medium', dotCls: 'medium' };
    alerts.unshift({ ts, type, count, sev });
  });

  // Keep max 10
  if (alerts.length > 10) alerts.splice(10);

  renderAlerts();
}

function renderAlerts() {
  if (alerts.length === 0) {
    alertsEmpty.style.display = 'flex';
    alertsCount.textContent   = '0';
    return;
  }

  alertsEmpty.style.display = 'none';
  alertsCount.textContent   = alerts.length;

  // Build HTML
  const html = alerts.map(a => `
    <div class="alert-item">
      <span class="alert-dot ${a.sev.dotCls}"></span>
      <div class="alert-body">
        <div class="alert-type">${a.type}</div>
        <div class="alert-time">${a.ts}</div>
      </div>
      <span class="badge badge-${a.sev.cls}">${a.sev.label}</span>
      <span class="alert-count">+${a.count}</span>
    </div>
  `).join('');

  // Preserve empty node, replace only items
  alertsList.innerHTML = html;
}

// ── Timer ─────────────────────────────────────────────────────────────────
function updateTimer() {
  secondsAgo = 0;
}

setInterval(() => {
  secondsAgo += 1;
  lastUpdated.textContent = secondsAgo === 0 ? 'just now' :
    secondsAgo < 60 ? `${secondsAgo}s ago` : `${Math.floor(secondsAgo/60)}m ago`;
}, 1000);

// ── Boot ──────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  simulateCycle();                                   // run immediately
  setInterval(simulateCycle, 3000);                  // then every 3s
});

// ── Theme toggle chart update ─────────────────────────────────────────────
window.addEventListener('themeChanged', () => {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const textColor = isLight ? '#475569' : '#bbc9cf';
  const gridColor = isLight ? 'rgba(203,213,225,0.8)' : 'rgba(60,73,78,0.3)';
  const borderColor = isLight ? 'rgba(203,213,225,1)' : 'rgba(60,73,78,0.5)';

  if (barChart) {
    barChart.options.scales.x.ticks.color = textColor;
    barChart.options.scales.x.grid.color = gridColor;
    barChart.options.scales.x.border.color = borderColor;
    barChart.options.scales.y.ticks.color = textColor;
    barChart.options.scales.y.grid.color = gridColor;
    barChart.options.scales.y.border.color = borderColor;
    barChart.update();
  }
  if (donutChart) {
    donutChart.options.plugins.legend.labels.color = textColor;
    donutChart.update();
  }
});