const API_BASE = 'http://127.0.0.1:5000';

let isStreaming = false;
let streamTimer = null;
let activeInterface = 'auto';

// DOM Elements
const statusPill = document.getElementById('statusPill');
const statusText = document.getElementById('statusText');
const riskBadge = document.getElementById('riskBadge');
const riskMeterBar = document.getElementById('riskMeterBar');
const riskScore = document.getElementById('riskScore');
const activeIfaceTag = document.getElementById('activeIfaceTag');
const valTotal = document.getElementById('valTotal');
const valAttacks = document.getElementById('valAttacks');
const valBenign = document.getElementById('valBenign');
const ifaceSelect = document.getElementById('ifaceSelect');
const btnToggleStream = document.getElementById('btnToggleStream');
const streamBtnText = document.getElementById('streamBtnText');
const btnAttackBurst = document.getElementById('btnAttackBurst');
const btnOpenConsole = document.getElementById('btnOpenConsole');
const threatFeed = document.getElementById('threatFeed');
const feedCount = document.getElementById('feedCount');

// Initialize Extension Popup
document.addEventListener('DOMContentLoaded', () => {
  fetchStatus();
  fetchInterfaces();
  fetchRecentFlows();

  setInterval(fetchStatus, 1800);
  setInterval(fetchRecentFlows, 2200);

  btnToggleStream.addEventListener('click', toggleAutoStream);
  btnAttackBurst.addEventListener('click', triggerAttackBurst);
  btnOpenConsole.addEventListener('click', () => {
    chrome.tabs.create({ url: `${API_BASE}/dashboard` });
  });

  ifaceSelect.addEventListener('change', (e) => {
    const selectedIface = e.target.value;
    selectInterface(selectedIface);
  });
});

// Fetch Server Status & Telemetry
async function fetchStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (!res.ok) throw new Error('Server offline');
    const data = await res.json();

    // Update Connection Status
    statusPill.className = 'status-indicator online';
    statusText.textContent = 'ONLINE';

    // Update Metrics
    valTotal.textContent = Number(data.total_flows || 0).toLocaleString();
    valAttacks.textContent = Number(data.attack_flows || 0).toLocaleString();
    valBenign.textContent = Number(data.benign_flows || 0).toLocaleString();

    // Update Risk Meter
    const score = data.risk_score || 0;
    const level = data.risk_level || 'SAFE';

    riskBadge.textContent = level;
    riskBadge.className = `risk-badge ${level.toLowerCase()}`;
    riskMeterBar.style.width = `${Math.max(5, Math.min(100, score))}%`;
    riskScore.textContent = `Risk Index: ${score} / 100`;

    activeInterface = data.active_interface || 'auto';
    activeIfaceTag.textContent = `Adapter: ${activeInterface}`;
  } catch (err) {
    statusPill.className = 'status-indicator offline';
    statusText.textContent = 'DISCONNECTED';
    riskBadge.textContent = 'OFFLINE';
    riskBadge.className = 'risk-badge';
    riskScore.textContent = 'Cannot reach Sentinel AI server at localhost:5000';
  }
}

// Fetch Network Interfaces
async function fetchInterfaces() {
  try {
    const res = await fetch(`${API_BASE}/api/interfaces`);
    if (!res.ok) return;
    const data = await res.json();

    const ifaces = data.interfaces || [];
    ifaceSelect.innerHTML = '<option value="auto">⚡ Auto-Detect Best Active Interface</option>';

    ifaces.forEach((iface) => {
      const opt = document.createElement('option');
      opt.value = iface.name;
      opt.textContent = `${iface.type === 'Wi-Fi' ? '📶' : iface.type === 'Ethernet' ? '🌐' : '📱'} ${iface.name} (${iface.ip})`;
      if (iface.name === data.selected) {
        opt.selected = true;
      }
      ifaceSelect.appendChild(opt);
    });
  } catch (e) {}
}

// Select Network Interface
async function selectInterface(name) {
  try {
    const res = await fetch(`${API_BASE}/api/interfaces/select`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: name })
    });
    if (res.ok) {
      fetchStatus();
    }
  } catch (e) {}
}

// Fetch Recent Threat Logs
async function fetchRecentFlows() {
  try {
    const res = await fetch(`${API_BASE}/api/flows?limit=15`);
    if (!res.ok) return;
    const data = await res.json();
    const flows = data.flows || [];

    feedCount.textContent = `${flows.length} events`;

    if (flows.length === 0) {
      threatFeed.innerHTML = '<div class="empty-feed">No network anomalies detected. System secure.</div>';
      return;
    }

    threatFeed.innerHTML = '';
    flows.slice(0, 10).forEach((flow) => {
      const item = document.createElement('div');
      const isAttack = flow.is_attack;
      item.className = `feed-item ${isAttack ? 'attack' : ''}`;

      item.innerHTML = `
        <div class="feed-left">
          <span class="feed-label">${isAttack ? '🚨 ' + (flow.predicted_label || 'THREAT') : '✅ ' + (flow.predicted_label || 'BENIGN')}</span>
          <span class="feed-endpoints">${flow.src_ip}:${flow.src_port || '*'} ➔ ${flow.dst_ip}:${flow.dst_port || '*'}</span>
        </div>
        <span class="feed-proto">${flow.protocol || 'TCP'}</span>
      `;

      threatFeed.appendChild(item);
    });
  } catch (e) {}
}

// Toggle Auto Simulation Stream
function toggleAutoStream() {
  if (isStreaming) {
    clearInterval(streamTimer);
    streamTimer = null;
    isStreaming = false;
    btnToggleStream.classList.remove('active');
    streamBtnText.textContent = 'Auto Stream';
  } else {
    sendSingleSimulatedFlow();
    streamTimer = setInterval(sendSingleSimulatedFlow, 750);
    isStreaming = true;
    btnToggleStream.classList.add('active');
    streamBtnText.textContent = 'Pause Stream';
  }
}

// Trigger Attack Burst
function triggerAttackBurst() {
  for (let i = 0; i < 15; i++) {
    setTimeout(sendSingleSimulatedFlow, i * 100);
  }
}

// Send Single Flow Request to Backend
function sendSingleSimulatedFlow() {
  fetch(`${API_BASE}/api/simulate-flow`, { method: 'POST' })
    .then((r) => r.json())
    .then(() => {
      fetchStatus();
      fetchRecentFlows();
    })
    .catch(() => {});
}
