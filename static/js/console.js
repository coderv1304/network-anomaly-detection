/* ============================================================
   NetShield Live Capture Console
   Polls one snapshot endpoint and renders the queue, chart, label
   mix, and inspector.
   Predictions are model output, not ground truth.
   ============================================================ */

'use strict';

const $ = (id) => document.getElementById(id);

const POLL_MS = 2000;
const MAX_FLOWS = 400;
const MAX_BUCKETS = 240;
const DEMO_MS = 2500;

const STATUS_LABEL = {
  not_started: 'Not started',
  starting: 'Starting',
  listening: 'Listening',
  disabled: 'Disabled',
  unavailable: 'Unavailable',
  error: 'Error',
};

const state = {
  flows: [],
  capture: null,
  stats: { total: 0, benign: 0, attack: 0, attack_types: {} },
  alertBudget: null,
  sensors: [],
  sensorFleet: null,
  captureInterface: null,
  incidents: [],
  incidentBusy: null,
  incidentDrafts: {},
  incidentFlash: {},
  incidentPlans: {},
  intelCache: {},
  selectedId: null,
  filter: 'all',
  search: '',
  protocol: 'all',
  sensor: 'all',
  window: 60,
  paused: false,
  follow: true,
  demoRunning: false,
  demoTimer: null,
  pollTimer: null,
  buckets: [],
  prevTotal: 0,
  prevAttack: 0,
  pendingNew: 0,
  pendingAttack: 0,
  rateSmooth: 0,
  lastTickAt: Date.now(),
  lastSnapshotAt: null,
  lastError: null,
  newestStoredId: 0,
  loading: true,
  exporting: false,
  reviewFlash: null,
};

/* ---------- utilities ---------- */

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);
}

function fmtInt(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString('en-US') : '0';
}

function fmtCompact(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return '0';
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}m`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  if (n >= 10) return String(Math.round(n));
  return n.toFixed(1).replace(/\.0$/, '');
}

function parseTs(value) {
  if (!value) return null;
  const text = String(value);
  const hasZone = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(text);
  const date = new Date(hasZone ? text : `${text}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

function fmtClock(value) {
  const date = parseTs(value);
  if (!date) return '—';
  return date.toLocaleTimeString('en-GB', { hour12: false });
}

function fmtDateTime(value) {
  const date = parseTs(value);
  if (!date) return '—';
  return `${date.toISOString().slice(0, 19).replace('T', ' ')}Z`;
}

function relTime(value) {
  const date = parseTs(value);
  if (!date) return '—';
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function csrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

function apiFetch(resource, options = {}) {
  const headers = new Headers(options.headers || {});
  const method = String(options.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers.set('X-CSRF-Token', csrfToken());
  }
  return fetch(resource, { ...options, headers, credentials: 'same-origin' });
}

function isTypingTarget(target) {
  if (!target) return false;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
}

function sourceOf(flow) {
  if (flow.simulation) return 'demo';
  return 'stored';
}

function isBenign(flow) {
  return String(flow.predicted_label || '').toUpperCase() === 'BENIGN';
}

function haystack(flow) {
  return [
    flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
    flow.protocol, flow.predicted_label, flow.review?.status, sourceOf(flow),
    flow.sensor_id, flow.interface,
  ].join(' ').toLowerCase();
}

/* ---------- data merge ---------- */

function addFlow(flow, { countPending = true } = {}) {
  if (!flow || flow.id === undefined || flow.id === null) return false;
  const key = String(flow.id);
  if (state.flows.some((item) => String(item.id) === key)) return false;

  state.flows.unshift(flow);
  if (state.flows.length > MAX_FLOWS) state.flows.length = MAX_FLOWS;

  const numericId = Number(flow.id);
  if (Number.isFinite(numericId) && flow.persisted !== false) {
    state.newestStoredId = Math.max(state.newestStoredId, numericId);
  }
  if (countPending && flow.persisted === false) {
    state.pendingNew += 1;
    if (flow.is_attack) state.pendingAttack += 1;
  }
  return true;
}

function addFlows(list) {
  if (!Array.isArray(list) || !list.length) return 0;
  const existing = new Set(state.flows.map((flow) => String(flow.id)));
  const fresh = list.filter((flow) => flow && flow.id !== undefined && !existing.has(String(flow.id)));
  if (!fresh.length) return 0;

  state.flows = fresh.concat(state.flows).slice(0, MAX_FLOWS);
  // The first snapshot may mix newest rows with older flagged rows, so keep
  // the queue ordered by record id rather than insertion order.
  state.flows.sort((a, b) => {
    const na = Number(a.id);
    const nb = Number(b.id);
    if (Number.isFinite(na) && Number.isFinite(nb)) return nb - na;
    return String(b.timestamp || '').localeCompare(String(a.timestamp || ''));
  });
  for (const flow of fresh) {
    const numericId = Number(flow.id);
    if (Number.isFinite(numericId) && flow.persisted !== false) {
      state.newestStoredId = Math.max(state.newestStoredId, numericId);
    }
  }
  return fresh.length;
}

/* ---------- rendering: header / status ---------- */

function captureMode() {
  if (state.demoRunning) return 'demo';
  const capture = state.capture;
  if (!capture) return 'idle';
  if (capture.state === 'listening') {
    const last = parseTs(capture.last_flow_at);
    const fresh = last && Date.now() - last.getTime() < 90000;
    return fresh ? 'live' : 'idle';
  }
  if (capture.state === 'error' || capture.state === 'unavailable') return 'error';
  if (capture.state === 'disabled' || capture.state === 'not_started') {
    return state.flows.length ? 'stored' : 'idle';
  }
  return 'idle';
}

function renderHeader() {
  const capture = state.capture;
  const mode = captureMode();
  const chip = $('modeChip');
  chip.dataset.mode = mode;
  chip.textContent = mode.toUpperCase();

  const pill = $('capturePill');
  const pillText = $('capturePillText');
  const rawState = capture?.state || 'unknown';
  pill.dataset.state = rawState;
  pillText.textContent = STATUS_LABEL[rawState] || 'Checking sensor';

  let summary = 'Connecting to the sensor…';
  if (state.demoRunning) {
    summary = 'Replay sample running. Rows are synthetic fixtures, not model output, and are not stored. Stop the replay to return to sensor status.';
  } else if (capture) {
    summary = capture.message || 'Sensor status reported no message.';
    if (capture.state === 'listening') {
      summary = `Listening on ${capture.interface || 'the configured interface'}. ${fmtInt(state.stats.total)} flows in the store; ${fmtInt(capture.flows_received || 0)} accepted by the sensor.`;
    } else if (capture.state === 'disabled') {
      summary = 'Sensor offline. Stored flows remain available for review. Configure a capture interface to stream live traffic.';
    } else if (capture.state === 'unavailable') {
      summary = 'Capture engine unavailable. Stored flows and external sensor ingestion still work.';
    }
  }
  $('captureSummary').textContent = summary;

  const ifaceSelect = $('interfaceSelect');
  const ifaceName = capture?.interface || '';
  if (ifaceSelect && ifaceSelect.dataset.loaded !== ifaceName) {
    ifaceSelect.dataset.loaded = ifaceName;
    ifaceSelect.innerHTML = ifaceName
      ? `<option value="${escapeHtml(ifaceName)}">${escapeHtml(ifaceName)}</option>`
      : '<option value="">No capture interface</option>';
  }
  if (ifaceSelect) ifaceSelect.disabled = capture?.state !== 'listening';

  const sensorHint = $('sensorHint');
  if (sensorHint) {
    if (capture?.state === 'listening') {
      sensorHint.textContent = 'Capture active. Flow records appear in the tail below.';
    } else if (capture?.state === 'unavailable') {
      sensorHint.textContent = 'Capture engine unavailable. Stored flows remain available.';
    } else {
      sensorHint.textContent = 'Sensor offline. Stored flows remain available.';
    }
  }

  $('statState').textContent = STATUS_LABEL[rawState] || 'Unknown';
  $('statStateNote').textContent = capture?.message || 'No sensor message';
  $('statStateNote').title = capture?.message || '';

  const iface = capture?.interface || '—';
  $('statInterface').textContent = iface;
  $('statInterface').title = iface;
  $('statInterfaceNote').textContent = capture?.capture_requested ? 'Capture requested at startup' : 'Not requested at startup';

  $('statReceipts').textContent = fmtInt(capture?.flows_received || 0);
  $('statStored').textContent = fmtInt(state.stats.total);

  const total = state.stats.total || 0;
  const flagged = state.stats.attack || 0;
  const pct = total > 0 ? (flagged / total) * 100 : 0;
  $('statFlagged').textContent = `${pct.toFixed(1)}%`;
  $('statFlaggedNote').textContent = `${fmtInt(flagged)} predicted non-benign`;

  const budget = state.alertBudget;
  if (!budget || budget.state === 'no_data') {
    $('statBudget').textContent = '—';
    $('statBudgetNote').textContent = 'No budget data in the window';
  } else {
    const allowed = Number(budget.allowed_alerts) || 0;
    const alerts = Number(budget.alerts) || 0;
    $('statBudget').textContent = `${fmtInt(alerts)} / ${allowed.toFixed(1)}`;
    $('statBudgetNote').textContent = budget.state === 'over_budget'
      ? `${fmtInt(Math.abs(budget.remaining_alerts))} over the ${fmtInt(budget.budget_per_10k_flows)}/10k cap`
      : `${fmtInt(budget.remaining_alerts)} alerts left in the ${fmtInt(budget.window_minutes)}m window`;
  }

  if (state.paused) {
    $('statRate').textContent = 'paused';
    $('statRateNote').textContent = 'Feed paused by operator';
  } else {
    $('statRate').textContent = `${state.rateSmooth.toFixed(1)}/s`;
    const lastBucket = state.buckets[state.buckets.length - 1];
    $('statRateNote').textContent = lastBucket
      ? `${fmtInt(lastBucket.total)} new in the last interval`
      : 'Awaiting records';
  }
}

function renderQueueMeta() {
  const tick = $('liveTick');
  const tickText = $('liveTickText');
  const mode = captureMode();
  tick.classList.toggle('is-idle', mode === 'stored' || mode === 'idle');
  if (state.paused) {
    tick.classList.add('is-paused');
    tickText.textContent = 'Paused';
  } else {
    tick.classList.remove('is-paused');
    tickText.textContent = mode === 'live' || mode === 'demo'
      ? 'Live'
      : mode === 'stored'
        ? 'Stored'
        : 'Idle';
  }

  const updated = $('lastUpdated');
  if (state.lastError) {
    updated.textContent = 'Update failed';
    updated.style.color = 'var(--red)';
  } else if (state.lastSnapshotAt) {
    updated.textContent = `Updated ${relTime(new Date(state.lastSnapshotAt).toISOString())}`;
    updated.style.color = '';
  } else {
    updated.textContent = '—';
    updated.style.color = '';
  }

  $('flaggedCount').textContent = fmtInt(state.stats.attack || 0);
  $('btnPause').textContent = state.paused ? 'Resume feed' : 'Pause feed';
  $('btnPause').setAttribute('aria-pressed', String(state.paused));
  $('btnRefresh').hidden = !state.paused;
  $('btnFollow').setAttribute('aria-pressed', String(state.follow));
}

/* ---------- rendering: chart ---------- */

function recordBucket() {
  const now = Date.now();
  const elapsed = Math.max(1, (now - state.lastTickAt) / 1000);
  const storedDelta = Math.max(0, (state.stats.total || 0) - state.prevTotal);
  const attackDelta = Math.max(0, (state.stats.attack || 0) - state.prevAttack);
  const count = storedDelta + state.pendingNew;
  const attacks = Math.min(count, attackDelta + state.pendingAttack);

  state.prevTotal = state.stats.total || 0;
  state.prevAttack = state.stats.attack || 0;
  state.pendingNew = 0;
  state.pendingAttack = 0;
  state.lastTickAt = now;

  const instant = count / elapsed;
  state.rateSmooth = state.rateSmooth * 0.55 + instant * 0.45;

  state.buckets.push({ t: now, total: count, attack: attacks });
  if (state.buckets.length > MAX_BUCKETS) state.buckets.shift();
}

function drawChart() {
  const canvas = $('rateChart');
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (rect.width < 10 || rect.height < 10) return;

  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(rect.width * dpr);
  canvas.height = Math.round(rect.height * dpr);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const width = rect.width;
  const height = rect.height;
  ctx.clearRect(0, 0, width, height);

  const styles = getComputedStyle(document.documentElement);
  const lineColor = styles.getPropertyValue('--line').trim();
  const tealColor = styles.getPropertyValue('--teal').trim();
  const redColor = styles.getPropertyValue('--red').trim();
  const loColor = styles.getPropertyValue('--text-lo').trim();

  const padLeft = 32;
  const padRight = 6;
  const padTop = 8;
  const padBottom = 16;
  const plotW = Math.max(1, width - padLeft - padRight);
  const plotH = Math.max(1, height - padTop - padBottom);

  const cutoff = Date.now() - state.window * 1000;
  const buckets = state.buckets.filter((bucket) => bucket.t >= cutoff);
  const max = Math.max(1, ...buckets.map((bucket) => bucket.total));

  ctx.font = '9px "IBM Plex Mono", Consolas, monospace';
  ctx.textBaseline = 'middle';
  ctx.textAlign = 'right';

  for (let i = 0; i <= 2; i += 1) {
    const y = padTop + plotH - (plotH * i) / 2;
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(width - padRight, y);
    ctx.stroke();
    ctx.fillStyle = loColor;
    ctx.fillText(fmtCompact((max * i) / 2), padLeft - 6, y);
  }

  const hasData = buckets.some((bucket) => bucket.total > 0);
  $('chartEmpty').hidden = hasData;
  $('chartEmpty').textContent = state.stats.total > 0
    ? 'No records in this window.'
    : 'Waiting for flow records.';
  $('chartNote').textContent = `${buckets.length} interval${buckets.length === 1 ? '' : 's'}`;

  if (!buckets.length) return;

  const slot = plotW / buckets.length;
  const barWidth = Math.max(1, Math.min(10, slot * 0.62));

  for (let i = 0; i < buckets.length; i += 1) {
    const bucket = buckets[i];
    const x = padLeft + i * slot + (slot - barWidth) / 2;
    const totalHeight = (bucket.total / max) * plotH;
    const attackHeight = (bucket.attack / max) * plotH;
    const benignHeight = Math.max(0, totalHeight - attackHeight);

    if (benignHeight > 0) {
      ctx.fillStyle = tealColor;
      ctx.fillRect(x, padTop + plotH - benignHeight, barWidth, benignHeight);
    }
    if (attackHeight > 0) {
      ctx.fillStyle = redColor;
      ctx.fillRect(x, padTop + plotH - totalHeight, barWidth, attackHeight);
    }
  }

  ctx.textAlign = 'left';
  ctx.fillStyle = loColor;
  if (buckets.length) {
    ctx.fillText(fmtClock(new Date(buckets[0].t).toISOString()), padLeft, height - 6);
    ctx.textAlign = 'right';
    ctx.fillText(fmtClock(new Date(buckets[buckets.length - 1].t).toISOString()), width - padRight, height - 6);
  }
}

/* ---------- rendering: label mix ---------- */

function renderMix() {
  const entries = Object.entries(state.stats.attack_types || {})
    .filter(([, count]) => Number(count) > 0)
    .sort((a, b) => Number(b[1]) - Number(a[1]));

  $('mixTotal').textContent = fmtInt(state.stats.total);

  const bar = $('mixBar');
  const list = $('mixList');
  const total = state.stats.total || 0;

  if (!total || !entries.length) {
    bar.innerHTML = '';
    list.innerHTML = '<li class="mix-empty">No stored records yet.</li>';
    return;
  }

  const benign = Number(state.stats.benign) || 0;
  const attack = Number(state.stats.attack) || 0;
  const benignPct = (benign / total) * 100;
  const attackPct = (attack / total) * 100;

  bar.innerHTML = [
    benignPct > 0 ? `<span style="width:${benignPct.toFixed(2)}%;background:var(--teal)"></span>` : '',
    attackPct > 0 ? `<span style="width:${attackPct.toFixed(2)}%;background:var(--red)"></span>` : '',
  ].join('');

  const top = entries.slice(0, 6);
  const rest = entries.slice(6).reduce((sum, [, count]) => sum + Number(count), 0);
  if (rest > 0) top.push(['Other labels', rest]);

  list.innerHTML = top.map(([label, count]) => {
    const benignLabel = String(label).toUpperCase() === 'BENIGN';
    return `<li>
      <span class="mix-name"><i class="mix-dot" style="background:${benignLabel ? 'var(--teal)' : 'var(--red)'}"></i><span title="${escapeHtml(label)}">${escapeHtml(label)}</span></span>
      <span class="mix-count">${fmtInt(count)}</span>
    </li>`;
  }).join('');
}

function renderSensorList() {
  const list = $('sensorList');
  if (!list) return;
  const sensors = Array.isArray(state.sensors) ? state.sensors.filter((row) => row.sensor_id) : [];
  if (!sensors.length) {
    list.innerHTML = '<li class="mix-empty">No attributed sensors. Legacy and upload rows stay unattributed.</li>';
    return;
  }
  list.innerHTML = sensors.slice(0, 8).map((row) => {
    const rate = row.total ? (row.attacks / row.total) * 100 : 0;
    return `<li>
      <span class="mix-name" title="${escapeHtml(row.interface || row.sensor_id)}"><i class="mix-dot" style="background:var(--teal)"></i><span>${escapeHtml(row.sensor_id)}</span></span>
      <span class="mix-count">${fmtInt(row.total)} &middot; ${rate.toFixed(1)}%</span>
    </li>`;
  }).join('');
}

/* ---------- rendering: ingestion vectors, fleet, incidents ---------- */

const VECTOR_LABEL = {
  ethernet: 'Wired Ethernet',
  wlan: '802.11 wireless',
  wwan: 'Cellular / WWAN',
  vpn: 'VPN / tunnel',
  virtual: 'Virtual / container',
  loopback: 'Loopback',
  unknown: 'Unclassified',
};

function metricText(value, unit, digits) {
  if (value === null || value === undefined || value === '') return 'Not reported';
  const number = Number(value);
  if (!Number.isFinite(number)) return 'Not reported';
  return `${number.toLocaleString(undefined, { maximumFractionDigits: digits ?? 0 })}${unit || ''}`;
}

function renderVectors() {
  const host = $('vectorChips');
  if (!host) return;
  const sensors = Array.isArray(state.sensorFleet?.sensors) ? state.sensorFleet.sensors : [];
  const counts = {};
  for (const row of sensors) counts[row.vector || 'unknown'] = (counts[row.vector || 'unknown'] || 0) + 1;
  const local = state.captureInterface?.vector;
  const order = ['ethernet', 'wlan', 'wwan', 'vpn', 'virtual', 'loopback'];
  const chips = order.map((id) => {
    const active = counts[id] > 0 || local === id;
    const parts = [VECTOR_LABEL[id] || id];
    if (counts[id]) parts.push(`${counts[id]} probe${counts[id] === 1 ? '' : 's'}`);
    if (local === id) parts.push('local capture');
    return `<span class="vector-chip" data-state="${active ? 'active' : 'idle'}"><i aria-hidden="true"></i>${escapeHtml(parts.join(' · '))}</span>`;
  });
  if (!sensors.length && !local) chips.push('<span class="vector-chip" data-state="unknown">No adapter metadata</span>');
  host.innerHTML = chips.join('');
}

function renderFleet() {
  const grid = $('fleetGrid');
  const count = $('fleetCount');
  if (!grid) return;
  const fleet = state.sensorFleet;
  const sensors = Array.isArray(fleet?.sensors) ? fleet.sensors : [];
  if (count) {
    count.textContent = sensors.length
      ? `${fmtInt(fleet.online_count)}/${fmtInt(sensors.length)} online`
      : 'No probes';
  }
  if (!sensors.length) {
    grid.innerHTML = '<p class="note">No collector heartbeats have been received. Fleet metrics appear only when a collector posts to <code>/api/sensors/heartbeat</code>.</p>';
    return;
  }
  grid.innerHTML = sensors.map((row) => {
    const status = row.status || 'never_reported';
    const driver = row.capture_driver || 'Driver not reported';
    const speed = row.link_speed_mbps === null || row.link_speed_mbps === undefined
      ? 'Link speed not reported'
      : `${metricText(row.link_speed_mbps, ' Mbps', 1)} link`;
    const drops = row.rx_drop_rate === null || row.rx_drop_rate === undefined
      ? 'Drop rate not reported'
      : `${(Number(row.rx_drop_rate) * 100).toFixed(3)}% rx drops`;
    return `<article class="fleet-card" data-status="${escapeHtml(status)}">
      <header>
        <span class="fleet-status"><i aria-hidden="true"></i>${escapeHtml(status.replace('_', ' '))}</span>
        <span class="fleet-age">${row.age_seconds === null || row.age_seconds === undefined ? 'No heartbeat' : `${fmtInt(row.age_seconds)}s ago`}</span>
      </header>
      <h3 title="${escapeHtml(row.sensor_id || '')}">${escapeHtml(row.sensor_id || 'Unidentified sensor')}</h3>
      <p class="fleet-interface mono">${escapeHtml(row.interface || 'interface not reported')}</p>
      <p class="fleet-vector">${escapeHtml(row.vector_label || VECTOR_LABEL[row.vector] || 'Unclassified')}</p>
      <dl class="fleet-metrics">
        <div><dt>Capture driver</dt><dd>${escapeHtml(driver)}</dd></div>
        <div><dt>Link</dt><dd>${escapeHtml(speed)}</dd></div>
        <div><dt>Drops</dt><dd>${escapeHtml(drops)}</dd></div>
        <div><dt>Flows</dt><dd>${metricText(row.flows_total, '', 0)}</dd></div>
      </dl>
    </article>`;
  }).join('');
}

function slaText(sla) {
  if (!sla || sla.remaining_seconds === null || sla.remaining_seconds === undefined) return 'No deadline';
  const seconds = Number(sla.remaining_seconds);
  const abs = Math.abs(seconds);
  const hours = Math.floor(abs / 3600);
  const minutes = Math.floor((abs % 3600) / 60);
  const label = hours ? `${hours}h ${minutes}m` : `${minutes}m`;
  return seconds < 0 ? `${label} overdue` : `${label} left`;
}

function incidentDraft(incident) {
  const key = incident.incident_id;
  if (!state.incidentDrafts[key]) {
    state.incidentDrafts[key] = {
      status: incident.triage?.status || 'new',
      assignee: incident.triage?.assignee || '',
      note: incident.triage?.note || '',
    };
  }
  return state.incidentDrafts[key];
}

function renderIncidents() {
  const list = $('incidentList');
  const count = $('incidentCount');
  if (!list) return;
  const incidents = Array.isArray(state.incidents) ? state.incidents : [];
  if (count) count.textContent = fmtInt(incidents.length);
  if (!incidents.length) {
    list.innerHTML = '<p class="note">No open host/window incident. Multi-signal accumulation must reach the configured risk threshold.</p>';
    return;
  }
  const active = document.activeElement;
  const focusKey = active?.dataset?.field
    ? `${active.dataset.incident}|${active.dataset.field}`
    : null;

  list.innerHTML = incidents.map((incident) => {
    const severity = incident.severity || {};
    const triage = incident.triage || {};
    const draft = incidentDraft(incident);
    const options = (triage.allowed_statuses || ['new', 'investigating', 'suppressed', 'remediated'])
      .map((status) => `<option value="${escapeHtml(status)}"${status === draft.status ? ' selected' : ''}>${escapeHtml(status)}</option>`)
      .join('');
    const evidence = (incident.evidence || []).slice(-4).map((line) => `<li>${escapeHtml(line)}</li>`).join('');
    const flash = state.incidentFlash[incident.incident_id];
    const plan = state.incidentPlans[incident.incident_id];
    const planHtml = plan ? `<div class="incident-plan">
        <p class="section-title">Dry-run containment &middot; not executed</p>
        <ul>${(plan.commands || []).map((item) => `<li><code>${escapeHtml(item.command)}</code></li>`).join('')}</ul>
        <p class="note">${escapeHtml(plan.warning || '')}</p>
      </div>` : '';
    return `<article class="incident-card" data-incident="${escapeHtml(incident.incident_id)}" data-severity="${escapeHtml(severity.id || 'P4')}">
      <header>
        <div>
          <span class="severity-pill" data-severity="${escapeHtml(severity.id || 'P4')}">${escapeHtml(severity.id || 'P4')}</span>
          <strong class="mono">${escapeHtml(incident.source_ip)}</strong>
        </div>
        <span class="sla-pill" data-state="${escapeHtml(triage.sla?.state || 'unknown')}">${escapeHtml(slaText(triage.sla))}</span>
      </header>
      <p class="incident-meta">${escapeHtml(severity.label || 'Internal risk priority')} &middot; ${fmtInt(incident.max_risk_points)} risk points &middot; ${fmtInt(incident.active_signals)} signals &middot; ${fmtInt(incident.flow_count)} flows &middot; window ${fmtInt(incident.window_seconds)}s</p>
      <p class="incident-id mono">${escapeHtml(incident.incident_id)}</p>
      <div class="incident-controls">
        <label><span>Status</span>
          <select data-incident="${escapeHtml(incident.incident_id)}" data-field="status">${options}</select>
        </label>
        <label><span>Assignee</span>
          <input type="text" maxlength="120" placeholder="Unassigned" value="${escapeHtml(draft.assignee)}" data-incident="${escapeHtml(incident.incident_id)}" data-field="assignee">
        </label>
        <label class="wide"><span>Analyst note</span>
          <input type="text" maxlength="2000" placeholder="Triage note" value="${escapeHtml(draft.note)}" data-incident="${escapeHtml(incident.incident_id)}" data-field="note">
        </label>
        <button class="btn compact" type="button" data-incident-action="save" data-incident="${escapeHtml(incident.incident_id)}"${state.incidentBusy === incident.incident_id ? ' disabled' : ''}>Save triage</button>
        <button class="btn compact" type="button" data-incident-action="plan" data-incident="${escapeHtml(incident.incident_id)}">Containment plan</button>
        <button class="btn compact" type="button" data-incident-action="stix" data-incident="${escapeHtml(incident.incident_id)}">Export STIX</button>
      </div>
      ${evidence ? `<ul class="incident-evidence">${evidence}</ul>` : ''}
      ${planHtml}
      <p class="incident-flash ${flash ? flash.cls : ''}" data-incident="${escapeHtml(incident.incident_id)}" role="status" aria-live="polite">${flash ? escapeHtml(flash.text) : ''}</p>
    </article>`;
  }).join('');

  if (focusKey) {
    const [incidentId, field] = focusKey.split('|');
    const target = list.querySelector(`[data-incident="${CSS.escape(incidentId)}"][data-field="${CSS.escape(field)}"]`);
    if (target) target.focus();
  }
}

function flashIncident(incidentId, text, cls) {
  state.incidentFlash[incidentId] = { text, cls: cls || '' };
  window.setTimeout(() => {
    if (state.incidentFlash[incidentId]?.text === text) {
      delete state.incidentFlash[incidentId];
      renderIncidents();
    }
  }, 5000);
}

async function saveIncidentTriage(incidentId) {
  const incident = state.incidents.find((row) => row.incident_id === incidentId);
  const draft = state.incidentDrafts[incidentId] || {};
  state.incidentBusy = incidentId;
  renderIncidents();
  try {
    const response = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}/triage`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(draft),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    if (incident) {
      incident.triage = data.triage || incident.triage;
      incident.severity = data.severity || incident.severity;
    }
    flashIncident(incidentId, 'Triage saved', 'is-ok');
  } catch (error) {
    flashIncident(incidentId, error.message || 'Triage could not be saved', 'is-error');
  } finally {
    state.incidentBusy = null;
    renderIncidents();
  }
}

async function loadContainmentPlan(incidentId) {
  try {
    const response = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}/playbook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'containment_plan' }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `Plan failed (${response.status})`);
    state.incidentPlans[incidentId] = data;
    flashIncident(incidentId, 'Dry-run plan generated; nothing was executed', 'is-ok');
  } catch (error) {
    flashIncident(incidentId, error.message || 'Plan failed', 'is-error');
  }
  renderIncidents();
}

async function downloadIncidentStix(incidentId) {
  try {
    const response = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}/stix`, { cache: 'no-store' });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || `STIX export failed (${response.status})`);
    }
    const text = await response.text();
    const blob = new Blob([text], { type: 'application/stix+json;version=2.1' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `netshield-incident-${incidentId.replace(/[^a-zA-Z0-9._-]+/g, '_')}.stix.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    flashIncident(incidentId, 'STIX 2.1 bundle exported', 'is-ok');
  } catch (error) {
    flashIncident(incidentId, error.message || 'STIX export failed', 'is-error');
  }
  renderIncidents();
}

function intelHtml(flow) {
  if (flow.simulation) return '<p class="note">Synthetic fixture. No external lookup is made.</p>';
  const cached = state.intelCache[flow.src_ip];
  if (cached === null || cached === undefined || cached.loading) {
    return `<p class="note">Attribution is fetched when a public address is selected. <button class="btn compact" type="button" data-intel-action="refresh">Query attribution</button></p>
      <p class="note">Missing MaxMind or AbuseIPDB configuration renders as unknown, never as clean.</p>`;
  }
  if (cached.error) return `<p class="note is-error">${escapeHtml(cached.error)}</p>`;
  const geo = cached.geo || {};
  const asn = cached.asn || {};
  const reputation = cached.reputation || {};
  const asnText = asn.number ? `AS${asn.number} ${asn.organization || ''}`.trim() : 'Unknown';
  const geoText = geo.country_code ? `${geo.country_code}${geo.city ? ` · ${geo.city}` : ''}` : 'Unknown';
  const repText = reputation.status === 'live'
    ? `${reputation.abuse_score ?? 0}/100 (${reputation.total_reports ?? 0} reports)`
    : `Not available (${reputation.status || 'not queried'})`;
  return `<dl>
      <div class="kv"><dt>ASN</dt><dd>${escapeHtml(asnText)}</dd></div>
      <div class="kv"><dt>GeoIP</dt><dd>${escapeHtml(geoText)}</dd></div>
      <div class="kv"><dt>Scope</dt><dd>${escapeHtml(cached.scope || 'unknown')}</dd></div>
      <div class="kv"><dt>Reputation</dt><dd>${escapeHtml(repText)}</dd></div>
    </dl>
    <p class="note">${escapeHtml(cached.note || 'Attribution requires operator-supplied databases or keys.')}</p>`;
}

function ensureIntel(flow) {
  if (!flow || flow.simulation || !flow.src_ip) return;
  if (state.intelCache[flow.src_ip] !== undefined) return;
  state.intelCache[flow.src_ip] = { loading: true };
  apiFetch(`/api/intel/${encodeURIComponent(flow.src_ip)}?reputation=true`, { cache: 'no-store' })
    .then(async (response) => {
      const data = await response.json().catch(() => ({}));
      state.intelCache[flow.src_ip] = response.ok ? data : { error: data.error || `Lookup failed (${response.status})` };
    })
    .catch((error) => {
      state.intelCache[flow.src_ip] = { error: error.message || 'Lookup failed' };
    })
    .finally(() => {
      if (String(state.selectedId) === String(flow.id)) renderInspector();
    });
}



function filteredFlows() {
  const query = state.search.trim().toLowerCase();
  return state.flows.filter((flow) => {
    if (state.filter === 'flagged' && !flow.is_attack) return false;
    if (state.filter === 'benign' && flow.is_attack) return false;
    if (state.protocol !== 'all' && String(flow.protocol || '').toUpperCase() !== state.protocol) return false;
    if (state.sensor !== 'all' && String(flow.sensor_id || '') !== state.sensor) return false;
    if (query && !haystack(flow).includes(query)) return false;
    return true;
  });
}

function renderSensorOptions() {
  const select = $('sensorSelect');
  if (!select) return;
  const sensors = [...new Set(
    state.flows
      .map((flow) => flow.sensor_id)
      .filter((value) => value !== null && value !== undefined && value !== '')
  )].sort((a, b) => String(a).localeCompare(String(b)));

  if (state.sensor !== 'all' && !sensors.includes(state.sensor)) {
    state.sensor = 'all';
  }
  const options = ['<option value="all">All sensors</option>'].concat(
    sensors.map((sensor) => `<option value="${escapeHtml(sensor)}">${escapeHtml(sensor)}</option>`)
  );
  const next = options.join('');
  if (select.innerHTML !== next) select.innerHTML = next;
  select.value = state.sensor;
}

function rowHtml(flow) {
  const selected = state.selectedId !== null && String(state.selectedId) === String(flow.id);
  const attack = Boolean(flow.is_attack);
  const label = flow.predicted_label || 'unknown';
  const review = flow.review?.status || 'Unreviewed';
  const source = sourceOf(flow);
  const src = `${flow.src_ip || '—'}${flow.src_port ? `:${flow.src_port}` : ''}`;
  const dst = `${flow.dst_ip || '—'}${flow.dst_port ? `:${flow.dst_port}` : ''}`;

  return `<tr data-id="${escapeHtml(flow.id)}" tabindex="0"${selected ? ' class="is-selected" aria-selected="true"' : ''}>
    <td class="mono">${fmtClock(flow.timestamp)}</td>
    <td class="mono">${escapeHtml(src)}</td>
    <td class="mono">${escapeHtml(dst)}</td>
    <td class="mono">${escapeHtml(flow.protocol || '—')}</td>
    <td><span class="badge ${attack ? 'attack' : 'benign'}">${escapeHtml(label)}</span></td>
    <td><span class="badge review" data-status="${escapeHtml(review)}">${escapeHtml(review)}</span></td>
    <td><span class="badge ${source === 'demo' ? 'demo' : 'stored'}">${source === 'demo' ? 'Demo' : 'Stored'}</span></td>
  </tr>`;
}

function renderQueue() {
  const tbody = $('queueBody');
  const flows = filteredFlows();
  const shown = flows.slice(0, 200);

  if (state.loading) {
    tbody.innerHTML = '<tr class="state-row"><td colspan="7">Loading flows…</td></tr>';
    $('queueFoot').textContent = 'Loading recent records.';
    return;
  }

  if (!state.flows.length) {
    const demoButton = state.capture?.demo_stream_enabled
      ? '<button class="btn" type="button" data-action="start-demo">Replay sample</button>'
      : '';
    tbody.innerHTML = `<tr class="state-row"><td colspan="7">
      <span class="state-title">No flows yet</span>
      <span class="state-sub">No stored flows and no live ingestion. Start a sensor capture, connect a collector, or replay a sample.</span>
      ${demoButton}
    </td></tr>`;
    $('queueFoot').textContent = '0 records loaded.';
    return;
  }

  if (!shown.length) {
    tbody.innerHTML = `<tr class="state-row"><td colspan="7">
      <span class="state-title">No flows match this filter</span>
      <span class="state-sub">Clear the search or choose a different prediction filter.</span>
      <button class="btn" type="button" data-action="clear-filters">Clear filters</button>
    </td></tr>`;
    $('queueFoot').textContent = `0 of ${fmtInt(flows.length)} matching · ${fmtInt(state.flows.length)} loaded · ${fmtInt(state.stats.total)} stored`;
    return;
  }

  tbody.innerHTML = shown.map(rowHtml).join('');
  const truncated = flows.length > shown.length ? ` (showing first ${fmtInt(shown.length)})` : '';
  $('queueFoot').textContent = `${fmtInt(flows.length)} matching${truncated} · ${fmtInt(state.flows.length)} loaded · ${fmtInt(state.stats.total)} stored`;
}

/* ---------- rendering: inspector ---------- */

function renderInspector() {
  const empty = $('inspectorEmpty');
  const body = $('inspectorBody');
  const flow = state.flows.find((item) => String(item.id) === String(state.selectedId));

  if (!flow) {
    empty.hidden = false;
    body.hidden = true;
    body.innerHTML = '';
    return;
  }

  empty.hidden = true;
  body.hidden = false;

  const source = sourceOf(flow);
  const review = flow.review || { status: 'Unreviewed', note: '', updated_at: null, updated_by: null };
  const attack = Boolean(flow.is_attack);
  const persisted = flow.persisted !== false && Number.isFinite(Number(flow.id));
  const label = flow.predicted_label || 'unknown';
  const provenance = flow.provenance || {};
  const decisionBasis = provenance.decision_basis || null;
  const basisText = decisionBasis === 'attack_probability_threshold'
    ? 'Attack-score threshold'
    : decisionBasis === 'argmax'
      ? 'Argmax (no threshold)'
      : source === 'demo'
        ? 'Synthetic fixture'
        : 'Not recorded';
  const attackScore = Number.isFinite(Number(provenance.attack_score))
    ? Number(provenance.attack_score).toFixed(6)
    : 'Not recorded';
  const thresholdValue = Number.isFinite(Number(provenance.threshold_value))
    ? Number(provenance.threshold_value).toFixed(6)
    : 'Not recorded';
  const hasProvenance = Boolean(provenance.model_version || provenance.artifact_sha256);
  const src = `${flow.src_ip || '—'}${flow.src_port ? `:${flow.src_port}` : ''}`;
  const dst = `${flow.dst_ip || '—'}${flow.dst_port ? `:${flow.dst_port}` : ''}`;

  const reviewForm = persisted ? `
    <form class="review-form" id="reviewForm">
      <label>
        <span>Status</span>
        <select id="reviewStatus" name="status">
          ${['Unreviewed', 'New', 'Investigating', 'Suppressed', 'Closed']
            .map((status) => `<option value="${status}"${status === review.status ? ' selected' : ''}>${status}</option>`)
            .join('')}
        </select>
      </label>
      <label>
        <span>Analyst note</span>
        <textarea id="reviewNote" name="note" maxlength="2000" placeholder="What did you check?">${escapeHtml(review.note || '')}</textarea>
      </label>
      <button class="btn" type="submit" id="reviewSave">Save review</button>
      <span class="form-status ${state.reviewFlash && state.reviewFlash.id === String(flow.id) ? state.reviewFlash.cls : ''}" id="reviewStatusMessage" role="status" aria-live="polite">${state.reviewFlash && state.reviewFlash.id === String(flow.id) ? escapeHtml(state.reviewFlash.text) : ''}</span>
    </form>` : `
    <p class="note">This record is a synthetic demo fixture. It is not stored and cannot be reviewed.</p>`;

  body.innerHTML = `
    <div class="inspector-head">
      <p class="eyebrow">Flow record · ${source === 'demo' ? 'Demo fixture' : 'Stored'}</p>
      <div class="inspector-title">
        <h2>${escapeHtml(label)}</h2>
        <span class="badge ${attack ? 'attack' : 'benign'}">${attack ? 'Non-benign' : 'Benign'}</span>
      </div>
      <p class="inspector-route">${escapeHtml(src)} <span class="arrow">→</span> ${escapeHtml(dst)}</p>
    </div>

    <div class="inspector-section">
      <p class="section-title">Prediction</p>
      <dl>
        <div class="kv"><dt>Label</dt><dd>${escapeHtml(label)}</dd></div>
        <div class="kv"><dt>Flagged</dt><dd>${attack ? 'Yes' : 'No'}</dd></div>
        <div class="kv"><dt>Decision basis</dt><dd>${escapeHtml(basisText)}</dd></div>
        <div class="kv"><dt>Attack score</dt><dd>${escapeHtml(attackScore)}</dd></div>
        <div class="kv"><dt>Threshold</dt><dd>${escapeHtml(thresholdValue)}</dd></div>
        <div class="kv"><dt>Confidence</dt><dd>Not available</dd></div>
        <div class="kv"><dt>Source</dt><dd>${source === 'demo' ? 'Synthetic fixture' : 'Stored serving prediction'}</dd></div>
      </dl>
      <p class="note caution" style="margin-top:8px"><strong>Not ground truth.</strong> The serving bundle applies its recorded attack-score threshold. It is not calibrated, so no confidence percentage is shown.</p>
    </div>

    ${hasProvenance ? `
    <div class="inspector-section">
      <p class="section-title">Provenance</p>
      <dl>
        <div class="kv"><dt>Model version</dt><dd>${escapeHtml(provenance.model_version || '—')}</dd></div>
        <div class="kv"><dt>Artifact SHA-256</dt><dd class="hash">${escapeHtml(provenance.artifact_sha256 || '—')}</dd></div>
        <div class="kv"><dt>Feature schema</dt><dd>${escapeHtml(provenance.feature_schema_version || '—')}</dd></div>
        <div class="kv"><dt>Threshold policy</dt><dd>${escapeHtml(provenance.threshold_policy || '—')}</dd></div>
        <div class="kv"><dt>Calibration</dt><dd>${escapeHtml(provenance.calibration_version || '—')}</dd></div>
        <div class="kv"><dt>Argmax label</dt><dd>${escapeHtml(provenance.model_argmax_label || '—')}</dd></div>
      </dl>
    </div>` : ''}

    <div class="inspector-section">
      <p class="section-title">Threat context</p>
      <div id="intelBody">${intelHtml(flow)}</div>
    </div>

    <div class="inspector-section">
      <p class="section-title">Record</p>
      <dl>
        <div class="kv"><dt>Record ID</dt><dd>${escapeHtml(flow.id)}</dd></div>
        <div class="kv"><dt>Timestamp</dt><dd>${fmtDateTime(flow.timestamp)}</dd></div>
        <div class="kv"><dt>Sensor</dt><dd>${escapeHtml(flow.sensor_id || 'Unattributed')}</dd></div>
        <div class="kv"><dt>Interface</dt><dd>${escapeHtml(flow.interface || '—')}</dd></div>
        <div class="kv"><dt>Protocol</dt><dd>${escapeHtml(flow.protocol || '—')}</dd></div>
        <div class="kv"><dt>Source port</dt><dd>${escapeHtml(flow.src_port ?? '—')}</dd></div>
        <div class="kv"><dt>Dest. port</dt><dd>${escapeHtml(flow.dst_port ?? '—')}</dd></div>
        <div class="kv"><dt>Persisted</dt><dd>${persisted ? 'Yes' : 'No'}</dd></div>
        <div class="kv"><dt>Origin</dt><dd>${source === 'demo' ? 'Demo fixture' : 'Not recorded per row'}</dd></div>
      </dl>
    </div>

    <div class="inspector-section">
      <p class="section-title">Analyst review</p>
      <dl>
        <div class="kv"><dt>Status</dt><dd>${escapeHtml(review.status || 'Unreviewed')}</dd></div>
        <div class="kv"><dt>Updated</dt><dd>${review.updated_at ? fmtDateTime(review.updated_at) : '—'}</dd></div>
        <div class="kv"><dt>Updated by</dt><dd>${escapeHtml(review.updated_by || '—')}</dd></div>
      </dl>
      <div style="margin-top:8px">${reviewForm}</div>
    </div>

    <div class="inspector-section">
      <div class="inspector-actions">
        <button class="btn" type="button" id="btnCopyRecord">Copy record</button>
        <button class="btn" type="button" id="btnClearSelection">Clear selection</button>
      </div>
    </div>`;

  $('btnCopyRecord')?.addEventListener('click', async () => {
    const button = $('btnCopyRecord');
    try {
      await navigator.clipboard.writeText(JSON.stringify(flow, null, 2));
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = 'Copy record'; }, 1400);
    } catch {
      button.textContent = 'Copy failed';
      setTimeout(() => { button.textContent = 'Copy record'; }, 1400);
    }
  });

  $('btnClearSelection')?.addEventListener('click', () => {
    state.selectedId = null;
    renderQueue();
    renderInspector();
  });

  $('reviewForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = $('reviewForm');
    const message = $('reviewStatusMessage');
    const button = $('reviewSave');
    const status = $('reviewStatus').value;
    const note = $('reviewNote').value;
    button.disabled = true;
    message.textContent = 'Saving…';
    message.className = 'form-status';
    try {
      const response = await apiFetch(`/api/flows/${encodeURIComponent(flow.id)}/review`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, note }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
      flow.review = data.review || { ...review, status, note, updated_at: new Date().toISOString(), updated_by: 'local-user' };
      state.reviewFlash = {
        id: String(flow.id),
        text: data.changed === false ? 'No change' : 'Saved',
        cls: 'is-ok',
      };
      renderQueue();
      renderInspector();
      const flashId = String(flow.id);
      setTimeout(() => {
        if (state.reviewFlash && state.reviewFlash.id === flashId) {
          state.reviewFlash = null;
          renderInspector();
        }
      }, 4000);
    } catch (error) {
      message.textContent = error.message || 'Review could not be saved';
      message.className = 'form-status is-error';
    } finally {
      button.disabled = false;
    }
  });

  $('intelBody')?.addEventListener('click', (event) => {
    if (!event.target.closest('[data-intel-action="refresh"]')) return;
    delete state.intelCache[flow.src_ip];
    renderInspector();
  });

  ensureIntel(flow);
}

/* ---------- main render ---------- */

function renderAll() {
  renderHeader();
  renderQueueMeta();
  renderMix();
  renderSensorList();
  renderSensorOptions();
  renderVectors();
  renderFleet();
  renderIncidents();
  renderQueue();
  renderInspector();
  drawChart();
}

/* ---------- polling ---------- */

async function pollSnapshot({ initial = false, force = false } = {}) {
  if (state.paused && !initial && !force) return;
  const params = new URLSearchParams({ limit: initial ? '300' : '150' });
  if (initial) params.set('flagged_limit', '100');
  if (!initial && state.newestStoredId) params.set('after_id', String(state.newestStoredId));

  try {
    const response = await apiFetch(`/api/console/snapshot?${params.toString()}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Snapshot failed (${response.status})`);
    const data = await response.json();

    state.capture = data.capture || state.capture;
    state.stats = data.stats || state.stats;
    state.alertBudget = data.alert_budget || state.alertBudget;
    state.sensors = Array.isArray(data.sensors) ? data.sensors : state.sensors;
    state.sensorFleet = data.sensor_fleet || state.sensorFleet;
    state.captureInterface = data.capture_interface || state.captureInterface;

    if (initial) {
      state.flows = [];
      addFlows(data.flows || []);
      state.prevTotal = state.stats.total || 0;
      state.prevAttack = state.stats.attack || 0;
      state.lastTickAt = Date.now();
      state.pendingNew = 0;
      state.pendingAttack = 0;
      state.loading = false;
      recordBucket();
    } else {
      const added = addFlows(data.flows || []);
      if (added > 0 && state.follow) {
        const wrap = document.querySelector('.table-wrap');
        if (wrap) wrap.scrollTop = 0;
      }
      recordBucket();
    }

    state.lastError = null;
    state.lastSnapshotAt = Date.now();
    renderAll();
    if (initial || state.incidentTick % 3 === 0) pollIncidents();
    state.incidentTick = (state.incidentTick || 0) + 1;
  } catch (error) {
    state.lastError = error;
    state.loading = false;
    if (!state.flows.length) {
      const tbody = $('queueBody');
      tbody.innerHTML = `<tr class="state-row"><td colspan="7">
        <span class="state-title">Console could not reach the server</span>
        <span class="state-sub">${escapeHtml(error.message || 'Snapshot request failed')}. The last known view is unchanged.</span>
        <button class="btn" type="button" data-action="retry">Retry</button>
      </td></tr>`;
    }
    renderHeader();
    renderQueueMeta();
  }
}

async function pollIncidents() {
  try {
    const response = await apiFetch('/api/incidents?limit=50&open_only=true', { cache: 'no-store' });
    if (!response.ok) return;
    const data = await response.json();
    state.incidents = Array.isArray(data.incidents) ? data.incidents : [];
    const live = new Set(state.incidents.map((incident) => incident.incident_id));
    for (const key of Object.keys(state.incidentDrafts)) {
      if (!live.has(key)) delete state.incidentDrafts[key];
    }
    renderIncidents();
  } catch {
    // Incident polling is auxiliary; the flow snapshot remains the primary view.
  }
}

/* ---------- bundled 500-flow sample ---------- */

async function loadBundledSample() {
  const button = $('btnSampleLoad');
  if (!button || button.dataset.busy === 'true') return;
  const original = button.textContent;
  button.dataset.busy = 'true';
  button.disabled = true;
  button.textContent = 'Loading…';
  state.lastError = null;
  try {
    const response = await apiFetch('/api/load-sample', { method: 'POST' });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `Sample load failed (${response.status})`);
    const incidents = Number(data.incidents || 0);
    button.textContent = `Loaded ${data.accepted || 0} · ${incidents} incident${incidents === 1 ? '' : 's'}`;
    state.prevTotal = 0;
    state.prevAttack = 0;
    state.pendingNew = 0;
    state.pendingAttack = 0;
    await Promise.all([pollSnapshot({ force: true }), pollIncidents()]);
  } catch (error) {
    state.lastError = error;
    button.textContent = 'Sample failed';
    $('captureSummary').textContent = `Bundled sample failed: ${error.message || 'request failed'}.`;
    renderHeader();
  } finally {
    button.disabled = false;
    button.dataset.busy = 'false';
    setTimeout(() => { button.textContent = original; }, 5000);
  }
}

function startPolling() {
  pollSnapshot({ initial: true });
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(() => {
    if (!state.paused) pollSnapshot();
  }, POLL_MS);
}

/* ---------- demo feed ---------- */

async function emitDemo() {
  try {
    const response = await apiFetch('/api/simulate-flow', { method: 'POST' });
    if (response.status === 429) {
      $('captureSummary').textContent = 'Replay is being throttled by the server rate limit; it will keep trying.';
      return;
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `Demo request failed (${response.status})`);
    addFlow(data);
    renderAll();
  } catch (error) {
    stopDemo();
    $('captureSummary').textContent = `Replay stopped: ${error.message || 'request failed'}.`;
  }
}

function startDemo() {
  if (state.demoRunning) return;
  state.demoRunning = true;
  const button = $('btnDemo');
  button.setAttribute('aria-pressed', 'true');
  button.textContent = 'Stop replay';
  emitDemo();
  state.demoTimer = setInterval(emitDemo, DEMO_MS);
  renderHeader();
}

function stopDemo() {
  if (state.demoTimer) clearInterval(state.demoTimer);
  state.demoTimer = null;
  state.demoRunning = false;
  const button = $('btnDemo');
  if (button) {
    button.setAttribute('aria-pressed', 'false');
    button.textContent = 'Replay sample';
  }
  renderHeader();
}

/* ---------- actions ---------- */

function togglePause() {
  state.paused = !state.paused;
  if (state.paused) {
    renderQueueMeta();
  } else {
    state.prevTotal = state.stats.total || 0;
    state.prevAttack = state.stats.attack || 0;
    state.pendingNew = 0;
    state.pendingAttack = 0;
    state.lastTickAt = Date.now();
    pollSnapshot();
  }
  renderQueueMeta();
}

function exportCsv() {
  if (state.exporting) return;
  const flows = filteredFlows();
  if (!flows.length) {
    const button = $('btnExport');
    button.textContent = 'No rows';
    setTimeout(() => { button.textContent = 'Export CSV'; }, 1400);
    return;
  }

  state.exporting = true;
  const header = ['timestamp', 'id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'sensor_id', 'interface', 'predicted_label', 'is_attack', 'review_status', 'source'];
  const rows = flows.map((flow) => [
    flow.timestamp || '',
    flow.id,
    flow.src_ip || '',
    flow.src_port ?? '',
    flow.dst_ip || '',
    flow.dst_port ?? '',
    flow.protocol || '',
    flow.sensor_id || '',
    flow.interface || '',
    flow.predicted_label || '',
    flow.is_attack ? 'true' : 'false',
    flow.review?.status || 'Unreviewed',
    sourceOf(flow),
  ]);

  const csv = [header, ...rows]
    .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(','))
    .join('\r\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  link.href = url;
  link.download = `netshield-flows-${stamp}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  state.exporting = false;
}

function moveSelection(direction) {
  const flows = filteredFlows().slice(0, 200);
  if (!flows.length) return;
  const current = flows.findIndex((flow) => String(flow.id) === String(state.selectedId));
  let next = current + direction;
  if (current === -1) next = direction > 0 ? 0 : flows.length - 1;
  next = Math.max(0, Math.min(flows.length - 1, next));
  state.selectedId = flows[next].id;
  renderQueue();
  renderInspector();
  const row = document.querySelector(`#queueBody tr[data-id="${CSS.escape(String(state.selectedId))}"]`);
  row?.focus();
  row?.scrollIntoView({ block: 'nearest' });
}

function clearFilters() {
  state.filter = 'all';
  state.search = '';
  state.protocol = 'all';
  state.sensor = 'all';
  $('searchInput').value = '';
  $('protocolSelect').value = 'all';
  if ($('sensorSelect')) $('sensorSelect').value = 'all';
  document.querySelectorAll('[data-filter]').forEach((button) => {
    button.classList.toggle('is-active', button.dataset.filter === 'all');
  });
  renderQueue();
}

/* ---------- events ---------- */

let resizeTimer = null;

function bindEvents() {
  $('btnPause').addEventListener('click', togglePause);
  $('btnRefresh').addEventListener('click', () => pollSnapshot({ force: true }));
  $('btnExport').addEventListener('click', exportCsv);
  $('btnFollow').addEventListener('click', () => {
    state.follow = !state.follow;
    renderQueueMeta();
    if (state.follow) {
      const wrap = document.querySelector('.table-wrap');
      if (wrap) wrap.scrollTop = 0;
    }
  });

  const demoButton = $('btnDemo');
  demoButton.addEventListener('click', () => {
    if (state.demoRunning) stopDemo();
    else startDemo();
  });

  const sampleButton = $('btnSampleLoad');
  if (sampleButton) sampleButton.addEventListener('click', loadBundledSample);

  const incidentList = $('incidentList');
  if (incidentList) {
    const updateDraft = (event) => {
      const target = event.target.closest('[data-incident][data-field]');
      if (!target) return;
      const id = target.dataset.incident;
      state.incidentDrafts[id] = state.incidentDrafts[id] || {};
      state.incidentDrafts[id][target.dataset.field] = target.value;
    };
    incidentList.addEventListener('input', updateDraft);
    incidentList.addEventListener('change', updateDraft);
    incidentList.addEventListener('click', (event) => {
      const action = event.target.closest('[data-incident-action]');
      if (!action) return;
      const id = action.dataset.incident;
      if (action.dataset.incidentAction === 'save') saveIncidentTriage(id);
      else if (action.dataset.incidentAction === 'plan') loadContainmentPlan(id);
      else if (action.dataset.incidentAction === 'stix') downloadIncidentStix(id);
    });
  }

  document.querySelectorAll('[data-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      state.filter = button.dataset.filter;
      document.querySelectorAll('[data-filter]').forEach((other) => {
        other.classList.toggle('is-active', other === button);
      });
      renderQueue();
    });
  });

  $('searchInput').addEventListener('input', (event) => {
    state.search = event.target.value;
    renderQueue();
  });

  $('protocolSelect').addEventListener('change', (event) => {
    state.protocol = event.target.value;
    renderQueue();
  });

  $('sensorSelect').addEventListener('change', (event) => {
    state.sensor = event.target.value;
    renderQueue();
  });

  document.querySelectorAll('[data-window]').forEach((button) => {
    button.addEventListener('click', () => {
      state.window = Number(button.dataset.window) || 60;
      document.querySelectorAll('[data-window]').forEach((other) => {
        other.classList.toggle('is-active', other === button);
      });
      drawChart();
    });
  });

  $('queueBody').addEventListener('click', (event) => {
    const action = event.target.closest('[data-action]');
    if (action) {
      if (action.dataset.action === 'retry') pollSnapshot({ initial: !state.flows.length, force: true });
      if (action.dataset.action === 'clear-filters') clearFilters();
      if (action.dataset.action === 'start-demo') startDemo();
      return;
    }
    const row = event.target.closest('tr[data-id]');
    if (!row) return;
    state.selectedId = row.dataset.id;
    renderQueue();
    renderInspector();
    if (window.innerWidth <= 1220) {
      $('inspector').scrollIntoView({ block: 'start', behavior: 'smooth' });
    }
  });

  $('queueBody').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const row = event.target.closest('tr[data-id]');
    if (!row) return;
    event.preventDefault();
    state.selectedId = row.dataset.id;
    renderQueue();
    renderInspector();
  });

  document.addEventListener('keydown', (event) => {
    if (isTypingTarget(event.target)) {
      if (event.key === 'Escape') event.target.blur();
      return;
    }
    if (event.key === '/') {
      event.preventDefault();
      $('searchInput').focus();
    } else if (event.key.toLowerCase() === 'p') {
      event.preventDefault();
      togglePause();
    } else if (event.key.toLowerCase() === 'e') {
      event.preventDefault();
      exportCsv();
    } else if (event.key.toLowerCase() === 'j') {
      event.preventDefault();
      moveSelection(1);
    } else if (event.key.toLowerCase() === 'k') {
      event.preventDefault();
      moveSelection(-1);
    } else if (event.key === 'Escape') {
      state.selectedId = null;
      renderQueue();
      renderInspector();
    }
  });

  window.addEventListener('resize', () => {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(drawChart, 120);
  });

  window.addEventListener('themeChanged', () => {
    syncThemeLabel();
    drawChart();
  });
}

function syncThemeLabel() {
  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  const label = $('themeLabel');
  if (label) label.textContent = theme === 'light' ? 'Light' : 'Dark';
}

function startClock() {
  const clock = $('consoleClock');
  const tick = () => {
    clock.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
    clock.title = 'Local time';
    // Keep relative timestamps fresh without re-fetching.
    if (state.lastSnapshotAt) renderQueueMeta();
  };
  tick();
  setInterval(tick, 1000);
}

function init() {
  syncThemeLabel();
  startClock();
  bindEvents();
  renderHeader();
  renderQueueMeta();
  renderMix();
  renderVectors();
  renderFleet();
  renderIncidents();
  renderInspector();
  startPolling();

  // Demo availability arrives with the first snapshot; re-check once it lands.
  setTimeout(() => {
    if (state.capture?.demo_stream_enabled) $('btnDemo').hidden = false;
  }, 1200);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
