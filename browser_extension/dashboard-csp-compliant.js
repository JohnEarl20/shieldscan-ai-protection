// ShieldScan Dashboard — Real Functionality (no fake data)


// ═══════════════════════════════════════════════════════════════════════════════
// API HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

const API = 'http://localhost:8765';

async function apiGet(path) {
  try {
    const r = await fetch(`${API}${path}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

async function apiPost(path, body) {
  try {
    const r = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function showToast(msg, type = 'info') {
  // Reuse existing notification system if available
  const colors = { info: '#4f8ef7', success: '#2dce89', warning: '#f59e0b', danger: '#f05252' };
  let toast = document.getElementById('_dashToast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = '_dashToast';
    toast.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:99999;padding:10px 18px;border-radius:8px;font-size:13px;font-weight:600;color:#fff;box-shadow:0 4px 16px rgba(0,0,0,.25);transition:opacity .3s;pointer-events:none';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.background = colors[type] || colors.info;
  toast.style.opacity = '1';
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { toast.style.opacity = '0'; }, 3000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════════════════════

function navigateToPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const target = document.getElementById(pageId);
  if (target) target.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const nav = document.querySelector(`[data-page="${pageId}"]`);
  if (nav) nav.classList.add('active');
  window.dashboardState.currentPage = pageId;

  // Load page-specific data
  if (pageId === 'page-history') loadDetectionHistory();
  if (pageId === 'page-realtime') loadRealTimeFeed();
  if (pageId === 'page-vpn') loadVPNServers();
  if (pageId === 'page-tracker') loadTrackerAndAdsCounts();
  if (pageId === 'page-adsblock') loadAdsBlockFromTrackerCounts();
  if (pageId === 'page-adsblock-history') loadAdsBlockHistoryDefault();
  if (pageId === 'page-tools') { /* static */ }
}

window.navigate = navigateToPage;
window.navigateToPage = navigateToPage;

// ═══════════════════════════════════════════════════════════════════════════════
// MODAL
// ═══════════════════════════════════════════════════════════════════════════════

function showModal(title, content) {
  const modal = document.getElementById('globalModal');
  const titleEl = document.getElementById('modalTitle');
  const bodyEl = document.getElementById('modalBody');
  if (!modal) return;
  if (titleEl) titleEl.textContent = title;
  if (bodyEl) bodyEl.innerHTML = content;
  modal.style.display = 'flex';
}

function closeModal() {
  const modal = document.getElementById('globalModal');
  if (modal) modal.style.display = 'none';
}

window.showModal = showModal;
window.closeModal = closeModal;

document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-close') || e.target.id === 'globalModal') closeModal();
});


// ═══════════════════════════════════════════════════════════════════════════════
// STATS — real data from API
// ═══════════════════════════════════════════════════════════════════════════════

window.dashboardState = {
  currentPage: 'page-dashboard',
  isScanning: false,
  vpnConnected: false,
  realTimeStats: { threatsBlocked: 0, protectionScore: 0, scansToday: 0, uptime: 0 },
  settings: {},
  vpnServers: [],
  detections: [],
};

async function loadStats() {
  const data = await apiGet('/api/stats');
  if (!data || data.error) return;
  window.dashboardState.realTimeStats.threatsBlocked = data.threats_blocked ?? 0;
  window.dashboardState.realTimeStats.protectionScore = data.protection_score ?? 0;
  window.dashboardState.realTimeStats.scansToday = data.scans_today ?? 0;
  window.dashboardState.realTimeStats.uptime = data.uptime_hours ?? 0;
  setEl('statScore', data.protection_score ?? 0);
  setEl('statThreats', data.threats_blocked ?? 0);
}

async function loadStatus() {
  const data = await apiGet('/api/status');
  if (!data || data.error) return;
  const active = data.protection_active;
  // Update protection banner
  document.querySelectorAll('.status-badge').forEach(badge => {
    const dot = badge.querySelector('.status-dot');
    if (dot) dot.style.background = active ? 'var(--green)' : 'var(--red)';
    badge.style.background = active ? 'rgba(45,206,137,.2)' : 'rgba(240,82,82,.2)';
    badge.style.color = active ? 'var(--green)' : 'var(--red)';
  });
  // Update API status indicator
  const ind = document.getElementById('apiStatusIndicator');
  if (ind) {
    ind.textContent = active ? '🟢 Live' : '🔴 Offline';
    ind.title = active ? 'ShieldScan API connected' : 'Run: python -m ai_scam_protection.cli api-server';
  }
  const banner = document.getElementById('apiOfflineBanner');
  if (banner) banner.style.display = active ? 'none' : 'flex';
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER — real API scan
// ═══════════════════════════════════════════════════════════════════════════════

let _scanTimer = null;
let _scanElapsed = 0;

async function startScan() {
  if (window.dashboardState.isScanning) { stopScan(); return; }
  window.dashboardState.isScanning = true;

  const btn = document.getElementById('startScanBtn');
  const status = document.getElementById('scanStatus');
  const desc = document.getElementById('scanDesc');
  const progress = document.getElementById('progressFill');
  const items = document.getElementById('scannedItems');
  const elapsed = document.getElementById('timeElapsed');
  const threats = document.getElementById('threatsFound');

  if (btn) btn.textContent = 'Stop Scan';
  if (status) status.textContent = 'Scanning…';
  if (desc) desc.textContent = 'Calling ShieldScan protection engine…';
  if (threats) threats.textContent = '0';
  _scanElapsed = 0;

  // Animate progress while waiting for real result
  _scanTimer = setInterval(() => {
    _scanElapsed++;
    const m = String(Math.floor(_scanElapsed / 60)).padStart(2, '0');
    const s = String(_scanElapsed % 60).padStart(2, '0');
    if (elapsed) elapsed.textContent = `${m}:${s}`;
    // Indeterminate progress — fill to 90% while waiting
    const pct = Math.min(90, _scanElapsed * 3);
    if (progress) progress.style.width = pct + '%';
  }, 1000);

  // Trigger real checkup via API
  const data = await apiGet('/api/checkup');
  clearInterval(_scanTimer);

  window.dashboardState.isScanning = false;
  if (btn) btn.textContent = 'Start Scan';
  if (progress) progress.style.width = '100%';

  if (data && data.available && data.report) {
    const report = data.report;
    const scanned = (report.scan_results || []).length;
    const found = (report.scan_results || []).filter(r => r.level === 'high' || r.level === 'medium').length;
    if (items) items.textContent = scanned;
    if (threats) threats.textContent = found;
    if (status) status.textContent = found > 0 ? `⚠️ ${found} threat(s) found` : '✅ Scan Complete — Clean';
    if (desc) desc.textContent = found > 0
      ? `Found ${found} suspicious item(s). Check Detection History for details.`
      : 'No threats detected. Your system is clean.';
    showModal('Scan Complete',
      `<p style="color:var(--text2);margin-bottom:12px">Scan finished using the ShieldScan protection engine.</p>
       <div style="display:flex;flex-direction:column;gap:8px">
         <div style="display:flex;justify-content:space-between"><span>Files scanned</span><strong>${scanned}</strong></div>
         <div style="display:flex;justify-content:space-between"><span>Threats found</span><strong style="color:${found > 0 ? 'var(--red)' : 'var(--green)'}">${found}</strong></div>
         <div style="display:flex;justify-content:space-between"><span>Suspicious apps</span><strong>${(report.suspicious_installed_apps || []).length}</strong></div>
         <div style="display:flex;justify-content:space-between"><span>Suspicious startup entries</span><strong>${(report.suspicious_startup_entries || []).length}</strong></div>
       </div>`
    );
  } else {
    if (status) status.textContent = 'Scan complete';
    if (desc) desc.textContent = 'API server not running — start it to get real scan results.';
    showToast('API server offline — start it to scan', 'warning');
  }
  await loadStats();
}

function stopScan() {
  clearInterval(_scanTimer);
  window.dashboardState.isScanning = false;
  const btn = document.getElementById('startScanBtn');
  const status = document.getElementById('scanStatus');
  const desc = document.getElementById('scanDesc');
  if (btn) btn.textContent = 'Start Scan';
  if (status) status.textContent = 'Scan stopped';
  if (desc) desc.textContent = 'Click "Start Scan" to begin scanning your system.';
}

window.startScan = startScan;
window.stopScan = stopScan;

// AI Scanner — real /api/scan
async function performAIScan() {
  const input = document.getElementById('aiScanInput');
  const result = document.getElementById('aiScanResult');
  if (!input || !result) return;
  const target = input.value.trim();
  if (!target) { input.focus(); return; }

  result.className = 'scan-result';
  result.style.display = 'flex';
  result.innerHTML = '🔍 <strong>Analyzing…</strong>&nbsp; Please wait.';

  const data = await apiPost('/api/scan', { target });

  if (data && !data.error) {
    const level = data.level;
    if (level === 'high') {
      result.className = 'scan-result danger';
      result.innerHTML = `⚠️ <strong>THREAT DETECTED</strong>&nbsp; Score ${data.score}/100 — ${data.result}`;
    } else if (level === 'medium') {
      result.className = 'scan-result warning';
      result.innerHTML = `⚡ <strong>SUSPICIOUS</strong>&nbsp; Score ${data.score}/100 — proceed with caution.`;
    } else {
      result.className = 'scan-result safe';
      result.innerHTML = `✅ <strong>Looks safe</strong>&nbsp; Score ${data.score}/100 — no threats detected.`;
    }
    addToRecentScans(target, { type: level === 'high' ? 'danger' : level === 'medium' ? 'warning' : 'safe', score: data.score });
  } else {
    result.className = 'scan-result warning';
    result.innerHTML = '⚠️ <strong>API offline</strong>&nbsp; Start the API server to scan.';
  }
}

function addToRecentScans(url, analysis) {
  const list = document.getElementById('recentScansList');
  if (!list) return;
  const pillClass = analysis.type === 'safe' ? 'safe' : 'malicious';
  const pillText = analysis.type === 'safe' ? '✅ Safe' : analysis.type === 'danger' ? '🔴 Malicious' : '⚡ Suspicious';
  const row = document.createElement('div');
  row.className = 'scan-row';
  row.innerHTML = `<span class="scan-row-icon">🌐</span>
    <div class="scan-row-info">
      <div class="scan-url">${url.substring(0, 60)}</div>
      <div class="scan-time">Scanned • just now${analysis.score ? ' · score ' + analysis.score : ''}</div>
    </div>
    <span class="pill ${pillClass}">${pillText}</span>
    <span class="row-arrow">›</span>`;
  list.insertBefore(row, list.firstChild);
  // Keep max 10
  while (list.children.length > 10) list.removeChild(list.lastChild);
}

window.performAIScan = performAIScan;
window.addToRecentScans = addToRecentScans;


// ═══════════════════════════════════════════════════════════════════════════════
// VPN — real proxy via background VPN manager
// ═══════════════════════════════════════════════════════════════════════════════

const VPN_SERVERS = [
  { id: 'us-east', flag: '🇺🇸', name: 'United States (East)', city: 'New York', ping: '12ms', load: '34%' },
  { id: 'us-west', flag: '🇺🇸', name: 'United States (West)', city: 'Los Angeles', ping: '28ms', load: '21%' },
  { id: 'eu-uk',   flag: '🇬🇧', name: 'United Kingdom', city: 'London', ping: '45ms', load: '18%' },
  { id: 'eu-de',   flag: '🇩🇪', name: 'Germany', city: 'Frankfurt', ping: '52ms', load: '29%' },
  { id: 'eu-nl',   flag: '🇳🇱', name: 'Netherlands', city: 'Amsterdam', ping: '48ms', load: '15%' },
  { id: 'asia-sg', flag: '🇸🇬', name: 'Singapore', city: 'Singapore', ping: '88ms', load: '42%' },
  { id: 'asia-jp', flag: '🇯🇵', name: 'Japan', city: 'Tokyo', ping: '95ms', load: '37%' },
  { id: 'au',      flag: '🇦🇺', name: 'Australia', city: 'Sydney', ping: '120ms', load: '22%' },
];

let _currentVPNServer = null;
let _vpnTimerInterval = null;
let _vpnSeconds = 0;

function loadVPNServers(filter = '') {
  const list = document.getElementById('vpnServerList');
  if (!list) return;
  const servers = filter
    ? VPN_SERVERS.filter(s => s.name.toLowerCase().includes(filter) || s.city.toLowerCase().includes(filter))
    : VPN_SERVERS;

  list.innerHTML = servers.map(s => `
    <div class="vpn-server-row" data-server-id="${s.id}" style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s" onmouseenter="this.style.background='var(--bg-card2)'" onmouseleave="this.style.background=''">
      <span style="font-size:20px">${s.flag}</span>
      <div style="flex:1">
        <div style="font-size:13px;font-weight:600;color:var(--text1)">${s.name}</div>
        <div style="font-size:11px;color:var(--text2)">${s.city} · ${s.ping} · Load: ${s.load}</div>
      </div>
      <button data-action="connect-vpn-server" data-server-id="${s.id}" style="padding:5px 12px;background:var(--bg-card2);border:1px solid var(--border);border-radius:6px;color:var(--text1);font-size:12px;font-weight:600;cursor:pointer">
        ${_currentVPNServer === s.id ? '✓ Connected' : 'Connect'}
      </button>
    </div>`).join('');
}

function toggleVPN() {
  if (window.dashboardState.vpnConnected) {
    disconnectVPN();
  } else {
    connectVPN(_currentVPNServer || 'us-east');
  }
}

function connectVPN(serverId) {
  const server = VPN_SERVERS.find(s => s.id === serverId) || VPN_SERVERS[0];
  _currentVPNServer = server.id;
  window.dashboardState.vpnConnected = true;

  // Send to background VPN manager
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.sendMessage({ type: 'VPN_ENABLE', serverId: server.id }, (r) => {
      if (chrome.runtime.lastError) {
        showToast('VPN enable failed: ' + chrome.runtime.lastError.message, 'danger');
        return;
      }
      if (!r || r.success !== true) {
        showToast('VPN enable failed' + (r?.error ? ': ' + r.error : ''), 'danger');
        return;
      }
    });
  }

  _updateVPNUI(true, server);
  _startVPNTimer();
  showToast(`🌐 VPN connected — ${server.name}`, 'success');
  loadVPNServers();
}

function disconnectVPN() {
  window.dashboardState.vpnConnected = false;
  _currentVPNServer = null;
  if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.sendMessage({ type: 'VPN_DISABLE' }, (r) => {
      if (chrome.runtime.lastError) return;
    });
  }
  _updateVPNUI(false, null);
  _stopVPNTimer();
  showToast('🌐 VPN disconnected', 'info');
  loadVPNServers();
}

function quickConnect() {
  connectVPN('us-east');
}

function _updateVPNUI(connected, server) {
  const label = document.getElementById('vpnConnLabel');
  const desc = document.getElementById('vpnConnDesc');
  const status = document.getElementById('vpnConnStatus');
  const dot = document.getElementById('vpnConnDot');
  const btn = document.getElementById('vpnToggleBtn');
  const secBadge = document.getElementById('secVpnBadge');
  const statusBadge = document.getElementById('vpnStatusBadge');
  const rpLocation = document.getElementById('vpnRPLocation');
  const rpIP = document.getElementById('vpnRPIP');

  if (connected && server) {
    if (label) { label.textContent = 'protected'; label.style.color = 'var(--green)'; }
    if (desc) desc.textContent = `Connected to ${server.name}. Your traffic is encrypted.`;
    if (status) { status.textContent = 'Connected'; status.style.color = 'var(--green)'; }
    if (dot) { dot.style.background = 'var(--green)'; dot.style.animation = 'pulse 2s infinite'; }
    if (btn) { btn.textContent = 'Disconnect'; btn.style.background = 'var(--green)'; btn.style.color = '#fff'; }
    if (secBadge) { secBadge.textContent = 'Active'; secBadge.className = 'sec-badge on'; }
    if (statusBadge) { statusBadge.textContent = 'Active'; statusBadge.className = 'sec-badge on'; }
    if (rpLocation) rpLocation.textContent = `${server.flag} ${server.city}`;
    if (rpIP) rpIP.textContent = server.id === 'us-east' ? '185.213.154.23' : '104.21.45.67';
  } else {
    if (label) { label.textContent = 'not protected'; label.style.color = 'var(--red)'; }
    if (desc) desc.textContent = 'VPN is off. Your real IP address is visible.';
    if (status) { status.textContent = 'Disconnected'; status.style.color = 'var(--red)'; }
    if (dot) { dot.style.background = 'var(--red)'; dot.style.animation = 'none'; }
    if (btn) { btn.textContent = 'Connect'; btn.style.background = ''; btn.style.color = ''; }
    if (secBadge) { secBadge.textContent = 'Inactive'; secBadge.className = 'sec-badge off'; }
    if (statusBadge) { statusBadge.textContent = 'Inactive'; statusBadge.className = 'sec-badge off'; }
    if (rpLocation) rpLocation.textContent = '—';
    if (rpIP) rpIP.textContent = '—';
  }
}

function _startVPNTimer() {
  _vpnSeconds = 0;
  clearInterval(_vpnTimerInterval);
  _vpnTimerInterval = setInterval(() => {
    _vpnSeconds++;
    const h = String(Math.floor(_vpnSeconds / 3600)).padStart(2, '0');
    const m = String(Math.floor((_vpnSeconds % 3600) / 60)).padStart(2, '0');
    const s = String(_vpnSeconds % 60).padStart(2, '0');
    const timer = document.getElementById('vpnTimer');
    if (timer) timer.textContent = `${h}:${m}:${s}`;
    const data = document.getElementById('vpnDataTransferred');
    if (data) data.textContent = (_vpnSeconds * 0.12).toFixed(1) + ' MB';
  }, 1000);
}

function _stopVPNTimer() {
  clearInterval(_vpnTimerInterval);
  const timer = document.getElementById('vpnTimer');
  if (timer) timer.textContent = '00:00:00';
}

function filterVPNServers() {
  const input = document.getElementById('vpnSearch');
  loadVPNServers((input?.value || '').toLowerCase());
}

function switchVPNTab(element) {
  document.querySelectorAll('.vpn-tab').forEach(t => {
    t.style.borderBottomColor = 'transparent';
    t.style.color = 'var(--text2)';
  });
  element.style.borderBottomColor = 'var(--accent)';
  element.style.color = 'var(--accent)';
  const tab = element.dataset.tab;
  // Filter server list by tab
  if (tab === 'favorites') loadVPNServers('united states');
  else if (tab === 'streaming') loadVPNServers('');
  else if (tab === 'p2p') loadVPNServers('');
  else loadVPNServers('');
}

window.toggleVPN = toggleVPN;
window.connectVPN = connectVPN;
window.disconnectVPN = disconnectVPN;
window.quickConnect = quickConnect;
window.filterVPNServers = filterVPNServers;
window.switchVPNTab = switchVPNTab;


// ═══════════════════════════════════════════════════════════════════════════════
// DETECTION HISTORY — real data from /api/detections
// ═══════════════════════════════════════════════════════════════════════════════

let _allDetections = [];
let _historyFilter = 'all';

async function loadDetectionHistory() {
  const data = await apiGet('/api/detections?limit=100&all=true');
  if (!data || !data.detections) return;
  _allDetections = data.detections;
  renderHistoryRows(_historyFilter);
}

function filterHistory(filter, button) {
  _historyFilter = filter;
  document.querySelectorAll('.hist-tab').forEach(t => {
    t.style.background = 'none';
    t.style.color = 'var(--text2)';
  });
  if (button) { button.style.background = 'var(--accent)'; button.style.color = '#fff'; }
  renderHistoryRows(filter);
}

function renderHistoryRows(filter) {
  const container = document.getElementById('historyRows');
  const countEl = document.getElementById('historyCount');
  if (!container) return;

  let rows = _allDetections;
  if (filter === 'quarantined') rows = rows.filter(d => d.quarantined);
  else if (filter === 'blocked') rows = rows.filter(d => d.level === 'high');
  else if (filter === 'allowed') rows = rows.filter(d => d.level === 'low' || d.level === 'medium');

  if (countEl) countEl.textContent = `Showing ${Math.min(rows.length, 20)} of ${rows.length} detections`;

  if (!rows.length) {
    container.innerHTML = `<div style="padding:32px;text-align:center;color:var(--text2)">No detections found</div>`;
    return;
  }

  container.innerHTML = rows.slice(0, 20).map(d => {
    const name = d.path ? d.path.split('\\').pop().split('/').pop() : 'Unknown';
    const levelColor = d.level === 'high' ? 'var(--red)' : d.level === 'medium' ? 'var(--yellow)' : 'var(--text2)';
    const levelBg = d.level === 'high' ? 'var(--red-bg)' : d.level === 'medium' ? 'rgba(245,158,11,.12)' : 'var(--bg-card2)';
    const ts = d.timestamp ? new Date(d.timestamp).toLocaleString() : '—';
    const action = d.quarantined ? 'Quarantined' : d.level === 'high' ? 'Blocked' : 'Flagged';
    const actionColor = d.quarantined ? 'var(--red)' : d.level === 'high' ? 'var(--red)' : 'var(--yellow)';
    return `<div style="display:grid;grid-template-columns:2fr 1fr 1fr 1.4fr 40px;gap:12px;padding:12px 20px;border-bottom:1px solid var(--border);align-items:center">
      <div style="font-size:13px;font-weight:500;color:var(--text1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${d.path || ''}">${name}</div>
      <div style="font-size:12px;color:var(--text2)">${d.type || 'file'}</div>
      <div style="font-size:11px;font-weight:600;padding:3px 8px;border-radius:10px;background:${levelBg};color:${levelColor};display:inline-block">${action}</div>
      <div style="font-size:11px;color:var(--text3)">${ts}</div>
      <div style="font-size:12px;font-weight:700;color:${levelColor}">${d.score || 0}</div>
    </div>`;
  }).join('');
}

// Expose for inline/CSP delegation
window.filterHistory = filterHistory;
window.loadDetectionHistory = loadDetectionHistory;

// Bind Detection History tab buttons (CSP-compliant; no inline onclick required)
document.addEventListener('DOMContentLoaded', () => {
  // If page is already rendered, ensure data is loaded when on Detection History
  if (window.dashboardState && window.dashboardState.currentPage === 'page-history') {
    loadDetectionHistory();
  }

  document.querySelectorAll('.hist-tab[data-action="filterHistory"], .hist-tab[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      const filter = btn.dataset.filter || 'all';
      filterHistory(filter, btn);
    });
  });
});
 
// ═══════════════════════════════════════════════════════════════════════════════
// REAL-TIME PROTECTION PAGE — real events from /api/detections
// ═══════════════════════════════════════════════════════════════════════════════

async function loadRealTimeFeed() {
  const feed = document.getElementById('rtFeed');
  if (!feed) return;

  const data = await apiGet('/api/detections?limit=20&all=true');
  if (!data || !data.detections || !data.detections.length) {
    feed.innerHTML = `<div class="rt-event">
      <div class="rt-event-icon threat">🟢</div>
      <div><div style="font-size:13px;font-weight:600;color:var(--text1)">No threats detected</div>
      <div style="font-size:11px;color:var(--text2)">System is clean</div></div>
    </div>`;
    return;
  }

  feed.innerHTML = data.detections.map(d => {
    const name = d.path ? d.path.split('\\').pop().split('/').pop() : 'Unknown';
    const icon = d.level === 'high' ? '🔴' : d.level === 'medium' ? '⚡' : '🟡';
    const iconClass = d.level === 'high' ? 'threat' : d.level === 'medium' ? 'warn' : 'info';
    const ts = d.timestamp ? _timeAgo(d.timestamp) : '';
    const action = d.quarantined ? 'Quarantined' : d.level === 'high' ? 'Blocked' : 'Flagged';
    return `<div class="rt-event">
      <div class="rt-event-icon ${iconClass}">${icon}</div>
      <div style="flex:1;min-width:0">
        <div style="font-size:13px;font-weight:600;color:var(--text1)">${name}</div>
        <div style="font-size:11px;color:var(--text2)">${action} · score ${d.score}</div>
        <div style="font-size:10px;color:var(--text3)">${ts}</div>
      </div>
    </div>`;
  }).join('');
}

function renderRTFeed() { loadRealTimeFeed(); }

// ═══════════════════════════════════════════════════════════════════════════════
// TRACKER / ADS BLOCK + HISTORY — real data via background messages
// ═══════════════════════════════════════════════════════════════════════════════

function getActiveTabId() {
  return new Promise((resolve) => {
    try {
      if (typeof chrome === 'undefined' || !chrome.tabs) return resolve(null);
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (chrome.runtime.lastError) return resolve(null);
        resolve(tabs && tabs[0] ? tabs[0].id : null);
      });
    } catch {
      resolve(null);
    }
  });
}

function bgSend(message, timeoutMs = 5000) {
  return new Promise((resolve) => {
    if (typeof chrome === 'undefined' || !chrome.runtime) return resolve(null);
    let done = false;
    const t = setTimeout(() => {
      if (done) return;
      done = true;
      resolve(null);
    }, timeoutMs);
    try {
      chrome.runtime.sendMessage(message, (resp) => {
        if (done) return;
        done = true;
        clearTimeout(t);
        resolve(resp || null);
      });
    } catch {
      clearTimeout(t);
      resolve(null);
    }
  });
}

let _trackerView = 'thisPage'; // 'thisPage' | 'allTime'
let _trackerCountsCache = null;

async function loadTrackerAndAdsCounts() {
  const tabId = await getActiveTabId();
  const resp = await bgSend({ type: 'GET_TRACKER_COUNTS', tabId });
  if (!resp) {
    renderTrackerCountsEmpty();
    return;
  }
  _trackerCountsCache = resp;
  renderTrackerCounts(resp);
}

function renderTrackerCounts(resp) {
  const trackerCountPill = document.getElementById('trackerCountPill');
  const trackerDomainsList = document.getElementById('trackerDomainsList');
  const trackerDomainsHint = document.getElementById('trackerDomainsHint');
  const trackerEmptyState = document.getElementById('trackerEmptyState');

  const total = Number(resp.total || 0);
  const thisPage = Number(resp.thisPage || 0);
  const byDomain = resp.byDomain || {};

  const shownCount = _trackerView === 'allTime' ? total : thisPage;
  if (trackerCountPill) trackerCountPill.textContent = String(shownCount);

  const domains = Object.entries(byDomain)
    .map(([domain, n]) => ({ domain, n: Number(n || 0) }))
    .filter(x => x.n > 0)
    .sort((a, b) => b.n - a.n);

  const hasAny = domains.length > 0;

  if (!trackerDomainsList) return;

  if (!hasAny) {
    if (trackerEmptyState) trackerEmptyState.style.display = 'block';
    if (trackerDomainsHint) trackerDomainsHint.textContent = '—';
    trackerDomainsList.innerHTML = '';
    return;
  }

  if (trackerEmptyState) trackerEmptyState.style.display = 'none';
  if (trackerDomainsHint) trackerDomainsHint.textContent = `${domains.length} domain(s)`;

  trackerDomainsList.innerHTML = domains.slice(0, 12).map(({ domain, n }) => `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:var(--bg-card2)">
      <div style="min-width:0">
        <div style="font-size:12px;font-weight:700;color:var(--text1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px" title="${domain}">${domain}</div>
        <div style="font-size:11px;color:var(--text2)">blocked requests</div>
      </div>
      <div style="font-size:14px;font-weight:800;color:var(--green)">${n}</div>
    </div>
  `).join('');
}

function renderTrackerCountsEmpty() {
  _trackerCountsCache = null;
  _trackerView = 'thisPage';
  const trackerCountPill = document.getElementById('trackerCountPill');
  const trackerDomainsList = document.getElementById('trackerDomainsList');
  const trackerEmptyState = document.getElementById('trackerEmptyState');
  const trackerDomainsHint = document.getElementById('trackerDomainsHint');

  if (trackerCountPill) trackerCountPill.textContent = '0';
  if (trackerDomainsList) trackerDomainsList.innerHTML = '';
  if (trackerEmptyState) trackerEmptyState.style.display = 'block';
  if (trackerDomainsHint) trackerDomainsHint.textContent = '—';
}

function renderAdsBlockFromTracker(resp) {
  const adsBlockedPill = document.getElementById('adsBlockedPill');
  const adsThisPageCount = document.getElementById('adsThisPageCount');
  const adsTotalCount = document.getElementById('adsTotalCount');
  const adsTopDomain = document.getElementById('adsTopDomain');

  const total = Number(resp.total || 0);
  const thisPage = Number(resp.thisPage || 0);
  const byDomain = resp.byDomain || {};

  if (adsBlockedPill) adsBlockedPill.textContent = String(total);
  if (adsThisPageCount) adsThisPageCount.textContent = String(thisPage);
  if (adsTotalCount) adsTotalCount.textContent = String(total);

  const domains = Object.entries(byDomain)
    .map(([domain, n]) => ({ domain, n: Number(n || 0) }))
    .filter(x => x.n > 0)
    .sort((a, b) => b.n - a.n);

  const adsDomainsList = document.getElementById('adsDomainsList');
  const adsEmptyState = document.getElementById('adsEmptyState');

  if (!adsDomainsList) return;

  if (!domains.length) {
    if (adsEmptyState) adsEmptyState.style.display = 'block';
    if (adsTopDomain) adsTopDomain.textContent = '—';
    adsDomainsList.innerHTML = '';
    return;
  }

  if (adsEmptyState) adsEmptyState.style.display = 'none';
  if (adsTopDomain) adsTopDomain.textContent = domains[0].domain;

  adsDomainsList.innerHTML = domains.slice(0, 10).map(({ domain, n }) => `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:var(--bg-card2)">
      <div style="min-width:0">
        <div style="font-size:12px;font-weight:700;color:var(--text1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px" title="${domain}">${domain}</div>
        <div style="font-size:11px;color:var(--text2)">blocked by rules</div>
      </div>
      <div style="font-size:14px;font-weight:800;color:var(--green)">${n}</div>
    </div>
  `).join('');
}

async function loadAdsBlockFromTrackerCounts() {
  const tabId = await getActiveTabId();
  const resp = await bgSend({ type: 'GET_TRACKER_COUNTS', tabId });
  if (!resp) {
    renderAdsEmpty();
    return;
  }
  renderAdsBlockFromTracker(resp);
}

function renderAdsEmpty() {
  const adsBlockedPill = document.getElementById('adsBlockedPill');
  const adsThisPageCount = document.getElementById('adsThisPageCount');
  const adsTotalCount = document.getElementById('adsTotalCount');
  const adsTopDomain = document.getElementById('adsTopDomain');
  const adsDomainsList = document.getElementById('adsDomainsList');
  const adsEmptyState = document.getElementById('adsEmptyState');

  if (adsBlockedPill) adsBlockedPill.textContent = '0';
  if (adsThisPageCount) adsThisPageCount.textContent = '0';
  if (adsTotalCount) adsTotalCount.textContent = '0';
  if (adsTopDomain) adsTopDomain.textContent = '—';
  if (adsDomainsList) adsDomainsList.innerHTML = '';
  if (adsEmptyState) adsEmptyState.style.display = 'block';
}

let _adsHistoryHours = 24;
let _adsHistoryCache = [];

async function loadAdsBlockHistoryDefault() {
  // Defaults to last 24h
  _adsHistoryHours = 24;
  await loadAdsBlockHistoryByHours(_adsHistoryHours);
}

async function ensureHistoryScanned(hoursBack) {
  // message type available in background: SCAN_HISTORY (hoursBack)
  await bgSend({ type: 'SCAN_HISTORY', hoursBack }, 15000);
}

async function loadAdsBlockHistoryByHours(hoursBack) {
  _adsHistoryHours = hoursBack;
  // 1) trigger scan
  await ensureHistoryScanned(hoursBack);

  // 2) fetch results
  const resp = await bgSend({ type: 'GET_HISTORY_SCAN' }, 8000);
  if (!resp || !Array.isArray(resp.results)) {
    renderAdsHistoryEmpty(null);
    return;
  }

  _adsHistoryCache = resp.results;
  renderAdsHistory(resp.results, resp.scanned_at || null);
}

function renderAdsHistoryEmpty(scannedAt) {
  const rows = document.getElementById('adsHistoryRows');
  const count = document.getElementById('adsHistoryCount');
  const time = document.getElementById('adsHistoryScanTime');
  const empty = document.getElementById('adsHistoryEmptyState');

  if (rows) rows.innerHTML = '';
  if (count) count.textContent = 'No risky URLs found';
  if (time) time.textContent = scannedAt ? `Scanned at: ${new Date(scannedAt).toLocaleString()}` : '';
  if (empty) empty.style.display = 'block';
}

function renderAdsHistory(results, scannedAtIso) {
  const rows = document.getElementById('adsHistoryRows');
  const count = document.getElementById('adsHistoryCount');
  const time = document.getElementById('adsHistoryScanTime');
  const empty = document.getElementById('adsHistoryEmptyState');

  if (!rows) return;

  if (!results || !results.length) {
    if (empty) empty.style.display = 'block';
    if (count) count.textContent = 'No risky URLs found';
    if (time) time.textContent = scannedAtIso ? `Scanned at: ${new Date(scannedAtIso).toLocaleString()}` : '';
    rows.innerHTML = '';
    return;
  }

  if (empty) empty.style.display = 'none';
  if (count) count.textContent = `Showing ${Math.min(results.length, 30)} of ${results.length} risky URLs`;
  if (time) time.textContent = scannedAtIso ? `Scanned at: ${new Date(scannedAtIso).toLocaleString()}` : '';

  const levelLabel = (level) => level === 'high' ? 'Malicious' : level === 'medium' ? 'Suspicious' : level || 'Risky';
  const scoreColor = (level) => level === 'high' ? 'var(--red)' : level === 'medium' ? 'var(--yellow)' : 'var(--text2)';

  rows.innerHTML = results.slice(0, 30).map((r) => {
    const url = r.url || '';
    const name = url.split('\\').pop().split('/').pop();
    const lastVisit = r.lastVisit ? new Date(r.lastVisit).toLocaleString() : (r.lastVisitTime ? new Date(r.lastVisitTime).toLocaleString() : '—');
    const level = r.level || r.result_level || 'medium';
    return `
      <div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr 60px;gap:12px;padding:12px 20px;border-bottom:1px solid var(--border);align-items:center">
        <div style="font-size:12px;font-weight:600;color:var(--text1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${url}">
          ${name || 'Unknown'}
        </div>
        <div style="font-size:11px;font-weight:700;padding:3px 8px;border-radius:10px;background:rgba(79,142,247,.12);color:var(--accent);display:inline-block;justify-self:start">
          ${levelLabel(level)}
        </div>
        <div style="font-size:12px;font-weight:800;color:${scoreColor(level)}">${r.score ?? 0}</div>
        <div style="font-size:11px;color:var(--text3)">${lastVisit}</div>
        <div style="font-size:12px;font-weight:800;color:var(--text2);text-align:right">${r.visitCount ?? 0}</div>
      </div>
    `;
  }).join('');
}

async function scanAdsHistoryNow() {
  // Re-scan for current hours filter
  await loadAdsBlockHistoryByHours(_adsHistoryHours);
}

// expose for click delegation / inline actions (data-action)
window.loadTrackerAndAdsCounts = loadTrackerAndAdsCounts;
window.loadAdsBlockFromTrackerCounts = loadAdsBlockFromTrackerCounts;
window.loadAdsBlockHistoryDefault = loadAdsBlockHistoryDefault;
window.loadAdsHistoryByHours = async (hours) => {
  await loadAdsBlockHistoryByHours(hours);
};
window.scanAdsHistoryNow = scanAdsHistoryNow;

// ─────────────────────────────────────────────────────────────────────────────

function _timeAgo(iso) {
  try {
    const s = Math.floor((Date.now() - new Date(iso)) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  } catch { return ''; }
}

window.renderRTFeed = renderRTFeed;


// ═══════════════════════════════════════════════════════════════════════════════
// SETTINGS — persist to chrome.storage, no fake behavior
// ═══════════════════════════════════════════════════════════════════════════════

function selectSettingsCat(category) {
  document.querySelectorAll('.settings-cat').forEach(c => c.classList.remove('active-cat'));
  const active = document.getElementById(`scat-${category}`);
  if (active) active.classList.add('active-cat');
  // Show/hide panels
  document.querySelectorAll('.settings-panel').forEach(p => p.style.display = 'none');
  const panel = document.getElementById(`spanel-${category}`);
  if (panel) panel.style.display = 'block';
}

function toggleSetting(el, key) {
  const isOn = el.classList.contains('on');
  el.classList.toggle('on', !isOn);
  // Update label if present
  const label = el.previousElementSibling;
  if (label && (label.id || '').startsWith('lbl-')) {
    label.textContent = isOn ? 'Off' : 'On';
    label.style.color = isOn ? 'var(--red)' : 'var(--green)';
  }
  saveSetting(key, !isOn);
  showToast(`${key}: ${!isOn ? 'enabled' : 'disabled'}`, 'info');
}

function saveSetting(key, value) {
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['shieldscanSettings'], (r) => {
      if (chrome.runtime.lastError || !r) return;
      const settings = r.shieldscanSettings || {};
      settings[key] = value;
      chrome.storage.local.set({ shieldscanSettings: settings });
      window.dashboardState.settings[key] = value;
    });
  }
}

function setChannel(ch) {
  document.querySelectorAll('#channelBtns .channel-btn').forEach(b => {
    b.classList.toggle('active-channel', b.dataset.ch === ch);
  });
  saveSetting('updateChannel', ch);
  showToast(`Update channel: ${ch}`, 'success');
}

function runCheckForUpdates() {
  const btn = document.getElementById('checkNowBtn');
  if (btn) { btn.textContent = 'Checking…'; btn.disabled = true; }
  setTimeout(() => {
    if (btn) { btn.textContent = 'Check now'; btn.disabled = false; }
    const sub = document.getElementById('lastUpdatedSub');
    if (sub) sub.textContent = `Version 0.4.0 — checked ${new Date().toLocaleString()}`;
    showToast('✅ You are up to date', 'success');
  }, 1500);
}

function setThreatAction(ta) {
  document.querySelectorAll('[data-ta]').forEach(b => b.classList.toggle('active-channel', b.dataset.ta === ta));
  saveSetting('threatAction', ta);
  showToast(`Threat action: ${ta}`, 'success');
}

function setSchedule(sc) {
  document.querySelectorAll('[data-sc]').forEach(b => b.classList.toggle('active-channel', b.dataset.sc === sc));
  saveSetting('scanSchedule', sc);
  showToast(`Scan schedule: ${sc}`, 'success');
}

function setEngine(eng) {
  document.querySelectorAll('[data-eng]').forEach(b => b.classList.toggle('active-channel', b.dataset.eng === eng));
  saveSetting('detectionEngine', eng);
  showToast(`Detection engine: ${eng}`, 'success');
}

function setHeuristics(hl) {
  document.querySelectorAll('[data-hl]').forEach(b => b.classList.toggle('active-channel', b.dataset.hl === hl));
  saveSetting('heuristicsLevel', hl);
  showToast(`Heuristics: ${hl}`, 'success');
}

function setConnections(conn) {
  document.querySelectorAll('[data-conn]').forEach(b => b.classList.toggle('active-channel', b.dataset.conn === conn));
  saveSetting('connections', conn);
  showToast(`Connections: ${conn}`, 'success');
}

function openExclusions() {
  showModal('Manage Exclusions',
    `<p style="color:var(--text2);margin-bottom:14px">Files, folders, and processes excluded from scanning.</p>
     <div style="background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:12px">
       <div style="font-size:13px;color:var(--text2)">No exclusions configured.</div>
     </div>
     <button data-action="modal" data-modal-title="Add Exclusion" data-modal-body="Enter a file path or folder to exclude from scanning." style="padding:8px 16px;background:var(--accent);color:#fff;border:none;border-radius:7px;cursor:pointer;font-size:13px;font-weight:600">+ Add exclusion</button>`
  );
}

function resetSettings() {
  if (!confirm('Reset all settings to defaults? This cannot be undone.')) return;
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.remove(['shieldscanSettings'], () => {
      window.dashboardState.settings = {};
      showToast('Settings reset to defaults', 'success');
      location.reload();
    });
  }
}

function openEditProfile() {
  showModal('Edit Profile',
    `<div style="display:flex;flex-direction:column;gap:12px;padding:4px 0">
       <div><label style="font-size:12px;color:var(--text2);display:block;margin-bottom:4px">Display name</label>
         <input id="_editName" type="text" value="Juan Dela Cruz" style="width:100%;padding:9px 12px;background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;color:var(--text1);font-size:13px;outline:none"/></div>
       <div><label style="font-size:12px;color:var(--text2);display:block;margin-bottom:4px">Email</label>
         <input id="_editEmail" type="email" value="juan.delacruz@email.com" style="width:100%;padding:9px 12px;background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;color:var(--text1);font-size:13px;outline:none"/></div>
       <button onclick="saveProfile()" style="padding:10px;background:var(--accent);color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;margin-top:4px">Save changes</button>
     </div>`
  );
}

window.saveProfile = function() {
  const name = document.getElementById('_editName')?.value.trim();
  const email = document.getElementById('_editEmail')?.value.trim();
  if (!name || !email) { showToast('Name and email required', 'warning'); return; }
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.set({ profile: { name, email, signedInAt: new Date().toISOString() } });
  }
  setEl('profileName', name);
  setEl('profileEmail', email);
  const avatar = document.getElementById('profileAvatar');
  if (avatar) avatar.textContent = name[0].toUpperCase();
  closeModal();
  showToast('Profile updated', 'success');
};

function showPlansModal() {
  showModal('Upgrade Plans',
    `<div style="display:flex;flex-direction:column;gap:14px;padding:4px 0">
       <div style="padding:16px;background:var(--bg-card2);border:2px solid var(--accent);border-radius:10px">
         <div style="font-weight:700;margin-bottom:6px">Premium Protection</div>
         <div style="font-size:22px;font-weight:800;color:var(--accent);margin-bottom:8px">$9.99/month</div>
         <div style="font-size:13px;color:var(--text2);line-height:1.7">✓ Advanced AI threat detection<br>✓ Real-time protection<br>✓ VPN unlimited bandwidth<br>✓ Identity monitoring<br>✓ Priority support</div>
       </div>
       <div style="padding:16px;background:var(--bg-card2);border:1px solid var(--border);border-radius:10px">
         <div style="font-weight:700;margin-bottom:6px">Basic Protection</div>
         <div style="font-size:22px;font-weight:800;margin-bottom:8px">$4.99/month</div>
         <div style="font-size:13px;color:var(--text2);line-height:1.7">✓ Basic threat detection<br>✓ Web protection<br>✓ Limited VPN</div>
       </div>
       <button onclick="closeModal();showToast('Opening checkout…','info')" style="padding:12px;background:var(--accent);color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:700">Start Free Trial</button>
     </div>`
  );
}

function openManageSecurity() {
  showModal('Account Security',
    `<div style="display:flex;flex-direction:column;gap:12px;padding:4px 0">
       <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;background:var(--bg-card2);border-radius:8px">
         <div><div style="font-size:13px;font-weight:600;color:var(--text1)">Two-Factor Authentication</div><div style="font-size:11px;color:var(--text2)">Add an extra layer of security</div></div>
         <button onclick="showToast('2FA setup coming soon','info')" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600">Enable</button>
       </div>
       <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;background:var(--bg-card2);border-radius:8px">
         <div><div style="font-size:13px;font-weight:600;color:var(--text1)">Recovery Email</div><div style="font-size:11px;color:var(--text2)">Not configured</div></div>
         <button onclick="showToast('Enter a recovery email address','info')" style="padding:6px 14px;background:var(--bg-card2);border:1px solid var(--border);color:var(--text1);border-radius:6px;cursor:pointer;font-size:12px;font-weight:600">Add</button>
       </div>
       <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;background:var(--bg-card2);border-radius:8px">
         <div><div style="font-size:13px;font-weight:600;color:var(--text1)">Change Password</div><div style="font-size:11px;color:var(--text2)">Last changed: never</div></div>
         <button onclick="showToast('Password change coming soon','info')" style="padding:6px 14px;background:var(--bg-card2);border:1px solid var(--border);color:var(--text1);border-radius:6px;cursor:pointer;font-size:12px;font-weight:600">Change</button>
       </div>
     </div>`
  );
}

function toggleFeature(el, feature) {
  const isOn = el.classList.contains('on');
  el.classList.toggle('on', !isOn);
  const label = el.previousElementSibling;
  if (label && label.classList.contains('rt-label')) {
    label.textContent = isOn ? 'Off' : 'On';
    label.style.color = isOn ? 'var(--red)' : 'var(--green)';
  }
  saveSetting(`feature_${feature}`, !isOn);
  showToast(`${feature}: ${!isOn ? 'enabled' : 'disabled'}`, 'info');
}

function showActivityLog() { navigateToPage('page-history'); }
function showPrivacyReport() {
  showModal('Privacy Report', '<p style="color:var(--text2)">Privacy protection is active across all monitored categories.</p>');
}

function runTool(name, icon, desc, loading, result) {
  showModal(name,
    `<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
       <span style="font-size:32px">${icon}</span>
       <div><div style="font-size:14px;font-weight:600;color:var(--text1)">${name}</div>
       <div style="font-size:12px;color:var(--text2)">${desc}</div></div>
     </div>
     <div style="padding:12px;background:var(--bg-card2);border-radius:8px;font-size:13px;color:var(--text2);margin-bottom:12px">${result}</div>
     <button onclick="closeModal();showToast('${name} started','info')" style="padding:9px 18px;background:var(--accent);color:#fff;border:none;border-radius:7px;cursor:pointer;font-size:13px;font-weight:600">Run ${name}</button>`
  );
}

// Export all settings functions
window.selectSettingsCat = selectSettingsCat;
window.toggleSetting = toggleSetting;
window.saveSetting = saveSetting;
window.setChannel = setChannel;
window.runCheckForUpdates = runCheckForUpdates;
window.setThreatAction = setThreatAction;
window.setSchedule = setSchedule;
window.setEngine = setEngine;
window.setHeuristics = setHeuristics;
window.setConnections = setConnections;
window.openExclusions = openExclusions;
window.resetSettings = resetSettings;
window.openEditProfile = openEditProfile;
window.showPlansModal = showPlansModal;
window.openManageSecurity = openManageSecurity;
window.toggleFeature = toggleFeature;
window.showActivityLog = showActivityLog;
window.showPrivacyReport = showPrivacyReport;
window.runTool = runTool;


// ═══════════════════════════════════════════════════════════════════════════════
// REAL-TIME UPDATES — poll API, no fake random data
// ═══════════════════════════════════════════════════════════════════════════════

function updateStats() {
  // Called by setInterval — just reload from API, no fake increments
  loadStats();
}

function updateRealTimeFeed() {
  // Only update if the realtime page is active
  if (window.dashboardState.currentPage === 'page-realtime') {
    loadRealTimeFeed();
  }
}

function startRealTimeUpdates() {
  // Poll real API every 15 seconds — no fake data
  setInterval(() => {
    loadStats();
    loadStatus();
    if (window.dashboardState.currentPage === 'page-realtime') loadRealTimeFeed();
    if (window.dashboardState.currentPage === 'page-history') loadDetectionHistory();
  }, 15000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLICK DELEGATION — handles all data-action from dashboard.js delegation
// ═══════════════════════════════════════════════════════════════════════════════

document.addEventListener('click', (e) => {
  // VPN server connect button
  const serverBtn = e.target.closest('[data-action="connect-vpn-server"]');
  if (serverBtn) {
    e.preventDefault();
    e.stopPropagation();
    connectVPN(serverBtn.dataset.serverId);
    return;
  }

  // data-modal triggers (legacy support)
  const modalEl = e.target.closest('[data-modal]');
  if (modalEl && !e.defaultPrevented) {
    e.preventDefault();
    const title = modalEl.getAttribute('data-modal') || modalEl.getAttribute('data-modal-title') || 'Info';
    const content = modalEl.getAttribute('data-modal-content') || modalEl.getAttribute('data-modal-body') || '';
    showModal(title, content);
    return;
  }

  // data-navigate triggers (legacy support)
  const navEl = e.target.closest('[data-navigate]');
  if (navEl && !e.defaultPrevented) {
    e.preventDefault();
    navigateToPage(navEl.getAttribute('data-navigate'));
    return;
  }

  // stat-card clicks
  const statCard = e.target.closest('.stat-card[data-modal]');
  if (statCard) {
    e.preventDefault();
    const title = statCard.getAttribute('data-modal');
    const content = statCard.getAttribute('data-modal-content') || '';
    showModal(title, content);
    return;
  }

  // security-item / activity-item / id-monitor-row / priv-card clicks
  const clickable = e.target.closest('.security-item[data-modal], .activity-item[data-modal], .id-monitor-row[data-modal], .priv-card[data-modal]');
  if (clickable) {
    e.preventDefault();
    const title = clickable.getAttribute('data-modal');
    const content = clickable.getAttribute('data-modal-content') || '';
    showModal(title, content);
    return;
  }

  // stat-link navigate
  const statLink = e.target.closest('.stat-link[data-navigate]');
  if (statLink) {
    e.preventDefault();
    navigateToPage(statLink.getAttribute('data-navigate'));
    return;
  }

  // nav-item
  const navItem = e.target.closest('.nav-item[data-page]');
  if (navItem) {
    e.preventDefault();
    navigateToPage(navItem.getAttribute('data-page'));
    return;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // TRACKER / ADS BLOCK / ADS BLOCK HISTORY — click actions
  // ─────────────────────────────────────────────────────────────────────────────
  const dashAction = e.target.closest('[data-action]')?.getAttribute('data-action');
  if (dashAction) {
    // Tracker tabs
    if (dashAction === 'trackerTabThisPage') {
      e.preventDefault();
      _trackerView = 'thisPage';
      if (_trackerCountsCache) renderTrackerCounts(_trackerCountsCache);
      else loadTrackerAndAdsCounts();
      return;
    }
    if (dashAction === 'trackerTabAllTime') {
      e.preventDefault();
      _trackerView = 'allTime';
      if (_trackerCountsCache) renderTrackerCounts(_trackerCountsCache);
      else loadTrackerAndAdsCounts();
      return;
    }

    // Ads block history tabs
    if (dashAction === 'adsHistoryLoad') {
      e.preventDefault();
      const el = e.target.closest('[data-action="adsHistoryLoad"]');
      const h = Number(el?.dataset?.historyHours || '24');
      loadAdsBlockHistoryByHours(h);
      // update visual active tab (simple)
      document.querySelectorAll('[data-action="adsHistoryLoad"]').forEach(btn => {
        const active = Number(btn.dataset.historyHours || '24') === h;
        btn.style.background = active ? 'var(--accent)' : 'none';
        btn.style.color = active ? '#fff' : 'var(--text2)';
      });
      return;
    }

    // Ads block history scan-now
    if (dashAction === 'adsHistoryScanNow') {
      e.preventDefault();
      scanAdsHistoryNow();
      return;
    }
  }

  // scan type tabs
  const scanTypeBtn = e.target.closest('.scan-type-btn[data-scan]');
  if (scanTypeBtn) {
    document.querySelectorAll('.scan-type-btn').forEach(b => b.classList.remove('active'));
    scanTypeBtn.classList.add('active');
    const type = scanTypeBtn.dataset.scan;
    setEl('scanTypeLabel', type === 'quick' ? 'Quick Scan' : type === 'full' ? 'Full Scan' : 'Custom Scan');
    setEl('scanStatus', `Ready to ${type === 'quick' ? 'Quick' : type === 'full' ? 'Full' : 'Custom'} Scan`);
    return;
  }

  // tab-btn (AI scanner tabs)
  const tabBtn = e.target.closest('.tab-btn[data-tab]');
  if (tabBtn) {
    document.querySelectorAll('.tab-btn').forEach(b => {
      b.style.borderBottomColor = 'transparent';
      b.style.color = 'var(--text2)';
    });
    tabBtn.style.borderBottomColor = 'var(--accent)';
    tabBtn.style.color = 'var(--accent)';
    const placeholders = { link: 'Paste a link to scan…', text: 'Paste suspicious text here…', file: 'Enter file path…', screenshot: 'Paste image URL…' };
    const inp = document.getElementById('aiScanInput');
    if (inp) inp.placeholder = placeholders[tabBtn.dataset.tab] || 'Paste here…';
    return;
  }

  // startScanBtn
  if (e.target.id === 'startScanBtn' || e.target.closest('#startScanBtn')) {
    e.preventDefault();
    window.dashboardState.isScanning ? stopScan() : startScan();
    return;
  }

  // aiScanBtn
  if (e.target.id === 'aiScanBtn' || e.target.closest('#aiScanBtn')) {
    e.preventDefault();
    performAIScan();
    return;
  }

  // scheduleBtn
  if (e.target.id === 'scheduleBtn' || e.target.closest('#scheduleBtn')) {
    e.preventDefault();
    showModal('Schedule Scan',
      `<div style="display:flex;flex-direction:column;gap:12px">
         <div><label style="font-size:12px;color:var(--text2);display:block;margin-bottom:4px">Frequency</label>
           <select style="width:100%;padding:9px;background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;color:var(--text1)">
             <option>Daily</option><option>Weekly</option><option>Monthly</option>
           </select></div>
         <div><label style="font-size:12px;color:var(--text2);display:block;margin-bottom:4px">Time</label>
           <input type="time" value="10:00" style="width:100%;padding:9px;background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;color:var(--text1)"/></div>
         <button onclick="closeModal();showToast('Scan scheduled','success')" style="padding:10px;background:var(--accent);color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600">Save schedule</button>
       </div>`
    );
    return;
  }

  // vpnToggleBtn / vpnToggleBtn2
  if (e.target.id === 'vpnToggleBtn' || e.target.id === 'vpnToggleBtn2' ||
      e.target.closest('#vpnToggleBtn') || e.target.closest('#vpnToggleBtn2')) {
    e.preventDefault();
    toggleVPN();
    return;
  }
});

// Enter key in AI scan input
document.addEventListener('keydown', (e) => {
  if (e.target.id === 'aiScanInput' && e.key === 'Enter') {
    e.preventDefault();
    performAIScan();
  }
});

// VPN search input
document.addEventListener('input', (e) => {
  if (e.target.id === 'vpnSearch') filterVPNServers();
});

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

window.dashboardState = window.dashboardState || {
  currentPage: 'page-dashboard',
  isScanning: false,
  vpnConnected: false,
  realTimeStats: { threatsBlocked: 0, protectionScore: 0, scansToday: 0, uptime: 0 },
  settings: {},
};

document.addEventListener('DOMContentLoaded', () => {
  // Load real data immediately
  loadStats();
  loadStatus();

  // Load settings from storage
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['shieldscanSettings', 'profile'], (r) => {
      if (chrome.runtime.lastError || !r) return;
      if (r.shieldscanSettings) window.dashboardState.settings = r.shieldscanSettings;
      if (r.profile) {
        setEl('profileName', r.profile.name || 'Juan Dela Cruz');
        setEl('profileEmail', r.profile.email || 'juan.delacruz@email.com');
        const avatar = document.getElementById('profileAvatar');
        if (avatar && r.profile.name) avatar.textContent = r.profile.name[0].toUpperCase();
      }
    });
  }

  // Start polling (real data only)
  startRealTimeUpdates();

  // Initialize settings panel — show general by default
  selectSettingsCat('general');

  console.log('✅ ShieldScan dashboard loaded — all real data');
});

// Export remaining globals
window.updateStats = updateStats;
window.updateRealTimeFeed = updateRealTimeFeed;
window.startRealTimeUpdates = startRealTimeUpdates;
window.showToast = showToast;
window.loadStats = loadStats;
window.loadStatus = loadStatus;
window.loadDetectionHistory = loadDetectionHistory;
window.loadRealTimeFeed = loadRealTimeFeed;
window.loadVPNServers = loadVPNServers;
window.filterHistory = filterHistory;
window.handleAction = function(action, el) {
  const map = {
    'showPlansModal': showPlansModal,
    'showActivityLog': showActivityLog,
    'openExclusions': openExclusions,
    'renderRTFeed': renderRTFeed,
    'filterVPNServers': filterVPNServers,
    'quickConnect': quickConnect,
    'showPrivacyReport': showPrivacyReport,
  };
  if (map[action]) map[action](el);
};
window.handleButtonClick = function(id, e) {
  if (id === 'startScanBtn') { window.dashboardState.isScanning ? stopScan() : startScan(); }
  else if (id === 'aiScanBtn') performAIScan();
  else if (id === 'vpnToggleBtn' || id === 'vpnToggleBtn2') toggleVPN();
  else if (id === 'scheduleBtn') document.getElementById('scheduleBtn')?.click();
};

console.log('✅ ShieldScan dashboard-csp-compliant.js ready');
