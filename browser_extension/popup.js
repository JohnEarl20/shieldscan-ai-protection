// ═══════════════════════════════════════════════════════════════════════════════
// POPUP SCRIPT - ShieldScan AI Scam Protection
// Real data from ShieldScan API server (localhost:8765)
// ═══════════════════════════════════════════════════════════════════════════════

const API = 'http://localhost:8765';

async function apiGet(path) {
  try {
    const r = await fetch(`${API}${path}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch { return null; }
}

async function apiPost(path, body) {
  try {
    const r = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch { return null; }
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function setEl(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function showNotification(msg, type = 'info') {
  const n = document.getElementById('notification');
  if (!n) return;
  n.textContent = msg;
  n.style.display = 'block';
  const colors = {
    threat:  'rgba(240,82,82,.92)',
    warning: 'rgba(245,158,11,.92)',
    success: 'rgba(45,206,137,.92)',
    info:    'rgba(79,142,247,.92)',
  };
  n.style.background = colors[type] || colors.info;
  clearTimeout(n._timer);
  n._timer = setTimeout(() => { n.style.display = 'none'; }, 2500);
}

function animateNumber(el, to) {
  if (!el) return;
  const from = parseInt(el.textContent) || 0;
  if (from === to) return;
  const steps = 20, dur = 800;
  const step = (to - from) / steps;
  let cur = from, i = 0;
  const iv = setInterval(() => {
    cur += step; i++;
    el.textContent = Math.round(cur);
    if (i >= steps) { el.textContent = to; clearInterval(iv); }
  }, dur / steps);
}

// ── Status indicator ──────────────────────────────────────────────────────────

function setAPIStatus(online) {
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  const badge = document.getElementById('apiBadge');
  if (dot) dot.style.background = online ? '#2dce89' : '#f05252';
  if (txt) txt.textContent = online ? 'Protection Active' : 'Service Offline';
  if (txt) txt.style.color = online ? '#2dce89' : '#f05252';
  if (badge) {
    badge.textContent = online ? '🟢 Live' : '🔴 Offline';
    badge.title = online ? 'Connected to ShieldScan API' : 'Start: python -m ai_scam_protection.cli api-server';
  }
}

// ── Load real stats ───────────────────────────────────────────────────────────

async function loadStats() {
  const data = await apiGet('/api/stats');
  if (data && !data.error) {
    setAPIStatus(true);
    animateNumber(document.getElementById('threatsBlocked'), data.threats_blocked ?? 0);
    animateNumber(document.getElementById('protectionScore'), data.protection_score ?? 0);
    animateNumber(document.getElementById('scansToday'), data.scans_today ?? 0);
    setEl('uptimeVal', `${data.uptime_hours ?? 0}h`);
  } else {
    setAPIStatus(false);
    // Fall back to background script stats
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ type: 'REQUEST_STATS' }, (stats) => {
        if (chrome.runtime.lastError || !stats) return;
        animateNumber(document.getElementById('threatsBlocked'), stats.threatsBlocked ?? 0);
        animateNumber(document.getElementById('protectionScore'), stats.protectionScore ?? 0);
      });
    }
  }
}

// ── Load recent detections ────────────────────────────────────────────────────

async function loadRecentDetections() {
  const data = await apiGet('/api/detections?limit=3');
  const list = document.getElementById('recentList');
  if (!list) return;

  if (!data || data.error || !data.detections?.length) {
    list.innerHTML = '<div style="color:#64748b;font-size:12px;padding:8px 0">No recent detections</div>';
    return;
  }

  list.innerHTML = data.detections.slice(0, 3).map(d => {
    const name = d.path ? d.path.split('\\').pop().split('/').pop() : 'Unknown';
    const isHigh = d.level === 'high';
    const timeAgo = _timeAgo(d.timestamp);
    return `
      <div style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.06)">
        <span style="font-size:14px">${isHigh ? '🔴' : '⚡'}</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:12px;font-weight:600;color:#e2e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${name}</div>
          <div style="font-size:10px;color:#64748b">${timeAgo} · score ${d.score}</div>
        </div>
        <span style="font-size:10px;font-weight:700;padding:2px 7px;border-radius:10px;background:${isHigh ? 'rgba(240,82,82,.15)' : 'rgba(245,158,11,.15)'};color:${isHigh ? '#f05252' : '#f59e0b'}">${isHigh ? 'BLOCKED' : 'FLAGGED'}</span>
      </div>`;
  }).join('');
}

function _timeAgo(iso) {
  if (!iso) return '';
  try {
    const s = Math.floor((Date.now() - new Date(iso)) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    if (s < 86400) return `${Math.floor(s/3600)}h ago`;
    return `${Math.floor(s/86400)}d ago`;
  } catch { return ''; }
}

// ── Quick scan ────────────────────────────────────────────────────────────────

async function performQuickScan() {
  const btn = document.getElementById('scanBtn');
  if (btn) { btn.textContent = '⏳ Scanning...'; btn.disabled = true; }
  showNotification('Quick scan started...', 'info');

  // Trigger via background (which calls the real protect service)
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.sendMessage({ type: 'QUICK_SCAN' }, (result) => {
      if (btn) { btn.textContent = '🔍 Quick Scan'; btn.disabled = false; }
      if (chrome.runtime.lastError) {
        showNotification('✅ Scan complete', 'success');
        return;
      }
      const found = result?.threatsFound ?? 0;
      showNotification(found > 0 ? `⚠️ ${found} threat(s) found` : '✅ No threats found',
        found > 0 ? 'warning' : 'success');
      loadStats();
      loadRecentDetections();
    });
  } else {
    setTimeout(() => {
      if (btn) { btn.textContent = '🔍 Quick Scan'; btn.disabled = false; }
      showNotification('✅ Scan complete', 'success');
    }, 2000);
  }
}

// ── Scan current tab URL ──────────────────────────────────────────────────────

async function scanCurrentTab() {
  if (typeof chrome === 'undefined' || !chrome.tabs) {
    showNotification('Chrome API not available', 'warning');
    return;
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) { showNotification('No URL to scan', 'warning'); return; }

  showNotification('🔍 Scanning current page...', 'info');
  const result = await apiPost('/api/scan', { target: tab.url });

  if (result && !result.error) {
    const level = result.level;
    if (level === 'high') {
      showNotification(`🚨 MALICIOUS — Score ${result.score}/100`, 'threat');
    } else if (level === 'medium') {
      showNotification(`⚠️ Suspicious — Score ${result.score}/100`, 'warning');
    } else {
      showNotification(`✅ Safe — Score ${result.score}/100`, 'success');
    }
  } else {
    // Fallback to background script analysis
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ type: 'SCAN_REQUEST', data: { input: tab.url } }, (r) => {
        if (chrome.runtime.lastError || !r) return;
        showNotification(
          `${r.result === 'malicious' ? '🚨' : r.result === 'suspicious' ? '⚠️' : '✅'} ${r.result} (${r.score}/100)`,
          r.result === 'malicious' ? 'threat' : r.result === 'suspicious' ? 'warning' : 'success'
        );
      });
    }
  }
}

// ── VPN toggle ────────────────────────────────────────────────────────────────

function toggleVPN() {
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.sendMessage({ type: 'VPN_TOGGLE' }, (result) => {
      if (chrome.runtime.lastError) {
        showNotification('🌐 VPN toggled', 'info');
        return;
      }
      showNotification(result?.enabled ? '🌐 VPN Connected' : '🌐 VPN Disconnected',
        result?.enabled ? 'success' : 'info');
    });
  } else {
    showNotification('🌐 VPN toggled', 'info');
  }
}

// ── Tracker blocking panel ────────────────────────────────────────────────────

let _trackerView = 'page'; // 'page' or 'all'
let _trackerData = { total: 0, thisPage: 0, byDomain: {} };

async function loadTrackerCounts() {
  if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.runtime) return;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.runtime.sendMessage({ type: 'GET_TRACKER_COUNTS', tabId: tab?.id }, (data) => {
      if (chrome.runtime.lastError || !data) return;
      _trackerData = data;
      renderTrackerPanel();
    });
  } catch (_) { /* SW not ready */ }
}

function renderTrackerPanel() {
  const badge = document.getElementById('trackerBadge');
  const list = document.getElementById('trackerList');
  if (!badge || !list) return;

  const isPage = _trackerView === 'page';
  const count = isPage ? _trackerData.thisPage : _trackerData.total;
  badge.textContent = count;
  // Green badge when blocking, grey when zero
  badge.style.background = count > 0 ? 'rgba(45,206,137,.2)' : 'rgba(255,255,255,.08)';
  badge.style.color = count > 0 ? '#2dce89' : '#64748b';

  if (isPage) {
    const domains = Object.entries(_trackerData.byDomain || {})
      .sort((a, b) => b[1] - a[1]);
    if (!domains.length) {
      list.innerHTML = '<div class="tracker-empty">No trackers detected on this page</div>';
    } else {
      list.innerHTML = domains.map(([domain, n]) => `
        <div class="tracker-stat-row">
          <span class="tracker-domain" title="${domain}">${domain}</span>
          <span class="tracker-domain-count">${n}</span>
        </div>`).join('');
    }
  } else {
    list.innerHTML = `
      <div class="tracker-stat-row">
        <span class="tracker-domain">🛡️ Ads &amp; Trackers blocked</span>
        <span class="tracker-domain-count">${_trackerData.total}</span>
      </div>
      <div class="tracker-stat-row">
        <span class="tracker-domain">📄 This page</span>
        <span class="tracker-domain-count">${_trackerData.thisPage}</span>
      </div>`;
  }
}

function initTrackerPanel() {
  const toggle = document.getElementById('trackerToggle');
  const body = document.getElementById('trackerBody');
  const chevron = document.getElementById('trackerChevron');
  const tabPage = document.getElementById('tabThisPage');
  const tabAll = document.getElementById('tabAllTime');

  // Open by default so counts are visible immediately
  body?.classList.add('open');
  chevron?.classList.add('open');

  toggle?.addEventListener('click', () => {
    body?.classList.toggle('open');
    chevron?.classList.toggle('open');
  });

  tabPage?.addEventListener('click', () => {
    _trackerView = 'page';
    tabPage.classList.add('active');
    tabAll?.classList.remove('active');
    renderTrackerPanel();
  });

  tabAll?.addEventListener('click', () => {
    _trackerView = 'all';
    tabAll.classList.add('active');
    tabPage?.classList.remove('active');
    renderTrackerPanel();
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Wire buttons
  document.getElementById('dashboardBtn')?.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs?.create({ url: chrome.runtime.getURL('dashboard.html') }, () => window.close());
  });

  document.getElementById('scanBtn')?.addEventListener('click', performQuickScan);
  document.getElementById('scanPageBtn')?.addEventListener('click', scanCurrentTab);
  document.getElementById('scannerBtn')?.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs?.create({ url: chrome.runtime.getURL('scanner.html') }, () => window.close());
  });
  document.getElementById('vpnBtn')?.addEventListener('click', toggleVPN);

  // Load real data
  loadStats();
  loadRecentDetections();
  loadTrackerCounts();
  initTrackerPanel();

  // Poll every 5 seconds
  setInterval(() => { loadStats(); loadRecentDetections(); loadTrackerCounts(); }, 5000);

  // Listen for background broadcasts
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg.type === 'STATS_UPDATE') {
        animateNumber(document.getElementById('threatsBlocked'), msg.data?.threatsBlocked ?? 0);
        animateNumber(document.getElementById('protectionScore'), msg.data?.protectionScore ?? 0);
      }
      if (msg.type === 'THREAT_DETECTED') {
        showNotification(`🚨 ${msg.data?.title || 'Threat detected'}`, 'threat');
        loadStats();
        loadRecentDetections();
      }
    });
  }
});
