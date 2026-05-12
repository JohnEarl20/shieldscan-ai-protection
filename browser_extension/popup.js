// ═══════════════════════════════════════════════════════════════════════════════
// POPUP SCRIPT — ShieldScan AI Scam Protection
// Matches dashboard.js design system and API integration
// ═══════════════════════════════════════════════════════════════════════════════

const API = 'http://localhost:8765';
const WG_API = 'http://127.0.0.1:51821';

// ── API helpers ───────────────────────────────────────────────────────────────
async function apiGet(path, base = API) {
  try {
    const r = await fetch(`${base}${path}`, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

async function apiPost(path, body = {}, base = API) {
  try {
    const r = await fetch(`${base}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// ── Cloud threat APIs (work without local server) ─────────────────────────────
async function cloudCheckURL(url) {
  if (!url || !url.startsWith('http')) return null;

  // URLhaus — free, no key needed
  try {
    const body = new URLSearchParams({ url });
    const r = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST', body,
      signal: AbortSignal.timeout(5000),
    });
    if (r.ok) {
      const data = await r.json();
      if (data.query_status === 'is_malware') {
        return { result: 'malicious', score: 95, source: 'URLhaus', threat: data.threat || 'malware' };
      }
    }
  } catch (_) {}

  // Local heuristics fallback
  const suspicious = [
    'secure-login', 'verify-account', 'update-payment', 'claim-reward',
    'phishing', 'malware', 'free-gift', 'click-here', 'urgent',
    'account-suspended', 'confirm-identity', 'bitcoin', 'crypto-reward',
  ];
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click'];
  let score = 0;
  const lower = url.toLowerCase();
  for (const kw of suspicious) { if (lower.includes(kw)) score += 20; }
  for (const tld of suspiciousTLDs) { if (lower.includes(tld)) score += 25; }
  // IP address URLs are suspicious
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) score += 40;
  // Very long URLs
  if (url.length > 200) score += 15;
  // Multiple subdomains
  if ((url.match(/\./g) || []).length > 4) score += 15;

  score = Math.min(score, 100);
  return {
    result: score >= 70 ? 'malicious' : score >= 35 ? 'suspicious' : 'safe',
    score,
    source: 'heuristics',
  };
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function showToast(msg, type = 'info') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = `popup-toast ${type}`;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = 'popup-toast hidden'; }, 2800);
}

function animateNum(el, to) {
  if (!el) return;
  const from = parseInt(el.textContent) || 0;
  if (from === to) { el.textContent = to; return; }
  const steps = 18, dur = 600;
  let i = 0;
  const iv = setInterval(() => {
    i++;
    el.textContent = Math.round(from + (to - from) * (i / steps));
    if (i >= steps) { el.textContent = to; clearInterval(iv); }
  }, dur / steps);
}

function timeAgo(iso) {
  if (!iso) return '';
  try {
    const s = Math.floor((Date.now() - new Date(iso)) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  } catch { return ''; }
}

// ── API status ────────────────────────────────────────────────────────────────
function setAPIStatus(online) {
  const dot  = document.querySelector('.popup-api-dot');
  const text = document.getElementById('apiBadgeText');
  if (dot)  { dot.className = `popup-api-dot${online ? '' : ' offline'}`; }
  if (text) text.textContent = online ? 'Live' : 'Protected';
  // Even when local API is offline, protection is still active via background
}

// ── Load stats ────────────────────────────────────────────────────────────────
async function loadStats() {
  // Try local API first
  const data = await apiGet('/api/stats');
  if (data && !data.error) {
    setAPIStatus(true);
    animateNum(document.getElementById('threatsBlocked'), data.threats_blocked ?? 0);
    animateNum(document.getElementById('protectionScore'), data.protection_score ?? 0);
    animateNum(document.getElementById('scansToday'), data.scans_today ?? 0);
    return;
  }

  // Local API offline — get stats from background service worker
  setAPIStatus(false); // shows "Protected" not "Offline"
  sendBg({ type: 'REQUEST_STATS' }, (stats) => {
    if (!stats) {
      // Background also unavailable — show defaults
      animateNum(document.getElementById('protectionScore'), 85);
      return;
    }
    animateNum(document.getElementById('threatsBlocked'), stats.threatsBlocked ?? 0);
    animateNum(document.getElementById('protectionScore'), stats.protectionScore ?? 85);
    animateNum(document.getElementById('scansToday'), stats.scansToday ?? 0);
  });
}

// ── Load recent detections ────────────────────────────────────────────────────
async function loadRecentDetections() {
  const data = await apiGet('/api/detections?limit=4');
  const list = document.getElementById('recentList');
  if (!list) return;

  if (!data?.detections?.length) {
    list.innerHTML = '<div class="popup-loading">No recent detections</div>';
    return;
  }

  list.innerHTML = data.detections.slice(0, 4).map(d => {
    const name   = d.path ? d.path.split('\\').pop().split('/').pop() : (d.type || 'Unknown');
    const isHigh = d.level === 'high';
    const isMed  = d.level === 'medium';
    const pillClass = isHigh ? 'blocked' : isMed ? 'flagged' : 'safe';
    const pillText  = isHigh ? 'Blocked' : isMed ? 'Flagged' : 'Safe';
    const icon      = isHigh ? '🔴' : isMed ? '⚡' : '✅';
    return `
      <div class="popup-detection-row">
        <span class="popup-detection-icon">${icon}</span>
        <div class="popup-detection-info">
          <div class="popup-detection-name">${name}</div>
          <div class="popup-detection-meta">${timeAgo(d.timestamp)} · score ${d.score ?? 0}</div>
        </div>
        <span class="popup-detection-pill ${pillClass}">${pillText}</span>
      </div>`;
  }).join('');
}

// ── Scan a link ───────────────────────────────────────────────────────────────
async function scanLink(url) {
  if (!url) return;
  const resultEl = document.getElementById('scanResult');
  if (resultEl) { resultEl.className = 'popup-scan-result warning'; resultEl.innerHTML = '⏳ Scanning…'; }

  // 1. Try local API
  let result = await apiPost('/api/scan', { target: url });

  // 2. Try background service
  if (!result || result.error) {
    result = await new Promise(resolve => {
      sendBg({ type: 'SCAN_REQUEST', data: { input: url } }, (r) => resolve(r));
    });
  }

  // 3. Fallback: cloud APIs directly from popup
  if (!result || result.error) {
    result = await cloudCheckURL(url);
  }

  if (!resultEl) return;

  if (result) {
    const r = result.result || (result.score >= 70 ? 'malicious' : result.score >= 35 ? 'suspicious' : 'safe');
    const score = result.score ?? 0;
    const src = result.source ? ` · ${result.source}` : '';
    if (r === 'malicious') {
      resultEl.className = 'popup-scan-result danger';
      resultEl.innerHTML = `🚫 <strong>Malicious</strong> — Score ${score}/100${src}`;
    } else if (r === 'suspicious') {
      resultEl.className = 'popup-scan-result warning';
      resultEl.innerHTML = `⚠️ <strong>Suspicious</strong> — Score ${score}/100${src}`;
    } else {
      resultEl.className = 'popup-scan-result safe';
      resultEl.innerHTML = `✅ <strong>Safe</strong> — Score ${score}/100${src}`;
    }
  } else {
    resultEl.className = 'popup-scan-result warning';
    resultEl.innerHTML = '⚠️ Could not scan — check your connection';
  }
}

// ── Quick scan ────────────────────────────────────────────────────────────────
async function quickScan() {
  const btn = document.getElementById('quickScanBtn');
  if (btn) { btn.textContent = '⏳ Scanning…'; btn.disabled = true; }
  showToast('Quick scan started…', 'info');

  sendBg({ type: 'QUICK_SCAN' }, (result) => {
    if (btn) { btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Quick Scan`; btn.disabled = false; }
    const found = result?.threatsFound ?? 0;
    showToast(found > 0 ? `⚠️ ${found} threat(s) found` : '✅ No threats found', found > 0 ? 'warning' : 'success');
    loadStats();
    loadRecentDetections();
  });
}

// ── Scan current page ─────────────────────────────────────────────────────────
async function scanCurrentPage() {
  if (typeof chrome === 'undefined' || !chrome.tabs) { showToast('Chrome API unavailable', 'warning'); return; }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) { showToast('No URL to scan', 'warning'); return; }
  showToast('🔍 Scanning current page…', 'info');
  await scanLink(tab.url);
}

// ── VPN toggle ────────────────────────────────────────────────────────────────
let _vpnOn = false;
async function toggleVPN() {
  const btn = document.getElementById('vpnBtn');
  const txt = document.getElementById('vpnBtnText');

  if (_vpnOn) {
    // Disconnect
    await apiPost('/vpn/disconnect', {}, WG_API);
    sendBg({ type: 'VPN_DISABLE' }, null);
    _vpnOn = false;
    if (btn) btn.classList.remove('active');
    if (txt) txt.textContent = 'VPN Off';
    showToast('🌐 VPN Disconnected', 'info');
  } else {
    // Connect
    showToast('🔒 Connecting VPN…', 'info');
    const result = await apiPost('/vpn/connect', { server_id: 'optimal' }, WG_API);
    if (result?.success) {
      _vpnOn = true;
      if (btn) btn.classList.add('active');
      if (txt) txt.textContent = 'VPN On';
      showToast(`🔒 WireGuard Connected`, 'success');
    } else {
      sendBg({ type: 'VPN_ENABLE' }, (r) => {
        _vpnOn = r?.success ?? false;
        if (_vpnOn) {
          if (btn) btn.classList.add('active');
          if (txt) txt.textContent = 'VPN On';
          showToast('🌐 VPN Connected', 'success');
        } else {
          showToast('⚠️ VPN unavailable', 'warning');
        }
      });
    }
  }
}

// ── Tracker panel ─────────────────────────────────────────────────────────────
let _trackerView = 'page';
let _trackerData = { total: 0, thisPage: 0, byDomain: {} };

async function loadTrackerCounts() {
  if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.runtime) return;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    sendBg({ type: 'GET_TRACKER_COUNTS', tabId: tab?.id }, (data) => {
      if (!data) return;
      _trackerData = data;
      renderTrackerPanel();
    });
  } catch (_) {}
}

function renderTrackerPanel() {
  const badge = document.getElementById('trackerBadge');
  const list  = document.getElementById('trackerList');
  if (!badge || !list) return;

  const count = _trackerView === 'page' ? _trackerData.thisPage : _trackerData.total;
  badge.textContent = count;

  if (_trackerView === 'page') {
    const domains = Object.entries(_trackerData.byDomain || {}).sort((a, b) => b[1] - a[1]);
    if (!domains.length) {
      list.innerHTML = '<div class="popup-tracker-empty">No trackers on this page</div>';
    } else {
      list.innerHTML = domains.map(([d, n]) => `
        <div class="popup-tracker-row">
          <span class="popup-tracker-domain" title="${d}">${d}</span>
          <span class="popup-tracker-count">${n}</span>
        </div>`).join('');
    }
  } else {
    list.innerHTML = `
      <div class="popup-tracker-row">
        <span class="popup-tracker-domain">🛡️ Total blocked</span>
        <span class="popup-tracker-count">${_trackerData.total}</span>
      </div>
      <div class="popup-tracker-row">
        <span class="popup-tracker-domain">📄 This page</span>
        <span class="popup-tracker-count">${_trackerData.thisPage}</span>
      </div>`;
  }
}

// ── Background message helper ─────────────────────────────────────────────────
function sendBg(msg, cb) {
  if (typeof chrome === 'undefined' || !chrome.runtime?.id) { if (cb) cb(null); return; }
  try {
    chrome.runtime.sendMessage(msg, (r) => {
      if (chrome.runtime.lastError) { if (cb) cb(null); return; }
      if (cb) cb(r);
    });
  } catch (_) { if (cb) cb(null); }
}

// ── Open dashboard ────────────────────────────────────────────────────────────
function openDashboard(page) {
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    const url = chrome.runtime.getURL('dashboard.html') + (page ? `#${page}` : '');
    chrome.tabs.create({ url }, () => window.close());
  }
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

  // Dashboard button
  document.getElementById('dashboardBtn')?.addEventListener('click', () => openDashboard());

  // Scan link button + Enter key
  document.getElementById('scanLinkBtn')?.addEventListener('click', () => {
    const val = document.getElementById('scanInput')?.value.trim();
    if (val) scanLink(val);
  });
  document.getElementById('scanInput')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = e.target.value.trim();
      if (val) scanLink(val);
    }
  });

  // Quick scan
  document.getElementById('quickScanBtn')?.addEventListener('click', quickScan);

  // Scan page
  document.getElementById('scanPageBtn')?.addEventListener('click', scanCurrentPage);

  // VPN
  document.getElementById('vpnBtn')?.addEventListener('click', toggleVPN);

  // History → open dashboard on detection page
  document.getElementById('historyBtn')?.addEventListener('click', () => openDashboard('page-detection'));

  // View all detections
  document.getElementById('viewAllBtn')?.addEventListener('click', () => openDashboard('page-detection'));

  // Tracker panel toggle
  const trackerToggle = document.getElementById('trackerToggle');
  const trackerBody   = document.getElementById('trackerBody');
  const trackerChevron = document.getElementById('trackerChevron');
  trackerToggle?.addEventListener('click', () => {
    trackerBody?.classList.toggle('open');
    trackerChevron?.classList.toggle('open');
  });

  // Tracker tabs
  document.getElementById('tabThisPage')?.addEventListener('click', function() {
    _trackerView = 'page';
    this.classList.add('active');
    document.getElementById('tabAllTime')?.classList.remove('active');
    renderTrackerPanel();
  });
  document.getElementById('tabAllTime')?.addEventListener('click', function() {
    _trackerView = 'all';
    this.classList.add('active');
    document.getElementById('tabThisPage')?.classList.remove('active');
    renderTrackerPanel();
  });

  // Load data
  loadStats();
  loadRecentDetections();
  loadTrackerCounts();

  // Poll every 5s
  setInterval(() => { loadStats(); loadRecentDetections(); loadTrackerCounts(); }, 5000);

  // Background message listener
  if (typeof chrome !== 'undefined' && chrome.runtime?.id) {
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg.type === 'STATS_UPDATE') {
        animateNum(document.getElementById('threatsBlocked'), msg.data?.threatsBlocked ?? 0);
        animateNum(document.getElementById('protectionScore'), msg.data?.protectionScore ?? 0);
      }
      if (msg.type === 'THREAT_DETECTED') {
        showToast(`🚨 ${msg.data?.title || 'Threat detected'}`, 'danger');
        loadStats();
        loadRecentDetections();
      }
    });
  }
});
