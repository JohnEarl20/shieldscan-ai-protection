// ═══════════════════════════════════════════════════════════════════════════════
// ShieldScan Local API Client
// Connects the browser extension/dashboard to the Python backend API server
// running on http://localhost:8765
// ═══════════════════════════════════════════════════════════════════════════════

const SHIELDSCAN_API = 'http://localhost:8765';
const API_TIMEOUT_MS = 5000;

class ShieldScanAPI {
  constructor() {
    this._available = null;       // null = unknown, true/false = checked
    this._lastCheck = 0;
    this._checkInterval = 15000;  // re-check availability every 15s
  }

  // ── Availability check ───────────────────────────────────────────────────

  async isAvailable() {
    const now = Date.now();
    if (this._available !== null && (now - this._lastCheck) < this._checkInterval) {
      return this._available;
    }
    try {
      const res = await this._fetch('/api/health', { timeout: 2000 });
      this._available = res.ok === true;
    } catch {
      this._available = false;
    }
    this._lastCheck = now;
    return this._available;
  }

  // ── Core endpoints ───────────────────────────────────────────────────────

  async getStats() {
    return this._get('/api/stats');
  }

  async getStatus() {
    return this._get('/api/status');
  }

  async getDetections(limit = 20, includeAll = false) {
    return this._get(`/api/detections?limit=${limit}&all=${includeAll}`);
  }

  async getQuarantine() {
    return this._get('/api/quarantine');
  }

  async getCheckup() {
    return this._get('/api/checkup');
  }

  async getRootkitResult() {
    return this._get('/api/rootkit');
  }

  async scan(target) {
    return this._post('/api/scan', { target });
  }

  async cloudLookup(target) {
    return this._post('/api/cloud-lookup', { target });
  }

  async startRootkitScan() {
    return this._post('/api/rootkit/scan', {});
  }

  // ── HTTP helpers ─────────────────────────────────────────────────────────

  async _get(path) {
    return this._fetch(path);
  }

  async _post(path, body) {
    return this._fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async _fetch(path, options = {}) {
    const controller = new AbortController();
    const timeout = options.timeout || API_TIMEOUT_MS;
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(`${SHIELDSCAN_API}${path}`, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }
}

// Singleton instance
const shieldScanAPI = new ShieldScanAPI();

// ── Dashboard data bridge ────────────────────────────────────────────────────
// Polls the API and updates the dashboard UI with real data.

class DashboardDataBridge {
  constructor() {
    this._pollInterval = null;
    this._apiAvailable = false;
    this._lastStats = null;
    this._lastDetections = [];
  }

  start(intervalMs = 15000) {
    this._poll();
    this._pollInterval = setInterval(() => this._poll(), intervalMs);
    console.log('📡 ShieldScan data bridge started — polling real backend data');
  }

  stop() {
    if (this._pollInterval) {
      clearInterval(this._pollInterval);
      this._pollInterval = null;
    }
  }

  async _poll() {
    const available = await shieldScanAPI.isAvailable();

    if (!available) {
      this._setAPIStatus(false);
      return;
    }

    this._setAPIStatus(true);

    // Fetch stats and detections in parallel
    const [statsResult, detectionsResult] = await Promise.allSettled([
      shieldScanAPI.getStats(),
      shieldScanAPI.getDetections(10, false),
    ]);

    if (statsResult.status === 'fulfilled') {
      this._applyStats(statsResult.value);
    }

    if (detectionsResult.status === 'fulfilled') {
      this._applyDetections(detectionsResult.value);
    }
  }

  _setAPIStatus(available) {
    this._apiAvailable = available;
    const indicator = document.getElementById('apiStatusIndicator');
    if (indicator) {
      indicator.textContent = available ? '🟢 Live' : '🔴 Offline';
      indicator.title = available
        ? 'Connected to ShieldScan protection service'
        : 'API server not running — start with: python -m ai_scam_protection.cli api-server';
    }

    // Show/hide offline banner
    const banner = document.getElementById('apiOfflineBanner');
    if (banner) {
      banner.style.display = available ? 'none' : 'flex';
    }
  }

  _applyStats(stats) {
    if (!stats || stats.error) return;
    this._lastStats = stats;

    // Protection score
    const scoreEl = document.getElementById('statScore');
    if (scoreEl) scoreEl.textContent = stats.protection_score ?? scoreEl.textContent;

    // Threats blocked
    const threatsEl = document.getElementById('statThreats');
    if (threatsEl) threatsEl.textContent = stats.threats_blocked ?? threatsEl.textContent;

    // Scans today
    const scansEl = document.getElementById('statScansToday');
    if (scansEl) scansEl.textContent = stats.scans_today ?? scansEl.textContent;

    // Uptime
    const uptimeEl = document.getElementById('statUptime');
    if (uptimeEl) uptimeEl.textContent = `${stats.uptime_hours ?? 0}h`;

    // Protection banner
    const protectedText = document.querySelector('.protected-text');
    if (protectedText) {
      protectedText.textContent = stats.protection_score >= 70 ? 'protected' : 'at risk';
      protectedText.style.color = stats.protection_score >= 70 ? '#2dce89' : '#f05252';
    }

    // Status badge
    const statusBadge = document.querySelector('.status-badge');
    if (statusBadge) {
      const dot = statusBadge.querySelector('.status-dot');
      statusBadge.innerHTML = '';
      if (dot) statusBadge.appendChild(dot);
      statusBadge.appendChild(document.createTextNode(' Active'));
    }

    // Quarantine count badge
    const qBadge = document.getElementById('quarantineCount');
    if (qBadge && stats.quarantine_count !== undefined) {
      qBadge.textContent = stats.quarantine_count;
      qBadge.style.display = stats.quarantine_count > 0 ? 'inline' : 'none';
    }
  }

  _applyDetections(data) {
    if (!data || data.error || !Array.isArray(data.detections)) return;
    const detections = data.detections;
    if (detections.length === 0) return;

    // Only update if data changed
    const newSig = JSON.stringify(detections.map(d => d.timestamp));
    if (newSig === this._lastSig) return;
    this._lastSig = newSig;
    this._lastDetections = detections;

    this._updateActivityFeed(detections);
    this._updateRecentScans(detections);
  }

  _updateActivityFeed(detections) {
    const container = document.querySelector('.section-card .activity-item')?.closest('.section-card');
    if (!container) return;

    const items = container.querySelectorAll('.activity-item');
    detections.slice(0, items.length).forEach((det, i) => {
      const item = items[i];
      if (!item) return;

      const icon = item.querySelector('.act-icon');
      const title = item.querySelector('.act-title');
      const sub = item.querySelector('.act-sub');
      const timeEl = item.querySelector('.act-time');

      const isHigh = det.level === 'high';
      const isMed = det.level === 'medium';

      if (icon) {
        icon.className = `act-icon ${isHigh ? 'bad' : isMed ? 'info' : 'good'}`;
        icon.textContent = isHigh ? '🔴' : isMed ? '⚡' : '🟢';
      }
      if (title) {
        const filename = det.path ? det.path.split('\\').pop().split('/').pop() : 'Unknown';
        title.textContent = isHigh
          ? `Threat blocked: ${filename}`
          : isMed
          ? `Suspicious file: ${filename}`
          : 'System scan completed';
      }
      if (sub) {
        sub.textContent = det.path
          ? det.path.length > 50 ? '...' + det.path.slice(-47) : det.path
          : `Score: ${det.score}`;
      }
      if (timeEl) timeEl.textContent = _timeAgo(det.timestamp);

      // Store detection data for modal
      item.dataset.detectionJson = JSON.stringify(det);
    });
  }

  _updateRecentScans(detections) {
    const list = document.getElementById('recentScansList');
    if (!list) return;

    // Only add new items at the top
    detections.slice(0, 5).forEach(det => {
      const filename = det.path
        ? det.path.split('\\').pop().split('/').pop()
        : 'Unknown file';
      const isHigh = det.level === 'high';
      const isMed = det.level === 'medium';

      const row = document.createElement('div');
      row.className = 'scan-row';
// If backend says it's quarantined, show it as such in the UI (instead of mapping by level only)
      const isQuarantined = !!det.quarantined;

      row.innerHTML = `
        <span class="scan-row-icon">${isHigh ? '🔴' : isMed ? '⚡' : '✅'}</span>
        <div class="scan-row-info">
          <div class="scan-url">${filename}</div>
          <div class="scan-time">${_timeAgo(det.timestamp)} · score ${det.score}</div>
        </div>
        <span class="pill ${isQuarantined ? 'warning' : isHigh ? 'malicious' : isMed ? 'warning' : 'safe'}">
          ${isQuarantined ? '🔒 Quarantined' : isHigh ? '🔴 Blocked' : isMed ? '⚠️ Flagged' : '✅ Clean'}
        </span>
        <span class="row-arrow">›</span>
      `;
      row.style.cursor = 'pointer';
      row.dataset.detectionJson = JSON.stringify(det);
      list.insertBefore(row, list.firstChild);
    });

    // Keep max 10 rows
    while (list.children.length > 10) list.removeChild(list.lastChild);
  }

  // ── Public helpers for on-demand fetches ──────────────────────────────────

  async fetchAndShowDetectionModal(det) {
    if (!det) return;
    const findings = (det.findings || []).map(f =>
      `<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:12px">
        <span style="color:var(--text2)">${f.rule || f.message || JSON.stringify(f)}</span>
      </div>`
    ).join('');

    const aiScore = det.ai_score
      ? `<div style="margin-top:10px;padding:10px;background:var(--bg-card2);border-radius:8px">
           <div style="font-size:12px;color:var(--text2);margin-bottom:4px">AI Score</div>
           <div style="font-size:22px;font-weight:700;color:${det.ai_score.score >= 70 ? 'var(--red)' : 'var(--yellow)'}">${det.ai_score.score}/100</div>
           <div style="font-size:11px;color:var(--text2)">${(det.ai_score.top_features || []).join(', ')}</div>
         </div>`
      : '';

    const sandboxBadge = det.sandbox_verdict
      ? `<span style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;background:${det.sandbox_verdict === 'malicious' ? 'var(--red-bg)' : 'var(--green-bg)'};color:${det.sandbox_verdict === 'malicious' ? 'var(--red)' : 'var(--green)'}">Sandbox: ${det.sandbox_verdict}</span>`
      : '';

    const content = `
      <div style="font-size:13px;color:var(--text2);word-break:break-all;margin-bottom:12px">${det.path || 'Unknown path'}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
        <span style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;background:${det.level === 'high' ? 'var(--red-bg)' : 'var(--green-bg)'};color:${det.level === 'high' ? 'var(--red)' : 'var(--green)'}">
          ${(det.level || 'unknown').toUpperCase()}
        </span>
        <span style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;background:var(--bg-card2);color:var(--text2)">Score: ${det.score}</span>
        ${sandboxBadge}
      </div>
      ${findings ? `<div style="margin-bottom:12px"><div style="font-size:12px;font-weight:600;color:var(--text1);margin-bottom:6px">Findings</div>${findings}</div>` : ''}
      ${aiScore}
      <div style="font-size:11px;color:var(--text3);margin-top:10px">${det.timestamp || ''}</div>
    `;

    if (typeof window.showModal === 'function') {
      window.showModal('Detection Details', content);
    }
  }

  getLastStats() { return this._lastStats; }
  getLastDetections() { return this._lastDetections; }
  isAPIAvailable() { return this._apiAvailable; }
}

// ── Time helper ──────────────────────────────────────────────────────────────

function _timeAgo(isoString) {
  if (!isoString) return 'unknown';
  try {
    const diff = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  } catch { return 'unknown'; }
}

// ── Global singleton ─────────────────────────────────────────────────────────

const dashboardBridge = new DashboardDataBridge();

// Auto-start when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => dashboardBridge.start());
} else {
  dashboardBridge.start();
}

// Click handler for detection rows (activity feed + recent scans)
document.addEventListener('click', (e) => {
  const row = e.target.closest('[data-detection-json]');
  if (row) {
    try {
      const det = JSON.parse(row.dataset.detectionJson);
      dashboardBridge.fetchAndShowDetectionModal(det);
    } catch {}
  }
});

// Expose globally for dashboard buttons
window.shieldScanAPI = shieldScanAPI;
window.dashboardBridge = dashboardBridge;
