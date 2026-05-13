// ═══════════════════════════════════════════════════════════════════════════════
// REAL-TIME INTEGRATION - ShieldScan
// Content script — polls local API with circuit breaker to prevent console spam
// ═══════════════════════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // Skip extension pages entirely
  const href = window.location.href;
  if (href.startsWith('chrome-extension://') ||
      href.startsWith('moz-extension://') ||
      href.startsWith('chrome://') ||
      href.startsWith('about:')) return;

  const API = 'http://localhost:8765';

  // ── Circuit breaker ──────────────────────────────────────────────────────────
  let _failCount = 0;
  let _retryAt = 0;
  let _stopped = false;
  let _lastDetectionTs = null;

  const MAX_FAILS = 3;       // stop after 3 consecutive failures
  const RETRY_AFTER = 120000; // retry after 2 minutes
  const POLL_INTERVAL = 30000; // poll every 30s (not 8s)

  function isCircuitOpen() {
    if (_failCount < MAX_FAILS) return false;
    if (Date.now() >= _retryAt) {
      // Half-open: allow one retry
      _failCount = 0;
      return false;
    }
    return true; // circuit open — skip request
  }

  function onSuccess() { _failCount = 0; }
  function onFailure() {
    _failCount++;
    if (_failCount >= MAX_FAILS) _retryAt = Date.now() + RETRY_AFTER;
  }

  // ── Extension context guard ──────────────────────────────────────────────────
  function isExtensionValid() {
    try { return typeof chrome !== 'undefined' && !!chrome.runtime?.id; }
    catch { return false; }
  }

  function stop() { _stopped = true; }

  // ── Fetch helper — silent, no console errors ─────────────────────────────────
  async function apiGet(path) {
    if (_stopped || isCircuitOpen()) return null;
    try {
      const r = await fetch(`${API}${path}`, { signal: AbortSignal.timeout(2000) });
      if (!r.ok) { onFailure(); return null; }
      onSuccess();
      return await r.json();
    } catch {
      onFailure();
      return null;
    }
  }

  async function apiPost(path, body) {
    if (_stopped || isCircuitOpen()) return null;
    try {
      const r = await fetch(`${API}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(3000),
      });
      if (!r.ok) { onFailure(); return null; }
      onSuccess();
      return await r.json();
    } catch {
      onFailure();
      return null;
    }
  }

  // ── Broadcast to background ──────────────────────────────────────────────────
  function send(message) {
    if (_stopped || !isExtensionValid()) return;
    try {
      chrome.runtime.sendMessage(message).catch(err => {
        if (err?.message?.includes('context invalidated') ||
            err?.message?.includes('Extension context')) stop();
      });
    } catch { stop(); }
  }

  // ── Poll detections ──────────────────────────────────────────────────────────
  async function pollDetections() {
    if (_stopped || !isExtensionValid()) { stop(); return; }
    const data = await apiGet('/api/detections?limit=5');
    if (!data?.detections?.length) return;

    if (!_lastDetectionTs) {
      _lastDetectionTs = data.detections[0].timestamp;
      return; // first run — just record timestamp, don't broadcast
    }

    const newOnes = data.detections.filter(d => d.timestamp > _lastDetectionTs);
    newOnes.forEach(det => {
      _lastDetectionTs = det.timestamp;
      send({
        type: 'REAL_THREAT_DETECTED',
        data: {
          id: Date.now(),
          timestamp: det.timestamp,
          type: det.level === 'high' ? 'malicious' : 'suspicious',
          title: det.path
            ? 'Threat detected: ' + det.path.split('\\').pop().split('/').pop()
            : 'Threat detected',
          path: det.path,
          score: det.score,
          level: det.level,
          category: (det.findings && det.findings[0] && det.findings[0].rule) || 'malware',
          action: det.quarantined ? 'quarantined' : (det.level === 'high' ? 'blocked' : 'flagged'),
        },
      });
    });
  }

  // ── Poll stats ───────────────────────────────────────────────────────────────
  async function pollStats() {
    if (_stopped || !isExtensionValid()) { stop(); return; }
    const data = await apiGet('/api/stats');
    if (!data || data.error) return;
    send({
      type: 'REAL_STATS_UPDATE',
      data: {
        threatsBlocked: data.threats_blocked,
        protectionScore: data.protection_score,
        scansToday: data.scans_today,
        uptimeHours: data.uptime_hours,
      },
    });
  }

  // ── Analyze current page (once, on load) ─────────────────────────────────────
  async function analyzeCurrentPage() {
    if (_stopped || !isExtensionValid() || isCircuitOpen()) return;
    const url = window.location.href;
    if (!url.startsWith('http')) return;

    const result = await apiPost('/api/scan', { target: url });
    if (!result || result.error) return;

    if (result.level === 'high' || result.level === 'medium') {
      send({
        type: 'PAGE_THREAT_DETECTED',
        data: { url, score: result.score, level: result.level, findings: result.url_findings || [] },
      });
    }
  }

  // ── Start ────────────────────────────────────────────────────────────────────
  // Initial poll after 3s (let page settle)
  setTimeout(() => {
    pollStats();
    pollDetections();
    analyzeCurrentPage();
  }, 3000);

  // Recurring poll — 30s interval with circuit breaker
  setInterval(() => {
    if (!isExtensionValid()) { stop(); return; }
    if (!isCircuitOpen()) {
      pollStats();
      pollDetections();
    }
  }, POLL_INTERVAL);

})();
