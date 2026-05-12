// ═══════════════════════════════════════════════════════════════════════════════
// REAL-TIME INTEGRATION - ShieldScan
// Polls the local API server (localhost:8765) for real threat data.
// Runs as a content script on every page — no fake/simulated data.
// ═══════════════════════════════════════════════════════════════════════════════

(function () {
  'use strict';

  const API = 'http://localhost:8765';
  let _lastDetectionTimestamp = null;
  let _pollTimer = null;
  let _stopped = false;

  // ── Extension context guard ──────────────────────────────────────────────────
  // Stop all polling if the extension is reloaded/invalidated

  function isExtensionValid() {
    try {
      return typeof chrome !== 'undefined' && !!chrome.runtime?.id;
    } catch { return false; }
  }

  function stopPolling() {
    _stopped = true;
    if (_pollTimer) {
      clearInterval(_pollTimer);
      _pollTimer = null;
    }
  }

  // ── Fetch helpers ────────────────────────────────────────────────────────────

  async function apiGet(path) {
    if (_stopped) return null;
    try {
      const r = await fetch(`${API}${path}`, { signal: AbortSignal.timeout(4000) });
      if (!r.ok) return null;
      return await r.json();
    } catch { return null; }
  }

  async function apiPost(path, body) {
    if (_stopped) return null;
    try {
      const r = await fetch(`${API}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(6000),
      });
      if (!r.ok) return null;
      return await r.json();
    } catch { return null; }
  }

  // ── Poll for new detections ──────────────────────────────────────────────────

  async function pollDetections() {
    if (_stopped || !isExtensionValid()) { stopPolling(); return; }

    const data = await apiGet('/api/detections?limit=5');
    if (!data || !Array.isArray(data.detections)) return;

    const newDetections = data.detections.filter(d => {
      if (!_lastDetectionTimestamp) return false;
      return d.timestamp > _lastDetectionTimestamp;
    });

    if (data.detections.length > 0 && !_lastDetectionTimestamp) {
      _lastDetectionTimestamp = data.detections[0].timestamp;
    }

    newDetections.forEach(det => {
      _lastDetectionTimestamp = det.timestamp;
      broadcastToBackground({
        type: 'REAL_THREAT_DETECTED',
        data: {
          id: Date.now(),
          timestamp: det.timestamp,
          type: det.level === 'high' ? 'malicious' : 'suspicious',
          title: det.path
            ? `Threat detected: ${det.path.split('\\').pop().split('/').pop()}`
            : 'Threat detected',
          path: det.path,
          score: det.score,
          level: det.level,
          category: det.findings?.[0]?.rule || 'malware',
          action: det.quarantined ? 'quarantined' : (det.level === 'high' ? 'blocked' : 'flagged'),
          ai_score: det.ai_score,
          sandbox_verdict: det.sandbox_verdict,
        },
      });
    });
  }

  // ── Poll stats ───────────────────────────────────────────────────────────────

  async function pollStats() {
    if (_stopped || !isExtensionValid()) { stopPolling(); return; }

    const data = await apiGet('/api/stats');
    if (!data || data.error) return;

    broadcastToBackground({
      type: 'REAL_STATS_UPDATE',
      data: {
        threatsBlocked: data.threats_blocked,
        protectionScore: data.protection_score,
        scansToday: data.scans_today,
        uptimeHours: data.uptime_hours,
      },
    });
  }

  // ── Analyze current page URL via real API ────────────────────────────────────

  async function analyzeCurrentPage() {
    if (_stopped || !isExtensionValid()) return;

    const url = window.location.href;
    if (!url || url.startsWith('chrome') || url.startsWith('about') || url.startsWith('moz-extension')) return;

    const result = await apiPost('/api/scan', { target: url });
    if (!result || result.error) return;

    if (result.level === 'high' || result.level === 'medium') {
      broadcastToBackground({
        type: 'PAGE_THREAT_DETECTED',
        data: {
          url,
          score: result.score,
          level: result.level,
          result: result.result,
          findings: result.url_findings || [],
          heuristic: result.heuristic,
          sandbox: result.sandbox,
        },
      });
    }
  }

  // ── Broadcast to background ──────────────────────────────────────────────────

  function broadcastToBackground(message) {
    if (_stopped) return;
    try {
      if (isExtensionValid()) {
        chrome.runtime.sendMessage(message).catch((err) => {
          // Extension was reloaded — stop all polling
          if (err?.message?.includes('Extension context invalidated') ||
              err?.message?.includes('context invalidated')) {
            stopPolling();
          }
        });
      } else {
        stopPolling();
      }
    } catch {
      stopPolling();
    }
  }

  // ── Start polling ────────────────────────────────────────────────────────────

  function startPolling() {
    // Initial load
    pollStats();
    pollDetections();

    // Poll every 8 seconds
    _pollTimer = setInterval(() => {
      if (!isExtensionValid()) {
        stopPolling();
        return;
      }
      pollStats();
      pollDetections();
    }, 8000);
  }

  // ── Init ─────────────────────────────────────────────────────────────────────

  // Only run on regular web pages, not extension pages
  if (!window.location.href.startsWith('chrome-extension://') &&
      !window.location.href.startsWith('moz-extension://')) {
    startPolling();

    // Analyze current page after a short delay (let page load first)
    setTimeout(analyzeCurrentPage, 2000);
  }

})();
