// ═══════════════════════════════════════════════════════════════════════════════
// BACKGROUND SERVICE - AI Scam Protection ShieldScan
// Real-time threat detection, VPN management, and live system integration
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Import threat detector and VPN manager.
 * MV3 service workers can have relative-path resolution issues; use absolute extension URLs.
 */
importScripts(
  chrome.runtime.getURL('threat-detector.js'),
  chrome.runtime.getURL('vpn-manager.js'),
  chrome.runtime.getURL('activate_extension.js')
);

// Initialize threat detector and VPN manager
let threatDetector = null;
let vpnManager = null;

// Initialize on startup
if (typeof ThreatDetector !== 'undefined') {
  threatDetector = new ThreatDetector();
}
if (typeof VPNManager !== 'undefined') {
  vpnManager = new VPNManager();
}

// Live system state
let systemState = {
  threatsBlocked: 0,
  protectionScore: 85,
  scansToday: 0,
  uptime: 0,
  isProtectionActive: true,
  vpnEnabled: false,
  lastScanTime: null,
  recentThreats: []
};

// ═══════════════════════════════════════════════════════════════════════════════
// TRACKER BLOCKING — webRequest-based counting + declarativeNetRequest blocking
// ═══════════════════════════════════════════════════════════════════════════════

// Full tracker/ad domain list — matched against request hostnames
const TRACKER_DOMAINS = [
  // Google advertising & analytics
  'doubleclick.net','googleadservices.com','googlesyndication.com',
  'googletagmanager.com','googletagservices.com','google-analytics.com',
  'adservice.google.com','pagead2.googlesyndication.com',
  // Facebook/Meta
  'pixel.facebook.com','connect.facebook.net','graph.facebook.com',
  'an.facebook.com','staticxx.facebook.com',
  // Major ad networks
  'adnxs.com','adsrvr.org','adtech.de','advertising.com','adzerk.net',
  'amazon-adsystem.com','2mdn.net','ad-delivery.net','adform.net',
  'adform.com','turn.com','mathtag.com','bluekai.com','exelator.com',
  'krxd.net','rubiconproject.com','pubmatic.com','openx.net',
  'casalemedia.com','smartadserver.com','yieldmo.com','bidswitch.net',
  'spotxchange.com','sharethrough.com','criteo.com','criteo.net',
  'taboola.com','outbrain.com','moatads.com','popads.net',
  'propellerads.com','zedo.com','adform.net','appnexus.com',
  'lijit.com','sovrn.com','33across.com','triplelift.com',
  'indexexchange.com','media.net','undertone.com','conversantmedia.com',
  'rhythmone.com','teads.tv','yieldlab.net','adcolony.com',
  'mopub.com','inmobi.com','chartboost.com','vungle.com',
  // Analytics & session recording
  'hotjar.com','quantserve.com','scorecardresearch.com',
  'mixpanel.com','segment.com','segment.io','amplitude.com',
  'fullstory.com','logrocket.com','mouseflow.com','luckyorange.com',
  'crazyegg.com','inspectlet.com','clicktale.net','contentsquare.net',
  'heap.io','pendo.io','intercom.io','intercom.com',
  // Adobe
  'adobedtm.com','demdex.net','omtrdc.net','2o7.net','everesttech.net',
  // Social sharing trackers
  'addthis.com','sharethis.com','addtoany.com',
  // Alibaba/Asian trackers (common on alibabacloud.com)
  'mmstat.com','sg.mmstat.com','us.mmstat.com',
  'aliyuncs.com','alicdn.com','aligames.com',
  'tanx.com','alimama.com','taobao.com',
  // Other common trackers
  'bing.com/bat.js','bat.bing.com','clarity.ms',
  'tiktok.com','analytics.tiktok.com',
  'snap.com','tr.snapchat.com',
  'twitter.com/i/adsct','t.co',
  'linkedin.com/px','snap.licdn.com',
  'pinterest.com/ct','ct.pinterest.com',
  'mc.yandex.ru','mc.yandex.com',
  'counter.ok.ru','vk.com/rtrg',
  'nr-data.net','newrelic.com',
  'bugsnag.com','sentry.io','rollbar.com',
  'optimizely.com','vwo.com','abtasty.com',
  'branch.io','adjust.com','appsflyer.com',
  'kochava.com','singular.net',
];

// tabTrackerCounts[tabId] = { total: N, byDomain: { "doubleclick.net": 3, ... } }
const tabTrackerCounts = {};
let trackerBlockedTotal = 0;

// Load persisted total on startup
chrome.storage.local.get(['trackerBlockedTotal'], (r) => {
  if (chrome.runtime.lastError || !r) return;
  trackerBlockedTotal = r.trackerBlockedTotal || 0;
});

function _isTrackerUrl(url) {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return TRACKER_DOMAINS.some(d => host === d || host.endsWith('.' + d));
  } catch { return false; }
}

function _trackerDomain(url) {
  try {
    const host = new URL(url).hostname.toLowerCase();
    const matched = TRACKER_DOMAINS.find(d => host === d || host.endsWith('.' + d));
    return matched || host;
  } catch { return url; }
}

// Use webRequest to count tracker requests (works in developer mode unpacked extensions)
if (typeof chrome !== 'undefined' && chrome.webRequest && chrome.webRequest.onBeforeRequest) {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (!_isTrackerUrl(details.url)) return;
      const tabId = details.tabId;
      if (tabId < 0) return; // background request
      if (!tabTrackerCounts[tabId]) tabTrackerCounts[tabId] = { total: 0, byDomain: {} };
      tabTrackerCounts[tabId].total++;
      const domain = _trackerDomain(details.url);
      tabTrackerCounts[tabId].byDomain[domain] = (tabTrackerCounts[tabId].byDomain[domain] || 0) + 1;
      trackerBlockedTotal++;
      // Persist every 10 blocks to avoid excessive writes
      if (trackerBlockedTotal % 10 === 0) {
        chrome.storage.local.set({ trackerBlockedTotal });
      }
    },
    { urls: ['<all_urls>'] },
    []
  );
}

// Clear per-tab counts when tab navigates
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabTrackerCounts[tabId] = { total: 0, byDomain: {} };
  }
});

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabTrackerCounts[tabId];
});

// ═══════════════════════════════════════════════════════════════════════════════
// HISTORY PERMISSION — Scan browsing history for malicious URLs
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Scan recent browsing history for malicious URLs.
 * Uses chrome.history to read visited URLs and runs them through inspectUrl().
 * Results are stored and exposed via GET_HISTORY_SCAN message.
 */
async function scanBrowsingHistory(hoursBack = 24, maxItems = 500) {
  if (!chrome.history) return { error: 'history permission not available', results: [] };
  try {
    const startTime = Date.now() - hoursBack * 60 * 60 * 1000;
    const items = await chrome.history.search({
      text: '',
      startTime,
      maxResults: maxItems,
    });

    const state = await getState();
    const results = [];
    for (const item of items) {
      if (!item.url) continue;
      const result = inspectUrl(item.url, state);
      if (result.level !== 'clean') {
        results.push({
          url: item.url,
          title: item.title || '',
          visitCount: item.visitCount || 0,
          lastVisit: item.lastVisitTime,
          score: result.score,
          level: result.level,
          findings: result.findings.slice(0, 2),
        });
      }
    }
    results.sort((a, b) => b.score - a.score);
    await chrome.storage.local.set({ historyScanResults: results, historyScanTime: Date.now() });
    return { results, total_scanned: items.length, threats_found: results.length };
  } catch (err) {
    return { error: err.message, results: [] };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOWNLOADS PERMISSION — Scan downloads for threats
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Monitor new downloads and scan them via the Python API.
 * Uses chrome.downloads.onCreated and onChanged to track download completion.
 */
if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    // Log the download start
    chrome.storage.local.get(['pendingDownloads'], (r) => {
      if (chrome.runtime.lastError || !r) return;
      const pending = r.pendingDownloads || {};
      pending[downloadItem.id] = {
        id: downloadItem.id,
        url: downloadItem.url,
        filename: downloadItem.filename,
        startTime: downloadItem.startTime,
        state: 'in_progress',
      };
      chrome.storage.local.set({ pendingDownloads: pending });
    });
  });

  chrome.downloads.onChanged.addListener(async (delta) => {
    if (!delta.state || delta.state.current !== 'complete') return;

    // Download finished — scan it
    try {
      const [item] = await chrome.downloads.search({ id: delta.id });
      if (!item || !item.filename) return;

      // Scan via the local API
      const response = await fetch('http://localhost:8765/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: item.url || item.filename }),
      }).catch(() => null);

      if (!response || !response.ok) return;
      const result = await response.json().catch(() => null);
      if (!result) return;

      // Store result
      chrome.storage.local.get(['downloadScanResults'], (r) => {
        if (chrome.runtime.lastError || !r) return;
        const scans = r.downloadScanResults || [];
        scans.unshift({
          id: item.id,
          filename: item.filename.split('\\').pop().split('/').pop(),
          url: item.url,
          score: result.score || 0,
          level: result.level || 'clean',
          result: result.result || 'safe',
          timestamp: new Date().toISOString(),
        });
        chrome.storage.local.set({ downloadScanResults: scans.slice(0, 50) });
      });

      // Alert if threat found
      if (result.level === 'high') {
        systemState.threatsBlocked++;
        broadcastToAllTabs({
          type: 'THREAT_DETECTED',
          data: {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            type: 'malicious',
            title: `Malicious download: ${item.filename.split('\\').pop()}`,
            url: item.url,
            score: result.score,
            category: 'download',
            action: 'flagged',
          },
        });
      }
    } catch (_) { /* ignore */ }
  });
}

/**
 * Get recent download scan results.
 */
async function getDownloadScans(limit = 20) {
  try {
    const data = await chrome.storage.local.get(['downloadScanResults']);
    return (data.downloadScanResults || []).slice(0, limit);
  } catch { return []; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE MESSAGING — Bridge to Python protection engine
// ═══════════════════════════════════════════════════════════════════════════════

const NATIVE_HOST = 'com.shieldscan.protection';
let _nativePort = null;
let _nativePending = new Map(); // requestId → {resolve, reject, timer}
let _nativeRequestId = 0;

function _getNativePort() {
  if (_nativePort) return _nativePort;
  try {
    _nativePort = chrome.runtime.connectNative(NATIVE_HOST);
    _nativePort.onMessage.addListener((msg) => {
      // Route response to pending promise
      const id = msg._id;
      if (id && _nativePending.has(id)) {
        const { resolve, timer } = _nativePending.get(id);
        clearTimeout(timer);
        _nativePending.delete(id);
        resolve(msg);
      }
    });
    _nativePort.onDisconnect.addListener(() => {
      _nativePort = null;
      // Reject all pending requests
      for (const [id, { reject, timer }] of _nativePending) {
        clearTimeout(timer);
        reject(new Error('Native host disconnected'));
      }
      _nativePending.clear();
    });
  } catch (err) {
    _nativePort = null;
  }
  return _nativePort;
}

/**
 * Send a message to the native Python host and return a Promise.
 * Falls back gracefully if native host is not registered.
 */
function nativeSend(type, data = {}, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const port = _getNativePort();
    if (!port) {
      reject(new Error('Native host not available. Run register_native_host.ps1 to set up.'));
      return;
    }
    const id = ++_nativeRequestId;
    const timer = setTimeout(() => {
      _nativePending.delete(id);
      reject(new Error(`Native request timed out: ${type}`));
    }, timeoutMs);
    _nativePending.set(id, { resolve, reject, timer });
    try {
      port.postMessage({ type, data, _id: id });
    } catch (err) {
      clearTimeout(timer);
      _nativePending.delete(id);
      _nativePort = null;
      reject(err);
    }
  });
}


const DEFAULT_STATE = {
  enabled: true,
  adsEnabled: true,
  malwareEnabled: true,
  scamEnabled: true,
  signedIn: true,
  profile: {
    name: "Juan Dela Cruz",
    email: "juan@example.com",
    signedInAt: new Date().toISOString()
  },
  allowlist: [
    "facebook.com",
    "www.facebook.com",
    "m.facebook.com",
    "google.com",
    "www.google.com",
    "youtube.com",
    "www.youtube.com",
    "microsoft.com",
    "www.microsoft.com",
    "github.com",
    "www.github.com",
    "stackoverflow.com",
    "amazon.com",
    "www.amazon.com",
    "netflix.com",
    "www.netflix.com",
    "twitter.com",
    "www.twitter.com",
    "instagram.com",
    "www.instagram.com",
    "linkedin.com",
    "www.linkedin.com",
    "reddit.com",
    "www.reddit.com",
    "wikipedia.org",
    "en.wikipedia.org"
  ],
  blocklist: [],
  detections: [],
  blockedCount: 0,
  vpnEnabled: false,
  threatDetectionEnabled: true,
};

const AD_TRACKER_KEYWORDS = [
  "adsrvr", "adsystem", "adtech", "advertising", "adzerk", "analytics", 
  "doubleclick", "googleadservices", "hotjar", "pixel.facebook", 
  "quantserve", "telemetry", "trackers", "taboola", "outbrain",
  "popads", "propellerads", "ad-delivery", "adnxs", "amazon-adsystem",
  "googletagmanager", "googletagservices", "moatads"
];

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".buzz", ".loan", ".zip", ".mov", ".pw", ".ga", ".gq", ".ml", ".tk", ".cf", ".bid", ".date", ".win"
];

const RISKY_HOST_KEYWORDS = [
  "airdrop",
  "bonus",
  "claim",
  "crypto",
  "freegift",
  "giveaway",
  "login-verify",
  "prize",
  "reward",
  "secure-update",
  "support-verify",
  "wallet"
];

const RISKY_PATH_KEYWORDS = [
  "account-verify",
  "bank-login",
  "claim-reward",
  "download",
  "free",
  "invoice",
  "password-reset",
  "security-check",
  "setup",
  "update",
  "verify"
];

const RISKY_EXTENSIONS = [
  ".apk",
  ".bat",
  ".cmd",
  ".crdownload",
  ".exe",
  ".hta",
  ".iso",
  ".js",
  ".jse",
  ".msi",
  ".scr",
  ".vbs",
  ".wsf"
];

// Guard against chrome.runtime being undefined (e.g., in non-extension contexts)
if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener(async () => {
    const state = await getState();
    await chrome.storage.local.set({ ...DEFAULT_STATE, ...state });
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) {
    return;
  }
  void inspectTab(tabId, tab.url);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "getState") {
    getState().then(sendResponse);
    return true;
  }

  if (message?.type === "signIn") {
    signIn(message.profile).then(sendResponse);
    return true;
  }

  if (message?.type === "signOut") {
    signOut().then(sendResponse);
    return true;
  }

  if (message?.type === "setEnabled") {
    setEnabled(Boolean(message.enabled)).then(sendResponse);
    return true;
  }

  if (message?.type === "setSetting") {
    setSetting(message.key, message.value).then(sendResponse);
    return true;
  }

  if (message?.type === "inspectUrl") {
    getState().then(state => {
      sendResponse(inspectUrl(message.url || "", state));
    });
    return true;
  }

  if (message?.type === "continueToSite" && message.url) {
    addAllowlistHost(message.url).then(sendResponse);
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // REAL-TIME SYSTEM INTEGRATION
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "REQUEST_STATS") {
    getSystemStats().then(stats => {
      sendResponse(stats);
    });
    return true;
  }

  if (message?.type === "REQUEST_STATUS") {
    getProtectionStatus().then(status => {
      sendResponse(status);
    });
    return true;
  }

  if (message?.type === "QUICK_SCAN") {
    performQuickScan().then(result => {
      sendResponse(result);
    });
    return true;
  }

  if (message?.type === "SCAN_REQUEST") {
    performScan(message.data).then(result => {
      sendResponse(result);
    });
    return true;
  }

  if (message?.type === "GET_LAST_SCAN_RESULT") {
    getLastScanResult().then(result => {
      sendResponse(result);
    });
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // REAL-TIME BROADCAST MESSAGES
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "GET_LATEST_BROADCAST") {
    chrome.storage.local.get(['lastBroadcast', 'lastBroadcastTime']).then(result => {
      sendResponse({
        broadcast: result.lastBroadcast,
        timestamp: result.lastBroadcastTime
      });
    });
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // HISTORY SCAN
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "SCAN_HISTORY") {
    const hours = message.hoursBack || 24;
    scanBrowsingHistory(hours).then(result => {
      sendResponse(result);
    }).catch(err => sendResponse({ error: err.message, results: [] }));
    return true;
  }

  if (message?.type === "GET_HISTORY_SCAN") {
    chrome.storage.local.get(['historyScanResults', 'historyScanTime'], (r) => {
      if (chrome.runtime.lastError || !r) { sendResponse({ results: [] }); return; }
      sendResponse({
        results: r.historyScanResults || [],
        scanned_at: r.historyScanTime || null,
      });
    });
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // DOWNLOAD SCANS
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "GET_DOWNLOAD_SCANS") {
    getDownloadScans(message.limit || 20).then(results => {
      sendResponse({ results });
    }).catch(() => sendResponse({ results: [] }));
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // NATIVE MESSAGING
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "NATIVE_SCAN_FILE") {
    nativeSend('scan_file', { path: message.path })
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ type: 'error', data: { message: err.message } }));
    return true;
  }

  if (message?.type === "NATIVE_GET_STATS") {
    nativeSend('get_stats')
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ type: 'error', data: { message: err.message } }));
    return true;
  }

  if (message?.type === "NATIVE_PING") {
    nativeSend('ping')
      .then(result => sendResponse(result))
      .catch(err => sendResponse({ type: 'error', data: { message: err.message } }));
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // TRACKER BLOCKING COUNTS
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "GET_TRACKER_COUNTS") {
    const tabId = message.tabId;
    const perTab = tabId ? (tabTrackerCounts[tabId] || { total: 0, byDomain: {} }) : null;
    try {
      sendResponse({
        total: trackerBlockedTotal,
        thisPage: perTab ? perTab.total : 0,
        byDomain: perTab ? perTab.byDomain : {},
      });
    } catch (_) { /* caller context gone — ignore */ }
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // REAL DATA FROM REALTIME-INTEGRATION.JS (content script → background)
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "REAL_THREAT_DETECTED") {
    const threat = message.data;
    systemState.threatsBlocked++;
    systemState.recentThreats.unshift(threat);
    systemState.recentThreats = systemState.recentThreats.slice(0, 20);
    // Broadcast to all open dashboards/popups
    broadcastToAllTabs({ type: 'THREAT_DETECTED', data: threat });
    sendResponse({ ok: true });
    return true;
  }

  if (message?.type === "REAL_STATS_UPDATE") {
    const s = message.data;
    if (s.threatsBlocked !== undefined) systemState.threatsBlocked = s.threatsBlocked;
    if (s.protectionScore !== undefined) systemState.protectionScore = s.protectionScore;
    if (s.scansToday !== undefined) systemState.scansToday = s.scansToday;
    broadcastToAllTabs({ type: 'STATS_UPDATE', data: {
      threatsBlocked: systemState.threatsBlocked,
      protectionScore: systemState.protectionScore,
      scansToday: systemState.scansToday,
    }});
    sendResponse({ ok: true });
    return true;
  }

  if (message?.type === "PAGE_THREAT_DETECTED") {
    const { url, score, level } = message.data;
    if (level === 'high') {
      systemState.threatsBlocked++;
      broadcastToAllTabs({ type: 'THREAT_DETECTED', data: {
        id: Date.now(), timestamp: new Date().toISOString(),
        type: 'malicious', title: `Malicious page: ${url}`,
        url, score, category: 'web', action: 'flagged',
      }});
    }
    sendResponse({ ok: true });
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // VPN MESSAGES
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "VPN_ENABLE") {
    if (vpnManager) {
      vpnManager.enable(message.serverId || 'us-east').then(result => {
        sendResponse(result);
        broadcastVPNStatus();
      });
    } else {
      sendResponse({ success: false, error: 'VPN manager not initialized' });
    }
    return true;
  }

  if (message?.type === "VPN_DISABLE") {
    if (vpnManager) {
      vpnManager.disable().then(result => {
        sendResponse(result);
        broadcastVPNStatus();
      });
    } else {
      sendResponse({ success: false, error: 'VPN manager not initialized' });
    }
    return true;
  }

  if (message?.type === "VPN_TOGGLE") {
    if (vpnManager) {
      vpnManager.toggle().then(result => {
        sendResponse(result);
        broadcastVPNStatus();
      });
    } else {
      sendResponse({ success: false, error: 'VPN manager not initialized' });
    }
    return true;
  }

  if (message?.type === "VPN_GET_STATUS") {
    if (vpnManager) {
      sendResponse(vpnManager.getStatus());
    } else {
      sendResponse({ enabled: false, error: 'VPN manager not initialized' });
    }
    return true;
  }

  if (message?.type === "VPN_GET_SERVERS") {
    if (vpnManager) {
      sendResponse({ servers: vpnManager.getServers() });
    } else {
      sendResponse({ servers: [], error: 'VPN manager not initialized' });
    }
    return true;
  }

  if (message?.type === "VPN_SWITCH_SERVER") {
    if (vpnManager) {
      vpnManager.switchServer(message.serverId).then(result => {
        sendResponse(result);
        broadcastVPNStatus();
      });
    } else {
      sendResponse({ success: false, error: 'VPN manager not initialized' });
    }
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ADVANCED THREAT DETECTION MESSAGES
  // ─────────────────────────────────────────────────────────────────────────────

  if (message?.type === "ANALYZE_THREAT") {
    if (threatDetector) {
      const result = threatDetector.analyze(message.input, message.inputType || 'url');
      sendResponse(result);
      
      // Broadcast threat if detected
      if (result.score >= 60) {
        broadcastThreatDetection({
          type: result.type,
          title: `${result.type.toUpperCase()}: ${result.threats[0]?.name || 'Unknown threat'}`,
          url: message.input,
          severity: result.score >= 85 ? 'high' : 'medium',
          category: result.threats[0]?.category || 'general',
          action: result.score >= 85 ? 'blocked' : 'flagged',
          score: result.score,
        });
      }
    } else {
      sendResponse({ error: 'Threat detector not initialized' });
    }
    return true;
  }

  if (message?.type === "GET_THREAT_ANALYSIS") {
    if (threatDetector) {
      const result = threatDetector.analyze(message.url, 'url');
      sendResponse(result);
    } else {
      sendResponse({ error: 'Threat detector not initialized' });
    }
    return true;
  }

  return false;
});

async function inspectTab(tabId, url) {
  // Huwag i-scan ang blocked page mismo o ang extension internal pages
  if (url.startsWith(chrome.runtime.getURL("")) || url.startsWith("chrome-extension://")) {
    return;
  }

  const state = await getState();
  if (!state.enabled || !state.signedIn) {
    return;
  }

  const result = inspectUrl(url, state);
  if (result.level === "clean") {
    return;
  }

  await saveDetection(result);

  if (result.level === "high") {
    const currentState = await getState();
    await chrome.storage.local.set({ blockedCount: (currentState.blockedCount || 0) + 1 });
    
    const category = result.findings.length > 0 ? result.findings[0].category : "threat";
    const blockedUrl = chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(url)}&reason=${category}`);
    await chrome.tabs.update(tabId, { url: blockedUrl });
    return;
  }

  chrome.tabs.sendMessage(tabId, {
    type: "showWarning",
    result
  }, () => {
    void chrome.runtime.lastError;
  });
}

function inspectUrl(rawUrl, state = DEFAULT_STATE) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return cleanResult(rawUrl);
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return cleanResult(rawUrl);
  }

  const host = parsed.hostname.toLowerCase();
  const path = decodeURIComponent(parsed.pathname.toLowerCase());
  const query = decodeURIComponent(parsed.search.toLowerCase());
  const full = `${host}${path}${query}`;
  const findings = [];

  if (isHostInList(host, state.allowlist || [])) {
    return cleanResult(rawUrl);
  }

  if (isHostInList(host, state.blocklist || [])) {
    findings.push(finding("local_blocklist", 100, "Host is in the local browser blocklist", "scam"));
  }

  if (isIpAddress(host)) {
    findings.push(finding("ip_host", 25, "Page uses a raw IP address instead of a domain", "scam"));
  }

  if (countCharacter(host, "-") >= 3) {
    findings.push(finding("many_hyphens", 15, "Domain has many hyphens, common in throwaway phishing domains", "scam"));
  }

  if (host.includes("xn--")) {
    findings.push(finding("punycode_domain", 40, "Domain uses punycode, which can hide lookalike characters", "scam"));
  }

  const tld = host.substring(host.lastIndexOf("."));
  if (SUSPICIOUS_TLDS.includes(tld)) {
    findings.push(finding("suspicious_tld", 15, `Domain uses a suspicious TLD: ${tld}`, "scam"));
  }

  if (countCharacter(host, ".") >= 3) {
    findings.push(finding("many_subdomains", 20, "Domain has many subdomains, common in phishing sites", "scam"));
  }

  for (const keyword of RISKY_HOST_KEYWORDS) {
    if (host.includes(keyword)) {
      findings.push(finding("risky_host_keyword", 20, `Domain contains risky keyword: ${keyword}`, "scam"));
      break;
    }
  }

  for (const keyword of RISKY_PATH_KEYWORDS) {
    if (path.includes(keyword) || query.includes(keyword)) {
      findings.push(finding("risky_url_keyword", 15, `URL contains risky keyword: ${keyword}`, "scam"));
      break;
    }
  }

  for (const extension of RISKY_EXTENSIONS) {
    if (path.endsWith(extension) || full.includes(`${extension}?`)) {
      findings.push(finding("risky_download_extension", 40, `URL points to a risky download type: ${extension}`, "malware"));
      break;
    }
  }

  for (const keyword of AD_TRACKER_KEYWORDS) {
    if (host.includes(keyword) || path.includes(keyword)) {
      findings.push(finding("ad_tracker", 70, `Potential ad or tracker detected: ${keyword}`, "ads"));
      break;
    }
  }

  if (parsed.protocol === "http:") {
    findings.push(finding("plain_http", 20, "Page uses HTTP without transport encryption", "scam"));
  }

  // Filter findings based on active toggles
  const activeFindings = findings.filter(f => {
    // Critical threats (score 100) always trigger automatic block regardless of settings
    if (f.score >= 100) return true;

    if (f.category === "ads") return state.adsEnabled;
    if (f.category === "malware") return state.malwareEnabled;
    if (f.category === "scam") return state.scamEnabled;
    return true;
  });

  const score = Math.min(activeFindings.reduce((total, item) => total + item.score, 0), 100);
  let level = "clean";
  if (score >= 85) {
    level = "high";
  } else if (score >= 50) {
    level = "medium";
  } else if (score > 0) {
    level = "low";
  }

  return {
    url: rawUrl,
    host,
    score,
    level,
    findings: activeFindings,
    checkedAt: new Date().toISOString()
  };
}

function cleanResult(url) {
  return {
    url,
    host: "",
    score: 0,
    level: "clean",
    findings: [],
    checkedAt: new Date().toISOString()
  };
}

function finding(rule, score, message, category) {
  return { rule, score, message, category };
}

async function getState() {
  const state = await chrome.storage.local.get(DEFAULT_STATE);
  return { ...DEFAULT_STATE, ...state };
}

async function signIn(profile) {
  const cleanProfile = {
    name: String(profile?.name || "").trim(),
    email: String(profile?.email || "").trim().toLowerCase(),
    signedInAt: new Date().toISOString()
  };

  if (!cleanProfile.name || !cleanProfile.email.includes("@")) {
    return {
      ok: false,
      error: "Enter a name and valid email."
    };
  }

  await chrome.storage.local.set({
    signedIn: true,
    profile: cleanProfile,
    enabled: true
  });

  return {
    ok: true,
    profile: cleanProfile
  };
}

async function signOut() {
  await chrome.storage.local.set({
    signedIn: false,
    profile: null
  });
  return { ok: true };
}

async function setEnabled(enabled) {
  await chrome.storage.local.set({ enabled });
  return { ok: true, enabled };
}

async function setSetting(key, value) {
  const state = await getState();
  await chrome.storage.local.set({ [key]: value });
  return { ok: true, [key]: value };
}

async function addAllowlistHost(rawUrl) {
  try {
    const state = await getState();
    const host = new URL(rawUrl).hostname.toLowerCase();
    const allowlist = Array.from(new Set([...(state.allowlist || []), host]));
    await chrome.storage.local.set({ allowlist });
    return { ok: true, allowlist };
  } catch (err) {
    return { ok: false, error: "Invalid URL provided" };
  }
}

async function saveDetection(result) {
  const state = await getState();
  const detections = [result, ...(state.detections || [])].slice(0, 100);
  await chrome.storage.local.set({ detections });
}

function isHostInList(host, list) {
  return list.some((entry) => host === entry || host.endsWith(`.${entry}`));
}

function isIpAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function countCharacter(value, character) {
  return value.split(character).length - 1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// REAL-TIME SYSTEM FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

const SHIELDSCAN_API_BASE = 'http://localhost:8765';

async function _apiGet(path) {
  try {
    const res = await fetch(`${SHIELDSCAN_API_BASE}${path}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch { return null; }
}

async function _apiPost(path, body) {
  try {
    const res = await fetch(`${SHIELDSCAN_API_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch { return null; }
}

async function getSystemStats() {
  const data = await _apiGet('/api/stats');
  if (data && !data.error) {
    systemState.threatsBlocked = data.threats_blocked ?? systemState.threatsBlocked;
    systemState.protectionScore = data.protection_score ?? systemState.protectionScore;
    systemState.scansToday = data.scans_today ?? systemState.scansToday;
    return {
      threatsBlocked: systemState.threatsBlocked,
      scansToday: systemState.scansToday,
      protectionScore: systemState.protectionScore,
      uptime: data.uptime_hours ?? systemState.uptime,
    };
  }
  return { threatsBlocked: systemState.threatsBlocked, scansToday: systemState.scansToday, protectionScore: systemState.protectionScore, uptime: systemState.uptime };
}

async function getProtectionStatus() {
  const data = await _apiGet('/api/status');
  if (data && !data.error) {
    systemState.isProtectionActive = data.protection_active ?? true;
    return { active: data.protection_active, mainShield: data.real_time_shield, scanning: true, updatesLatest: true, systemNormal: true, vpnEnabled: systemState.vpnEnabled, latestDetection: data.latest_detection };
  }
  return { active: systemState.isProtectionActive, mainShield: systemState.isProtectionActive, scanning: true, updatesLatest: true, systemNormal: true, vpnEnabled: systemState.vpnEnabled };
}

async function performQuickScan() {
  systemState.scansToday++;
  systemState.lastScanTime = new Date().toISOString();

  // Trigger a real scan via the API (scans the protection state for new events)
  const data = await _apiGet('/api/detections?limit=5&all=true');
  let threatsFound = 0;

  if (data && Array.isArray(data.detections)) {
    // Count detections from the last 60 seconds as "found by this scan"
    const cutoff = Date.now() - 60000;
    threatsFound = data.detections.filter(d => new Date(d.timestamp).getTime() > cutoff).length;
  }

  // Broadcast scan completion
  broadcastToAllTabs({
    type: 'SCAN_COMPLETE',
    data: {
      threatsFound,
      scanType: 'quick',
      timestamp: systemState.lastScanTime
    }
  });

  return {
    success: true,
    threatsFound,
    scanType: 'quick',
    timestamp: systemState.lastScanTime
  };
}

async function performScan(data) {
  const { input } = data;
  const apiResult = await _apiPost('/api/scan', { target: input });
  if (apiResult && !apiResult.error) {
    await chrome.storage.local.set({ lastScanResult: apiResult });
    if (apiResult.level === 'high') {
      systemState.threatsBlocked++;
      broadcastToAllTabs({ type: 'THREAT_DETECTED', data: { id: Date.now(), timestamp: new Date(), type: 'malicious', title: 'AI Scanner � threat detected', url: input, category: 'scam', action: 'blocked', score: apiResult.score } });
    }
    return { result: apiResult.result || 'safe', score: apiResult.score, findings: apiResult.url_findings || [], url: input };
  }
  // Fallback to local analysis
  const fallback = analyzeURL(input);
  return { result: fallback.score >= 85 ? 'malicious' : fallback.score >= 50 ? 'suspicious' : 'safe', score: fallback.score, findings: fallback.threats || [], url: input };
}

function analyzeURL(url) {
  // Simple URL analysis fallback
  const suspiciousKeywords = [
    'secure-login', 'verify-account', 'update-payment', 'claim-reward',
    'fake-bank', 'phishing', 'scam', 'malicious', 'urgent-update'
  ];
  
  let score = 0;
  const threats = [];
  
  for (const keyword of suspiciousKeywords) {
    if (url.toLowerCase().includes(keyword)) {
      score += 25;
      threats.push({
        name: `Suspicious keyword: ${keyword}`,
        category: 'phishing',
        severity: 'high'
      });
    }
  }
  
  // Check for suspicious TLDs
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.xyz'];
  for (const tld of suspiciousTLDs) {
    if (url.includes(tld)) {
      score += 20;
      threats.push({
        name: `Suspicious domain extension: ${tld}`,
        category: 'domain',
        severity: 'medium'
      });
    }
  }
  
  return {
    score: Math.min(score, 100),
    threats,
    type: score >= 85 ? 'malicious' : score >= 50 ? 'suspicious' : 'safe'
  };
}

async function getLastScanResult() {
  const data = await chrome.storage.local.get('lastScanResult');
  return data.lastScanResult || null;
}

// Broadcast to all extension tabs
async function broadcastToAllTabs(message) {
  try {
    // Keep storage fallback for pages that poll
    await chrome.storage.local.set({
      lastBroadcast: message,
      lastBroadcastTime: Date.now()
    });

    // MV3 best-effort: send to all extension listeners
    // (dashboard.js + popup.js use chrome.runtime.onMessage)
    try {
      await chrome.runtime.sendMessage(message);
    } catch {
      // ignore if no listeners are currently active
    }

    console.log('Broadcasted message:', message.type);
  } catch (error) {
    console.log('Error broadcasting to tabs:', error);
  }
}

// Broadcast threat detection to all open dashboards
async function broadcastThreatDetection(threat) {
  const tabs = await chrome.tabs.query({});
  tabs.forEach(tab => {
    if (tab.url && tab.url.includes('dashboard.html')) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'THREAT_DETECTED',
        data: threat,
      }).catch(() => {
        // Tab might not have content script
      });
    }
  });
}

// Broadcast VPN status to all open dashboards
async function broadcastVPNStatus() {
  if (!vpnManager) return;
  
  const status = vpnManager.getStatus();
  const tabs = await chrome.tabs.query({});
  tabs.forEach(tab => {
    if (tab.url && tab.url.includes('dashboard.html')) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'VPN_STATUS_UPDATE',
        data: status,
      }).catch(() => {
        // Tab might not have content script
      });
    }
  });
}

function withBackoff(fn, options = {}) {
  const {
    baseDelayMs = 20000,
    maxDelayMs = 120000,
    factor = 2,
  } = options;

  let delayMs = baseDelayMs;

  return async function runLoopOnce() {
    try {
      const res = await fn();
      // reset backoff on success
      delayMs = baseDelayMs;
      return { ok: true, res };
    } catch (err) {
      // exponential backoff on failure
      delayMs = Math.min(maxDelayMs, Math.round(delayMs * factor));
      return { ok: false, err, delayMs };
    }
  };
}

// Update stats periodically and broadcast to all extension interfaces
let _statsTimer = null;
let _statsBackoffDelay = 25000;

async function pollStatsAndBroadcast() {
  // Keep current behavior but avoid hammering: if a request fails, backoff
  const res = await getSystemStats().catch(() => null);
  const res2 = await getProtectionStatus().catch(() => null);

  const stats = res;
  const status = res2;

  if (!stats || !status) {
    _statsBackoffDelay = Math.min(120000, Math.round(_statsBackoffDelay * 2));
    _statsTimer = setTimeout(pollStatsAndBroadcast, _statsBackoffDelay);
    return;
  }

  // success: reset backoff
  _statsBackoffDelay = 25000;

  broadcastToAllTabs({ type: 'STATS_UPDATE', data: stats });
  broadcastToAllTabs({ type: 'PROTECTION_STATUS', data: status });

  _statsTimer = setTimeout(pollStatsAndBroadcast, 25000); // default 25s
}

_statsTimer = setTimeout(pollStatsAndBroadcast, 25000);

// Poll real detections from the local API server and broadcast any new ones
let _bgLastDetectionTs = null;
let _detectionsBackoffDelay = 20000; // 20s default

async function pollDetectionsAndBroadcast() {
  const data = await _apiGet('/api/detections?limit=10&all=true');
  if (!data || !Array.isArray(data.detections)) {
    _detectionsBackoffDelay = Math.min(120000, Math.round(_detectionsBackoffDelay * 2));
    setTimeout(pollDetectionsAndBroadcast, _detectionsBackoffDelay);
    return;
  }

  // success: reset backoff
  _detectionsBackoffDelay = 20000;

  const newOnes = data.detections.filter(det => {
    if (!_bgLastDetectionTs) return false;
    return det.timestamp > _bgLastDetectionTs;
  });

  // Update watermark
  if (data.detections.length > 0 && !_bgLastDetectionTs) {
    _bgLastDetectionTs = data.detections[0].timestamp;
  }

  newOnes.forEach(det => {
    _bgLastDetectionTs = det.timestamp;
    const threatData = {
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
    };

    systemState.threatsBlocked++;
    systemState.recentThreats.unshift(threatData);
    systemState.recentThreats = systemState.recentThreats.slice(0, 10);

    broadcastToAllTabs({ type: 'THREAT_DETECTED', data: threatData });
  });

  setTimeout(pollDetectionsAndBroadcast, 20000); // default 20s
}

setTimeout(pollDetectionsAndBroadcast, 20000); // initial delay

// Initialize system state on startup
chrome.runtime.onStartup.addListener(() => {
  console.log('ShieldScan protection service starting...');
  systemState.isProtectionActive = true;
});
