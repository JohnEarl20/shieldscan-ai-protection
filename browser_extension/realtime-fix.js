// ═══════════════════════════════════════════════════════════════════════════════
// REALTIME FIX - ShieldScan Dashboard (minimal shim)
// Real-time data handled by dashboard.js setupLiveData()
// ═══════════════════════════════════════════════════════════════════════════════

// Threat notification helper (used by background message listener)
window.showThreatNotification = function(threat) {
  const notification = document.createElement('div');
  notification.style.cssText = 'position:fixed;top:20px;right:20px;background:rgba(240,82,82,0.95);color:white;padding:12px 16px;border-radius:8px;font-size:14px;font-weight:600;z-index:10000;box-shadow:0 4px 12px rgba(0,0,0,0.3)';
  notification.innerHTML = '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:18px">🚨</span><div><div>' + (threat.title || 'Threat Detected') + '</div><div style="font-size:12px;opacity:0.9">' + (threat.category || 'Security Alert') + '</div></div></div>';
  document.body.appendChild(notification);
  setTimeout(() => notification.remove(), 5000);
};

// Minimal RealtimeManager stub — avoids conflicts with dashboard.js
window.realtimeManager = {
  on: function() {},
  send: function(msg, cb) {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
      try { chrome.runtime.sendMessage(msg, cb); } catch(_) { if (cb) cb(null); }
    } else { if (cb) cb(null); }
  }
};

window.setupRealtimeIntegration = function() {};
