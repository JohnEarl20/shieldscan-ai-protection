// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD FIX SCRIPT - Minimal shim (all logic handled by dashboard.js)
// ═══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', function() {
  addMissingIds();
});

function addMissingIds() {
  // Ensure stat card IDs exist
  const statCards = document.querySelectorAll('.stat-card');
  if (statCards.length >= 4) {
    const scoreValue = statCards[0].querySelector('.stat-value');
    if (scoreValue && !scoreValue.id) scoreValue.id = 'statScore';
    const threatsValue = statCards[2].querySelector('.stat-value');
    if (threatsValue && !threatsValue.id) threatsValue.id = 'statThreats';
  }
  // Ensure VPN badge ID exists
  document.querySelectorAll('.security-item').forEach(item => {
    const title = item.querySelector('.sec-title');
    if (title && title.textContent.includes('VPN')) {
      const badge = item.querySelector('.sec-badge');
      if (badge && !badge.id) badge.id = 'secVpnBadge';
    }
  });
}

function initializeActivityFeed() {}

// Global navigate shim — delegates to dashboard.js RealtimeDashboard
window.navigate = function(pageId) {
  if (window.realtimeDashboard) {
    window.realtimeDashboard.navigateToPage(pageId);
  }
};

// Global showModal shim
window.showModal = function(title, content) {
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:10000';
  modal.innerHTML = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;max-width:500px;width:90%;padding:20px"><h2 style="color:var(--text1);margin:0 0 12px">' + title + '</h2><div style="color:var(--text2);font-size:13px">' + content + '</div><button onclick="this.closest(\'.modal-overlay\').remove()" style="margin-top:16px;background:var(--accent);color:#fff;border:none;border-radius:8px;padding:8px 18px;cursor:pointer">Close</button></div>';
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
};
