// ═══════════════════════════════════════════════════════════════════════════════
// EVENT HANDLERS - ShieldScan Dashboard (minimal shim)
// Navigation and all interactions handled by dashboard.js
// ═══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', function() {
  // Handle modal close for legacy globalModal
  document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal-close') || e.target.closest('.modal-close')) {
      const modal = document.getElementById('globalModal');
      if (modal) modal.style.display = 'none';
    }
  });
});

window.showPlansModal = function() {
  if (typeof window.showModal === 'function') {
    window.showModal('ShieldScan Free', 'ShieldScan is completely free with unlimited protection for all your devices.');
  }
};

window.showActivityLog = function() {
  if (window.realtimeDashboard) window.realtimeDashboard.navigateToPage('page-detection');
};
