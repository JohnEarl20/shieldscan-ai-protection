// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD INLINE SCRIPT - ShieldScan AI Scam Protection
// Extracted from inline script to fix CSP violations
// ═══════════════════════════════════════════════════════════════════════════════

// ── NAVIGATION ──────────────────────────────────────────────────────────────
function navigate(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const target = document.getElementById(pageId);
  if (target) target.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.dataset.page === pageId);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', e => {
      e.preventDefault();
      navigate(item.dataset.page);
    });
  });
});

// ── MODAL ────────────────────────────────────────────────────────────────────
function showModal(title, html) {
  document.getElementById('modalTitle').textContent = title;
  document.getElementById('modalBody').innerHTML = '<p style="color:var(--text2);line-height:1.7;margin:0">' + html + '</p>';
  document.getElementById('globalModal').style.display = 'flex';
}

function showActivityLog() {
  showModal('Full Activity Log',
    '<b style="color:var(--text1)">Recent Activity</b><br><br>' +
    '&#x1F534; Malicious website blocked &mdash; https://freeview.tiktok.com &mdash; 1 min ago<br>' +
    '&#x1F7E2; Real-time protection &mdash; Threat blocked &mdash; 8 min ago<br>' +
    '&#x1F50D; Scan completed &mdash; Quick scan &mdash; 1 hour ago<br>' +
    '&#x1F6E1;&#xFE0F; AI Scam Protection &mdash; Blocked scam &mdash; 3 hours ago<br>' +
    '&#x1F510; Privacy Protection &mdash; Protected 3 issues &mdash; 5 hours ago'
  );
}

// ── AI SCANNER ───────────────────────────────────────────────────────────────
(function() {
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('aiScanBtn');
    const input = document.getElementById('aiScanInput');
    const result = document.getElementById('aiScanResult');
    if (!btn) return;

    function analyze(val) {
      const malicious = [/banking.*verify|verify.*banking|secure.*login/i,/claim.*prize|free.*money/i,/ransomware|trojan|malware|phishing|scam/i,/secure-verify|verify-account|update-now/i,/\.xyz|\.top|\.buzz|\.loan|\.pw|\.tk|\.cf/i];
      const suspicious = [/download|free.*software/i,/airdrop|bonus|reward|claim/i,/urgent|limited.*time|act.*now/i];
      const safe = [/google\.com|github\.com|stackoverflow\.com|amazon\.com|microsoft\.com|apple\.com/i];
      for (const p of safe) if (p.test(val)) return {type:'safe',msg:'No threats detected.'};
      for (const p of malicious) if (p.test(val)) return {type:'danger',msg:'THREAT DETECTED! This link/content is dangerous and has been blocked.'};
      for (const p of suspicious) if (p.test(val)) return {type:'warning',msg:'SUSPICIOUS! Proceed with caution.'};
      return {type:'safe',msg:'Looks safe! No threats detected in this content.'};
    }

    function doScan() {
      const val = input.value.trim();
      if (!val) { input.focus(); return; }
      result.className = 'scan-result';
      result.style.display = 'flex';
      result.style.background = 'rgba(79,142,247,.1)';
      result.style.color = 'var(--accent)';
      result.style.border = '1px solid rgba(79,142,247,.3)';
      result.innerHTML = '&#x1F50D; <strong>Analyzing&hellip;</strong>';
      setTimeout(() => {
        const r = analyze(val);
        result.style.background = '';
        result.style.color = '';
        result.style.border = '';
        result.className = 'scan-result ' + r.type;
        const icons = {safe:'&#x2714;&#xFE0F;', danger:'&#x26A0;&#xFE0F;', warning:'&#x26A1;'};
        result.innerHTML = icons[r.type] + ' <strong>' + r.msg + '</strong>';
        // Add to recent scans
        const list = document.getElementById('recentScansList');
        if (list) {
          const row = document.createElement('div');
          row.className = 'scan-row';
          const pillClass = r.type === 'safe' ? 'safe' : 'malicious';
          const pillText = r.type === 'safe' ? '&#x2713; Safe' : '&#x1F534; ' + (r.type === 'danger' ? 'Malicious' : 'Suspicious');
          row.innerHTML = '<span class="scan-row-icon">&#x1F310;</span><div class="scan-row-info"><div class="scan-url">' + val.substring(0,60) + '</div><div class="scan-time">Scanned &bull; just now</div></div><span class="pill ' + pillClass + '">' + pillText + '</span><span class="row-arrow">&rsaquo;</span>';
          list.insertBefore(row, list.firstChild);
        }
      }, 600);
    }

    btn.addEventListener('click', doScan);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') doScan(); });

    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(t => {
      t.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => { b.style.borderBottomColor='transparent'; b.style.color='var(--text2)'; });
        t.style.borderBottomColor = 'var(--accent)';
        t.style.color = 'var(--accent)';
        const placeholders = {link:'Paste a link to scan (e.g. https://example.com)', text:'Paste suspicious text here…', file:'Enter file path or upload…', screenshot:'Paste image URL or take a screenshot…'};
        input.placeholder = placeholders[t.dataset.tab] || '';
      });
    });
  });
})();

// ── VPN FUNCTIONS ─────────────────────────────────────────────────────────────
window.vpnState = {
  on: localStorage.getItem('vpnEnabled') === 'true',
  country: localStorage.getItem('vpnCountry') || 'United States',
  seconds: 0,
  timerInterval: null,
  dataTransferred: parseFloat(localStorage.getItem('vpnData') || '0'),
};

const VPN_SERVERS = [
  { flag:'⚡', name:'Optimal location', city:'Let ShieldScan choose the best server', ping:null,  ip:'185.213.154.23', tab:['all'],                    optimal:true },
  { flag:'🇺🇸', name:'United States',   city:'New York',    ping:32,  ip:'185.213.154.23', tab:['all','streaming','p2p'], fav:true  },
  { flag:'🇬🇧', name:'United Kingdom',  city:'London',      ping:48,  ip:'178.62.52.100',  tab:['all','streaming'],       fav:false },
  { flag:'🇨🇦', name:'Canada',          city:'Toronto',     ping:52,  ip:'142.93.128.50',  tab:['all','p2p'],             fav:false },
  { flag:'🇩🇪', name:'Germany',         city:'Frankfurt',   ping:60,  ip:'138.68.64.68',   tab:['all','streaming'],       fav:false },
  { flag:'🇳🇱', name:'Netherlands',     city:'Amsterdam',   ping:55,  ip:'167.99.200.50',  tab:['all','p2p'],             fav:true  },
  { flag:'🇸🇬', name:'Singapore',       city:'Singapore',   ping:110, ip:'128.199.192.50', tab:['all','streaming'],       fav:false },
  { flag:'🇯🇵', name:'Japan',           city:'Tokyo',       ping:130, ip:'139.59.208.50',  tab:['all'],                   fav:false },
  { flag:'🇦🇺', name:'Australia',       city:'Sydney',      ping:155, ip:'159.65.128.50',  tab:['all'],                   fav:false },
  { flag:'🇫🇷', name:'France',          city:'Paris',       ping:58,  ip:'51.15.128.50',   tab:['all','streaming'],       fav:false },
  { flag:'🇧🇷', name:'Brazil',          city:'São Paulo',   ping:180, ip:'177.71.128.50',  tab:['all','p2p'],             fav:false },
  { flag:'🇮🇳', name:'India',           city:'Mumbai',      ping:95,  ip:'139.59.64.50',   tab:['all'],                   fav:false },
];

let vpnTabFilter = 'all';
let vpnSearchQuery = '';

function pingColor(p) {
  if (!p) return 'var(--accent)';
  if (p < 60) return 'var(--green)';
  if (p < 120) return 'var(--yellow)';
  return 'var(--red)';
}

window.switchVPNTab = function(btn) {
  document.querySelectorAll('.vpn-tab').forEach(t => {
    t.style.borderBottomColor = 'transparent'; t.style.color = 'var(--text2)';
  });
  btn.style.borderBottomColor = 'var(--accent)'; btn.style.color = 'var(--accent)';
  vpnTabFilter = btn.dataset.tab;
  renderVPNServers();
};

window.filterVPNServers = function() {
  vpnSearchQuery = document.getElementById('vpnSearch')?.value || '';
  renderVPNServers();
};

window.toggleFav = function(name) {
  const s = VPN_SERVERS.find(x => x.name === name);
  if (s) { s.fav = !s.fav; renderVPNServers(); }
};

window.connectVPN = function(name, ip) {
  window.vpnState.on = true;
  window.vpnState.country = name;
  window.vpnState.seconds = 0;
  localStorage.setItem('vpnEnabled', 'true');
  localStorage.setItem('vpnCountry', name);
  updateVPN();
  renderVPNServers();
};

window.quickConnect = function() {
  connectVPN('United States', '185.213.154.23');
};

// Initialize VPN functionality
document.addEventListener('DOMContentLoaded', () => {
  // VPN toggle buttons
  const vpnToggleBtn = document.getElementById('vpnToggleBtn');
  const vpnToggleBtn2 = document.getElementById('vpnToggleBtn2');
  
  if (vpnToggleBtn) {
    vpnToggleBtn.addEventListener('click', () => {
      window.vpnState.on = !window.vpnState.on;
      if (!window.vpnState.on) window.vpnState.seconds = 0;
      updateVPN();
      renderVPNServers();
    });
  }
  
  if (vpnToggleBtn2) {
    vpnToggleBtn2.addEventListener('click', (e) => {
      e.preventDefault();
      window.vpnState.on = !window.vpnState.on;
      if (!window.vpnState.on) window.vpnState.seconds = 0;
      updateVPN();
      renderVPNServers();
    });
  }
  
  // Initialize VPN
  updateVPN();
  if (window.vpnState.on) startVPNTimer();
});

// Global functions for VPN
function renderVPNServers() {
  const list = document.getElementById('vpnServerList');
  if (!list) return;
  const q = vpnSearchQuery.toLowerCase();
  const shown = VPN_SERVERS.filter(s => {
    const matchTab = vpnTabFilter === 'all' || s.tab.includes(vpnTabFilter) ||
                     (vpnTabFilter === 'favorites' && s.fav);
    const matchQ = !q || s.name.toLowerCase().includes(q) || s.city.toLowerCase().includes(q);
    return matchTab && matchQ;
  });

  if (shown.length === 0) {
    list.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text3);font-size:13px">No locations found</div>';
    return;
  }

  list.innerHTML = shown.map(s => {
    const isActive = window.vpnState.on && window.vpnState.country === s.name;
    return `<div class="vpn-server-row" data-name="${s.name}" data-ip="${s.ip}"
      style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;${isActive ? 'background:rgba(79,142,247,.08)' : ''}"
      onmouseover="this.style.background='var(--bg-card2)'" onmouseout="this.style.background='${isActive ? 'rgba(79,142,247,.08)' : ''}'">
      <div style="font-size:22px;flex-shrink:0">${s.flag}</div>
      <div style="flex:1;min-width:0">
        <div style="font-size:13px;font-weight:600;color:var(--text1);margin-bottom:1px">${s.name}</div>
        <div style="font-size:11px;color:var(--text3)">${s.city}</div>
      </div>
      ${s.ping ? `<div style="font-size:12px;font-weight:600;color:${pingColor(s.ping)}">${s.ping} ms</div>` : ''}
      <button onclick="event.stopPropagation();toggleFav('${s.name}')" style="background:none;border:none;cursor:pointer;font-size:16px;padding:2px 4px;color:${s.fav ? 'var(--yellow)' : 'var(--text3)'}" title="Favorite">★</button>
      ${s.optimal
        ? `<button onclick="event.stopPropagation();connectVPN('${s.name}','${s.ip}')" style="padding:6px 16px;background:var(--accent);color:#fff;border:none;border-radius:7px;font-size:12px;font-weight:700;cursor:pointer">Connect</button>`
        : isActive
          ? `<span style="font-size:11px;font-weight:700;color:var(--green)">● Connected</span>`
          : `<button onclick="event.stopPropagation();connectVPN('${s.name}','${s.ip}')" style="padding:6px 14px;background:var(--bg-card2);color:var(--text2);border:1px solid var(--border);border-radius:7px;font-size:12px;font-weight:600;cursor:pointer">Connect</button>`
      }
    </div>`;
  }).join('');

  list.querySelectorAll('.vpn-server-row').forEach(row => {
    row.addEventListener('click', () => connectVPN(row.dataset.name, row.dataset.ip));
  });
}

function startVPNTimer() {
  if (window.vpnState.timerInterval) clearInterval(window.vpnState.timerInterval);
  window.vpnState.timerInterval = setInterval(() => {
    if (!window.vpnState.on) { clearInterval(window.vpnState.timerInterval); return; }
    window.vpnState.seconds++;
    window.vpnState.dataTransferred += 0.04 + Math.random() * 0.06;
    localStorage.setItem('vpnData', window.vpnState.dataTransferred.toFixed(2));
    const h = String(Math.floor(window.vpnState.seconds / 3600)).padStart(2,'0');
    const m = String(Math.floor((window.vpnState.seconds % 3600) / 60)).padStart(2,'0');
    const s = String(window.vpnState.seconds % 60).padStart(2,'0');
    const el = document.getElementById('vpnTimer');
    if (el) el.textContent = `${h}:${m}:${s}`;
    // Update right panel data transferred
    const dtEl = document.getElementById('vpnDataTransferred');
    if (dtEl) dtEl.textContent = window.vpnState.dataTransferred.toFixed(1) + ' MB';
  }, 1000);
}

function updateVPN() {
  const s = window.vpnState;
  const server = VPN_SERVERS.find(x => x.name === s.country) || VPN_SERVERS[1];

  // ── VPN Page ──
  const connLabel = document.getElementById('vpnConnLabel');
  const connDesc  = document.getElementById('vpnConnDesc');
  const connDot   = document.getElementById('vpnConnDot');
  const connStatus= document.getElementById('vpnConnStatus');
  const maskedIP  = document.getElementById('vpnMaskedIP');
  const toggleBtn = document.getElementById('vpnToggleBtn');
  const banner    = document.getElementById('vpnBanner');

  if (s.on) {
    if (connLabel)  { connLabel.textContent = 'protected'; connLabel.style.color = 'var(--green)'; }
    if (connDesc)   connDesc.textContent = 'ShieldScan VPN is encrypting your internet traffic and hiding your IP address.';
    if (connDot)    { connDot.style.background = 'var(--green)'; }
    if (connStatus) { connStatus.textContent = 'Connected'; connStatus.style.color = 'var(--green)'; }
    if (maskedIP)   maskedIP.textContent = server.ip || '185.213.154.23';
    if (toggleBtn)  { toggleBtn.textContent = 'Disconnect'; toggleBtn.style.background = 'linear-gradient(90deg,var(--red),#f97316)'; toggleBtn.style.color = '#fff'; toggleBtn.style.border = 'none'; }
    if (banner)     banner.style.borderColor = 'rgba(45,206,137,.3)';
    startVPNTimer();
  } else {
    if (window.vpnState.timerInterval) clearInterval(window.vpnState.timerInterval);
    if (connLabel)  { connLabel.textContent = 'unprotected'; connLabel.style.color = 'var(--red)'; }
    if (connDesc)   connDesc.textContent = 'Your connection is not encrypted. Enable VPN to protect your privacy.';
    if (connDot)    { connDot.style.background = 'var(--red)'; connDot.style.animation = 'none'; }
    if (connStatus) { connStatus.textContent = 'Disconnected'; connStatus.style.color = 'var(--red)'; }
    if (maskedIP)   maskedIP.textContent = '—';
    if (toggleBtn)  { toggleBtn.textContent = 'Connect'; toggleBtn.style.background = 'linear-gradient(90deg,var(--accent),#6366f1)'; toggleBtn.style.color = '#fff'; toggleBtn.style.border = 'none'; }
    if (banner)     banner.style.borderColor = 'rgba(240,82,82,.3)';
    const timerEl = document.getElementById('vpnTimer');
    if (timerEl) timerEl.textContent = '00:00:00';
  }

  // ── Right panel ──
  const rpStatus  = document.getElementById('vpnStatus');
  const rpBtn     = document.getElementById('vpnToggleBtn2');
  const rpBadge   = document.getElementById('vpnStatusBadge');
  const rpLoc     = document.getElementById('vpnRPLocation');
  const rpIP      = document.getElementById('vpnRPIP');
  const label     = s.on ? `VPN is ON (${s.country})` : 'VPN is OFF';
  if (rpStatus)   rpStatus.textContent = label;
  if (rpBtn)      { rpBtn.textContent = s.on ? 'Turn off' : 'Turn on'; rpBtn.style.background = s.on ? '#10b981' : ''; rpBtn.style.color = s.on ? '#fff' : ''; }
  if (rpBadge)    { rpBadge.textContent = s.on ? 'Active' : 'Inactive'; rpBadge.className = 'sec-badge ' + (s.on ? 'on' : 'off'); }
  if (rpLoc)      rpLoc.textContent = s.on ? s.country + (server.city ? ', ' + server.city : '') : '—';
  if (rpIP)       rpIP.textContent  = s.on ? (server.ip || '—') : '—';

  // ── Security overview badge ──
  const secBadge = document.getElementById('secVpnBadge');
  if (secBadge)   { secBadge.textContent = s.on ? 'Active' : 'Inactive'; secBadge.className = 'sec-badge ' + (s.on ? 'on' : 'off'); }

  localStorage.setItem('vpnEnabled', s.on);
  localStorage.setItem('vpnCountry', s.country);
}

// ── REAL-TIME PROTECTION ─────────────────────────────────────────────────────
(function() {
  const RT_EVENTS = [
    { type:'threat', icon:'🛡️', iconClass:'threat', title:'Threat blocked',         desc:'Malicious file detected and blocked',                  sub:'C:\\Users\\User\\Downloads\\setup.exe',    time:'10:24 AM' },
    { type:'warn',   icon:'⚠️', iconClass:'warn',   title:'Suspicious behavior detected', desc:'Blocked suspicious registry modification',         sub:'HKLM\\Software\\Run\\svchost32',           time:'10:18 AM' },
    { type:'threat', icon:'🛡️', iconClass:'threat', title:'Web threat blocked',      desc:'Access to phishing site prevented',                    sub:'bad-site.example.com',                     time:'10:15 AM' },
    { type:'scan',   icon:'🔍', iconClass:'scan',   title:'File scanned',            desc:'File is safe',                                         sub:'C:\\Users\\User\\Documents\\report.pdf',   time:'10:10 AM' },
    { type:'threat', icon:'🛡️', iconClass:'threat', title:'Threat blocked',          desc:'Malware detected and quarantined',                     sub:'C:\\Users\\User\\AppData\\malware.exe',    time:'10:05 AM' },
  ];

  const LIVE_POOL = [
    { type:'threat', icon:'🛡️', iconClass:'threat', title:'Threat blocked',      desc:'Malicious URL blocked in real time',    sub:'https://claim-prize-now.buzz' },
    { type:'scan',   icon:'🔍', iconClass:'scan',   title:'File scanned',        desc:'File is safe',                          sub:'C:\\Users\\User\\Downloads\\doc.pdf' },
    { type:'warn',   icon:'⚠️', iconClass:'warn',   title:'Suspicious activity', desc:'Unusual network connection detected',   sub:'192.168.1.105 → 45.33.32.156' },
    { type:'threat', icon:'🛡️', iconClass:'threat', title:'Web threat blocked',  desc:'Phishing site prevented',               sub:'https://secure-verify-account.xyz' },
  ];

  let liveEvents = [...RT_EVENTS];

  function now() {
    const d = new Date();
    return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0') + ':' + d.getSeconds().toString().padStart(2,'0');
  }

  window.renderRTFeed = function() {
    const feed = document.getElementById('rtFeed');
    if (!feed) return;
    const filter = document.getElementById('rtFilter')?.value || 'all';
    const shown = liveEvents.filter(e => {
      if (filter === 'threat') return e.type === 'threat' || e.type === 'warn';
      if (filter === 'scan')   return e.type === 'scan';
      return true;
    }).slice(0, 8);

    feed.innerHTML = shown.map(e => `
      <div class="rt-event">
        <div class="rt-event-icon ${e.iconClass}">${e.icon}</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;font-weight:600;color:var(--text1);margin-bottom:2px">${e.title}</div>
          <div style="font-size:11px;color:var(--text2);margin-bottom:2px">${e.desc}</div>
          <div style="font-size:10px;color:var(--text3);word-break:break-all">${e.sub}</div>
        </div>
        <div style="font-size:11px;color:var(--text3);white-space:nowrap;flex-shrink:0">${e.time}</div>
      </div>
    `).join('');
  };

  // Live feed injection
  setInterval(() => {
    if (!document.getElementById('page-realtime')?.classList.contains('active')) return;
    const e = LIVE_POOL[Math.floor(Math.random() * LIVE_POOL.length)];
    liveEvents.unshift({ ...e, time: now() });
    if (liveEvents.length > 50) liveEvents.pop();
    renderRTFeed();
  }, 12000);

  // Toggle feature switches
  window.toggleFeature = function(toggle, key) {
    const isOn = toggle.classList.contains('on');
    toggle.classList.toggle('on', !isOn);
    const label = toggle.previousElementSibling;
    if (label) { label.textContent = isOn ? 'Off' : 'On'; label.style.color = isOn ? 'var(--red)' : 'var(--green)'; }
  };

  // Re-render when navigating to realtime page
  const origNav = window.navigate;
  window.navigate = function(pageId) {
    origNav(pageId);
    if (pageId === 'page-realtime') renderRTFeed();
    if (pageId === 'page-history') { if(typeof render==='function') render(); }
  };

  document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('page-realtime')?.classList.contains('active')) renderRTFeed();
  });
})();

// ── GLOBAL FUNCTIONS ─────────────────────────────────────────────────────────
window.showModal = showModal;
window.showActivityLog = showActivityLog;
window.navigate = navigate;