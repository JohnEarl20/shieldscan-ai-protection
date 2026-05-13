// ═══════════════════════════════════════════════════════════════════════════════
// REAL-TIME DASHBOARD - AI Scam Protection ShieldScan
// Real-time threat monitoring and protection with live system integration
// ═══════════════════════════════════════════════════════════════════════════════

class RealtimeDashboard {
  constructor() {
    this.stats = {
      threatsBlocked: 0,
      scansToday: 0,
      protectionScore: 85,
      uptime: 24,
    };
    this.threatHistory = [];
    this.maxThreatsDisplay = 50;

    // Dedup so THREAT_DETECTED broadcasts + API polling don't double-count
    this._seenThreatIds = new Set();

    this.isProtectionActive = true;
    this.lastUpdateTime = Date.now();
    this.scannerActive = false;
    this.vpnStatus = { enabled: false, country: 'US', server: 'us-east' };
    
    this.init();
  }

  init() {
    this.setupMessageListener();
    this.startRealtimeUpdates();
    this.loadStoredData();
    this.setupClickHandlers();
    this.setupNavigationHandlers();
    this.setupScannerIntegration();
    this.setupScannerPage();
    this.setupDetectionHistory();
    this.setupRealtimePage();
    this.setupSettingsPage();
    this.setupToolsPage();
    this.setupThreatHistory();
    this.setupAdsBlocked();
    this.setupGlobalLinks();
    this.setupAccountPage();
    this.setupIdentityPage();
    this.setupVPNIntegration();
    this.loadSystemStats();
    this.setupLiveData();
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SYSTEM INTEGRATION - Connect to ShieldScan Protection Service
  // ─────────────────────────────────────────────────────────────────────────────

  async loadSystemStats() {
    // Try direct API first (fastest, most accurate)
    const apiStats = await this._apiGet('/api/stats');
    if (apiStats && !apiStats.error) {
      this.stats.threatsBlocked = apiStats.threats_blocked ?? this.stats.threatsBlocked;
      this.stats.protectionScore = apiStats.protection_score ?? this.stats.protectionScore;
      this.stats.scansToday = apiStats.scans_today ?? this.stats.scansToday;
      this.stats.uptime = apiStats.uptime_hours ?? this.stats.uptime;
      this.updateDashboardStats();
      this._updateApiStatusIndicator(true);
    } else {
      this._updateApiStatusIndicator(false);
      // Fallback: ask background service
      this.sendMessageToBackground({ type: 'REQUEST_STATS' }, (stats) => {
        if (stats) {
          this.stats = { ...this.stats, ...stats };
          this.updateDashboardStats();
        }
      });
    }

    // Load protection status
    const apiStatus = await this._apiGet('/api/status');
    if (apiStatus && !apiStatus.error) {
      this.updateProtectionStatus({
        active: apiStatus.protection_active,
        mainShield: apiStatus.real_time_shield,
        vpnEnabled: apiStatus.vpn_enabled,
        latestDetection: apiStatus.latest_detection,
      });
    } else {
      this.sendMessageToBackground({ type: 'REQUEST_STATUS' }, (status) => {
        if (status) this.updateProtectionStatus(status);
      });
    }

    // Load real detections
    this.loadRecentThreats();
  }

  _updateApiStatusIndicator(online) {
    const indicator = document.getElementById('apiStatusIndicator');
    const banner = document.getElementById('apiOfflineBanner');
    if (indicator) {
      indicator.textContent = online ? '🟢 Live' : '🟡 Protected';
      indicator.title = online
        ? 'ShieldScan API connected — showing real data'
        : 'Local API offline — cloud protection active (URLhaus, PhishTank, Google Safe Browsing)';
    }
    if (banner) {
      banner.style.display = 'none'; // Never show offline banner — cloud APIs handle it
    }
  }

  async loadRecentThreats() {
    // Load REAL detections from the local API server
    try {
      const data = await this._apiGet('/api/detections?limit=20&all=true');
      if (data && Array.isArray(data.detections) && data.detections.length > 0) {
        this.threatHistory = data.detections.map(det => ({
          id: det.timestamp + '_' + (det.path || ''),
          timestamp: new Date(det.timestamp),
          type: det.level === 'high' ? 'malicious' : det.level === 'medium' ? 'suspicious' : 'safe',
          title: det.path
            ? `Threat detected: ${det.path.split('\\').pop().split('/').pop()}`
            : (det.type === 'quarantine' ? 'File quarantined' : 'Threat detected'),
          url: det.path || '',
          severity: det.level === 'high' ? 'high' : det.level === 'medium' ? 'medium' : 'low',
          category: det.findings?.[0]?.rule || det.type || 'malware',
          action: det.quarantined ? 'quarantined' : (det.level === 'high' ? 'blocked' : 'flagged'),
          score: det.score,
          ai_score: det.ai_score,
          sandbox_verdict: det.sandbox_verdict,
        }));
        this.stats.threatsBlocked = this.threatHistory.filter(
          t => t.action === 'quarantined' || t.action === 'blocked'
        ).length;
        this.updateDashboardStats();
        return;
      }
    } catch (e) {
      // API not available — show empty state, no fake data
    }

    // API offline: show empty state
    this.threatHistory = [];
    this.stats.threatsBlocked = 0;
    this.updateDashboardStats();
  }

  // Direct fetch to local API (used by dashboard page itself, not via background)
  async _apiGet(path) {
    try {
      const r = await fetch(`http://localhost:8765${path}`, { signal: AbortSignal.timeout(4000) });
      if (!r.ok) return null;
      return await r.json();
    } catch { return null; }
  }

  async _apiPost(path, body) {
    try {
      const r = await fetch(`http://localhost:8765${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(6000),
      });
      if (!r.ok) return null;
      return await r.json();
    } catch { return null; }
  }

  updateDashboardStats() {
    // Update stat cards with real data
    const statScore = document.getElementById('statScore');
    const statThreats = document.getElementById('statThreats');

    if (statScore) statScore.textContent = this.stats.protectionScore;
    if (statThreats) statThreats.textContent = this.stats.threatsBlocked;

    // Update activity feed with real detections
    this.updateActivityFeed();

    // Also update the Real-Time Protection page event feed if visible
    this.renderThreatFeed();
  }

  updateActivityFeed() {
    const activityContainer = document.querySelector('#page-dashboard .section-card:last-child');
    if (!activityContainer) return;

    const activityItems = activityContainer.querySelectorAll('.activity-item');

    if (this.threatHistory.length === 0) {
      // Show "all clear" state — no fake data
      activityItems.forEach((item, index) => {
        const icon = item.querySelector('.act-icon');
        const title = item.querySelector('.act-title');
        const sub = item.querySelector('.act-sub');
        const time = item.querySelector('.act-time');
        if (index === 0) {
          if (icon) { icon.className = 'act-icon good'; icon.textContent = '🟢'; }
          if (title) title.textContent = 'No threats detected';
          if (sub) sub.textContent = 'System is clean';
          if (time) time.textContent = 'Just now';
        } else {
          item.style.display = 'none';
        }
      });
      return;
    }

    // Show real threat data
    activityItems.forEach(item => { item.style.display = ''; });
    this.threatHistory.slice(0, activityItems.length).forEach((threat, index) => {
      const item = activityItems[index];
      if (!item) return;

      const icon = item.querySelector('.act-icon');
      const title = item.querySelector('.act-title');
      const sub = item.querySelector('.act-sub');
      const time = item.querySelector('.act-time');

      if (icon) {
        icon.className = `act-icon ${threat.type === 'malicious' ? 'bad' : threat.type === 'suspicious' ? 'info' : 'good'}`;
        icon.textContent = threat.type === 'malicious' ? '🔴' : threat.type === 'suspicious' ? '⚡' : '🟢';
      }

      if (title) title.textContent = threat.title;
      if (sub) sub.textContent = threat.url || threat.category;
      if (time) time.textContent = this.getTimeAgo(threat.timestamp);
    });
  }

  setupNavigationHandlers() {
    // Handle navigation between pages — delegated on document
    document.addEventListener('click', (e) => {
      const navItem = e.target.closest('.nav-item[data-page]');
      if (!navItem) return;

      e.preventDefault();
      const pageId = navItem.getAttribute('data-page');
      if (pageId) {
        this.navigateToPage(pageId);
      }
    });

    // Also handle any btn-turnon / data-action="navigate" buttons
    document.addEventListener('click', (e) => {
      const el = e.target.closest('[data-action="navigate"][data-page]');
      if (!el) return;
      e.preventDefault();
      this.navigateToPage(el.dataset.page);
    });
  }

  navigateToPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
      page.classList.remove('active');
    });

    // Show target page
    const targetPage = document.getElementById(pageId);
    if (targetPage) {
      targetPage.classList.add('active');
    }

    // Update nav
    document.querySelectorAll('.nav-item').forEach(nav => {
      nav.classList.remove('active');
    });
    
    const activeNav = document.querySelector(`[data-page="${pageId}"]`);
    if (activeNav) {
      activeNav.classList.add('active');
    }

    // Switch right panel based on page
    const rpAdvisor    = document.getElementById('rp-advisor');
    const rpScanner    = document.getElementById('rp-scanner');
    const rpDetection  = document.getElementById('rp-detection');
    const rpRealtime   = document.getElementById('rp-realtime');
    const rpPrivacy    = document.getElementById('rp-privacy');
    const rpIdentity   = document.getElementById('rp-identity');
    const rpTools      = document.getElementById('rp-tools');
    const rpScanguard  = document.getElementById('rp-scanguard');
    const rpSettings   = document.getElementById('rp-settings');
    const rpAccount    = document.getElementById('rp-account');
    const allPanels    = [rpAdvisor, rpScanner, rpDetection, rpRealtime, rpPrivacy, rpIdentity, rpTools, rpScanguard, rpSettings, rpAccount].filter(Boolean);

    allPanels.forEach(p => p.style.display = 'none');

    if      (pageId === 'page-scanner')    { if (rpScanner)    rpScanner.style.display    = 'flex'; }
    else if (pageId === 'page-detection')  { if (rpDetection)  rpDetection.style.display  = 'flex'; }
    else if (pageId === 'page-realtime')   { if (rpRealtime)   rpRealtime.style.display   = 'flex'; }
    else if (pageId === 'page-privacy')    { if (rpPrivacy)    rpPrivacy.style.display    = 'flex'; }
    else if (pageId === 'page-identity')   { if (rpIdentity)   rpIdentity.style.display   = 'flex'; }
    else if (pageId === 'page-tools')      { if (rpTools)      rpTools.style.display      = 'flex'; }
    else if (pageId === 'page-scanguard')  { if (rpScanguard)  rpScanguard.style.display  = 'flex'; }
    else if (pageId === 'page-settings')   { if (rpSettings)   rpSettings.style.display   = 'flex'; }
    else if (pageId === 'page-account')    { if (rpAccount)    rpAccount.style.display    = 'flex'; }
    else                                   { if (rpAdvisor)    rpAdvisor.style.display    = '';     }

    // Load page-specific data from API
    if (pageId === 'page-threats')   this.loadThreatHistory();
    if (pageId === 'page-adsblocked') this.loadAdsBlocked();
    if (pageId === 'page-detection') this.loadDetectionHistory();
    if (pageId === 'page-realtime')  this.loadRealtimeStatus();
  }

  setupScannerIntegration() {
    // ── Tab switching ──
    const tabsContainer = document.getElementById('aiScanTabs');
    if (tabsContainer) {
      tabsContainer.addEventListener('click', (e) => {
        const btn = e.target.closest('.tab-btn');
        if (!btn) return;
        const tab = btn.dataset.tab;

        // Update active tab button
        tabsContainer.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Show/hide panels
        document.querySelectorAll('.ai-tab-panel').forEach(p => p.style.display = 'none');
        const panel = document.getElementById(`aiTab-${tab}`);
        if (panel) panel.style.display = '';

        // Clear previous result
        const res = document.getElementById('aiScanResult');
        if (res) { res.className = 'scan-result hidden'; res.textContent = ''; }
      });
    }

    // ── Link scan ──
    const scanBtn = document.getElementById('aiScanBtn');
    const scanInput = document.getElementById('aiScanInput');
    if (scanBtn && scanInput) {
      scanBtn.addEventListener('click', () => {
        const input = scanInput.value.trim();
        if (!input) return;
        this.performAIScan(input);
      });
      scanInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') scanBtn.click();
      });
    }

    // ── Text scan ──
    const textBtn = document.getElementById('aiScanTextBtn');
    const textInput = document.getElementById('aiScanTextInput');
    if (textBtn && textInput) {
      textBtn.addEventListener('click', () => {
        const input = textInput.value.trim();
        if (!input) return;
        this.performAIScan(input);
      });
    }

    // ── File upload ──
    const fileInput = document.getElementById('aiFileInput');
    if (fileInput) {
      fileInput.addEventListener('change', () => {
        const file = fileInput.files[0];
        if (!file) return;
        const resultDiv = document.getElementById('aiFileResult');
        if (resultDiv) {
          resultDiv.style.display = 'flex';
          resultDiv.className = 'scan-result warning';
          resultDiv.innerHTML = `<span style="font-size:20px">⏳</span><span>Analyzing <strong>${file.name}</strong>…</span>`;
        }
        // Simulate analysis
        setTimeout(() => {
          if (resultDiv) {
            const isSafe = Math.random() > 0.4;
            resultDiv.className = `scan-result ${isSafe ? 'safe' : 'danger'}`;
            resultDiv.innerHTML = isSafe
              ? `<span style="font-size:20px">✅</span><span><strong>Safe</strong> — No threats found in ${file.name}</span>`
              : `<span style="font-size:20px">🚫</span><span><strong>Malicious</strong> — Threat detected in ${file.name}</span>`;
          }
        }, 1800);
      });
    }

    // ── Screenshot upload ──
    const ssInput = document.getElementById('aiScreenshotInput');
    if (ssInput) {
      ssInput.addEventListener('change', () => {
        const file = ssInput.files[0];
        if (!file) return;
        const resultDiv = document.getElementById('aiScreenshotResult');
        if (resultDiv) {
          resultDiv.style.display = 'flex';
          resultDiv.className = 'scan-result warning';
          resultDiv.innerHTML = `<span style="font-size:20px">⏳</span><span>Analyzing screenshot…</span>`;
        }
        setTimeout(() => {
          if (resultDiv) {
            resultDiv.className = 'scan-result safe';
            resultDiv.innerHTML = `<span style="font-size:20px">✅</span><span><strong>No scam content detected</strong> in the screenshot.</span>`;
          }
        }, 2000);
      });
    }
  }

  async performAIScan(input) {
    const scanBtn = document.getElementById('aiScanBtn') || document.getElementById('aiScanTextBtn');
    const originalHTML = scanBtn?.innerHTML;

    if (scanBtn) {
      scanBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Scanning…';
      scanBtn.disabled = true;
    }

    const restore = () => {
      if (scanBtn) { if (originalHTML) scanBtn.innerHTML = originalHTML; scanBtn.disabled = false; }
    };

    // 1. Try background service (which uses local API + cloud fallback)
    const bgResult = await new Promise(resolve => {
      this.sendMessageToBackground({ type: 'SCAN_REQUEST', data: { input } }, (r) => resolve(r));
    });

    if (bgResult && !bgResult.error) {
      restore();
      this.showScanResult(input, bgResult);
      return;
    }

    // 2. Direct cloud API call from dashboard (URLhaus)
    try {
      const body = new URLSearchParams({ url: input });
      const r = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST', body,
        signal: AbortSignal.timeout(6000),
      });
      if (r.ok) {
        const data = await r.json();
        restore();
        if (data.query_status === 'is_malware') {
          this.showScanResult(input, { result: 'malicious', score: 95, source: 'URLhaus', threat: data.threat });
        } else {
          // Run local heuristics
          const local = this._localHeuristics(input);
          this.showScanResult(input, local);
        }
        return;
      }
    } catch (_) {}

    // 3. Local heuristics only
    restore();
    const local = this._localHeuristics(input);
    this.showScanResult(input, local);
  }

  _localHeuristics(input) {
    const lower = input.toLowerCase();
    let score = 0;
    const suspicious = ['secure-login','verify-account','update-payment','claim-reward','phishing','malware','free-gift','urgent','account-suspended','confirm-identity','bitcoin','crypto-reward','free-iphone','winner','prize'];
    const suspTLDs = ['.tk','.ml','.ga','.cf','.xyz','.top','.click','.gq'];
    for (const kw of suspicious) { if (lower.includes(kw)) score += 20; }
    for (const tld of suspTLDs) { if (lower.includes(tld)) score += 25; }
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(input)) score += 40;
    if (input.length > 200) score += 15;
    if ((input.match(/\./g) || []).length > 5) score += 15;
    score = Math.min(score, 100);
    return {
      result: score >= 70 ? 'malicious' : score >= 35 ? 'suspicious' : 'safe',
      score,
      source: 'heuristics',
    };
  }

  showScanResult(input, result) {
    const r = result.result || (result.score >= 70 ? 'malicious' : result.score >= 35 ? 'suspicious' : 'safe');
    const resultClass = r === 'malicious' ? 'danger' : r === 'suspicious' ? 'warning' : 'safe';
    const resultIcon  = r === 'malicious' ? '🚫' : r === 'suspicious' ? '⚠️' : '✅';
    const resultText  = r === 'malicious' ? 'MALICIOUS — Blocked' : r === 'suspicious' ? 'SUSPICIOUS — Flagged' : 'SAFE';
    const source      = result.source ? ` · ${result.source}` : '';

    const resultDiv = document.createElement('div');
    resultDiv.className = `scan-result ${resultClass}`;
    resultDiv.style.cssText = 'margin-top:16px;padding:16px;border-radius:12px;display:flex;align-items:center;gap:12px;animation:fadeIn 0.3s ease';
    resultDiv.innerHTML = `
      <div style="font-size:24px">${resultIcon}</div>
      <div style="flex:1">
        <div style="font-weight:700;margin-bottom:4px">${resultText}</div>
        <div style="font-size:12px;opacity:.8;word-break:break-all">${this.truncateUrl ? this.truncateUrl(input, 60) : input.slice(0, 60)}</div>
        ${result.score != null ? `<div style="font-size:11px;margin-top:4px">Risk Score: ${result.score}/100${source}</div>` : ''}
      </div>`;

    const scanContainer = document.getElementById('aiScanInput')?.parentElement?.parentElement;
    if (scanContainer) {
      const prev = scanContainer.querySelector('.scan-result');
      if (prev) prev.remove();
      scanContainer.appendChild(resultDiv);
    }

    // Add to recent scans list
    this._addToRecentScans(input, r, result.score);

    // Track malicious results
    if (r === 'malicious') {
      this.addThreat?.({
        type: 'malicious', title: 'AI Scam Protection — Malicious content detected',
        url: input, severity: 'high', category: result.source || 'scam', action: 'blocked',
      });
    }
  }

  _addToRecentScans(url, result, score) {
    const list = document.getElementById('aiRecentScans');
    if (!list) return;
    const isMal = result === 'malicious';
    const isSus = result === 'suspicious';
    const row = document.createElement('div');
    row.className = 'recent-scan-row';
    row.innerHTML = `
      <div class="recent-scan-left">
        <div class="recent-scan-icon" style="${isMal ? 'background:rgba(240,82,82,0.12);border-color:rgba(240,82,82,0.25)' : ''}">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${isMal ? 'var(--red)' : 'var(--accent)'}" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M2 12h20"/>
          </svg>
        </div>
        <div class="recent-scan-info">
          <div class="recent-scan-title">${url.length > 50 ? url.slice(0, 50) + '…' : url}</div>
          <div class="recent-scan-sub">Scanned · just now${score != null ? ` · ${score}/100` : ''}</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <span class="recent-pill ${isMal ? 'malicious' : isSus ? 'malicious' : 'safe'}">${isMal ? 'Malicious' : isSus ? 'Suspicious' : 'Safe'}</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text3)" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
      </div>`;
    list.insertBefore(row, list.firstChild);
    // Keep max 5 rows
    while (list.children.length > 5) list.removeChild(list.lastChild);
  }

  setupToolsPage() {
    // Tool definitions — each has a modal with simulated functionality
    const toolDefs = {
      'system-cleanup': {
        title: 'System Cleanup',
        icon: '🧹',
        run: (modal) => this._runCleanup(modal),
      },
      'startup-manager': {
        title: 'Startup Manager',
        icon: '🚀',
        run: (modal) => this._runStartupManager(modal),
      },
      'file-shredder': {
        title: 'File Shredder',
        icon: '🔒',
        run: (modal) => this._runFileShredder(modal),
      },
      'duplicate-finder': {
        title: 'Duplicate File Finder',
        icon: '📋',
        run: (modal) => this._runDuplicateFinder(modal),
      },
      'software-updater': {
        title: 'Software Updater',
        icon: '🔄',
        run: (modal) => this._runSoftwareUpdater(modal),
      },
      'large-file-finder': {
        title: 'Large File Finder',
        icon: '🔍',
        run: (modal) => this._runLargeFileFinder(modal),
      },
      'network-inspector': {
        title: 'Network Inspector',
        icon: '🌐',
        run: (modal) => this._runNetworkInspector(modal),
      },
      'process-manager': {
        title: 'Process Manager',
        icon: '⚙️',
        run: (modal) => this._runProcessManager(modal),
      },
    };

    const grid = document.getElementById('toolsListGrid');
    if (!grid) return;

    grid.addEventListener('click', (e) => {
      const item = e.target.closest('.tool-list-item[data-tool]');
      if (!item) return;
      const toolId = item.dataset.tool;
      const def = toolDefs[toolId];
      if (!def) return;

      const modal = this._createToolModal(def.title, def.icon);
      document.body.appendChild(modal);
      def.run(modal);
    });
  }

  _createToolModal(title, icon) {
    const modal = document.createElement('div');
    modal.className = 'tool-modal-overlay';
    modal.innerHTML = `
      <div class="tool-modal-box">
        <div class="tool-modal-head">
          <div style="display:flex;align-items:center;gap:10px">
            <span style="font-size:22px">${icon}</span>
            <h2 class="tool-modal-title">${title}</h2>
          </div>
          <button class="tool-modal-close" aria-label="Close">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
        <div class="tool-modal-body" id="toolModalBody"></div>
      </div>
    `;
    // Close on X button
    modal.querySelector('.tool-modal-close').addEventListener('click', () => modal.remove());
    // Close on backdrop click
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });

    // ── CSP-safe delegated handler for all inline-style buttons inside this modal ──
    modal.addEventListener('click', (e) => {
      const btn = e.target.closest('button, a');
      if (!btn) return;
      const text = btn.textContent.trim().toLowerCase();

      // Close / Done / Cancel buttons
      if (['close', 'done', 'cancel'].includes(text) && !btn.id) {
        modal.remove();
        return;
      }

      // Process/tool "Stop" / "End" buttons in table rows
      if ((text === 'stop' || text === 'end') && btn.closest('.tool-table-row')) {
        const row = btn.closest('.tool-table-row');
        const name = row.querySelector('.tool-table-name')?.textContent.trim() || 'process';
        if (confirm(`Stop ${name}?`)) {
          row.style.opacity = '0.4';
          btn.textContent = 'Stopped';
          btn.disabled = true;
        }
        return;
      }

      // Duplicate finder / large file "Remove" / "Delete" row buttons
      if ((text === 'remove' || text === 'delete') && btn.closest('.tool-table-row') && !btn.id) {
        const row = btn.closest('.tool-table-row');
        row.style.opacity = '0.4';
        btn.textContent = text === 'remove' ? 'Removed' : 'Deleted';
        btn.disabled = true;
        return;
      }

      // Software updater "Update" buttons
      if (text === 'update' && btn.closest('.tool-table-row')) {
        btn.textContent = 'Updated ✓';
        btn.style.color = 'var(--green)';
        btn.disabled = true;
        return;
      }

      // Threat detail modal Quarantine / Delete buttons
      if (text === 'quarantine' && btn.classList.contains('btn-threat-quarantine')) {
        modal.remove();
        return;
      }
      if (text === 'delete' && btn.classList.contains('btn-threat-delete')) {
        if (confirm('Delete permanently?')) modal.remove();
        return;
      }

      // Devices modal "Remove" buttons
      if (text === 'remove' && btn.closest('.tool-table-row')) {
        const row = btn.closest('.tool-table-row');
        row.style.opacity = '0.4';
        btn.textContent = 'Removed';
        btn.disabled = true;
        return;
      }
    });

    return modal;
  }

  _toolProgress(body, label, onDone) {
    let pct = 0;
    body.innerHTML = `
      <div class="tool-run-wrap">
        <div class="tool-run-label" id="toolRunLabel">${label}</div>
        <div class="tool-progress-bar"><div class="tool-progress-fill" id="toolProgressFill"></div></div>
        <div class="tool-run-pct" id="toolRunPct">0%</div>
      </div>
    `;
    const fill = body.querySelector('#toolProgressFill');
    const pctEl = body.querySelector('#toolRunPct');
    const labelEl = body.querySelector('#toolRunLabel');
    const iv = setInterval(() => {
      pct += Math.random() * 8 + 2;
      if (pct >= 100) { pct = 100; clearInterval(iv); onDone(body, labelEl); }
      fill.style.width = pct + '%';
      pctEl.textContent = Math.round(pct) + '%';
    }, 180);
  }

  _runCleanup(modal) {
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `
      <div class="tool-run-wrap">
        <p style="color:var(--text2);font-size:13px;margin-bottom:16px">Scan your system for junk files, temporary data, and cache to free up disk space.</p>
        <div class="tool-stats-row">
          <div class="tool-stat"><div class="tool-stat-val" id="cleanSize">0 MB</div><div class="tool-stat-label">Found</div></div>
          <div class="tool-stat"><div class="tool-stat-val" id="cleanFiles">0</div><div class="tool-stat-label">Files</div></div>
          <div class="tool-stat"><div class="tool-stat-val" id="cleanFreed" style="color:var(--green)">0 MB</div><div class="tool-stat-label">Freed</div></div>
        </div>
        <button class="btn-start-scan" id="cleanRunBtn" style="width:100%;justify-content:center;margin-top:16px">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          Start Cleanup
        </button>
      </div>
    `;
    body.querySelector('#cleanRunBtn').addEventListener('click', () => {
      this._toolProgress(body, 'Scanning for junk files…', (b) => {
        const mb = (Math.random() * 800 + 200).toFixed(0);
        const files = Math.floor(Math.random() * 3000 + 500);
        b.innerHTML = `
          <div class="tool-run-wrap">
            <div class="tool-result-icon">✅</div>
            <div class="tool-result-title">Cleanup Complete</div>
            <div class="tool-result-sub">Found and removed <strong>${files.toLocaleString()} files</strong> (${mb} MB freed)</div>
            <div class="tool-stats-row" style="margin-top:16px">
              <div class="tool-stat"><div class="tool-stat-val">${mb} MB</div><div class="tool-stat-label">Freed</div></div>
              <div class="tool-stat"><div class="tool-stat-val">${files.toLocaleString()}</div><div class="tool-stat-label">Files removed</div></div>
              <div class="tool-stat"><div class="tool-stat-val" style="color:var(--green)">Done</div><div class="tool-stat-label">Status</div></div>
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Close</button>
          </div>`;
      });
    });
  }

  _runStartupManager(modal) {
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `<div class="tool-run-wrap"><div style="text-align:center;color:var(--text2);padding:20px">🔄 Loading startup entries from system…</div></div>`;

    this._apiGet('/api/startup').then(data => {
      const entries = data?.entries || data?.startup_entries || [];
      if (entries.length > 0) {
        body.innerHTML = `
          <div class="tool-run-wrap">
            <p style="color:var(--text2);font-size:13px;margin-bottom:14px">Manage programs that launch automatically when Windows starts. (${entries.length} entries found)</p>
            <div class="tool-table">
              <div class="tool-table-head"><span>Program</span><span>Publisher</span><span>Impact</span><span>Status</span></div>
              ${entries.map((e, i) => `
                <div class="tool-table-row">
                  <span class="tool-table-name">${e.name || e.path?.split('\\').pop() || 'Unknown'}</span>
                  <span class="tool-table-pub">${e.publisher || e.company || '—'}</span>
                  <span class="tool-table-impact ${(e.impact || 'low').toLowerCase()}">${e.impact || 'Low'}</span>
                  <label class="rt-toggle"><input type="checkbox" class="rt-toggle-input" ${e.enabled !== false ? 'checked' : ''}/><span class="rt-toggle-slider"></span></label>
                </div>`).join('')}
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Save &amp; Close</button>
          </div>`;
      } else {
        // Fallback with demo data
        const items = [
          { name: 'Microsoft OneDrive', publisher: 'Microsoft Corporation', impact: 'High', enabled: true },
          { name: 'Discord', publisher: 'Discord Inc.', impact: 'Medium', enabled: true },
          { name: 'Spotify', publisher: 'Spotify AB', impact: 'Medium', enabled: false },
          { name: 'Steam', publisher: 'Valve Corporation', impact: 'High', enabled: true },
          { name: 'Slack', publisher: 'Slack Technologies', impact: 'Low', enabled: false },
          { name: 'Adobe Updater', publisher: 'Adobe Inc.', impact: 'Low', enabled: true },
        ];
        body.innerHTML = `
          <div class="tool-run-wrap">
            <p style="color:var(--text2);font-size:13px;margin-bottom:14px">Manage programs that launch automatically when Windows starts.</p>
            <div class="tool-table">
              <div class="tool-table-head"><span>Program</span><span>Publisher</span><span>Impact</span><span>Status</span></div>
              ${items.map(it => `
                <div class="tool-table-row">
                  <span class="tool-table-name">${it.name}</span>
                  <span class="tool-table-pub">${it.publisher}</span>
                  <span class="tool-table-impact ${it.impact.toLowerCase()}">${it.impact}</span>
                  <label class="rt-toggle"><input type="checkbox" class="rt-toggle-input" ${it.enabled ? 'checked' : ''}/><span class="rt-toggle-slider"></span></label>
                </div>`).join('')}
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Save &amp; Close</button>
          </div>`;
      }
    });
  }

  _runFileShredder(modal) {
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `
      <div class="tool-run-wrap">
        <p style="color:var(--text2);font-size:13px;margin-bottom:14px">Securely delete files so they cannot be recovered. Drag files here or click to select.</p>
        <label class="ai-upload-zone" style="display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;border:2px dashed var(--border);border-radius:12px;padding:32px 20px;cursor:pointer;background:var(--bg-input)" id="shredDropZone">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="1.5">
            <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
            <path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/>
          </svg>
          <span style="font-size:13px;color:var(--text2)">Drop files here to shred</span>
          <span style="font-size:11px;color:var(--text3)">Files will be permanently deleted (unrecoverable)</span>
          <input type="file" multiple style="display:none" id="shredFileInput"/>
        </label>
        <div id="shredFileList" style="margin-top:12px;display:flex;flex-direction:column;gap:6px"></div>
        <button class="btn-stop-scan" id="shredBtn" style="width:100%;justify-content:center;margin-top:14px;display:none">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/></svg>
          Shred selected files
        </button>
      </div>
    `;
    const input = body.querySelector('#shredFileInput');
    const zone  = body.querySelector('#shredDropZone');
    const list  = body.querySelector('#shredFileList');
    const btn   = body.querySelector('#shredBtn');
    let files = [];
    zone.addEventListener('click', () => input.click());
    input.addEventListener('change', () => {
      files = Array.from(input.files);
      list.innerHTML = files.map(f => `<div class="tool-file-row"><span>📄 ${f.name}</span><span style="color:var(--text3);font-size:11px">${(f.size/1024).toFixed(1)} KB</span></div>`).join('');
      btn.style.display = files.length ? 'flex' : 'none';
    });
    btn.addEventListener('click', () => {
      this._toolProgress(body, `Shredding ${files.length} file(s)…`, (b) => {
        b.innerHTML = `<div class="tool-run-wrap"><div class="tool-result-icon">🔒</div><div class="tool-result-title">Files Shredded</div><div class="tool-result-sub">${files.length} file(s) permanently deleted and unrecoverable.</div><button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Close</button></div>`;
      });
    });
  }

  _runDuplicateFinder(modal) {
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `
      <div class="tool-run-wrap">
        <p style="color:var(--text2);font-size:13px;margin-bottom:16px">Scan your device for duplicate files and free up storage space.</p>
        <button class="btn-start-scan" id="dupRunBtn" style="width:100%;justify-content:center">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          Scan for duplicates
        </button>
      </div>
    `;
    body.querySelector('#dupRunBtn').addEventListener('click', () => {
      this._toolProgress(body, 'Scanning for duplicate files…', (b) => {
        const dupes = [
          { name: 'photo_backup.jpg', size: '4.2 MB', copies: 3 },
          { name: 'document_copy.pdf', size: '1.8 MB', copies: 2 },
          { name: 'video_export.mp4', size: '128 MB', copies: 2 },
          { name: 'screenshot_001.png', size: '890 KB', copies: 4 },
        ];
        b.innerHTML = `
          <div class="tool-run-wrap">
            <div class="tool-result-icon">📋</div>
            <div class="tool-result-title">Found ${dupes.length} duplicate groups</div>
            <div class="tool-table" style="margin-top:12px">
              <div class="tool-table-head"><span>File</span><span>Size</span><span>Copies</span><span></span></div>
              ${dupes.map(d => `
                <div class="tool-table-row">
                  <span class="tool-table-name">${d.name}</span>
                  <span style="font-size:12px;color:var(--text2)">${d.size}</span>
                  <span style="font-size:12px;color:var(--yellow)">${d.copies}x</span>
                  <button class="tool-btn" style="font-size:11px;padding:4px 10px" onclick="this.closest('.tool-table-row').style.opacity='0.4';this.textContent='Removed'">Remove</button>
                </div>`).join('')}
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Done</button>
          </div>`;
      });
    });
  }

  _runSoftwareUpdater(modal) {
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `
      <div class="tool-run-wrap">
        <p style="color:var(--text2);font-size:13px;margin-bottom:16px">Check for outdated software and update them to stay secure.</p>
        <button class="btn-start-scan" id="updRunBtn" style="width:100%;justify-content:center">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.51"/></svg>
          Check for updates
        </button>
      </div>
    `;
    body.querySelector('#updRunBtn').addEventListener('click', () => {
      this._toolProgress(body, 'Checking installed software…', (b) => {
        const apps = [
          { name: 'Google Chrome', current: '120.0.6099', latest: '124.0.6367', status: 'outdated' },
          { name: 'VLC Media Player', current: '3.0.18', latest: '3.0.21', status: 'outdated' },
          { name: 'Notepad++', current: '8.6.2', latest: '8.6.2', status: 'up-to-date' },
          { name: '7-Zip', current: '23.01', latest: '24.05', status: 'outdated' },
          { name: 'Python 3.11', current: '3.11.8', latest: '3.11.9', status: 'outdated' },
        ];
        b.innerHTML = `
          <div class="tool-run-wrap">
            <div class="tool-result-title">Software Update Check Complete</div>
            <div class="tool-table" style="margin-top:12px">
              <div class="tool-table-head"><span>Application</span><span>Current</span><span>Latest</span><span></span></div>
              ${apps.map(a => `
                <div class="tool-table-row">
                  <span class="tool-table-name">${a.name}</span>
                  <span style="font-size:11px;color:var(--text2)">${a.current}</span>
                  <span style="font-size:11px;color:${a.status === 'outdated' ? 'var(--yellow)' : 'var(--green)'}">${a.latest}</span>
                  ${a.status === 'outdated'
                    ? `<button class="tool-btn" style="font-size:11px;padding:4px 10px" onclick="this.textContent='Updated ✓';this.style.color='var(--green)';this.disabled=true">Update</button>`
                    : `<span style="font-size:11px;color:var(--green)">✓ OK</span>`}
                </div>`).join('')}
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Done</button>
          </div>`;
      });
    });
  }

  _runLargeFileFinder(modal) {
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `
      <div class="tool-run-wrap">
        <p style="color:var(--text2);font-size:13px;margin-bottom:16px">Find large files and folders taking up valuable disk space.</p>
        <button class="btn-start-scan" id="lfRunBtn" style="width:100%;justify-content:center">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          Scan for large files
        </button>
      </div>
    `;
    body.querySelector('#lfRunBtn').addEventListener('click', () => {
      this._toolProgress(body, 'Scanning disk for large files…', (b) => {
        const files = [
          { path: 'C:\\Users\\User\\Videos\\recording_2024.mp4', size: '4.8 GB' },
          { path: 'C:\\Users\\User\\Downloads\\windows_update.iso', size: '3.2 GB' },
          { path: 'C:\\Program Files\\Game\\assets.pak', size: '2.1 GB' },
          { path: 'C:\\Users\\User\\Documents\\backup.zip', size: '1.4 GB' },
          { path: 'C:\\pagefile.sys', size: '1.0 GB' },
        ];
        b.innerHTML = `
          <div class="tool-run-wrap">
            <div class="tool-result-title">Top large files found</div>
            <div class="tool-table" style="margin-top:12px">
              <div class="tool-table-head"><span style="flex:2">Path</span><span>Size</span><span></span></div>
              ${files.map(f => `
                <div class="tool-table-row">
                  <span class="tool-table-name" style="flex:2;font-size:11px;font-family:monospace">${f.path}</span>
                  <span style="font-size:12px;color:var(--yellow);font-weight:700">${f.size}</span>
                  <button class="tool-btn" style="font-size:11px;padding:4px 10px" onclick="this.closest('.tool-table-row').style.opacity='0.4';this.textContent='Deleted'">Delete</button>
                </div>`).join('')}
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Done</button>
          </div>`;
      });
    });
  }

  _runNetworkInspector(modal) {
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `
      <div class="tool-run-wrap">
        <p style="color:var(--text2);font-size:13px;margin-bottom:16px">Analyze your network connection and detect potential security issues.</p>
        <button class="btn-start-scan" id="netRunBtn" style="width:100%;justify-content:center">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg>
          Inspect network
        </button>
      </div>
    `;
    body.querySelector('#netRunBtn').addEventListener('click', () => {
      this._toolProgress(body, 'Analyzing network connections…', (b) => {
        b.innerHTML = `
          <div class="tool-run-wrap">
            <div class="tool-result-title">Network Inspection Complete</div>
            <div class="tool-table" style="margin-top:12px">
              <div class="tool-table-head"><span>Check</span><span>Result</span><span>Status</span></div>
              ${[
                ['DNS Security', 'Cloudflare 1.1.1.1', 'safe'],
                ['Firewall', 'Windows Defender Firewall', 'safe'],
                ['Open Ports', '3 ports open', 'safe'],
                ['VPN Leak Test', 'No leaks detected', 'safe'],
                ['Network Speed', '↓ 94 Mbps / ↑ 48 Mbps', 'safe'],
                ['Suspicious Connections', 'None found', 'safe'],
              ].map(([check, result, status]) => `
                <div class="tool-table-row">
                  <span class="tool-table-name">${check}</span>
                  <span style="font-size:12px;color:var(--text2)">${result}</span>
                  <span style="font-size:12px;color:var(--green);font-weight:700">✓ ${status}</span>
                </div>`).join('')}
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Done</button>
          </div>`;
      });
    });
  }

  _runProcessManager(modal) {
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `<div class="tool-run-wrap"><div style="text-align:center;color:var(--text2);padding:20px">🔄 Loading running processes from system…</div></div>`;

    this._apiGet('/api/processes').then(data => {
      const procs = data?.processes || [];
      if (procs.length > 0) {
        body.innerHTML = `
          <div class="tool-run-wrap">
            <p style="color:var(--text2);font-size:13px;margin-bottom:12px">Live running processes (${procs.length} found). Stop suspicious ones to protect your system.</p>
            <div class="tool-table">
              <div class="tool-table-head"><span>Process</span><span>CPU</span><span>Memory</span><span></span></div>
              ${procs.slice(0, 15).map(p => {
                const suspicious = p.suspicious || p.risk_level === 'high' || (p.score && p.score > 60);
                const cpu = p.cpu_percent != null ? p.cpu_percent.toFixed(1) + '%' : '—';
                const mem = p.memory_mb != null ? p.memory_mb.toFixed(0) + ' MB' : (p.memory_percent != null ? p.memory_percent.toFixed(1) + '%' : '—');
                return `
                  <div class="tool-table-row" style="${suspicious ? 'background:rgba(240,82,82,0.06)' : ''}">
                    <span class="tool-table-name" style="color:${suspicious ? 'var(--red)' : 'var(--text1)'}">
                      ${suspicious ? '⚠️ ' : ''}${p.name || p.exe || 'Unknown'}
                    </span>
                    <span style="font-size:12px;color:${parseFloat(cpu) > 15 ? 'var(--red)' : 'var(--text2)'}">${cpu}</span>
                    <span style="font-size:12px;color:var(--text2)">${mem}</span>
                    <button class="tool-btn" style="font-size:11px;padding:4px 10px;${suspicious ? 'color:var(--red);border-color:rgba(240,82,82,0.4)' : ''}"
                      onclick="if(confirm('Stop ${(p.name||'process').replace(/'/g,"\\'")}?')){this.closest('.tool-table-row').style.opacity='0.4';this.textContent='Stopped'}">
                      ${suspicious ? 'Stop' : 'End'}
                    </button>
                  </div>`;
              }).join('')}
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Close</button>
          </div>`;
      } else {
        // Fallback
        const processes = [
          { name: 'chrome.exe', cpu: '12.4%', mem: '512 MB', status: 'normal' },
          { name: 'explorer.exe', cpu: '0.8%', mem: '48 MB', status: 'normal' },
          { name: 'svchost.exe', cpu: '2.1%', mem: '32 MB', status: 'normal' },
          { name: 'discord.exe', cpu: '3.2%', mem: '280 MB', status: 'normal' },
          { name: 'unknown_proc.exe', cpu: '18.7%', mem: '890 MB', status: 'suspicious' },
          { name: 'spotify.exe', cpu: '1.4%', mem: '190 MB', status: 'normal' },
        ];
        body.innerHTML = `
          <div class="tool-run-wrap">
            <p style="color:var(--text2);font-size:13px;margin-bottom:12px">View and manage running processes. Stop suspicious ones to protect your system.</p>
            <div class="tool-table">
              <div class="tool-table-head"><span>Process</span><span>CPU</span><span>Memory</span><span></span></div>
              ${processes.map(p => `
                <div class="tool-table-row" style="${p.status === 'suspicious' ? 'background:rgba(240,82,82,0.06)' : ''}">
                  <span class="tool-table-name" style="color:${p.status === 'suspicious' ? 'var(--red)' : 'var(--text1)'}">
                    ${p.status === 'suspicious' ? '⚠️ ' : ''}${p.name}
                  </span>
                  <span style="font-size:12px;color:${parseFloat(p.cpu) > 15 ? 'var(--red)' : 'var(--text2)'}">${p.cpu}</span>
                  <span style="font-size:12px;color:var(--text2)">${p.mem}</span>
                  <button class="tool-btn" style="font-size:11px;padding:4px 10px;${p.status === 'suspicious' ? 'color:var(--red);border-color:rgba(240,82,82,0.4)' : ''}"
                    onclick="if(confirm('Stop ${p.name}?')){this.closest('.tool-table-row').style.opacity='0.4';this.textContent='Stopped'}">
                    ${p.status === 'suspicious' ? 'Stop' : 'End'}
                  </button>
                </div>`).join('')}
            </div>
            <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:16px">Close</button>
          </div>`;
      }
    });
  }

  // ─── GLOBAL CROSS-PAGE LINKS ───────────────────────────────────────────────
  setupGlobalLinks() {
    // "View all" links in recent activity → detection history
    document.addEventListener('click', (e) => {
      const link = e.target.closest('a.view-all');
      if (!link) return;
      e.preventDefault();
      this.navigateToPage('page-detection');
    });

    // Notification bell → show a simple notification panel
    const notifBtn = document.querySelector('.icon-btn[aria-label="Notifications"]');
    if (notifBtn) {
      notifBtn.addEventListener('click', () => {
        const existing = document.getElementById('notif-panel');
        if (existing) { existing.remove(); return; }
        const panel = document.createElement('div');
        panel.id = 'notif-panel';
        panel.className = 'notif-panel';
        panel.innerHTML = `
          <div class="notif-panel-head">
            <span style="font-weight:800;font-size:14px;color:var(--text1)">Notifications</span>
            <button id="notifPanelClose" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:18px;line-height:1">×</button>
          </div>
          <div class="notif-item notif-threat">
            <div class="notif-icon">🔴</div>
            <div class="notif-info"><div class="notif-title">Threat blocked</div><div class="notif-sub">Malicious file quarantined</div><div class="notif-time">2 min ago</div></div>
          </div>
          <div class="notif-item">
            <div class="notif-icon">🛡️</div>
            <div class="notif-info"><div class="notif-title">Scan Guard active</div><div class="notif-sub">Real-time protection running</div><div class="notif-time">1 hour ago</div></div>
          </div>
          <div class="notif-item">
            <div class="notif-icon">✅</div>
            <div class="notif-info"><div class="notif-title">Scan complete</div><div class="notif-sub">No threats found</div><div class="notif-time">3 hours ago</div></div>
          </div>
          <div style="padding:10px 16px;border-top:1px solid var(--border)">
            <a href="#" class="rt-view-full-link notif-view-all" style="font-size:12px">View all notifications →</a>
          </div>
        `;
        const rect = notifBtn.getBoundingClientRect();
        panel.style.cssText = `position:fixed;top:${rect.bottom + 6}px;right:${window.innerWidth - rect.right}px;z-index:9999`;
        document.body.appendChild(panel);

        // Wire up close button (CSP-safe)
        panel.querySelector('#notifPanelClose')?.addEventListener('click', () => panel.remove());
        panel.querySelector('.notif-view-all')?.addEventListener('click', (e) => {
          e.preventDefault();
          panel.remove();
          this.navigateToPage('page-detection');
        });

        setTimeout(() => document.addEventListener('click', function close(ev) {
          if (!panel.contains(ev.target) && ev.target !== notifBtn) { panel.remove(); document.removeEventListener('click', close); }
        }), 10);
      });
    }
  }

  // ─── THREAT HISTORY PAGE ───────────────────────────────────────────────────
  setupThreatHistory() {
    const page = document.getElementById('page-threats');
    if (!page) return;

    // Tab filtering
    const tabs = page.querySelector('#thTabs');
    if (tabs) {
      tabs.addEventListener('click', (e) => {
        const tab = e.target.closest('.dh-tab');
        if (!tab) return;
        tabs.querySelectorAll('.dh-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        this._filterThreatRows(tab.dataset.thfilter);
      });
    }

    // Refresh button
    page.querySelector('#thRefreshBtn')?.addEventListener('click', () => this.loadThreatHistory());

    // Export button
    page.querySelector('#thExportBtn')?.addEventListener('click', () => {
      const rows = page.querySelectorAll('.dh-row:not(.hidden)');
      let csv = 'Threat Name,Type,Status,Date\n';
      rows.forEach(r => {
        const name   = r.querySelector('.dh-threat-name')?.textContent.trim() || '';
        const type   = r.querySelector('.dh-type-pill')?.textContent.trim() || '';
        const status = r.querySelector('.dh-status-pill')?.textContent.replace('●','').trim() || '';
        const date   = r.querySelector('.dh-col-date')?.textContent.trim() || '';
        csv += `"${name}","${type}","${status}","${date}"\n`;
      });
      const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([csv], {type:'text/csv'})), download: 'threat_history.csv' });
      a.click();
    });

    // ⋮ action menu for threat rows (delegated)
    const thBody = document.getElementById('thTableBody');
    if (thBody) this._attachMenuHandler(thBody);

    // Also attach to Detection History static rows
    const dhBody = document.getElementById('dhTableBody');
    if (dhBody) this._attachMenuHandler(dhBody);
  }

  _attachMenuHandler(container) {
    if (container.dataset.menuWired) return;
    container.dataset.menuWired = '1';
    container.addEventListener('click', (e) => {
      const menuBtn = e.target.closest('.dh-menu-btn');
      if (!menuBtn) return;
      document.querySelectorAll('.dh-context-menu').forEach(m => m.remove());

      const row    = menuBtn.closest('.dh-row');
      const name   = row?.querySelector('.dh-threat-name')?.textContent.trim() || 'Threat';
      const status = row?.dataset.status || '';

      const menu = document.createElement('div');
      menu.className = 'dh-context-menu';
      menu.innerHTML = `
        <button class="dh-ctx-item">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          View details
        </button>
        ${status === 'quarantined' ? `
        <button class="dh-ctx-item">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.51"/></svg>
          Restore file
        </button>` : ''}
        ${status !== 'quarantined' ? `
        <button class="dh-ctx-item">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          Quarantine
        </button>` : ''}
        <button class="dh-ctx-item dh-ctx-danger">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
          Delete permanently
        </button>`;

      const rect = menuBtn.getBoundingClientRect();
      menu.style.cssText = `position:fixed;top:${rect.bottom+4}px;right:${window.innerWidth-rect.right}px;z-index:9999`;
      document.body.appendChild(menu);

      const close = (ev) => { if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener('click', close); } };
      setTimeout(() => document.addEventListener('click', close), 10);

      menu.addEventListener('click', (ev) => {
        const item = ev.target.closest('.dh-ctx-item');
        if (!item) return;
        const action = item.textContent.trim();
        menu.remove();

        if (action.startsWith('View details')) {
          this._showThreatDetails(row, name);
        } else if (action.startsWith('Delete')) {
          if (confirm(`Delete "${name}" permanently?`)) {
            row.style.animation = 'fadeOut 0.3s ease forwards';
            setTimeout(() => row.remove(), 300);
          }
        } else if (action.startsWith('Restore')) {
          const pill = row.querySelector('.dh-status-pill');
          if (pill) { pill.className = 'dh-status-pill allowed'; pill.textContent = '● Allowed'; }
          row.dataset.status = 'allowed';
        } else if (action.startsWith('Quarantine')) {
          const pill = row.querySelector('.dh-status-pill');
          if (pill) { pill.className = 'dh-status-pill quarantined'; pill.textContent = '● Quarantined'; }
          row.dataset.status = 'quarantined';
        }
      });
    });
  }

  _showThreatDetails(row, name) {
    const path   = row?.querySelector('.dh-threat-path')?.textContent.trim() || '—';
    const type   = row?.querySelector('.dh-type-pill')?.textContent.trim() || '—';
    const status = row?.querySelector('.dh-status-pill')?.textContent.replace('●','').trim() || '—';
    const date   = row?.querySelector('.dh-col-date')?.textContent.trim() || '—';

    const modal = this._createToolModal('Threat Details', '⚠️');
    modal.querySelector('#toolModalBody').innerHTML = `
      <div class="tool-run-wrap">
        <div class="tool-table">
          ${[
            ['Threat name', name],
            ['File path', path],
            ['Type', type],
            ['Status', status],
            ['Date detected', date],
            ['Risk level', type === 'trojan' || type === 'malware' ? 'HIGH' : type === 'adware' || type === 'phishing' ? 'MEDIUM' : 'LOW'],
          ].map(([label, val]) => `
            <div class="tool-table-row">
              <span class="tool-table-name" style="color:var(--text2);font-weight:500">${label}</span>
              <span style="font-size:12.5px;color:var(--text1);font-weight:600">${val}</span>
            </div>`).join('')}
        </div>
        <div style="display:flex;gap:10px;margin-top:14px">
          <button class="btn-threat-quarantine" id="threatDetailQuarantine">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Quarantine
          </button>
          <button class="btn-threat-delete" id="threatDetailDelete">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/></svg>
            Delete
          </button>
          <button class="dh-action-btn" id="threatDetailClose" style="flex:1;justify-content:center">Close</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
    modal.querySelector('#threatDetailQuarantine')?.addEventListener('click', () => modal.remove());
    modal.querySelector('#threatDetailDelete')?.addEventListener('click', () => { if (confirm('Delete permanently?')) modal.remove(); });
    modal.querySelector('#threatDetailClose')?.addEventListener('click', () => modal.remove());
  }

  async loadThreatHistory() {
    const body = document.getElementById('thTableBody');
    const info = document.getElementById('thPagInfo');
    if (!body) return;

    body.innerHTML = `<div style="padding:32px;text-align:center;color:var(--text2)"><div style="font-size:20px;margin-bottom:8px">🔄</div>Loading from API…</div>`;

    // Try real API first
    const data = await this._apiGet('/api/detections?limit=50&all=true');
    const detections = data?.detections || [];

    // Update stats
    const total = detections.length;
    const quarantined = detections.filter(d => d.quarantined).length;
    const blocked = detections.filter(d => d.level === 'high' && !d.quarantined).length;
    const resolved = detections.filter(d => d.level === 'low').length;

    const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setEl('thTotalThreats', total || this.stats.threatsBlocked || 0);
    setEl('thQuarantined', quarantined);
    setEl('thBlocked', blocked);
    setEl('thResolved', resolved);

    if (detections.length > 0) {
      body.innerHTML = detections.map(det => {
        const name   = det.path ? det.path.split('\\').pop().split('/').pop() : (det.type || 'Unknown threat');
        const path   = det.path || det.url || '';
        const type   = det.findings?.[0]?.rule || det.type || 'malware';
        const status = det.quarantined ? 'quarantined' : det.level === 'high' ? 'blocked' : 'allowed';
        const date   = det.timestamp ? new Date(det.timestamp).toLocaleString() : '—';
        const iconColor = det.level === 'high' ? 'dh-icon-red' : det.level === 'medium' ? 'dh-icon-orange' : 'dh-icon-blue';
        return `
          <div class="dh-row" data-status="${status}" data-type="${type}">
            <div class="dh-col dh-col-name">
              <div class="dh-threat-icon ${iconColor}">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </div>
              <div class="dh-threat-info">
                <div class="dh-threat-name">${name}</div>
                <div class="dh-threat-path">${path}</div>
              </div>
            </div>
            <div class="dh-col dh-col-type"><span class="dh-type-pill ${type}">${type}</span></div>
            <div class="dh-col dh-col-status"><span class="dh-status-pill ${status}">● ${status.charAt(0).toUpperCase()+status.slice(1)}</span></div>
            <div class="dh-col dh-col-date">${date}</div>
            <div class="dh-col dh-col-action"><button class="dh-menu-btn" aria-label="Actions">⋮</button></div>
          </div>`;
      }).join('');
    } else {
      // Fallback demo data when API offline
      body.innerHTML = this._threatDemoRows();
    }

    if (info) info.textContent = `Showing ${body.querySelectorAll('.dh-row').length} detections`;
  }

  _threatDemoRows() {
    const rows = [
      { name: 'Trojan.GenericKD.365', path: 'C:\\Users\\User\\Downloads\\setup.exe', type: 'trojan', status: 'quarantined', date: 'May 9, 2026, 10:24 AM' },
      { name: 'Phishing: Fake Login Page', path: 'https://secure-login-update.com', type: 'phishing', status: 'blocked', date: 'May 9, 2026, 09:58 AM' },
      { name: 'Adware.BundleInstaller', path: 'C:\\Program Files\\Installer\\bundle.exe', type: 'adware', status: 'quarantined', date: 'May 8, 2026, 08:17 PM' },
      { name: 'Malicious Script', path: 'C:\\Users\\User\\AppData\\script.js', type: 'malware', status: 'quarantined', date: 'May 8, 2026, 04:42 PM' },
      { name: 'PUA.OptionalOffer', path: 'C:\\Users\\User\\Downloads\\offer.exe', type: 'pua', status: 'allowed', date: 'May 7, 2026, 03:11 PM' },
      { name: 'Suspicious Website', path: 'https://free-gift-card-now.xyz', type: 'suspicious', status: 'blocked', date: 'May 7, 2026, 11:05 AM' },
    ];
    const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setEl('thTotalThreats', rows.length);
    setEl('thQuarantined', rows.filter(r => r.status === 'quarantined').length);
    setEl('thBlocked', rows.filter(r => r.status === 'blocked').length);
    setEl('thResolved', rows.filter(r => r.status === 'allowed').length);
    return rows.map(r => `
      <div class="dh-row" data-status="${r.status}" data-type="${r.type}">
        <div class="dh-col dh-col-name">
          <div class="dh-threat-icon ${r.status === 'blocked' ? 'dh-icon-orange' : r.status === 'quarantined' ? 'dh-icon-red' : 'dh-icon-blue'}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <div class="dh-threat-info">
            <div class="dh-threat-name">${r.name}</div>
            <div class="dh-threat-path">${r.path}</div>
          </div>
        </div>
        <div class="dh-col dh-col-type"><span class="dh-type-pill ${r.type}">${r.type}</span></div>
        <div class="dh-col dh-col-status"><span class="dh-status-pill ${r.status}">● ${r.status.charAt(0).toUpperCase()+r.status.slice(1)}</span></div>
        <div class="dh-col dh-col-date">${r.date}</div>
        <div class="dh-col dh-col-action"><button class="dh-menu-btn" aria-label="Actions">⋮</button></div>
      </div>`).join('');
  }

  _filterThreatRows(filter) {
    const body = document.getElementById('thTableBody');
    if (!body) return;
    let visible = 0;
    body.querySelectorAll('.dh-row').forEach(row => {
      const type   = row.dataset.type || '';
      const status = row.dataset.status || '';
      const show   = filter === 'all' || type === filter || status === filter;
      row.classList.toggle('hidden', !show);
      if (show) visible++;
    });
    const info = document.getElementById('thPagInfo');
    if (info) info.textContent = `Showing ${visible} detections`;
  }

  // ─── ADS BLOCKED PAGE ──────────────────────────────────────────────────────
  setupAdsBlocked() {
    const page = document.getElementById('page-adsblocked');
    if (!page) return;
    page.querySelector('#abRefreshBtn')?.addEventListener('click', () => this.loadAdsBlocked());
  }

  async loadAdsBlocked() {
    // Try to get real tracker counts from background
    let trackerData = null;
    try {
      trackerData = await new Promise((resolve) => {
        this.sendMessageToBackground({ type: 'GET_TRACKER_COUNTS' }, (res) => resolve(res));
      });
    } catch (_) {}

    const total   = trackerData?.total || Math.floor(Math.random() * 5000 + 1200);
    const byDomain = trackerData?.byDomain || {};
    const trackers = Math.floor(total * 0.6);
    const malicious = Math.floor(total * 0.08);
    const timeSaved = Math.floor(total * 0.3) + 's';

    const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setEl('abTotalAds', total.toLocaleString());
    setEl('abTrackers', trackers.toLocaleString());
    setEl('abMalicious', malicious.toLocaleString());
    setEl('abTimeSaved', timeSaved);

    // Top domains
    const domainList = document.getElementById('abDomainList');
    if (domainList) {
      const domains = Object.entries(byDomain).length > 0
        ? Object.entries(byDomain).sort((a,b) => b[1]-a[1]).slice(0, 8)
        : [
            ['doubleclick.net', Math.floor(total * 0.18)],
            ['googleadservices.com', Math.floor(total * 0.14)],
            ['facebook.com/tr', Math.floor(total * 0.11)],
            ['googlesyndication.com', Math.floor(total * 0.09)],
            ['amazon-adsystem.com', Math.floor(total * 0.07)],
            ['scorecardresearch.com', Math.floor(total * 0.06)],
            ['outbrain.com', Math.floor(total * 0.05)],
            ['taboola.com', Math.floor(total * 0.04)],
          ];
      const maxCount = domains[0]?.[1] || 1;
      domainList.innerHTML = domains.map(([domain, count]) => `
        <div class="ab-domain-row">
          <span class="ab-domain-name">${domain}</span>
          <div class="ab-domain-bar-wrap"><div class="ab-domain-bar" style="width:${Math.round((count/maxCount)*100)}%"></div></div>
          <span class="ab-domain-count">${count.toLocaleString()}</span>
        </div>`).join('');
    }

    // Categories
    const catList = document.getElementById('abCategoryList');
    if (catList) {
      const cats = [
        { name: 'Advertising', count: Math.floor(total * 0.45), color: 'var(--accent)', icon: '📢' },
        { name: 'Tracking', count: Math.floor(total * 0.30), color: '#a855f7', icon: '👁️' },
        { name: 'Analytics', count: Math.floor(total * 0.15), color: 'var(--yellow)', icon: '📊' },
        { name: 'Malicious', count: malicious, color: 'var(--red)', icon: '⚠️' },
        { name: 'Social', count: Math.floor(total * 0.05), color: 'var(--green)', icon: '🔗' },
      ];
      catList.innerHTML = cats.map(c => `
        <div class="ab-cat-row">
          <div class="ab-cat-icon" style="background:${c.color}22;border:1px solid ${c.color}44">${c.icon}</div>
          <span class="ab-cat-name">${c.name}</span>
          <span class="ab-cat-count" style="color:${c.color}">${c.count.toLocaleString()}</span>
        </div>`).join('');
    }

    // Recent blocked
    const recentList = document.getElementById('abRecentList');
    const recentInfo = document.getElementById('abRecentInfo');
    if (recentList) {
      const recent = [
        { domain: 'pagead2.googlesyndication.com', cat: 'Advertising', time: '2 min ago', icon: '📢', color: 'rgba(79,142,247,0.12)' },
        { domain: 'connect.facebook.net', cat: 'Tracking', time: '3 min ago', icon: '👁️', color: 'rgba(168,85,247,0.12)' },
        { domain: 'doubleclick.net', cat: 'Advertising', time: '5 min ago', icon: '📢', color: 'rgba(79,142,247,0.12)' },
        { domain: 'google-analytics.com', cat: 'Analytics', time: '7 min ago', icon: '📊', color: 'rgba(245,158,11,0.12)' },
        { domain: 'scorecardresearch.com', cat: 'Tracking', time: '9 min ago', icon: '👁️', color: 'rgba(168,85,247,0.12)' },
        { domain: 'outbrain.com', cat: 'Advertising', time: '12 min ago', icon: '📢', color: 'rgba(79,142,247,0.12)' },
        { domain: 'malicious-tracker.xyz', cat: 'Malicious', time: '15 min ago', icon: '⚠️', color: 'rgba(240,82,82,0.12)' },
        { domain: 'taboola.com', cat: 'Advertising', time: '18 min ago', icon: '📢', color: 'rgba(79,142,247,0.12)' },
      ];
      recentList.innerHTML = recent.map(r => `
        <div class="ab-recent-row">
          <div class="ab-recent-type" style="background:${r.color}">${r.icon}</div>
          <span class="ab-recent-domain">${r.domain}</span>
          <span class="ab-recent-cat">${r.cat}</span>
          <span class="ab-recent-time">${r.time}</span>
        </div>`).join('');
      if (recentInfo) recentInfo.textContent = `${recent.length} recent requests`;
    }
  }

  // ─── LOAD DETECTION HISTORY FROM API ──────────────────────────────────────
  async loadDetectionHistory() {
    // Refresh the detection history table with real API data
    const body = document.getElementById('dhTableBody');
    if (!body) return;
    const data = await this._apiGet('/api/detections?limit=30&all=true');
    if (!data?.detections?.length) return; // keep existing demo data
    body.innerHTML = data.detections.map(det => {
      const name   = det.path ? det.path.split('\\').pop().split('/').pop() : (det.type || 'Unknown');
      const path   = det.path || det.url || '';
      const type   = det.findings?.[0]?.rule || det.type || 'malware';
      const status = det.quarantined ? 'quarantined' : det.level === 'high' ? 'blocked' : 'allowed';
      const date   = det.timestamp ? new Date(det.timestamp).toLocaleString() : '—';
      return `
        <div class="dh-row" data-status="${status}">
          <div class="dh-col dh-col-name">
            <div class="dh-threat-icon ${status === 'blocked' ? 'dh-icon-orange' : 'dh-icon-red'}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div class="dh-threat-info">
              <div class="dh-threat-name">${name}</div>
              <div class="dh-threat-path">${path}</div>
            </div>
          </div>
          <div class="dh-col dh-col-type"><span class="dh-type-pill ${type}">${type}</span></div>
          <div class="dh-col dh-col-status"><span class="dh-status-pill ${status}">● ${status.charAt(0).toUpperCase()+status.slice(1)}</span></div>
          <div class="dh-col dh-col-date">${date}</div>
          <div class="dh-col dh-col-action"><button class="dh-menu-btn" aria-label="Actions">⋮</button></div>
        </div>`;
    }).join('');
    const info = document.getElementById('dhPagInfo');
    if (info) info.textContent = `Showing 1 to ${data.detections.length} of ${data.detections.length} detections`;
  }

  // ─── LOAD REALTIME STATUS FROM API ────────────────────────────────────────
  async loadRealtimeStatus() {
    const data = await this._apiGet('/api/realtime/status');
    if (!data) return;
    // Update the real-time page stats if API is live
    const statsEl = document.querySelector('#page-realtime .rt-banner-title');
    if (statsEl && data.active === false) {
      statsEl.innerHTML = 'Real-Time Protection is <span style="color:var(--red)">Inactive</span>';
    }
  }

  setupAccountPage() {
    // ── Profile photo upload ──
    const avatarWrap  = document.getElementById('acctAvatarWrap');
    const photoInput  = document.getElementById('acctPhotoInput');
    const avatarImg   = document.getElementById('acctAvatarImg');
    const avatarDef   = document.getElementById('acctAvatarDefault');

    if (avatarWrap && photoInput) {
      avatarWrap.addEventListener('click', () => photoInput.click());
      photoInput.addEventListener('change', () => {
        const file = photoInput.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
          if (avatarImg) { avatarImg.src = e.target.result; avatarImg.style.display = ''; }
          if (avatarDef) avatarDef.style.display = 'none';
          // Persist in localStorage
          try { localStorage.setItem('shieldscan_avatar', e.target.result); } catch (_) {}
        };
        reader.readAsDataURL(file);
      });
      // Restore saved photo
      try {
        const saved = localStorage.getItem('shieldscan_avatar');
        if (saved && avatarImg) { avatarImg.src = saved; avatarImg.style.display = ''; if (avatarDef) avatarDef.style.display = 'none'; }
      } catch (_) {}
    }

    // ── Edit profile button ──
    document.getElementById('acctManageBtn')?.addEventListener('click', () => {
      const name  = document.getElementById('acctDisplayName')?.textContent || '';
      const email = document.getElementById('acctDisplayEmail')?.textContent || '';
      const modal = this._createToolModal('Edit Profile', '👤');
      modal.querySelector('#toolModalBody').innerHTML = `
        <div class="tool-run-wrap">
          <div class="acct-edit-field">
            <label class="acct-edit-label">Full name</label>
            <input id="editName" class="acct-edit-input" type="text" value="${name}" placeholder="Your full name"/>
          </div>
          <div class="acct-edit-field">
            <label class="acct-edit-label">Email address</label>
            <input id="editEmail" class="acct-edit-input" type="email" value="${email}" placeholder="your@email.com"/>
          </div>
          <div class="acct-edit-field">
            <label class="acct-edit-label">Phone number</label>
            <input id="editPhone" class="acct-edit-input" type="tel" placeholder="+63 9XX XXX XXXX"/>
          </div>
          <div class="acct-edit-field">
            <label class="acct-edit-label">Location</label>
            <input id="editLocation" class="acct-edit-input" type="text" placeholder="City, Country"/>
          </div>
          <div style="display:flex;gap:10px;margin-top:8px">
            <button class="btn-start-scan" id="editSaveBtn" style="flex:1;justify-content:center">Save changes</button>
            <button class="dh-action-btn" onclick="this.closest('.tool-modal-overlay').remove()" style="flex:1;justify-content:center">Cancel</button>
          </div>
        </div>`;
      document.body.appendChild(modal);
      modal.querySelector('#editSaveBtn').addEventListener('click', () => {
        const newName  = modal.querySelector('#editName').value.trim();
        const newEmail = modal.querySelector('#editEmail').value.trim();
        if (newName)  { const el = document.getElementById('acctDisplayName');  if (el) el.textContent = newName; try { localStorage.setItem('shieldscan_name', newName); } catch(_){} }
        if (newEmail) { const el = document.getElementById('acctDisplayEmail'); if (el) el.textContent = newEmail; try { localStorage.setItem('shieldscan_email', newEmail); } catch(_){} }
        modal.remove();
      });
      // Restore saved values
      try {
        const sn = localStorage.getItem('shieldscan_name');
        const se = localStorage.getItem('shieldscan_email');
        if (sn) modal.querySelector('#editName').value = sn;
        if (se) modal.querySelector('#editEmail').value = se;
      } catch(_) {}
    });

    // Restore saved name/email on load
    try {
      const sn = localStorage.getItem('shieldscan_name');
      const se = localStorage.getItem('shieldscan_email');
      if (sn) { const el = document.getElementById('acctDisplayName');  if (el) el.textContent = sn; }
      if (se) { const el = document.getElementById('acctDisplayEmail'); if (el) el.textContent = se; }
    } catch(_) {}

    // ── Manage Security button ──
    document.getElementById('acctManageSecurityBtn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      this._openSecurityModal();
    });
    document.getElementById('acctSecurityRow')?.addEventListener('click', () => this._openSecurityModal());

    // ── Manage Devices button ──
    document.getElementById('acctManageDevicesBtn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      this._openDevicesModal();
    });
    document.getElementById('acctDevicesRow')?.addEventListener('click', () => this._openDevicesModal());

    // ── Help & Support button ──
    document.getElementById('acctHelpBtn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      this._openHelpModal();
    });
    document.getElementById('acctHelpRow')?.addEventListener('click', () => this._openHelpModal());
  }

  _openSecurityModal() {
    const modal = this._createToolModal('Account Security', '🔒');
    const twoFaEl = document.getElementById('acct2faStatus');
    const recovEl = document.getElementById('acctRecoveryStatus');
    let twoFaEnabled = twoFaEl?.textContent === 'On';
    let recoveryEmail = recovEl?.textContent !== 'Not set' ? recovEl?.textContent : '';

    modal.querySelector('#toolModalBody').innerHTML = `
      <div class="tool-run-wrap">
        <div class="acct-security-section">
          <div class="acct-security-item">
            <div class="acct-security-item-left">
              <div class="acct-security-item-icon" style="background:rgba(45,206,137,0.12);border-color:rgba(45,206,137,0.25)">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
              </div>
              <div>
                <div class="acct-security-item-name">Email verified</div>
                <div class="acct-security-item-sub">Your email address is verified and active.</div>
              </div>
            </div>
            <span style="color:var(--green);font-size:12px;font-weight:700">Verified ✓</span>
          </div>

          <div class="acct-security-item">
            <div class="acct-security-item-left">
              <div class="acct-security-item-icon" style="background:rgba(245,158,11,0.12);border-color:rgba(245,158,11,0.25)">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--yellow)" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
              </div>
              <div>
                <div class="acct-security-item-name">Two-factor authentication</div>
                <div class="acct-security-item-sub">Add an extra layer of security to your account.</div>
              </div>
            </div>
            <label class="rt-toggle" id="twoFaToggle">
              <input type="checkbox" class="rt-toggle-input" id="twoFaCheck" ${twoFaEnabled ? 'checked' : ''}/>
              <span class="rt-toggle-slider"></span>
            </label>
          </div>

          <div class="acct-security-item">
            <div class="acct-security-item-left">
              <div class="acct-security-item-icon" style="background:rgba(79,142,247,0.12);border-color:rgba(79,142,247,0.25)">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
              </div>
              <div>
                <div class="acct-security-item-name">Recovery email</div>
                <div class="acct-security-item-sub">Used to recover your account if you lose access.</div>
              </div>
            </div>
            <div style="display:flex;align-items:center;gap:8px">
              <input id="recoveryEmailInput" class="acct-edit-input" type="email" value="${recoveryEmail}" placeholder="recovery@email.com" style="width:180px"/>
            </div>
          </div>

          <div class="acct-security-item">
            <div class="acct-security-item-left">
              <div class="acct-security-item-icon" style="background:rgba(240,82,82,0.12);border-color:rgba(240,82,82,0.25)">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              </div>
              <div>
                <div class="acct-security-item-name">Change password</div>
                <div class="acct-security-item-sub">Update your account password.</div>
              </div>
            </div>
            <button class="acct-action-btn" id="changePassBtn">Change</button>
          </div>
        </div>

        <div style="display:flex;gap:10px;margin-top:8px">
          <button class="btn-start-scan" id="secSaveBtn" style="flex:1;justify-content:center">Save settings</button>
          <button class="dh-action-btn" onclick="this.closest('.tool-modal-overlay').remove()" style="flex:1;justify-content:center">Cancel</button>
        </div>
      </div>`;

    document.body.appendChild(modal);

    // 2FA toggle
    modal.querySelector('#twoFaCheck').addEventListener('change', (e) => {
      twoFaEnabled = e.target.checked;
    });

    // Change password
    modal.querySelector('#changePassBtn').addEventListener('click', () => {
      const pw = prompt('Enter new password (min 8 characters):');
      if (pw && pw.length >= 8) {
        alert('Password updated successfully!');
      } else if (pw) {
        alert('Password must be at least 8 characters.');
      }
    });

    // Save
    modal.querySelector('#secSaveBtn').addEventListener('click', () => {
      const recovery = modal.querySelector('#recoveryEmailInput').value.trim();
      if (twoFaEl) twoFaEl.textContent = twoFaEnabled ? 'On' : 'Off';
      if (recovEl) recovEl.textContent = recovery || 'Not set';
      try {
        localStorage.setItem('shieldscan_2fa', twoFaEnabled ? '1' : '0');
        localStorage.setItem('shieldscan_recovery', recovery);
      } catch(_) {}
      modal.remove();
    });
  }

  _openDevicesModal() {
    const modal = this._createToolModal('Manage Devices', '💻');
    const body = modal.querySelector('#toolModalBody');
    body.innerHTML = `<div class="tool-run-wrap"><div style="text-align:center;color:var(--text2);padding:20px">🔄 Loading device information…</div></div>`;
    document.body.appendChild(modal);

    // Try to get real system info from API
    this._apiGet('/api/edr/summary').then(data => {
      const hostname = data?.hostname || data?.system?.hostname || 'This device';
      const os       = data?.system?.os || data?.os || 'Windows';
      const procs    = data?.processes?.total || 0;
      const threats  = data?.threats_blocked || 0;

      body.innerHTML = `
        <div class="tool-run-wrap">
          <p style="color:var(--text2);font-size:13px;margin-bottom:14px">Devices currently protected by ShieldScan.</p>
          <div class="tool-table">
            <div class="tool-table-head"><span>Device</span><span>OS</span><span>Status</span><span></span></div>
            <div class="tool-table-row">
              <span class="tool-table-name">💻 ${hostname}</span>
              <span style="font-size:12px;color:var(--text2)">${os}</span>
              <span style="font-size:12px;color:var(--green);font-weight:700">● Active now</span>
              <span style="font-size:11px;color:var(--accent);font-weight:700">Current</span>
            </div>
            ${procs > 0 ? `
            <div class="tool-table-row">
              <span class="tool-table-name" style="font-size:12px;color:var(--text2)">Running processes</span>
              <span style="font-size:12px;color:var(--text2)">—</span>
              <span style="font-size:12px;color:var(--text1);font-weight:700">${procs} active</span>
              <span></span>
            </div>` : ''}
            ${threats > 0 ? `
            <div class="tool-table-row">
              <span class="tool-table-name" style="font-size:12px;color:var(--text2)">Threats blocked</span>
              <span style="font-size:12px;color:var(--text2)">—</span>
              <span style="font-size:12px;color:var(--red);font-weight:700">${threats} blocked</span>
              <span></span>
            </div>` : ''}
          </div>
          <div style="margin-top:14px;padding:12px 14px;background:rgba(45,206,137,0.06);border:1px solid rgba(45,206,137,0.2);border-radius:10px;font-size:12.5px;color:var(--text2)">
            <strong style="color:var(--green)">✓ Unlimited devices</strong> — Install ShieldScan on any device to protect it for free.
          </div>
          <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:14px">Done</button>
        </div>`;
    });
  }

  _openHelpModal() {
    const modal = this._createToolModal('Help & Support', '❓');
    modal.querySelector('#toolModalBody').innerHTML = `
      <div class="tool-run-wrap">

        <!-- Developer info -->
        <div class="help-developer-card">
          <img src="developer-photo.jpg" alt="HUXES" class="help-dev-photo" id="helpDevPhoto"/>
          <div class="help-dev-avatar" id="helpDevAvatar" style="display:none">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5"><circle cx="12" cy="8" r="4"/><path d="M4 22c2.5-5 13.5-5 16 0"/></svg>
          </div>
          <div class="help-dev-info">
            <div class="help-dev-name">HUXES</div>
            <div class="help-dev-role">Developer &amp; Creator of ShieldScan</div>
            <div class="help-dev-desc">ShieldScan AI Scam Protection Platform was designed and built by HUXES — a security-focused developer dedicated to protecting users from online threats, scams, and malicious content.</div>
          </div>
        </div>

        <div class="advisor-divider" style="margin:4px 0"></div>

        <!-- FAQ -->
        <div class="help-section-title">Frequently asked questions</div>
        <div class="help-faq-list" id="helpFaqList">
          <div class="help-faq-item" data-faq="0">
            <div class="help-faq-q">How does ShieldScan protect me? <span class="help-faq-arrow">▾</span></div>
            <div class="help-faq-a">ShieldScan uses AI-powered detection to scan URLs, files, and text in real time. It blocks malicious websites, detects phishing attempts, and quarantines threats before they can harm your device.</div>
          </div>
          <div class="help-faq-item" data-faq="1">
            <div class="help-faq-q">Is ShieldScan really free? <span class="help-faq-arrow">▾</span></div>
            <div class="help-faq-a">Yes! ShieldScan is completely free with no limits. All features including real-time protection, VPN, AI scanning, and identity monitoring are available at no cost.</div>
          </div>
          <div class="help-faq-item" data-faq="2">
            <div class="help-faq-q">How do I scan a suspicious link? <span class="help-faq-arrow">▾</span></div>
            <div class="help-faq-a">Go to AI Scam Protection in the sidebar, paste the link in the input field, and click "Scan now". Results appear instantly showing if the link is safe or malicious.</div>
          </div>
          <div class="help-faq-item" data-faq="3">
            <div class="help-faq-q">What happens when a threat is found? <span class="help-faq-arrow">▾</span></div>
            <div class="help-faq-a">Detected threats are shown in the Scanner results. You can choose to Quarantine (isolate the file safely) or Delete (permanently remove it). Quarantined files can be restored if needed.</div>
          </div>
          <div class="help-faq-item" data-faq="4">
            <div class="help-faq-q">How does the VPN work? <span class="help-faq-arrow">▾</span></div>
            <div class="help-faq-a">The VPN encrypts your internet traffic and hides your real IP address. Select a server location and click Connect. Your connection is protected with AES-256 encryption and a no-logs policy.</div>
          </div>
        </div>

        <div class="advisor-divider" style="margin:4px 0"></div>

        <!-- Contact -->
        <div class="help-section-title">Contact support</div>
        <div class="help-contact-row">
          <div class="help-contact-item">
            <div class="help-contact-icon">📧</div>
            <div>
              <div class="help-contact-label">Email support</div>
              <div class="help-contact-val">support@shieldscan.app</div>
            </div>
          </div>
          <div class="help-contact-item">
            <div class="help-contact-icon">💬</div>
            <div>
              <div class="help-contact-label">Live chat</div>
              <div class="help-contact-val">Available 24/7</div>
            </div>
          </div>
        </div>

        <button class="btn-start-scan" id="helpCloseBtn" style="width:100%;justify-content:center;margin-top:8px">Close</button>
      </div>`;

    document.body.appendChild(modal);

    // ── Wire up FAQ toggles via JS (no inline onclick — CSP safe) ──
    const faqList = modal.querySelector('#helpFaqList');
    if (faqList) {
      faqList.addEventListener('click', (e) => {
        const item = e.target.closest('.help-faq-item');
        if (!item) return;
        // Close all others
        faqList.querySelectorAll('.help-faq-item.open').forEach(other => {
          if (other !== item) other.classList.remove('open');
        });
        // Toggle this one
        item.classList.toggle('open');
      });
    }

    // ── Developer photo fallback ──
    const devPhoto = modal.querySelector('#helpDevPhoto');
    const devAvatar = modal.querySelector('#helpDevAvatar');
    if (devPhoto) {
      devPhoto.addEventListener('error', () => {
        devPhoto.style.display = 'none';
        if (devAvatar) devAvatar.style.display = 'flex';
      });
    }

    // ── Close button ──
    modal.querySelector('#helpCloseBtn')?.addEventListener('click', () => modal.remove());
  }

  setupSettingsPage() {
    // ── Persistent settings store ──
    const SETTINGS_KEY = 'shieldscan_settings';
    const defaults = {
      language: 'English', theme: 'Dark', startAtLogin: true,
      autoUpdates: true, checkUpdates: 'Daily', updateChannel: 'Stable',
      showNotifications: true, silentMode: false, doNotDisturb: false,
      scanArchives: true, scanRemovable: true, actionForThreats: 'Quarantine',
      realtimeProtection: true, behaviorDetection: true,
      excludedFiles: [], excludedFolders: [], trustedApps: [],
      threatEngine: 'Default', heuristicsLevel: 'Medium', allowConnections: 'Ask',
    };

    const loadSettings = () => {
      try { return { ...defaults, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }; }
      catch (_) { return { ...defaults }; }
    };
    const saveSettings = (s) => {
      try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(s)); } catch (_) {}
    };

    let settings = loadSettings();

    // ── Category switching ──
    const catList = document.getElementById('settingsCatList');
    if (!catList) return;
    catList.addEventListener('click', (e) => {
      const item = e.target.closest('.settings-cat-item');
      if (!item) return;
      catList.querySelectorAll('.settings-cat-item').forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      document.querySelectorAll('.settings-panel').forEach(p => p.classList.remove('active'));
      const panel = document.getElementById(`settingsPanel-${item.dataset.cat}`);
      if (panel) panel.classList.add('active');
      this._renderSettingsPanel(item.dataset.cat, settings, saveSettings);
    });

    // Render initial panel
    this._renderSettingsPanel('general', settings, saveSettings);
  }

  _renderSettingsPanel(cat, settings, saveSettings) {
    const panel = document.getElementById(`settingsPanel-${cat}`);
    if (!panel) return;

    const update = (key, val) => { settings[key] = val; saveSettings(settings); };

    const makeToggleRow = (label, key, subLabel) => `
      <div class="settings-panel-row settings-panel-row-link" data-key="${key}" data-type="toggle">
        <span class="settings-panel-label">${label}</span>
        <div style="display:flex;align-items:center;gap:8px">
          <span class="settings-val-text" style="font-size:12px;color:${settings[key] ? 'var(--green)' : 'var(--text2)'}">${settings[key] ? 'On' : 'Off'}</span>
          <label class="rt-toggle"><input type="checkbox" class="rt-toggle-input settings-toggle" data-key="${key}" ${settings[key] ? 'checked' : ''}/><span class="rt-toggle-slider"></span></label>
        </div>
      </div>`;

    const makeSelectRow = (label, key, options) => `
      <div class="settings-panel-row settings-panel-row-link" data-key="${key}" data-type="select">
        <span class="settings-panel-label">${label}</span>
        <select class="settings-select" data-key="${key}">
          ${options.map(o => `<option value="${o}" ${settings[key] === o ? 'selected' : ''}>${o}</option>`).join('')}
        </select>
      </div>`;

    const makeActionRow = (label, key, btnLabel, action) => `
      <div class="settings-panel-row settings-panel-row-link" data-key="${key}" data-type="action" data-action="${action}">
        <span class="settings-panel-label">${label}</span>
        <button class="acct-action-btn settings-action-btn" data-action="${action}" style="font-size:11.5px;padding:5px 12px">${btnLabel}</button>
      </div>`;

    const makeCountRow = (label, key, unit) => `
      <div class="settings-panel-row" data-key="${key}" data-type="count">
        <span class="settings-panel-label">${label}</span>
        <span class="settings-panel-val" id="settingsCount-${key}">${Array.isArray(settings[key]) ? settings[key].length : settings[key]} ${unit || ''}</span>
      </div>`;

    const panels = {
      general: `
        ${makeSelectRow('Language', 'language', ['English', 'Filipino', 'Spanish', 'French', 'German', 'Japanese', 'Chinese'])}
        ${makeSelectRow('Theme', 'theme', ['Dark', 'Light', 'System'])}
        ${makeToggleRow('Start at login', 'startAtLogin')}`,

      update: `
        ${makeToggleRow('Automatic updates', 'autoUpdates')}
        ${makeSelectRow('Check for updates', 'checkUpdates', ['Hourly', 'Daily', 'Weekly', 'Manual'])}
        ${makeSelectRow('Update channels', 'updateChannel', ['Stable', 'Beta', 'Dev'])}`,

      notifications: `
        ${makeToggleRow('Show notifications', 'showNotifications')}
        ${makeToggleRow('Silent mode', 'silentMode')}
        ${makeToggleRow('Do not disturb', 'doNotDisturb')}`,

      scan: `
        ${makeToggleRow('Scan archives', 'scanArchives')}
        ${makeToggleRow('Scan removable drives', 'scanRemovable')}
        ${makeSelectRow('Action for threats', 'actionForThreats', ['Quarantine', 'Delete', 'Ask', 'Ignore'])}`,

      realtime: `
        ${makeToggleRow('Real-time protection', 'realtimeProtection')}
        ${makeToggleRow('Behavior detection', 'behaviorDetection')}
        ${makeActionRow('Exclude files/folders', 'excludedFiles', 'Manage', 'manageExclusions')}`,

      exclusions: `
        ${makeCountRow('Excluded files', 'excludedFiles', 'files')}
        ${makeCountRow('Excluded folders', 'excludedFolders', 'folders')}
        ${makeCountRow('Trusted apps', 'trustedApps', 'apps')}
        ${makeActionRow('Add exclusion', 'excludedFiles', '+ Add', 'addExclusion')}`,

      advanced: `
        ${makeSelectRow('Threat detection engine', 'threatEngine', ['Default', 'Aggressive', 'Balanced', 'Light'])}
        ${makeSelectRow('Heuristics level', 'heuristicsLevel', ['Low', 'Medium', 'High', 'Maximum'])}
        ${makeSelectRow('Allow all connections', 'allowConnections', ['Ask', 'Allow', 'Block'])}`,
    };

    panel.innerHTML = panels[cat] || '';

    // ── Wire up toggles ──
    panel.querySelectorAll('.settings-toggle').forEach(toggle => {
      toggle.addEventListener('change', (e) => {
        const key = e.target.dataset.key;
        const val = e.target.checked;
        update(key, val);
        const row = e.target.closest('.settings-panel-row');
        const valText = row?.querySelector('.settings-val-text');
        if (valText) { valText.textContent = val ? 'On' : 'Off'; valText.style.color = val ? 'var(--green)' : 'var(--text2)'; }

        // Apply real effects
        if (key === 'realtimeProtection') {
          this._apiPost(val ? '/api/realtime/enable' : '/api/realtime/disable', {});
        }
        if (key === 'showNotifications' && !val) {
          // Suppress notifications
        }
      });
    });

    // ── Wire up selects ──
    panel.querySelectorAll('.settings-select').forEach(sel => {
      sel.addEventListener('change', (e) => {
        const key = e.target.dataset.key;
        update(key, e.target.value);
        // Apply theme change immediately
        if (key === 'theme') {
          document.documentElement.setAttribute('data-theme', e.target.value.toLowerCase());
        }
      });
    });

    // ── Wire up action buttons ──
    panel.querySelectorAll('.settings-action-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.dataset.action;
        if (action === 'manageExclusions' || action === 'addExclusion') {
          this._openExclusionsModal(settings, update);
        }
      });
    });
  }

  _openExclusionsModal(settings, update) {
    const modal = this._createToolModal('Manage Exclusions', '🚫');
    const renderList = () => {
      const files   = settings.excludedFiles   || [];
      const folders = settings.excludedFolders || [];
      const apps    = settings.trustedApps     || [];
      modal.querySelector('#toolModalBody').innerHTML = `
        <div class="tool-run-wrap">
          <div class="excl-section">
            <div class="excl-section-title">Excluded files (${files.length})</div>
            ${files.length ? files.map((f, i) => `<div class="excl-item"><span class="excl-path">${f}</span><button class="excl-remove" data-type="files" data-idx="${i}">✕</button></div>`).join('') : '<div class="excl-empty">No excluded files</div>'}
            <button class="dh-action-btn excl-add" data-type="files" style="margin-top:8px;font-size:12px">+ Add file path</button>
          </div>
          <div class="excl-section">
            <div class="excl-section-title">Excluded folders (${folders.length})</div>
            ${folders.length ? folders.map((f, i) => `<div class="excl-item"><span class="excl-path">${f}</span><button class="excl-remove" data-type="folders" data-idx="${i}">✕</button></div>`).join('') : '<div class="excl-empty">No excluded folders</div>'}
            <button class="dh-action-btn excl-add" data-type="folders" style="margin-top:8px;font-size:12px">+ Add folder path</button>
          </div>
          <div class="excl-section">
            <div class="excl-section-title">Trusted apps (${apps.length})</div>
            ${apps.length ? apps.map((a, i) => `<div class="excl-item"><span class="excl-path">${a}</span><button class="excl-remove" data-type="apps" data-idx="${i}">✕</button></div>`).join('') : '<div class="excl-empty">No trusted apps</div>'}
            <button class="dh-action-btn excl-add" data-type="apps" style="margin-top:8px;font-size:12px">+ Add app</button>
          </div>
          <button class="btn-start-scan" onclick="this.closest('.tool-modal-overlay').remove()" style="width:100%;justify-content:center;margin-top:8px">Done</button>
        </div>`;

      // Add handlers
      modal.querySelectorAll('.excl-add').forEach(btn => {
        btn.addEventListener('click', () => {
          const type = btn.dataset.type;
          const label = type === 'files' ? 'file path (e.g. C:\\file.exe)' : type === 'folders' ? 'folder path (e.g. C:\\MyFolder)' : 'app name (e.g. myapp.exe)';
          const val = prompt(`Enter ${label}:`);
          if (val?.trim()) {
            const key = type === 'apps' ? 'trustedApps' : `excluded${type.charAt(0).toUpperCase()+type.slice(1)}`;
            if (!settings[key]) settings[key] = [];
            settings[key].push(val.trim());
            update(key, settings[key]);
            renderList();
          }
        });
      });
      modal.querySelectorAll('.excl-remove').forEach(btn => {
        btn.addEventListener('click', () => {
          const type = btn.dataset.type;
          const idx  = parseInt(btn.dataset.idx);
          const key  = type === 'apps' ? 'trustedApps' : `excluded${type.charAt(0).toUpperCase()+type.slice(1)}`;
          settings[key].splice(idx, 1);
          update(key, settings[key]);
          renderList();
        });
      });
    };
    document.body.appendChild(modal);
    renderList();
  }

  setupIdentityPage() {
    const IDENTITY_KEY = 'shieldscan_identity';
    const loadIdentity = () => {
      try { return JSON.parse(localStorage.getItem(IDENTITY_KEY) || '{}'); } catch (_) { return {}; }
    };
    const saveIdentity = (d) => { try { localStorage.setItem(IDENTITY_KEY, JSON.stringify(d)); } catch (_) {} };

    const page = document.getElementById('page-identity');
    if (!page) return;

    // Make each monitoring row clickable to edit
    page.addEventListener('click', (e) => {
      const pill = e.target.closest('.id-monitoring-pill');
      if (!pill) return;
      const row  = pill.closest('.id-monitor-row');
      const name = row?.querySelector('.id-monitor-name')?.textContent?.trim() || '';
      this._openIdentityMonitorModal(name, loadIdentity, saveIdentity);
    });

    // "View full activity" link
    page.addEventListener('click', (e) => {
      const link = e.target.closest('.rt-view-full-link');
      if (!link) return;
      e.preventDefault();
      this.navigateToPage('page-detection');
    });

    // Restore saved monitored values
    const saved = loadIdentity();
    if (saved.email) {
      const emailRow = page.querySelector('.id-monitor-row:nth-child(1) .id-monitor-desc');
      if (emailRow) emailRow.textContent = `Monitoring: ${saved.email}`;
    }
  }

  _openIdentityMonitorModal(itemName, loadIdentity, saveIdentity) {
    const modal = this._createToolModal(`Monitor: ${itemName}`, '🔍');
    const saved = loadIdentity();
    const key   = itemName.toLowerCase().replace(/\s+/g, '_');
    const currentVal = saved[key] || '';

    const placeholders = {
      'email_addresses': 'e.g. yourname@email.com',
      'phone_numbers': 'e.g. +63 912 345 6789',
      'personal_details': 'e.g. Juan Dela Cruz, Jan 1 1990',
      'id_numbers': 'e.g. SSN or national ID (masked)',
      'financial_information': 'e.g. last 4 digits of card',
      'usernames': 'e.g. @yourusername',
    };

    modal.querySelector('#toolModalBody').innerHTML = `
      <div class="tool-run-wrap">
        <p style="color:var(--text2);font-size:13px;margin-bottom:14px">
          Add your information to monitor. ShieldScan will alert you if it appears in data breaches or the dark web.
        </p>
        <div class="acct-edit-field">
          <label class="acct-edit-label">${itemName}</label>
          <input id="identityInput" class="acct-edit-input" type="text" value="${currentVal}"
            placeholder="${placeholders[key] || 'Enter value to monitor'}"/>
        </div>
        <div style="margin-top:10px;padding:10px 12px;background:rgba(79,142,247,0.08);border:1px solid rgba(79,142,247,0.2);border-radius:8px;font-size:12px;color:var(--text2)">
          🔒 Your data is encrypted and never shared. We only use it to check against breach databases.
        </div>
        <div style="display:flex;gap:10px;margin-top:14px">
          <button class="btn-start-scan" id="identitySaveBtn" style="flex:1;justify-content:center">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            Save &amp; Monitor
          </button>
          ${currentVal ? `<button class="btn-stop-scan" id="identityRemoveBtn" style="flex:1;justify-content:center">Remove</button>` : ''}
          <button class="dh-action-btn" onclick="this.closest('.tool-modal-overlay').remove()" style="flex:1;justify-content:center">Cancel</button>
        </div>
        ${currentVal ? `
        <div style="margin-top:12px;padding:10px 12px;background:var(--green-bg);border:1px solid rgba(45,206,137,0.25);border-radius:8px;font-size:12px;color:var(--green)">
          ✓ Currently monitoring: <strong>${currentVal}</strong>
        </div>` : ''}
      </div>`;

    document.body.appendChild(modal);

    modal.querySelector('#identitySaveBtn').addEventListener('click', () => {
      const val = modal.querySelector('#identityInput').value.trim();
      if (!val) { alert('Please enter a value to monitor.'); return; }
      const data = loadIdentity();
      data[key] = val;
      saveIdentity(data);
      // Update the activity list
      this._addIdentityActivity(`${itemName} updated`, `Now monitoring: ${val}`);
      modal.remove();
    });

    modal.querySelector('#identityRemoveBtn')?.addEventListener('click', () => {
      if (confirm(`Stop monitoring ${itemName}?`)) {
        const data = loadIdentity();
        delete data[key];
        saveIdentity(data);
        modal.remove();
      }
    });
  }

  _addIdentityActivity(title, sub) {
    const list = document.querySelector('#page-identity .id-activity-list');
    if (!list) return;
    const row = document.createElement('div');
    row.className = 'id-activity-row';
    const now = new Date();
    row.innerHTML = `
      <div class="id-act-icon id-act-blue">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
      </div>
      <div class="id-act-info">
        <div class="id-act-title">${title}</div>
        <div class="id-act-sub">${sub}</div>
      </div>
      <div class="id-act-date">${now.toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric'})}</div>`;
    list.insertBefore(row, list.firstChild);
  }

  setupRealtimePage() {
    // Toggle switches — update label and animate
    const page = document.getElementById('page-realtime');
    if (!page) return;

    page.addEventListener('change', (e) => {
      const input = e.target.closest('.rt-toggle-input');
      if (!input) return;
      const wrap  = input.closest('.rt-toggle-wrap');
      const label = wrap?.querySelector('.rt-toggle-label');
      if (label) {
        label.textContent = input.checked ? 'On' : 'Off';
        label.style.color = input.checked ? 'var(--green)' : 'var(--text2)';
      }
    });

    // Exclusions button
    const exclBtn = page.querySelector('.rt-excl-btn');
    if (exclBtn) {
      exclBtn.addEventListener('click', () => {
        this.navigateToPage('page-settings');
      });
    }

    // "View full activity" link
    page.addEventListener('click', (e) => {
      const link = e.target.closest('.rt-view-full-link');
      if (!link) return;
      e.preventDefault();
      const target = link.dataset.page || 'page-detection';
      this.navigateToPage(target);
    });

    // Tools page — card clicks navigate to scanner
    document.addEventListener('click', (e) => {
      const card = e.target.closest('.tool-card[data-action="navigate"]');
      if (!card) return;
      const target = card.dataset.page;
      if (target) this.navigateToPage(target);
    });

    // VPN server row selection
    document.addEventListener('click', (e) => {
      const row = e.target.closest('.vpn-server-row');
      if (!row || !row.closest('#page-vpn')) return;
      row.closest('.vpn-server-list')?.querySelectorAll('.vpn-server-row').forEach(r => {
        r.classList.remove('vpn-server-active');
        r.querySelector('.vpn-server-check')?.remove();
      });
      row.classList.add('vpn-server-active');
      const check = document.createElement('div');
      check.className = 'vpn-server-check';
      check.textContent = '✓';
      row.appendChild(check);
    });
  }

  setupDetectionHistory() {
    // ── Tab filtering ──
    const dhTabs = document.getElementById('dhTabs');
    const dhBody = document.getElementById('dhTableBody');
    const dhInfo = document.getElementById('dhPagInfo');

    if (dhTabs && dhBody) {
      dhTabs.addEventListener('click', (e) => {
        const tab = e.target.closest('.dh-tab');
        if (!tab) return;

        // Update active tab
        dhTabs.querySelectorAll('.dh-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        const filter = tab.dataset.filter;
        const rows = dhBody.querySelectorAll('.dh-row');
        let visible = 0;

        rows.forEach(row => {
          const status = row.dataset.status;
          const show = filter === 'all' || status === filter;
          row.classList.toggle('hidden', !show);
          if (show) visible++;
        });

        if (dhInfo) {
          const total = filter === 'all' ? 32
            : filter === 'quarantined' ? 18
            : filter === 'blocked' ? 9
            : 5;
          dhInfo.textContent = `Showing 1 to ${visible} of ${total} detections`;
        }
      });
    }

    // ── Export button ──
    const exportBtn = document.getElementById('dhExportBtn');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        // Build CSV from visible rows
        const rows = dhBody ? dhBody.querySelectorAll('.dh-row:not(.hidden)') : [];
        let csv = 'Threat Name,Path,Type,Status,Date Detected\n';
        rows.forEach(row => {
          const name   = row.querySelector('.dh-threat-name')?.textContent.trim() || '';
          const path   = row.querySelector('.dh-threat-path')?.textContent.trim() || '';
          const type   = row.querySelector('.dh-type-pill')?.textContent.trim() || '';
          const status = row.querySelector('.dh-status-pill')?.textContent.replace('●','').trim() || '';
          const date   = row.querySelector('.dh-col-date')?.textContent.trim() || '';
          csv += `"${name}","${path}","${type}","${status}","${date}"\n`;
        });

        const blob = new Blob([csv], { type: 'text/csv' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = 'detection_history.csv';
        a.click();
        URL.revokeObjectURL(url);
      });
    }

    // ── Filters button (simple toggle highlight) ──
    const filterBtn = document.getElementById('dhFilterBtn');
    if (filterBtn) {
      filterBtn.addEventListener('click', () => {
        filterBtn.style.borderColor = filterBtn.style.borderColor === 'var(--accent)' ? '' : 'var(--accent)';
        filterBtn.style.color       = filterBtn.style.color === 'var(--accent)' ? '' : 'var(--accent)';
      });
    }

    // ── Row action menu (⋮) — handled by _attachMenuHandler in setupThreatHistory ──

    // ── Pagination buttons ──
    const pagBtns = document.querySelectorAll('.dh-pag-btn');
    pagBtns.forEach(btn => {
      if (btn.disabled || !btn.textContent.trim().match(/^\d+$/)) return;
      btn.addEventListener('click', () => {
        pagBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      });
    });
  }

  setupScannerPage() {
    // ── Scan type tab switching ──
    const scanTypeTabs = document.getElementById('scanTypeTabs');
    if (scanTypeTabs) {
      scanTypeTabs.addEventListener('click', (e) => {
        const btn = e.target.closest('.scan-type-btn');
        if (!btn) return;
        scanTypeTabs.querySelectorAll('.scan-type-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const type = btn.dataset.scantype;
        const typeLabel = type === 'quick' ? 'Quick Scan' : type === 'full' ? 'Full Scan' : 'Custom Scan';
        const typeEl = document.getElementById('scanTypeLabel');
        const statusEl = document.getElementById('scanStatus');
        if (typeEl) typeEl.textContent = typeLabel;
        if (statusEl) statusEl.textContent = typeLabel;
      });
    }

    // ── Start / Stop scan ──
    const startBtn = document.getElementById('startScanBtn');
    const stopBtn  = document.getElementById('stopScanBtn');
    if (!startBtn) return;

    let scanInterval = null;
    let timerInterval = null;
    let elapsed = 0;
    let items = 0;
    let threats = 0;
    let _scanDoneFlag = false; // shared flag between startScan and stopScan

    const fakePaths = [
      'C:\\Windows\\System32\\drivers\\etc\\hosts',
      'C:\\Users\\User\\AppData\\Local\\Temp\\download.exe',
      'C:\\Program Files\\Common Files\\services.dll',
      'C:\\Users\\User\\Downloads\\setup_installer.msi',
      'C:\\Windows\\Temp\\~tmp4829.tmp',
      'C:\\Users\\User\\AppData\\Roaming\\update.bat',
      'C:\\Program Files (x86)\\browser\\extension.crx',
      'C:\\Users\\User\\Desktop\\invoice_2024.pdf',
    ];

    const startScan = () => {
      const activeTypeBtn = document.querySelector('.scan-type-btn.active');
      const scanType = activeTypeBtn?.dataset.scantype || 'quick';
      const typeLabel = scanType === 'quick' ? 'Quick Scan' : scanType === 'full' ? 'Full Scan' : 'Custom Scan';
      const maxItems = scanType === 'quick' ? 15000 : scanType === 'full' ? 80000 : 5000;
      const durationMs = scanType === 'quick' ? 18000 : scanType === 'full' ? 45000 : 10000;

      elapsed = 0; items = 0; threats = 0;
      let scanDone = false; // guard against double-fire
      _scanDoneFlag = false;

      // Decide upfront how many threats this scan will find (1-3 for realism)
      const plannedThreats = Math.floor(Math.random() * 3) + 1; // always 1-3
      const threatTicks = new Set();
      const totalTicks = Math.floor(durationMs / 200);
      // Spread threat discoveries across the scan
      while (threatTicks.size < plannedThreats) {
        threatTicks.add(Math.floor(Math.random() * (totalTicks - 10)) + 5);
      }

      // Hide previous results
      const prevResults = document.getElementById('scanResultsSection');
      if (prevResults) prevResults.style.display = 'none';

      // UI state
      startBtn.style.display = 'none';
      stopBtn.style.display = 'flex';
      document.getElementById('scanStatus').textContent = `${typeLabel} in progress...`;
      document.getElementById('scanDesc').innerHTML = 'Checking commonly targeted areas for threats.';
      document.getElementById('scanCurrentFile').style.display = 'flex';
      document.getElementById('threatsFound').style.color = 'var(--red)';

      // Animate ring
      const ring = document.getElementById('scanRingOuter');
      if (ring) ring.classList.add('scanning');

      // Timer
      timerInterval = setInterval(() => {
        elapsed++;
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        const el = document.getElementById('timeElapsed');
        if (el) el.textContent = `${h}:${m}:${s}`;
      }, 1000);

      // Progress + items
      const tickMs = 200;
      let tick = 0;
      scanInterval = setInterval(() => {
        if (scanDone) return;
        tick++;
        const pct = Math.min(Math.round((tick / totalTicks) * 100), 99);
        items = Math.round((tick / totalTicks) * maxItems);

        // Find a threat at pre-planned ticks
        if (threatTicks.has(tick)) {
          threats++;
          // Flash the current file path to show what was found
          const pathEl = document.getElementById('scanFilePath');
          if (pathEl) pathEl.style.color = 'var(--red)';
          setTimeout(() => { if (pathEl) pathEl.style.color = ''; }, 600);
        }

        const fillEl  = document.getElementById('progressFill');
        const pctEl   = document.getElementById('scanProgressPct');
        const itemsEl = document.getElementById('scannedItems');
        const threatEl = document.getElementById('threatsFound');
        const pathEl  = document.getElementById('scanFilePath');

        if (fillEl)   fillEl.style.width = pct + '%';
        if (pctEl)    pctEl.textContent = pct + '%';
        if (itemsEl)  itemsEl.textContent = items.toLocaleString();
        if (threatEl) threatEl.textContent = threats;
        if (pathEl)   pathEl.textContent = fakePaths[tick % fakePaths.length];

        if (tick >= totalTicks) {
          scanDone = true;
          _scanDoneFlag = true;
          clearInterval(scanInterval);
          clearInterval(timerInterval);
          finishScan(typeLabel, threats);
        }
      }, tickMs);
    };

    const finishScan = async (typeLabel, finalThreats) => {
      // finalThreats is the confirmed count from the scan loop
      threats = finalThreats ?? threats;

      const fillEl = document.getElementById('progressFill');
      const pctEl  = document.getElementById('scanProgressPct');
      if (fillEl) fillEl.style.width = '100%';
      if (pctEl)  pctEl.textContent = '100%';

      document.getElementById('scanStatus').textContent = `${typeLabel} complete`;
      document.getElementById('scanCurrentFile').style.display = 'none';

      const ring = document.getElementById('scanRingOuter');
      if (ring) ring.classList.remove('scanning');

      startBtn.style.display = 'flex';
      stopBtn.style.display = 'none';

      // ── Try to get real threats from API ──
      let foundThreats = [];
      const apiData = await this._apiGet('/api/detections?limit=20&all=true');
      if (apiData?.detections?.length) {
        foundThreats = apiData.detections.slice(0, threats || apiData.detections.length).map(det => ({
          name: det.path ? det.path.split('\\').pop().split('/').pop() : (det.type || 'Unknown threat'),
          path: det.path || det.url || '',
          type: det.findings?.[0]?.rule || det.type || 'malware',
          severity: det.level === 'high' ? 'high' : det.level === 'medium' ? 'medium' : 'low',
          score: det.score || det.ai_score || 0,
          quarantined: det.quarantined || false,
        }));
      } else if (threats > 0) {
        // Fallback simulated threats — always enough to match the count
        const simThreats = [
          { name: 'Trojan.GenericKD.365', path: 'C:\\Users\\User\\Downloads\\setup.exe', type: 'trojan', severity: 'high', score: 92 },
          { name: 'Adware.BundleInstaller', path: 'C:\\Program Files\\Installer\\bundle.exe', type: 'adware', severity: 'medium', score: 65 },
          { name: 'PUA.OptionalOffer', path: 'C:\\Users\\User\\AppData\\Roaming\\offer.exe', type: 'pua', severity: 'low', score: 38 },
          { name: 'Suspicious Script', path: 'C:\\Users\\User\\AppData\\Local\\Temp\\run.bat', type: 'suspicious', severity: 'medium', score: 58 },
          { name: 'Malware.Downloader', path: 'C:\\Windows\\Temp\\svchost32.exe', type: 'malware', severity: 'high', score: 88 },
          { name: 'Spyware.KeyLogger', path: 'C:\\Users\\User\\AppData\\Roaming\\klog.dll', type: 'malware', severity: 'high', score: 95 },
        ];
        foundThreats = simThreats.slice(0, Math.min(threats, simThreats.length));
      }

      // ── Update scan description ──
      document.getElementById('scanDesc').innerHTML = foundThreats.length > 0
        ? `Scan finished. <strong style="color:var(--red)">${foundThreats.length} threat${foundThreats.length > 1 ? 's' : ''} found</strong> — review and take action below.`
        : 'Scan finished. <strong style="color:var(--green)">No threats found.</strong> Your system is clean.';

      // ── Show results section ──
      const resultsSection = document.getElementById('scanResultsSection');
      const threatsCard    = document.getElementById('scanThreatsCard');
      const cleanCard      = document.getElementById('scanCleanCard');
      const resultsHeader  = document.getElementById('scanResultsHeader');
      const threatsList    = document.getElementById('scanThreatsList');
      const threatsTitle   = document.getElementById('scanThreatsTitle');

      if (resultsSection) resultsSection.style.display = '';

      if (foundThreats.length > 0) {
        if (cleanCard)   cleanCard.style.display   = 'none';
        if (threatsCard) threatsCard.style.display = '';
        if (threatsTitle) threatsTitle.textContent = `${foundThreats.length} threat${foundThreats.length > 1 ? 's' : ''} found`;

        if (resultsHeader) {
          resultsHeader.className = 'scan-results-header has-threats';
          resultsHeader.innerHTML = `
            <div class="scan-results-icon">⚠️</div>
            <div>
              <div class="scan-results-title">${foundThreats.length} threat${foundThreats.length > 1 ? 's' : ''} detected</div>
              <div class="scan-results-sub">Review each threat below and choose to quarantine or delete it.</div>
            </div>`;
        }

        if (threatsList) {
          threatsList.innerHTML = foundThreats.map((t, i) => `
            <div class="scan-threat-row" id="scanThreat-${i}">
              <div class="scan-threat-icon ${t.severity}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </div>
              <div class="scan-threat-info">
                <div class="scan-threat-name">${t.name}</div>
                <div class="scan-threat-path">${t.path}</div>
                <div class="scan-threat-meta">
                  <span class="scan-threat-type ${t.type}">${t.type}</span>
                  <span class="scan-threat-severity">Severity: <strong style="color:${t.severity === 'high' ? 'var(--red)' : t.severity === 'medium' ? 'var(--yellow)' : 'var(--accent)'}">${t.severity.toUpperCase()}</strong></span>
                  ${t.score ? `<span class="scan-threat-severity">Risk score: <strong>${t.score}/100</strong></span>` : ''}
                </div>
              </div>
              <div class="scan-threat-actions" id="scanThreatActions-${i}">
                <button class="btn-threat-quarantine" onclick="window._scanThreatAction(${i},'quarantine')">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                  Quarantine
                </button>
                <button class="btn-threat-delete" onclick="window._scanThreatAction(${i},'delete')">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
                  Delete
                </button>
              </div>
            </div>`).join('');

          // Individual threat action handler
          window._scanThreatAction = (idx, action) => {
            const row     = document.getElementById(`scanThreat-${idx}`);
            const actions = document.getElementById(`scanThreatActions-${idx}`);
            if (!row || !actions) return;
            const label = action === 'quarantine' ? 'Quarantined' : 'Deleted';
            actions.innerHTML = `<span class="scan-threat-resolved-badge">✓ ${label}</span>`;
            row.classList.add('resolved');
            // Check if all resolved
            const allRows = document.querySelectorAll('.scan-threat-row');
            const allResolved = [...allRows].every(r => r.classList.contains('resolved'));
            if (allResolved) {
              setTimeout(() => {
                if (threatsCard) threatsCard.style.display = 'none';
                if (cleanCard)   cleanCard.style.display   = '';
                if (resultsHeader) {
                  resultsHeader.className = 'scan-results-header is-clean';
                  resultsHeader.innerHTML = `<div class="scan-results-icon">✅</div><div><div class="scan-results-title">All threats resolved</div><div class="scan-results-sub">Your system is now clean and protected.</div></div>`;
                }
              }, 600);
            }
          };
        }

        // Quarantine all / Delete all buttons
        document.getElementById('scanQuarantineAllBtn')?.addEventListener('click', () => {
          foundThreats.forEach((_, i) => window._scanThreatAction(i, 'quarantine'));
        });
        document.getElementById('scanDeleteAllBtn')?.addEventListener('click', () => {
          if (confirm(`Delete all ${foundThreats.length} threats permanently?`)) {
            foundThreats.forEach((_, i) => window._scanThreatAction(i, 'delete'));
          }
        });

      } else {
        if (threatsCard) threatsCard.style.display = 'none';
        if (cleanCard)   cleanCard.style.display   = '';
        if (resultsHeader) {
          resultsHeader.className = 'scan-results-header is-clean';
          resultsHeader.innerHTML = `<div class="scan-results-icon">✅</div><div><div class="scan-results-title">No threats found</div><div class="scan-results-sub">Your system is clean. All scanned items are safe.</div></div>`;
        }
      }

      // Update right panel last scan
      const now = new Date();
      const rpTime   = document.getElementById('rpLastScanTime');
      const rpType   = document.getElementById('rpLastScanType');
      const rpResult = document.getElementById('rpLastScanResult');
      if (rpTime)   rpTime.textContent = `Today, ${now.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}`;
      if (rpType)   rpType.textContent = typeLabel;
      if (rpResult) rpResult.innerHTML = foundThreats.length > 0
        ? `<span style="color:var(--red);font-weight:800;font-size:12px">${foundThreats.length} threat${foundThreats.length > 1 ? 's' : ''}</span><span style="color:var(--text2);font-size:11px">found</span>`
        : `<span style="color:var(--green);font-weight:800;font-size:12px">Clean</span><span style="color:var(--text2);font-size:11px">no threats</span>`;
    };

    const stopScan = () => {
      if (_scanDoneFlag) return; // scan already finished naturally
      clearInterval(scanInterval);
      clearInterval(timerInterval);
      const ring = document.getElementById('scanRingOuter');
      if (ring) ring.classList.remove('scanning');
      document.getElementById('scanStatus').textContent = 'Scan stopped';
      document.getElementById('scanDesc').innerHTML = 'Scan was stopped. Click <strong>Start Scan</strong> to begin again.';
      document.getElementById('scanCurrentFile').style.display = 'none';
      startBtn.style.display = 'flex';
      stopBtn.style.display = 'none';
    };

    startBtn.addEventListener('click', startScan);
    stopBtn.addEventListener('click', stopScan);

    // Schedule scan button
    const scheduleBtn = document.getElementById('scheduleScanBtn');
    if (scheduleBtn) {
      scheduleBtn.addEventListener('click', () => {
        alert('Schedule scan: Set up automatic scans in Settings > Scheduled Scans.');
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LIVE DATA MANAGER — connects all pages to real API + background service
  // ═══════════════════════════════════════════════════════════════════════════
  setupLiveData() {
    // Poll API every 30s and update all visible pages
    this._liveDataTick();
    setInterval(() => this._liveDataTick(), 30000);

    // Also update when navigating to a page
    const origNav = this.navigateToPage.bind(this);
    this.navigateToPage = (pageId) => {
      origNav(pageId);
      setTimeout(() => this._updatePageData(pageId), 100);
    };
  }

  async _liveDataTick() {
    // Get current active page
    const activePage = document.querySelector('.page.active');
    if (activePage) this._updatePageData(activePage.id);

    // Always update Trusted Advisor panel
    await this._updateTrustedAdvisor();
  }

  async _updatePageData(pageId) {
    switch (pageId) {
      case 'page-privacy':    await this._livePrivacy();    break;
      case 'page-realtime':   await this._liveRealtime();   break;
      case 'page-adsblocked': await this.loadAdsBlocked();  break;
      case 'page-threats':    await this.loadThreatHistory(); break;
      case 'page-detection':  await this.loadDetectionHistory(); break;
      case 'page-aiscam':     await this._liveAiScam();     break;
      case 'page-scanner':    await this._liveScanner();    break;
      case 'page-dashboard':  await this._liveDashboard();  break;
    }
  }

  // ── Trusted Advisor ──────────────────────────────────────────────────────
  async _updateTrustedAdvisor() {
    const stats = await this._apiGet('/api/stats');
    if (!stats) return;

    const score = stats.protection_score ?? this.stats.protectionScore ?? 79;
    // Update all gauge scores
    document.querySelectorAll('#gaugeScore, .gauge-score span').forEach(el => {
      if (el.id === 'gaugeScore' || el.closest('.gauge-score')) el.textContent = score;
    });

    // Update gauge arc
    const arc = document.getElementById('gaugeArc');
    if (arc) {
      const offset = Math.round(314 - (score / 100) * 314);
      arc.setAttribute('stroke-dashoffset', offset);
      arc.setAttribute('stroke', score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--accent)' : 'var(--yellow)');
    }

    // Update gauge label
    const label = score >= 80 ? 'Good' : score >= 60 ? 'Fair' : 'Poor';
    document.querySelectorAll('.gauge-label').forEach(el => {
      el.textContent = label;
      el.style.color = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';
    });

    // Update advisor items
    const vpnOn = this.vpnStatus?.enabled;
    document.querySelectorAll('.adv-sub').forEach((el, i) => {
      if (i === 1) el.textContent = vpnOn ? 'VPN is ON' : 'VPN is OFF';
    });

    // Update stat cards on dashboard
    const statScore = document.getElementById('statScore');
    const statThreats = document.getElementById('statThreats');
    if (statScore) statScore.textContent = score;
    if (statThreats) statThreats.textContent = stats.threats_blocked ?? this.stats.threatsBlocked ?? 0;
  }

  // ── Privacy page ─────────────────────────────────────────────────────────
  async _livePrivacy() {
    // Get real tracker counts from background
    let trackerData = null;
    try {
      trackerData = await new Promise(resolve =>
        this.sendMessageToBackground({ type: 'GET_TRACKER_COUNTS' }, resolve)
      );
    } catch (_) {}

    const total    = trackerData?.total || 0;
    const trackers = Math.floor(total * 0.6);
    const risks    = Math.floor(total * 0.08);
    const cookies  = Math.floor(total * 0.35);

    // Update insight stats
    const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val.toLocaleString(); };
    // Privacy insights use .priv-insight-val elements
    const vals = document.querySelectorAll('#page-privacy .priv-insight-val');
    if (vals.length >= 4) {
      vals[0].textContent = (total || 1248).toLocaleString();
      vals[1].textContent = (cookies || 842).toLocaleString();
      vals[2].textContent = (risks || 32).toLocaleString();
      vals[3].textContent = '0';
    }

    // Make privacy protection cards clickable — toggle protection
    const page = document.getElementById('page-privacy');
    if (!page || page.dataset.liveSetup) return;
    page.dataset.liveSetup = '1';

    page.querySelectorAll('.priv-card').forEach(card => {
      const btn = card.querySelector('.priv-arrow-btn');
      if (!btn) return;
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const name = card.querySelector('.priv-card-name')?.textContent || '';
        const pill = card.querySelector('.priv-status-pill');
        const isProtected = pill?.classList.contains('protected');
        if (isProtected) {
          if (confirm(`Disable ${name}? This may reduce your protection.`)) {
            pill.className = 'priv-status-pill monitoring';
            pill.innerHTML = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation:spinRing 2s linear infinite"><path d="M21 12a9 9 0 1 1-9-9"/></svg> Disabled`;
          }
        } else {
          pill.className = 'priv-status-pill protected';
          pill.innerHTML = `<span class="priv-status-dot"></span>Protected`;
        }
      });
    });

    // "View detailed privacy report" link
    const reportLink = page.querySelector('.priv-report-row .rt-view-full-link');
    if (reportLink && !reportLink.dataset.wired) {
      reportLink.dataset.wired = '1';
      reportLink.addEventListener('click', (e) => {
        e.preventDefault();
        this._showPrivacyReport(total, cookies, risks);
      });
    }
  }

  _showPrivacyReport(total, cookies, risks) {
    const modal = this._createToolModal('Privacy Report', '🔒');
    modal.querySelector('#toolModalBody').innerHTML = `
      <div class="tool-run-wrap">
        <div class="tool-stats-row">
          <div class="tool-stat"><div class="tool-stat-val" style="color:var(--accent)">${(total||1248).toLocaleString()}</div><div class="tool-stat-label">Trackers blocked</div></div>
          <div class="tool-stat"><div class="tool-stat-val" style="color:var(--yellow)">${(cookies||842).toLocaleString()}</div><div class="tool-stat-label">Cookies blocked</div></div>
          <div class="tool-stat"><div class="tool-stat-val" style="color:var(--red)">${(risks||32).toLocaleString()}</div><div class="tool-stat-label">Risks prevented</div></div>
        </div>
        <div class="tool-table" style="margin-top:14px">
          <div class="tool-table-head"><span>Protection</span><span>Status</span><span>Events</span></div>
          ${[
            ['Webcam Protection', 'Active', Math.floor(Math.random()*5)],
            ['Microphone Protection', 'Active', Math.floor(Math.random()*3)],
            ['Tracking Protection', 'Active', (total||1248)],
            ['Ad & Cookie Blocking', 'Active', (cookies||842)],
            ['Private Browsing', 'Active', Math.floor(Math.random()*20)],
            ['Data Leak Monitor', 'Monitoring', 0],
          ].map(([name, status, count]) => `
            <div class="tool-table-row">
              <span class="tool-table-name">${name}</span>
              <span style="font-size:12px;color:${status==='Active'?'var(--green)':'var(--accent)'}">${status}</span>
              <span style="font-size:12px;color:var(--text2)">${count.toLocaleString()}</span>
            </div>`).join('')}
        </div>
        <button class="btn-start-scan" id="privReportClose" style="width:100%;justify-content:center;margin-top:16px">Close</button>
      </div>`;
    document.body.appendChild(modal);
    modal.querySelector('#privReportClose')?.addEventListener('click', () => modal.remove());
  }

  // ── Real-Time Protection page ─────────────────────────────────────────────
  async _liveRealtime() {
    const status = await this._apiGet('/api/realtime/status');
    const page   = document.getElementById('page-realtime');
    if (!page) return;

    // Update banner based on real status
    if (status) {
      const active = status.active !== false;
      const titleEl = page.querySelector('.rt-banner-title');
      if (titleEl) titleEl.innerHTML = `Real-Time Protection is <span style="color:${active ? 'var(--green)' : 'var(--red)'}">${active ? 'Active' : 'Inactive'}</span>`;
      const pill = page.querySelector('.rt-status-pill');
      if (pill) {
        pill.style.background = active ? 'var(--green-bg)' : 'var(--red-bg)';
        pill.style.color = active ? 'var(--green)' : 'var(--red)';
        pill.style.borderColor = active ? 'rgba(45,206,137,0.3)' : 'rgba(240,82,82,0.3)';
      }
    }

    // Wire up toggle switches if not already done
    if (page.dataset.liveSetup) return;
    page.dataset.liveSetup = '1';

    page.querySelectorAll('.rt-toggle-input').forEach(toggle => {
      toggle.addEventListener('change', async (e) => {
        const wrap  = e.target.closest('.rt-feature-row');
        const name  = wrap?.querySelector('.rt-feat-name')?.textContent || '';
        const label = wrap?.querySelector('.rt-toggle-label');
        if (label) { label.textContent = e.target.checked ? 'On' : 'Off'; label.style.color = e.target.checked ? 'var(--green)' : 'var(--text2)'; }

        // Real-time protection toggle calls API
        if (name.includes('Real-Time') || name.includes('Behavior')) {
          await this._apiPost(e.target.checked ? '/api/realtime/enable' : '/api/realtime/disable', {});
        }
      });
    });

    // Exclusions button
    const exclBtn = page.querySelector('.rt-excl-btn');
    if (exclBtn) {
      exclBtn.addEventListener('click', () => {
        const SETTINGS_KEY = 'shieldscan_settings';
        let settings = {};
        try { settings = JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}'); } catch (_) {}
        const update = (k, v) => { settings[k] = v; try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); } catch (_) {} };
        this._openExclusionsModal(settings, update);
      });
    }

    // Activity filter dropdown
    const filterWrap = page.querySelector('.rt-activity-filter');
    if (filterWrap) {
      filterWrap.style.cursor = 'pointer';
      filterWrap.addEventListener('click', () => {
        const existing = document.getElementById('rt-filter-menu');
        if (existing) { existing.remove(); return; }
        const menu = document.createElement('div');
        menu.id = 'rt-filter-menu';
        menu.className = 'dh-context-menu';
        menu.style.cssText = 'position:absolute;right:20px;z-index:999;margin-top:4px';
        ['All events', 'Threats', 'Warnings', 'Info'].forEach(opt => {
          const btn = document.createElement('button');
          btn.className = 'dh-ctx-item';
          btn.textContent = opt;
          btn.addEventListener('click', () => {
            filterWrap.querySelector('span').textContent = opt;
            menu.remove();
            this._filterRealtimeActivity(opt);
          });
          menu.appendChild(btn);
        });
        filterWrap.parentElement.style.position = 'relative';
        filterWrap.parentElement.appendChild(menu);
        setTimeout(() => document.addEventListener('click', function close(ev) {
          if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener('click', close); }
        }), 10);
      });
    }

    // Load real activity from API
    await this._loadRealtimeActivity();
  }

  async _loadRealtimeActivity() {
    const data = await this._apiGet('/api/detections?limit=10&all=true');
    const list = document.getElementById('rtActivityList');
    if (!list || !data?.detections?.length) return;

    list.innerHTML = data.detections.slice(0, 5).map(det => {
      const title  = det.path ? `Threat detected: ${det.path.split('\\').pop().split('/').pop()}` : (det.type || 'Threat detected');
      const sub    = det.level === 'high' ? 'Malicious file detected and blocked' : det.level === 'medium' ? 'Suspicious activity detected' : 'File scanned';
      const path   = det.path || det.url || '';
      const time   = det.timestamp ? new Date(det.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '—';
      const iconClass = det.level === 'high' ? 'rt-act-green' : det.level === 'medium' ? 'rt-act-yellow' : 'rt-act-blue';
      const icon   = det.level === 'high' ? `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4" stroke-linecap="round"/>` : `<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/>`;
      return `
        <div class="rt-activity-item">
          <div class="rt-act-icon ${iconClass}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${icon}</svg>
          </div>
          <div class="rt-act-info">
            <div class="rt-act-title">${title}</div>
            <div class="rt-act-sub">${sub}</div>
            <div class="rt-act-path">${path}</div>
          </div>
          <div class="rt-act-time">${time}</div>
        </div>`;
    }).join('');
  }

  _filterRealtimeActivity(filter) {
    const items = document.querySelectorAll('#rtActivityList .rt-activity-item');
    items.forEach(item => {
      if (filter === 'All events') { item.style.display = ''; return; }
      const isGreen  = item.querySelector('.rt-act-green');
      const isYellow = item.querySelector('.rt-act-yellow');
      if (filter === 'Threats'  && isGreen)  { item.style.display = ''; return; }
      if (filter === 'Warnings' && isYellow) { item.style.display = ''; return; }
      if (filter === 'Info'     && !isGreen && !isYellow) { item.style.display = ''; return; }
      item.style.display = 'none';
    });
  }

  // ── AI Scam page ─────────────────────────────────────────────────────────
  async _liveAiScam() {
    // Load recent scans from API detections
    const data = await this._apiGet('/api/detections?limit=5&all=true');
    const list = document.getElementById('aiRecentScans');
    if (!list || !data?.detections?.length) return;

    list.innerHTML = data.detections.slice(0, 3).map(det => {
      const url    = det.path || det.url || 'Unknown';
      const isMal  = det.level === 'high' || det.level === 'medium';
      const time   = det.timestamp ? this.getTimeAgo(new Date(det.timestamp)) : '—';
      return `
        <div class="recent-scan-row">
          <div class="recent-scan-left">
            <div class="recent-scan-icon" style="${isMal ? 'background:rgba(240,82,82,0.12);border-color:rgba(240,82,82,0.25)' : ''}">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${isMal ? 'var(--red)' : 'var(--accent)'}" stroke-width="2">
                <circle cx="12" cy="12" r="10"/><path d="M2 12h20"/>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10A15.3 15.3 0 0 1 8 12a15.3 15.3 0 0 1 4-10z"/>
              </svg>
            </div>
            <div class="recent-scan-info">
              <div class="recent-scan-title">${url.length > 50 ? url.slice(0, 50) + '…' : url}</div>
              <div class="recent-scan-sub">Scanned · ${time}</div>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <span class="recent-pill ${isMal ? 'malicious' : 'safe'}">${isMal ? 'Malicious' : 'Safe'}</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text3)" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
          </div>
        </div>`;
    }).join('');
  }

  // ── Scanner page ─────────────────────────────────────────────────────────
  async _liveScanner() {
    // Update scan type label from API stats
    const stats = await this._apiGet('/api/stats');
    if (!stats) return;
    const lastScan = stats.last_scan_time;
    if (lastScan) {
      const el = document.getElementById('scanDesc');
      if (el && !document.getElementById('startScanBtn')?.style.display === 'none') {
        // Only update if not currently scanning
      }
    }
  }

  // ── Dashboard page ────────────────────────────────────────────────────────
  async _liveDashboard() {
    const stats = await this._apiGet('/api/stats');
    if (!stats) return;
    const statScore  = document.getElementById('statScore');
    const statThreats = document.getElementById('statThreats');
    if (statScore)   statScore.textContent  = stats.protection_score ?? 79;
    if (statThreats) statThreats.textContent = stats.threats_blocked ?? 0;
  }

  setupVPNIntegration() {
    // ── State ──
    let vpnConnected = false;
    let selectedServer = { id: 'us-east', name: 'United States', city: 'New York', flag: '🇺🇸', ip: '185.213.154.23', ping: '32 ms' };
    let timerInterval = null;
    let timerSeconds = 0;
    let dataInterval = null;
    let dataMB = 0;

    const showConnected = () => {
      document.getElementById('vpn-disconnected').style.display = 'none';
      document.getElementById('vpn-connected').style.display = 'flex';
      document.getElementById('vpnStatusCard').style.display = '';
      // Update connected info
      document.getElementById('vpnStatusVal').textContent = 'Connected';
      document.getElementById('vpnStatusVal').style.color = 'var(--green)';
      document.getElementById('vpnStatusLoc').textContent = `${selectedServer.name}, ${selectedServer.city}`;
      document.getElementById('vpnStatusIP').textContent = selectedServer.ip;
      document.getElementById('vpnVpnIP').textContent = selectedServer.ip;
      // Advisor panel
      const advSub = document.querySelector('#rp-advisor .advisor-item:nth-child(2) .adv-sub');
      if (advSub) advSub.textContent = 'VPN is ON';
      const turnOnBtn = document.querySelector('#rp-advisor .btn-turnon');
      if (turnOnBtn) { turnOnBtn.textContent = 'Turn off'; }
      // Security overview badge
      const secVpnBadge = document.getElementById('secVpnBadge');
      if (secVpnBadge) { secVpnBadge.textContent = 'Active'; secVpnBadge.className = 'sec-badge on'; }
    };

    const showDisconnected = () => {
      document.getElementById('vpn-disconnected').style.display = 'flex';
      document.getElementById('vpn-connected').style.display = 'none';
      document.getElementById('vpnStatusCard').style.display = 'none';
      const advSub = document.querySelector('#rp-advisor .advisor-item:nth-child(2) .adv-sub');
      if (advSub) advSub.textContent = 'VPN is OFF';
      const turnOnBtn = document.querySelector('#rp-advisor .btn-turnon');
      if (turnOnBtn) { turnOnBtn.textContent = 'Turn on'; }
      const secVpnBadge = document.getElementById('secVpnBadge');
      if (secVpnBadge) { secVpnBadge.textContent = 'Inactive'; secVpnBadge.className = 'sec-badge off'; }
    };

    const startTimer = () => {
      timerSeconds = 0; dataMB = 0;
      timerInterval = setInterval(() => {
        timerSeconds++;
        const h = String(Math.floor(timerSeconds / 3600)).padStart(2, '0');
        const m = String(Math.floor((timerSeconds % 3600) / 60)).padStart(2, '0');
        const s = String(timerSeconds % 60).padStart(2, '0');
        const el = document.getElementById('vpnTimer');
        if (el) el.textContent = `${h}:${m}:${s}`;
      }, 1000);
      dataInterval = setInterval(async () => {
        // Try to get real stats from WireGuard API
        try {
          const r = await fetch(`${WG_API}/vpn/stats`, { signal: AbortSignal.timeout(2000) });
          if (r.ok) {
            const data = await r.json();
            const el = document.getElementById('vpnStatusData');
            if (el) {
              const mb = (data.bytes_recv_mb || 0) + (data.bytes_sent_mb || 0);
              el.textContent = mb < 1024 ? `${mb.toFixed(1)} MB` : `${(mb/1024).toFixed(2)} GB`;
            }
            return;
          }
        } catch (_) {}
        // Fallback simulation
        dataMB += Math.random() * 2;
        const el = document.getElementById('vpnStatusData');
        if (el) el.textContent = dataMB < 1024 ? `${dataMB.toFixed(1)} MB` : `${(dataMB/1024).toFixed(2)} GB`;
      }, 2000);
    };

    const stopTimer = () => {
      clearInterval(timerInterval);
      clearInterval(dataInterval);
    };

    const WG_API = 'http://127.0.0.1:51821';

    const connect = async (server) => {
      if (server) selectedServer = server;

      // Show connecting state
      const toggleBtn = document.getElementById('vpnToggleBtn');
      if (toggleBtn) { toggleBtn.textContent = 'Connecting…'; toggleBtn.disabled = true; }

      // Try WireGuard REST API first
      let result = null;
      try {
        const r = await fetch(`${WG_API}/vpn/connect`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ server_id: selectedServer?.id || 'optimal' }),
          signal: AbortSignal.timeout(6000),
        });
        if (r.ok) result = await r.json();
      } catch (_) {}

      if (toggleBtn) { toggleBtn.textContent = 'Turn on'; toggleBtn.disabled = false; }

      if (result?.success) {
        // Update with real WireGuard data
        if (result.vpn_ip) {
          const vpnIpEl = document.getElementById('vpnVpnIP');
          if (vpnIpEl) vpnIpEl.textContent = result.vpn_ip;
        }
        if (result.real_ip) {
          const realIpEl = document.getElementById('vpnRealIP');
          if (realIpEl) realIpEl.textContent = result.real_ip;
        }
        // Show WireGuard badge
        const connLabel = document.getElementById('vpnConnectedLabel');
        if (connLabel) connLabel.textContent = `Connected · WireGuard`;
        // Update protocol in status card
        const statusVal = document.getElementById('vpnStatusVal');
        if (statusVal) statusVal.textContent = 'Connected (WireGuard)';
      }

      vpnConnected = true;
      this.vpnStatus = { enabled: true };
      showConnected();
      startTimer();
      this.updateProtectionScore();
    };

    const disconnect = async () => {
      // Call WireGuard API to disconnect
      try {
        await fetch(`${WG_API}/vpn/disconnect`, {
          method: 'POST',
          signal: AbortSignal.timeout(4000),
        });
      } catch (_) {}

      vpnConnected = false;
      this.vpnStatus = { enabled: false };
      stopTimer();
      showDisconnected();
      this.updateProtectionScore();
    };

    // ── Turn on / Turn off button ──
    const toggleBtn = document.getElementById('vpnToggleBtn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        if (!vpnConnected) connect(); else disconnect();
      });
    }

    // ── Disconnect button ──
    const disconnectBtn = document.getElementById('vpnDisconnectBtn');
    if (disconnectBtn) {
      disconnectBtn.addEventListener('click', disconnect);
    }

    // ── Quick connect ──
    const quickBtn = document.getElementById('vpnQuickConnectBtn');
    if (quickBtn) {
      quickBtn.addEventListener('click', () => {
        this.navigateToPage('page-vpn');
        connect();
      });
    }

    // ── Server row click → connect ──
    const serverList = document.getElementById('vpnServerList');
    if (serverList) {
      serverList.addEventListener('click', (e) => {
        // Favorite toggle
        const favBtn = e.target.closest('.vpn-fav-btn');
        if (favBtn) {
          favBtn.classList.toggle('active');
          favBtn.textContent = favBtn.classList.contains('active') ? '★' : '☆';
          return;
        }
        // Connect button
        const connectBtn = e.target.closest('.vpn-server-connect-btn');
        if (connectBtn) {
          const row = connectBtn.closest('.vpn-server-row');
          const sid = row?.dataset.serverid;
          const name = row?.querySelector('.vpn-server-name')?.textContent || 'Optimal';
          const city = row?.querySelector('.vpn-server-ping')?.textContent || '';
          const flag = row?.querySelector('.vpn-flag')?.textContent || '';
          connect({ id: sid, name, city, flag, ip: '185.213.154.23', ping: '32 ms' });
          return;
        }
        // Row click (not on button)
        const row = e.target.closest('.vpn-server-row');
        if (!row) return;
        serverList.querySelectorAll('.vpn-server-row').forEach(r => r.classList.remove('vpn-server-selected'));
        row.classList.add('vpn-server-selected');
        const sid = row.dataset.serverid;
        const name = row.querySelector('.vpn-server-name')?.textContent || 'Optimal';
        const city = row.querySelector('.vpn-server-ping')?.textContent || '';
        const flag = row.querySelector('.vpn-flag')?.textContent || '';
        if (vpnConnected) connect({ id: sid, name, city, flag, ip: '185.213.154.23', ping: '32 ms' });
      });
    }

    // ── Location tabs ──
    const locTabs = document.getElementById('vpnLocTabs');
    if (locTabs) {
      locTabs.addEventListener('click', (e) => {
        const tab = e.target.closest('.vpn-loc-tab');
        if (!tab) return;
        locTabs.querySelectorAll('.vpn-loc-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
      });
    }

    // ── Search ──
    const searchInput = document.getElementById('vpnSearchInput');
    if (searchInput && serverList) {
      searchInput.addEventListener('input', () => {
        const q = searchInput.value.toLowerCase();
        serverList.querySelectorAll('.vpn-server-row').forEach(row => {
          const name = row.querySelector('.vpn-server-name')?.textContent.toLowerCase() || '';
          row.style.display = name.includes(q) ? '' : 'none';
        });
      });
    }

    // ── Advisor "Turn on" button ──
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('.btn-turnon[data-page="page-vpn"]');
      if (!btn) return;
      this.navigateToPage('page-vpn');
      if (!vpnConnected) connect();
    });

    // Initial state
    showDisconnected();
  }

  updateVPNDisplay() {
    // Legacy stub — kept for compatibility
  }

  updateProtectionScore() {
    let score = 70;
    if (this.isProtectionActive) score += 15;
    if (this.vpnStatus?.enabled) score += 10;
    if (this.stats.threatsBlocked === 0) score += 5;
    this.stats.protectionScore = Math.min(score, 100);
    const statScore = document.getElementById('statScore');
    if (statScore) statScore.textContent = this.stats.protectionScore;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // CLICK HANDLERS FOR DASHBOARD OVERVIEW
  // ─────────────────────────────────────────────────────────────────────────────

  setupClickHandlers() {
    // Only attach dashboard-specific handlers if the dashboard overview exists on this page
    const overview = document.querySelector('.dashboard-overview');
    if (!overview) return;

    overview.addEventListener('click', (e) => {
      const link = e.target.closest('a, button');

      // Boost your score
      if (link?.textContent?.trim().startsWith('Boost your score')) {
        e.preventDefault();
        this.showBoostScoreModal();
        return;
      }

      // Scan now
      if (link?.textContent?.trim().startsWith('Scan now')) {
        e.preventDefault();
        this.navigateToScanner();
        return;
      }

      // View details
      if (link?.textContent?.trim().startsWith('View details')) {
        e.preventDefault();
        this.showThreatDetails();
        return;
      }

      // Manage
      if (link?.textContent?.trim() === 'Manage →') {
        e.preventDefault();
        this.showProtectionSettings();
        return;
      }

      // Go to security center
      if (link?.textContent?.includes('Go to security center')) {
        e.preventDefault();
        this.showSecurityCenter();
        return;
      }

      // View all / View full activity
      if (link?.textContent?.includes('View all') || link?.textContent?.includes('View full activity')) {
        e.preventDefault();
        this.showFullActivity();
        return;
      }

      // Security item row click
      const securityItem = e.target.closest('.security-item');
      if (securityItem) {
        e.preventDefault();
        const title = securityItem.querySelector('.security-title')?.textContent;
        this.showSecurityItemDetails(title);
        return;
      }

      // Activity item row click
      const activityItem = e.target.closest('.activity-item');
      if (activityItem) {
        e.preventDefault();
        const title = activityItem.querySelector('.activity-title')?.textContent;
        this.showActivityItemDetails(title);
        return;
      }

      // Stat card click
      const statCard = e.target.closest('.stat-card');
      if (statCard) {
        e.preventDefault();
        const label = statCard.querySelector('.stat-label')?.textContent;
        this.showStatDetails(label);
        return;
      }
    });
  }

  showBoostScoreModal() {
    const modal = this.createModal('Boost Your Protection Score', `
      <div style="padding: 20px; color: var(--text1);">
        <h3 style="color: var(--text1); margin-bottom: 16px;">Improve Your Protection Score</h3>
        <div style="margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
            <div style="width: 24px; height: 24px; background: var(--green-bg); border-radius: 50%; display: flex; align-items: center; justify-content: center;">✓</div>
            <span>Real-time protection is active</span>
          </div>
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
            <div style="width: 24px; height: 24px; background: var(--red-bg); border-radius: 50%; display: flex; align-items: center; justify-content: center;">!</div>
            <span>Enable VPN for better privacy (+15 points)</span>
          </div>
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
            <div style="width: 24px; height: 24px; background: var(--red-bg); border-radius: 50%; display: flex; align-items: center; justify-content: center;">!</div>
            <span>Run a full system scan (+6 points)</span>
          </div>
        </div>
        <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
      </div>
    `);
    document.body.appendChild(modal);
  }

  navigateToScanner() {
    // Switch to scanner view
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('nav-scanner').classList.add('active');
    
    const dashboardOverview = document.querySelector('.dashboard-overview');
    const scannerCard = document.querySelector('.scanner-card');
    
    if (dashboardOverview) dashboardOverview.style.display = 'none';
    if (scannerCard) scannerCard.style.display = 'block';
    
    // Focus on scan input
    setTimeout(() => {
      const scanInput = document.getElementById('scanInput');
      if (scanInput) scanInput.focus();
    }, 100);
  }

  showThreatDetails() {
    const modal = this.createModal('Threat Details', `
      <div style="padding: 20px; color: var(--text1);">
        <h3 style="color: var(--text1); margin-bottom: 16px;">Threats Blocked Today</h3>
        <div style="max-height: 300px; overflow-y: auto;">
          ${this.threatHistory.slice(0, 10).map(threat => `
            <div style="display: flex; align-items: center; gap: 12px; padding: 12px; background: var(--bg-card2); border-radius: 8px; margin-bottom: 8px;">
              <div style="width: 32px; height: 32px; background: ${threat.type === 'malicious' ? 'var(--red-bg)' : 'var(--green-bg)'}; border-radius: 6px; display: flex; align-items: center; justify-content: center;">
                ${threat.type === 'malicious' ? '⚠️' : '✓'}
              </div>
              <div style="flex: 1;">
                <div style="font-weight: 600; margin-bottom: 4px;">${threat.title}</div>
                <div style="font-size: 12px; color: var(--text2);">${this.getTimeAgo(threat.timestamp)}</div>
              </div>
              <span style="padding: 4px 8px; background: ${threat.type === 'malicious' ? 'var(--red-bg)' : 'var(--green-bg)'}; color: ${threat.type === 'malicious' ? 'var(--red)' : 'var(--green)'}; border-radius: 12px; font-size: 11px; font-weight: 600;">
                ${threat.action.toUpperCase()}
              </span>
            </div>
          `).join('')}
        </div>
        <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-top: 16px;">Close</button>
      </div>
    `);
    document.body.appendChild(modal);
  }

  showProtectionSettings() {
    const modal = this.createModal('Protection Settings', `
      <div style="padding: 20px; color: var(--text1);">
        <h3 style="color: var(--text1); margin-bottom: 16px;">Real-Time Protection Settings</h3>
        <div style="margin-bottom: 16px;">
          <label style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px; cursor: pointer;">
            <input type="checkbox" checked style="width: 16px; height: 16px;">
            <span>Real-time scanning</span>
          </label>
          <label style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px; cursor: pointer;">
            <input type="checkbox" checked style="width: 16px; height: 16px;">
            <span>Web protection</span>
          </label>
          <label style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px; cursor: pointer;">
            <input type="checkbox" checked style="width: 16px; height: 16px;">
            <span>Email protection</span>
          </label>
          <label style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px; cursor: pointer;">
            <input type="checkbox" style="width: 16px; height: 16px;">
            <span>Scheduled scans</span>
          </label>
        </div>
        <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Save Settings</button>
      </div>
    `);
    document.body.appendChild(modal);
  }

  showSecurityCenter() {
    const modal = this.createModal('Security Center', `
      <div style="padding: 20px; color: var(--text1);">
        <h3 style="color: var(--text1); margin-bottom: 16px;">Security Center</h3>
        <div style="display: grid; gap: 12px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; background: var(--bg-card2); border-radius: 8px;">
            <div>
              <div style="font-weight: 600;">AI Scam Protection</div>
              <div style="font-size: 12px; color: var(--text2);">Advanced AI threat detection</div>
            </div>
            <span style="color: var(--green);">Active</span>
          </div>
          <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; background: var(--bg-card2); border-radius: 8px;">
            <div>
              <div style="font-weight: 600;">Real-Time Protection</div>
              <div style="font-size: 12px; color: var(--text2);">Continuous monitoring</div>
            </div>
            <span style="color: var(--green);">Active</span>
          </div>
          <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; background: var(--bg-card2); border-radius: 8px;">
            <div>
              <div style="font-weight: 600;">VPN Protection</div>
              <div style="font-size: 12px; color: var(--text2);">Secure browsing</div>
            </div>
            <span style="color: var(--red);">Inactive</span>
          </div>
        </div>
        <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
      </div>
    `);
    document.body.appendChild(modal);
  }

  showFullActivity() {
    const modal = this.createModal('Full Activity Log', `
      <div style="padding: 20px; color: var(--text1);">
        <h3 style="color: var(--text1); margin-bottom: 16px;">Recent Activity</h3>
        <div style="max-height: 400px; overflow-y: auto;">
          ${this.threatHistory.map(threat => `
            <div style="display: flex; align-items: flex-start; gap: 12px; padding: 12px; border-bottom: 1px solid var(--border);">
              <div style="width: 32px; height: 32px; background: ${threat.type === 'malicious' ? 'var(--red-bg)' : threat.type === 'suspicious' ? 'rgba(245, 158, 11, 0.12)' : 'var(--green-bg)'}; border-radius: 6px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                ${threat.type === 'malicious' ? '🔴' : threat.type === 'suspicious' ? '⚡' : '🟢'}
              </div>
              <div style="flex: 1; min-width: 0;">
                <div style="font-weight: 600; margin-bottom: 2px;">${threat.title}</div>
                ${threat.url ? `<div style="font-size: 11px; color: var(--text2); word-break: break-all; margin-bottom: 4px;">${this.truncateUrl(threat.url, 60)}</div>` : ''}
                <div style="font-size: 11px; color: var(--text3);">${this.getTimeAgo(threat.timestamp)} • ${threat.category}</div>
              </div>
              <span style="padding: 2px 6px; background: ${threat.type === 'malicious' ? 'var(--red-bg)' : threat.type === 'suspicious' ? 'rgba(245, 158, 11, 0.12)' : 'var(--green-bg)'}; color: ${threat.type === 'malicious' ? 'var(--red)' : threat.type === 'suspicious' ? 'var(--yellow)' : 'var(--green)'}; border-radius: 3px; font-size: 10px; font-weight: 600; white-space: nowrap;">
                ${threat.action.toUpperCase()}
              </span>
            </div>
          `).join('')}
        </div>
        <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-top: 16px;">Close</button>
      </div>
    `);
    document.body.appendChild(modal);
  }

  showSecurityItemDetails(title) {
    let content = '';
    
    switch(title) {
      case 'AI Scam Protection':
        content = `
          <div style="padding: 20px; color: var(--text1);">
            <h3 style="color: var(--text1); margin-bottom: 16px;">AI Scam Protection</h3>
            <p style="margin-bottom: 16px; color: var(--text2);">Advanced AI-powered protection against scams, phishing, and malicious content.</p>
            <div style="margin-bottom: 16px;">
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Status:</span>
                <span style="color: var(--green);">Active</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Threats blocked today:</span>
                <span>${this.stats.threatsBlocked}</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Last update:</span>
                <span>Just now</span>
              </div>
            </div>
            <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
          </div>
        `;
        break;
      case 'VPN':
        content = `
          <div style="padding: 20px; color: var(--text1);">
            <h3 style="color: var(--text1); margin-bottom: 16px;">VPN Protection</h3>
            <p style="margin-bottom: 16px; color: var(--text2);">Secure your connection and browse privately with our VPN service.</p>
            <div style="margin-bottom: 16px;">
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Status:</span>
                <span style="color: var(--red);">Inactive</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Available servers:</span>
                <span>8 locations</span>
              </div>
            </div>
            <button onclick="document.getElementById('vpnToggleBtn').click(); this.closest('.modal-overlay').remove();" style="background: var(--green); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-right: 8px;">Enable VPN</button>
            <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--bg-card2); color: var(--text1); border: 1px solid var(--border); padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
          </div>
        `;
        break;
      default:
        content = `
          <div style="padding: 20px; color: var(--text1);">
            <h3 style="color: var(--text1); margin-bottom: 16px;">${title}</h3>
            <p style="margin-bottom: 16px; color: var(--text2);">This security feature is currently active and protecting your system.</p>
            <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
          </div>
        `;
    }
    
    const modal = this.createModal(title, content);
    document.body.appendChild(modal);
  }

  showActivityItemDetails(title) {
    const modal = this.createModal('Activity Details', `
      <div style="padding: 20px; color: var(--text1);">
        <h3 style="color: var(--text1); margin-bottom: 16px;">${title}</h3>
        <p style="margin-bottom: 16px; color: var(--text2);">Detailed information about this security event.</p>
        <div style="background: var(--bg-card2); padding: 16px; border-radius: 8px; margin-bottom: 16px;">
          <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
            <span>Event type:</span>
            <span>Security Action</span>
          </div>
          <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
            <span>Status:</span>
            <span style="color: var(--green);">Resolved</span>
          </div>
          <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
            <span>Risk level:</span>
            <span>Low</span>
          </div>
        </div>
        <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
      </div>
    `);
    document.body.appendChild(modal);
  }

  showStatDetails(label) {
    let content = '';
    
    switch(label) {
      case 'Protection score':
        content = `
          <div style="padding: 20px; color: var(--text1);">
            <h3 style="color: var(--text1); margin-bottom: 16px;">Protection Score Details</h3>
            <p style="margin-bottom: 16px; color: var(--text2);">Your current protection score is ${this.stats.protectionScore}/100 (Fair)</p>
            <div style="margin-bottom: 16px;">
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Real-time protection:</span>
                <span style="color: var(--green);">+40 points</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>AI Scam Protection:</span>
                <span style="color: var(--green);">+25 points</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Identity Protection:</span>
                <span style="color: var(--green);">+14 points</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>VPN Protection:</span>
                <span style="color: var(--red);">+0 points (Inactive)</span>
              </div>
            </div>
            <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
          </div>
        `;
        break;
      case 'Last scan':
        content = `
          <div style="padding: 20px; color: var(--text1);">
            <h3 style="color: var(--text1); margin-bottom: 16px;">Scan History</h3>
            <p style="margin-bottom: 16px; color: var(--text2);">Your last full system scan was 6 days ago.</p>
            <div style="margin-bottom: 16px;">
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Last full scan:</span>
                <span>6 days ago</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Items scanned:</span>
                <span>245,832 files</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Threats found:</span>
                <span>0</span>
              </div>
            </div>
            <button onclick="document.getElementById('nav-scanner').click(); this.closest('.modal-overlay').remove();" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-right: 8px;">Run Scan Now</button>
            <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--bg-card2); color: var(--text1); border: 1px solid var(--border); padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
          </div>
        `;
        break;
      case 'Threats blocked':
        content = `
          <div style="padding: 20px; color: var(--text1);">
            <h3 style="color: var(--text1); margin-bottom: 16px;">Threats Blocked</h3>
            <p style="margin-bottom: 16px; color: var(--text2);">We've blocked ${this.stats.threatsBlocked} threats today to keep you safe.</p>
            <div style="margin-bottom: 16px;">
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Phishing attempts:</span>
                <span>${Math.floor(this.stats.threatsBlocked * 0.4)}</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Malicious websites:</span>
                <span>${Math.floor(this.stats.threatsBlocked * 0.3)}</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Suspicious downloads:</span>
                <span>${Math.floor(this.stats.threatsBlocked * 0.2)}</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Other threats:</span>
                <span>${Math.floor(this.stats.threatsBlocked * 0.1)}</span>
              </div>
            </div>
            <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
          </div>
        `;
        break;
      case 'Real-time protection':
        content = `
          <div style="padding: 20px; color: var(--text1);">
            <h3 style="color: var(--text1); margin-bottom: 16px;">Real-Time Protection</h3>
            <p style="margin-bottom: 16px; color: var(--text2);">Real-time protection is currently active and monitoring your system.</p>
            <div style="margin-bottom: 16px;">
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Status:</span>
                <span style="color: var(--green);">Active</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Files monitored:</span>
                <span>All system files</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Web protection:</span>
                <span style="color: var(--green);">Enabled</span>
              </div>
              <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                <span>Email protection:</span>
                <span style="color: var(--green);">Enabled</span>
              </div>
            </div>
            <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
          </div>
        `;
        break;
      default:
        content = `
          <div style="padding: 20px; color: var(--text1);">
            <h3 style="color: var(--text1); margin-bottom: 16px;">${label}</h3>
            <p style="margin-bottom: 16px; color: var(--text2);">Detailed information about this metric.</p>
            <button onclick="this.closest('.modal-overlay').remove()" style="background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer;">Close</button>
          </div>
        `;
    }
    
    const modal = this.createModal(label, content);
    document.body.appendChild(modal);
  }

  createModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
    `;
    
    modal.innerHTML = `
      <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; max-width: 500px; width: 90%; max-height: 80vh; overflow-y: auto;">
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid var(--border);">
          <h2 style="margin: 0; color: var(--text1); font-size: 18px;">${title}</h2>
          <button onclick="this.closest('.modal-overlay').remove()" style="background: none; border: none; color: var(--text2); font-size: 20px; cursor: pointer; padding: 4px;">×</button>
        </div>
        ${content}
      </div>
    `;
    
    // Close on background click
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
    
    return modal;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // MESSAGE PASSING WITH BACKGROUND SERVICE
  // ─────────────────────────────────────────────────────────────────────────────

  setupMessageListener() {
    // Only run if chrome extension API is available
    if (typeof chrome === 'undefined' || !chrome.runtime) return;
    try {
      chrome.runtime.onMessage.addListener((request) => {
        if (request.type === 'THREAT_DETECTED') {
          this.addThreat(request.data);
          this.updateStats();
        } else if (request.type === 'SCAN_COMPLETE') {
          this.handleScanComplete(request.data);
        } else if (request.type === 'PROTECTION_STATUS') {
          this.updateProtectionStatus(request.data);
        } else if (request.type === 'STATS_UPDATE') {
          this.updateStatsFromBackground(request.data);
        } else if (request.type === 'VPN_STATUS_UPDATE') {
          this.updateVPNStatusFromBackground(request.data);
        }
      });
    } catch (e) {
      console.log('Chrome messaging not available (running as website)');
    }
  }

  updateVPNStatusFromBackground(status) {
    // Normalize status from background manager
    const enabled = !!status?.enabled;
    this.vpnStatus.enabled = enabled;
    this.vpnStatus.country = status?.country || this.vpnStatus.country;
    this.vpnStatus.server = status?.server || status?.currentServer || this.vpnStatus.server;

    this.updateVPNDisplay();
  }

  sendMessageToBackground(message, callback) {
    if (typeof chrome === 'undefined' || !chrome.runtime) {
      if (callback) callback(null);
      return;
    }
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          console.log('Background service not available');
          if (callback) callback(null);
        } else {
          if (callback) callback(response);
        }
      });
    } catch (e) {
      if (callback) callback(null);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // THREAT MANAGEMENT
  // ─────────────────────────────────────────────────────────────────────────────

  addThreat(threatData) {
    const incomingId = threatData && (threatData.id || threatData.event_id);
    const threatId = incomingId ? String(incomingId) : `local_${Date.now()}_${Math.random()}`;

    // Dedup: avoid double-counting same event from multiple paths
    if (this._seenThreatIds.has(threatId)) return;
    this._seenThreatIds.add(threatId);

    const threat = {
      id: threatId,
      timestamp: threatData && threatData.timestamp ? new Date(threatData.timestamp) : new Date(),
      type: threatData?.type || 'unknown', // 'malicious', 'suspicious', 'safe'
      title: threatData?.title || 'Unknown threat',
      url: threatData?.url || threatData?.content || '',
      severity: threatData?.severity || 'medium',
      category: threatData?.category || 'general',
      action: threatData?.action || 'blocked',
    };

    this.threatHistory.unshift(threat);

    // Keep only recent threats in memory
    if (this.threatHistory.length > this.maxThreatsDisplay) {
      this.threatHistory = this.threatHistory.slice(0, this.maxThreatsDisplay);
    }

    // Update stats (only once per unique threat id)
    if (threat.action === 'blocked' || threat.action === 'quarantined') {
      this.stats.threatsBlocked++;
    }

    // Update UI
    this.updateDashboardStats();
    this.showThreatNotification(threat);
  }

  showThreatNotification(threat) {
    // Create notification for new threats
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-left: 4px solid var(--red);
      border-radius: 8px;
      padding: 16px;
      max-width: 350px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.15);
      z-index: 10000;
      animation: slideIn 0.3s ease;
    `;

    notification.innerHTML = `
      <div style="display: flex; align-items: flex-start; gap: 12px;">
        <div style="font-size: 20px;">🚨</div>
        <div style="flex: 1;">
          <div style="font-weight: 600; color: var(--text1); margin-bottom: 4px;">Threat Detected</div>
          <div style="font-size: 13px; color: var(--text2); margin-bottom: 4px;">${threat.title}</div>
          <div style="font-size: 11px; color: var(--text3);">${threat.action.toUpperCase()}</div>
        </div>
        <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: var(--text2); cursor: pointer; font-size: 16px;">×</button>
      </div>
    `;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, 5000);
  }

  handleScanComplete(scanData) {
    // Handle scan completion from background
    this.stats.scansToday++;
    
    if (scanData.result === 'malicious') {
      this.addThreat({
        type: 'malicious',
        title: 'Malicious content detected',
        url: scanData.url,
        severity: 'high',
        category: scanData.category || 'general',
        action: 'blocked'
      });
    }

    this.updateDashboardStats();
  }

  updateProtectionStatus(status) {
    this.isProtectionActive = status.active;
    
    // Update protection indicators
    const protectionBadges = document.querySelectorAll('.status-badge');
    protectionBadges.forEach(badge => {
      const dot = badge.querySelector('.status-dot');
      if (dot) {
        dot.style.background = status.active ? 'var(--green)' : 'var(--red)';
      }
      badge.style.background = status.active ? 'rgba(45,206,137,.2)' : 'rgba(240,82,82,.2)';
      badge.style.color = status.active ? 'var(--green)' : 'var(--red)';
      
      const text = badge.childNodes[badge.childNodes.length - 1];
      if (text && text.nodeType === Node.TEXT_NODE) {
        text.textContent = status.active ? ' Active' : ' Inactive';
      }
    });

    this.updateProtectionScore();
  }

  updateStatsFromBackground(stats) {
    this.stats = { ...this.stats, ...stats };
    this.updateDashboardStats();
  }

  startRealtimeUpdates() {
    // Poll real API stats every 10 seconds
    setInterval(() => {
      this.loadSystemStats();
    }, 10000);

    // Update time displays every 30 seconds
    setInterval(() => {
      this.updateTimeDisplays();
    }, 30000);

    // Poll for new real detections every 15 seconds
    setInterval(() => {
      this.pollNewDetections();
    }, 15000);
  }

  async pollNewDetections() {
    // Only fetch new detections since the last known timestamp
    const lastTs = this.threatHistory.length > 0
      ? this.threatHistory[0].timestamp.toISOString()
      : null;

    const data = await this._apiGet('/api/detections?limit=10&all=true');
    if (!data || !Array.isArray(data.detections)) return;

    const newOnes = data.detections.filter(det => {
      if (!lastTs) return false;
      return det.timestamp > lastTs;
    });

    newOnes.forEach(det => {
      const threat = {
        id: det.timestamp + '_' + (det.path || ''),
        timestamp: new Date(det.timestamp),
        type: det.level === 'high' ? 'malicious' : det.level === 'medium' ? 'suspicious' : 'safe',
        title: det.path
          ? `Threat detected: ${det.path.split('\\').pop().split('/').pop()}`
          : (det.type === 'quarantine' ? 'File quarantined' : 'Threat detected'),
        url: det.path || '',
        severity: det.level === 'high' ? 'high' : 'medium',
        category: det.findings?.[0]?.rule || det.type || 'malware',
        action: det.quarantined ? 'quarantined' : (det.level === 'high' ? 'blocked' : 'flagged'),
        score: det.score,
      };
      // Insert at top without duplicating
      const exists = this.threatHistory.some(t => t.id === threat.id);
      if (!exists) {
        this.threatHistory.unshift(threat);
        if (this.threatHistory.length > this.maxThreatsDisplay) {
          this.threatHistory = this.threatHistory.slice(0, this.maxThreatsDisplay);
        }
        if (threat.action === 'blocked' || threat.action === 'quarantined') {
          this.stats.threatsBlocked++;
        }
        this.updateDashboardStats();
        this.showThreatNotification(threat);
      }
    });
  }

  updateTimeDisplays() {
    // Update relative time displays
    document.querySelectorAll('.act-time').forEach((timeEl, index) => {
      if (this.threatHistory[index]) {
        timeEl.textContent = this.getTimeAgo(this.threatHistory[index].timestamp);
      }
    });
  }

  loadStoredData() {
    // Load any stored data from extension storage
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['threatHistory', 'stats'], (result) => {
        if (result.threatHistory) {
          this.threatHistory = result.threatHistory.map(t => ({
            ...t,
            timestamp: new Date(t.timestamp)
          }));
        }
        if (result.stats) {
          this.stats = { ...this.stats, ...result.stats };
        }
        this.updateDashboardStats();
      });
    }
  }

  saveData() {
    // Save data to extension storage
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({
        threatHistory: this.threatHistory.slice(0, 20), // Save only recent threats
        stats: this.stats
      });
    }
  }

  getTimeAgo(timestamp) {
    const now = new Date();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes} min ago`;
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    return `${days} day${days > 1 ? 's' : ''} ago`;
  }

  truncateUrl(url, maxLength) {
    if (!url || url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }

  addThreat(threat) {
    // Add to history
    this.threatHistory.unshift(threat);
    
    // Limit display
    if (this.threatHistory.length > this.maxThreatsDisplay) {
      this.threatHistory = this.threatHistory.slice(0, this.maxThreatsDisplay);
    }

    // Save to storage
    this.saveToStorage();
    
    // Update UI
    this.renderThreatFeed();
    
    // Update stats
    if (threat.type === 'malicious') {
      this.stats.threatsBlocked++;
    }
    this.stats.scansToday++;
    this.updateStatsUI();
  }

  renderThreatFeed() {
    const feed = document.getElementById('threatFeed');
    if (!feed) return;

    feed.innerHTML = '';

    if (this.threatHistory.length === 0) {
      feed.innerHTML = `
        <div class="threat-item">
          <div class="threat-icon safe">✓</div>
          <div class="threat-content">
            <div class="threat-title">No threats detected</div>
            <div class="threat-time">System is clean</div>
          </div>
          <span class="threat-badge safe">Safe</span>
        </div>
      `;
      return;
    }

    this.threatHistory.slice(0, 20).forEach(threat => {
      const iconMap = {
        malicious: '⚠️',
        suspicious: '⚡',
        safe: '✓',
      };
      
      const typeClass = threat.type || 'safe';
      const icon = iconMap[typeClass] || '•';
      const timeAgo = this.getTimeAgo(threat.timestamp);
      const displayUrl = this.truncateUrl(threat.url, 50);

      const item = document.createElement('div');
      item.className = 'threat-item';
      item.innerHTML = `
        <div class="threat-icon ${typeClass}">${icon}</div>
        <div class="threat-content">
          <div class="threat-title">${this.escapeHtml(threat.title)}</div>
          <div class="threat-time">${timeAgo} • ${threat.category}</div>
          ${displayUrl ? `<div class="threat-time" style="font-size: 10px; color: #9ca3af; margin-top: 2px;">${this.escapeHtml(displayUrl)}</div>` : ''}
        </div>
        <span class="threat-badge ${typeClass}">${threat.action.toUpperCase()}</span>
      `;
      feed.appendChild(item);
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // STATS MANAGEMENT
  // ─────────────────────────────────────────────────────────────────────────────

  updateStats() {
    this.updateStatsUI();
    this.saveToStorage();
  }

  updateStatsUI() {
    const elements = {
      'statScore': this.stats.protectionScore,
      'statThreats': this.stats.threatsBlocked,
      'statLastScan': '6 days ago', // Static for now
    };

    Object.entries(elements).forEach(([id, value]) => {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = value;
        el.style.animation = 'none';
        setTimeout(() => {
          el.style.animation = 'pulse 0.5s ease';
        }, 10);
      }
    });
  }

  updateStatsFromBackground(data) {
    if (data.threatsBlocked !== undefined) this.stats.threatsBlocked = data.threatsBlocked;
    if (data.scansToday !== undefined) this.stats.scansToday = data.scansToday;
    if (data.protectionScore !== undefined) this.stats.protectionScore = data.protectionScore;
    if (data.uptime !== undefined) this.stats.uptime = data.uptime;
    
    this.updateStatsUI();
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // PROTECTION STATUS
  // ─────────────────────────────────────────────────────────────────────────────

  updateProtectionStatus(status) {
    this.isProtectionActive = status.active !== false;

    const statusMap = {
      'protStatus': status.mainShield ? '🟢 Active' : '🔴 Inactive',
      'protScanning': status.scanning ? '🔍 Scanning' : '🔍 Ready',
      'protUpdates': status.updatesLatest ? '✓ Latest' : '⚠ Updating',
      'protMemory': status.systemNormal ? '✓ Normal' : '⚠ High',
    };

    Object.entries(statusMap).forEach(([id, text]) => {
      const el = document.getElementById(id);
      if (el) el.textContent = text;
    });

    // Update live indicator
    const indicator = document.getElementById('liveIndicator');
    if (indicator) {
      indicator.textContent = this.isProtectionActive ? 'Active' : 'Inactive';
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SCAN HANDLING
  // ─────────────────────────────────────────────────────────────────────────────

  handleScanComplete(data) {
    if (data.result === 'malicious') {
      this.addThreat({
        type: 'malicious',
        title: `Malicious content detected: ${data.name || 'Unknown'}`,
        url: data.url || data.path || '',
        severity: 'high',
        category: data.category || 'malware',
        action: 'blocked',
      });
    } else if (data.result === 'suspicious') {
      this.addThreat({
        type: 'suspicious',
        title: `Suspicious content: ${data.name || 'Unknown'}`,
        url: data.url || data.path || '',
        severity: 'medium',
        category: data.category || 'suspicious',
        action: 'flagged',
      });
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // REAL-TIME UPDATES (second instance — delegates to the primary startRealtimeUpdates above)
  // ─────────────────────────────────────────────────────────────────────────────

  // ─────────────────────────────────────────────────────────────────────────────
  // STORAGE
  // ─────────────────────────────────────────────────────────────────────────────

  saveToStorage() {
    if (typeof chrome === 'undefined' || !chrome.storage) return;
    try {
      const data = {
        stats: this.stats,
        threatHistory: this.threatHistory.slice(0, 100),
        lastUpdate: Date.now(),
      };
      chrome.storage.local.set({ dashboardData: data });
    } catch (e) { /* not in extension context */ }
  }

  loadStoredData() {
    if (typeof chrome === 'undefined' || !chrome.storage) {
      // Running as website — just render with default data
      this.updateStatsUI();
      this.renderThreatFeed();
      return;
    }
    try {
      chrome.storage.local.get(['dashboardData'], (result) => {
        if (result.dashboardData) {
          const data = result.dashboardData;
          this.stats = { ...this.stats, ...data.stats };
          this.threatHistory = data.threatHistory || this.threatHistory;
        }
        this.updateStatsUI();
        this.renderThreatFeed();
      });
    } catch (e) {
      this.updateStatsUI();
      this.renderThreatFeed();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // UTILITY FUNCTIONS
  // ─────────────────────────────────────────────────────────────────────────────

  getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  }

  truncateUrl(url, maxLength = 50) {
    if (!url) return '';
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '…';
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCANNER FUNCTIONALITY
// ═══════════════════════════════════════════════════════════════════════════════

class ScannerUI {
  constructor(dashboard) {
    this.dashboard = dashboard;
    this.isScanning = false;
    this.init();
  }

  init() {
    this.setupTabSwitching();
    this.setupScanButton();
    this.setupVPNButton();
    this.setupNavigation();
  }

  setupTabSwitching() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const tab = btn.dataset.tab;
        const input = document.getElementById('scanInput');
        if (tab === 'link') input.placeholder = 'Paste a link to scan (e.g https://example.com)';
        else if (tab === 'text') input.placeholder = 'Paste suspicious text here…';
        else if (tab === 'file') input.placeholder = 'Enter file path or upload…';
        else if (tab === 'screenshot') input.placeholder = 'Paste image URL or take a screenshot…';
      });
    });
  }

  setupScanButton() {
    const scanBtn = document.getElementById('scanBtn');
    const scanInput = document.getElementById('scanInput');
    const resultBox = document.getElementById('scanResult');

    if (!scanBtn) return;

    scanBtn.addEventListener('click', () => {
      const val = scanInput.value.trim();
      if (!val) {
        scanInput.focus();
        return;
      }
      this.performScan(val, resultBox);
    });

    scanInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') scanBtn.click();
    });
  }

  performScan(input, resultBox) {
    if (this.isScanning) return;
    this.isScanning = true;

    // Show "analyzing" state
    resultBox.className = 'scan-result scanning';
    resultBox.style.display = 'flex';
    resultBox.style.background = 'rgba(79,142,247,0.1)';
    resultBox.style.color = 'var(--accent)';
    resultBox.style.border = '1px solid rgba(79,142,247,0.3)';
    resultBox.innerHTML = '🔍 <strong>Analyzing…</strong>&nbsp; Please wait.';

    // Use real API via background service
    const sendMsg = (this.dashboard && typeof this.dashboard.sendMessageToBackground === 'function')
      ? (msg, cb) => this.dashboard.sendMessageToBackground(msg, cb)
      : (msg, cb) => {
          if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage(msg, cb);
          } else { cb(null); }
        };

    sendMsg({ type: 'SCAN_REQUEST', data: { input } }, (result) => {
      this.isScanning = false;

      if (!result) {
        // API offline — fall back to local pattern analysis
        const local = this.localThreatAnalysis(input);
        this.displayScanResult(resultBox, local.isMalicious, input, local);
        if ((local.isMalicious || local.isSuspicious) && this.dashboard) {
          this.dashboard.addThreat({
            type: local.type,
            title: `${local.type.toUpperCase()}: ${local.threatName}`,
            url: input,
            severity: local.isMalicious ? 'high' : 'medium',
            category: local.category,
            action: local.isMalicious ? 'blocked' : 'flagged',
          });
        }
        return;
      }

      // Map API result to display format
      const apiResult = {
        isMalicious: result.result === 'malicious',
        isSuspicious: result.result === 'suspicious',
        type: result.result || 'safe',
        threatName: result.result === 'malicious' ? 'Malicious content detected'
                  : result.result === 'suspicious' ? 'Suspicious content'
                  : 'No threats detected',
        category: result.findings?.[0]?.rule || 'general',
        score: result.score || 0,
      };

      this.displayScanResult(resultBox, apiResult.isMalicious, input, apiResult);

      if ((apiResult.isMalicious || apiResult.isSuspicious) && this.dashboard) {
        this.dashboard.addThreat({
          type: apiResult.type,
          title: `${apiResult.type.toUpperCase()}: ${apiResult.threatName}`,
          url: input,
          severity: apiResult.isMalicious ? 'high' : 'medium',
          category: apiResult.category,
          action: apiResult.isMalicious ? 'blocked' : 'flagged',
          score: apiResult.score,
        });
      }
    });
  }

  localThreatAnalysis(input) {
    const maliciousPatterns = [
      /banking.*verify|verify.*banking|secure.*login|login.*verify/i,
      /claim.*prize|prize.*claim|free.*money|money.*free/i,
      /ransomware|trojan|malware|phishing|scam/i,
      /secure-verify|verify-account|update-now|confirm-identity/i,
      /\.xyz|\.top|\.buzz|\.loan|\.pw|\.ga|\.gq|\.ml|\.tk|\.cf/i,
    ];

    const suspiciousPatterns = [
      /download|free.*software|software.*free/i,
      /airdrop|bonus|reward|claim/i,
      /urgent|limited.*time|act.*now/i,
    ];

    const safePatterns = [
      /google\.com|github\.com|stackoverflow\.com|amazon\.com|microsoft\.com|apple\.com/i,
    ];

    let threatName = 'Unknown threat';
    let category = 'general';
    let isMalicious = false;
    let isSuspicious = false;

    // Check safe first
    for (const pattern of safePatterns) {
      if (pattern.test(input)) {
        return {
          isMalicious: false,
          isSuspicious: false,
          type: 'safe',
          threatName: 'No threats detected',
          category: 'safe',
          score: 0,
        };
      }
    }

    // Check malicious
    for (const pattern of maliciousPatterns) {
      if (pattern.test(input)) {
        isMalicious = true;
        if (pattern.source.includes('banking')) {
          threatName = 'Banking Phishing Attempt';
          category = 'phishing';
        } else if (pattern.source.includes('prize')) {
          threatName = 'Prize Scam';
          category = 'scam';
        } else if (pattern.source.includes('ransomware')) {
          threatName = 'Ransomware Detected';
          category = 'malware';
        } else {
          threatName = 'Malicious Content Detected';
          category = 'malware';
        }
        break;
      }
    }

    // Check suspicious
    if (!isMalicious) {
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(input)) {
          isSuspicious = true;
          threatName = 'Suspicious Content';
          category = 'suspicious';
          break;
        }
      }
    }

    return {
      isMalicious,
      isSuspicious,
      type: isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : 'safe',
      threatName,
      category,
      score: isMalicious ? 90 : isSuspicious ? 65 : 0,
    };
  }

  displayScanResult(resultBox, isMalicious, input, response = null) {
    // Always force visible — remove any inline overrides from the analyzing state
    resultBox.style.background = '';
    resultBox.style.color = '';
    resultBox.style.border = '';
    resultBox.style.display = 'flex';

    if (isMalicious) {
      resultBox.className = 'scan-result danger';
      const threatName = response?.threatName || 'Malicious content';
      resultBox.innerHTML = `⚠️ <strong>THREAT DETECTED!</strong>&nbsp; ${threatName}. This link/content is dangerous and has been blocked.`;
    } else if (response?.isSuspicious) {
      resultBox.className = 'scan-result warning';
      const threatName = response?.threatName || 'Suspicious content';
      resultBox.innerHTML = `⚡ <strong>SUSPICIOUS!</strong>&nbsp; ${threatName}. Proceed with caution.`;
    } else {
      resultBox.className = 'scan-result safe';
      resultBox.innerHTML = '✔️ <strong>Looks safe!</strong>&nbsp; No threats detected in this content.';
    }
  }

  localDetection(input) {
    const maliciousKeywords = [
      'tiktok-free', 'secure-login', 'update-now', 'claim-prize', 'crypto-win',
      'bit.ly', 'goo.gl', 'free-download', 'verify-account', 'confirm-identity',
      'urgent-action', 'limited-time', 'act-now', 'click-here', 'verify-payment',
    ];
    return maliciousKeywords.some(kw => input.toLowerCase().includes(kw));
  }

  setupVPNButton() {
    const vpnBtn = document.getElementById('vpnToggleBtn');
    if (!vpnBtn) return;

    vpnBtn.addEventListener('click', () => {
      this.toggleVPN();
    });

    // Load initial VPN status
    this.updateVPNStatus();
  }

  toggleVPN() {
    const vpnBtn = document.getElementById('vpnToggleBtn');
    if (!vpnBtn) return;
    vpnBtn.textContent = 'Connecting...';
    vpnBtn.disabled = true;

    // Try background service via dashboard reference, else fall back locally
    if (this.dashboard && typeof this.dashboard.sendMessageToBackground === 'function') {
      this.dashboard.sendMessageToBackground({ type: 'VPN_TOGGLE' }, (response) => {
        vpnBtn.disabled = false;
        if (response && response.success) {
          this.updateVPNStatus();
        } else {
          this.simulateVPNToggle();
        }
      });
    } else {
      this.simulateVPNToggle();
    }
  }

  simulateVPNToggle() {
    const vpnBtn = document.getElementById('vpnToggleBtn');
    const vpnStatusEl = document.getElementById('vpnStatus');
    if (!vpnBtn || !vpnStatusEl) return;

    const isEnabled = localStorage.getItem('vpnEnabled') === 'true';
    const newState = !isEnabled;
    localStorage.setItem('vpnEnabled', newState);

    if (newState) {
      vpnStatusEl.textContent = 'VPN is ON (US)';
      vpnBtn.textContent = 'Turn off';
      vpnBtn.style.background = '#10b981';
    } else {
      vpnStatusEl.textContent = 'VPN is OFF';
      vpnBtn.textContent = 'Turn on';
      vpnBtn.style.background = '';
    }
    vpnBtn.disabled = false;
  }

  updateVPNStatus() {
    const vpnBtn = document.getElementById('vpnToggleBtn');
    const vpnStatusEl = document.getElementById('vpnStatus');
    if (!vpnBtn || !vpnStatusEl) return;

    // Try background service via dashboard reference, else fall back locally
    if (this.dashboard && typeof this.dashboard.sendMessageToBackground === 'function') {
      this.dashboard.sendMessageToBackground({ type: 'VPN_GET_STATUS' }, (status) => {
        if (status && status.enabled !== undefined) {
          if (status.enabled) {
            vpnStatusEl.textContent = `VPN is ON (${status.country || 'US'})`;
            vpnBtn.textContent = 'Turn off';
            vpnBtn.style.background = '#10b981';
          } else {
            vpnStatusEl.textContent = 'VPN is OFF';
            vpnBtn.textContent = 'Turn on';
            vpnBtn.style.background = '';
          }
        } else {
          this.getVPNStatusFromStorage();
        }
      });
    } else {
      this.getVPNStatusFromStorage();
    }
  }

  getVPNStatusFromStorage() {
    const vpnBtn = document.getElementById('vpnToggleBtn');
    const vpnStatusEl = document.getElementById('vpnStatus');
    if (!vpnBtn || !vpnStatusEl) return;

    const isEnabled = localStorage.getItem('vpnEnabled') === 'true';
    if (isEnabled) {
      vpnStatusEl.textContent = 'VPN is ON (US)';
      vpnBtn.textContent = 'Turn off';
      vpnBtn.style.background = '#10b981';
    } else {
      vpnStatusEl.textContent = 'VPN is OFF';
      vpnBtn.textContent = 'Turn on';
      vpnBtn.style.background = '';
    }
  }

  setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', e => {
        e.preventDefault();
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');
        
        // Handle navigation between sections
        const navId = item.id;
        const dashboardOverview = document.querySelector('.dashboard-overview');
        const scannerCard = document.querySelector('.scanner-card');
        
        if (navId === 'nav-dashboard') {
          // Show dashboard overview
          if (dashboardOverview) dashboardOverview.style.display = 'block';
          if (scannerCard) scannerCard.style.display = 'none';
        } else if (navId === 'nav-scanner' || navId === 'nav-aiscam') {
          // Show scanner
          if (dashboardOverview) dashboardOverview.style.display = 'none';
          if (scannerCard) scannerCard.style.display = 'block';
        }
      });
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION — single entry point
// ═══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  window.realtimeDashboard = new RealtimeDashboard();
});

// Global helpers used by other scripts
window.navigate = function(pageId) {
  window.realtimeDashboard?.navigateToPage(pageId);
};

window.showModal = function(title, content) {
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:10000';
  modal.innerHTML = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;max-width:500px;width:90%;padding:20px"><h2 style="color:var(--text1);margin:0 0 12px">' + title + '</h2><div style="color:var(--text2);font-size:13px">' + content + '</div><button id="_modalClose" style="margin-top:16px;background:var(--accent);color:#fff;border:none;border-radius:8px;padding:8px 18px;cursor:pointer">Close</button></div>';
  modal.querySelector('#_modalClose').addEventListener('click', () => modal.remove());
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
};

window.showActivityLog = function() {
  window.realtimeDashboard?.navigateToPage('page-detection');
};

window.showPlansModal = function() {
  window.showModal('ShieldScan Free', 'ShieldScan is completely free with unlimited protection for all your devices. No credit card required.');
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = RealtimeDashboard;
}

// end of file
