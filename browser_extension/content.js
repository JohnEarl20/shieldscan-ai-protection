chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "showWarning" && message.result) {
    showWarning(message.result);
  }
});

// ── Page content phishing scanner ─────────────────────────────────────────────
// Runs after page load and scans visible text for phishing patterns.
// Sends findings to background.js for scoring.

(function scanPageContent() {
  // Only run on http/https pages, not extension pages
  if (!location.href.startsWith('http')) return;

  // Wait for DOM to be ready
  const run = () => {
    const text = (document.body?.innerText || '').toLowerCase().slice(0, 8000);
    if (!text || text.length < 100) return;

    const findings = [];
    let score = 0;

    // ── Phishing text patterns ───────────────────────────────────────────
    const PHISHING_PATTERNS = [
      { pattern: /your account (has been|will be) (suspended|locked|disabled)/i, score: 40, msg: 'Account suspension threat' },
      { pattern: /verify your (account|identity|payment|card|bank)/i, score: 35, msg: 'Verification request' },
      { pattern: /click here (to|and) (verify|confirm|update|secure)/i, score: 30, msg: 'Suspicious call-to-action' },
      { pattern: /enter your (password|pin|ssn|social security|credit card)/i, score: 45, msg: 'Credential harvesting prompt' },
      { pattern: /you (have|ve) won|congratulations.*prize|claim your (reward|prize|gift)/i, score: 50, msg: 'Prize/reward scam' },
      { pattern: /urgent.*action required|immediate(ly)? (verify|update|confirm)/i, score: 35, msg: 'Urgency manipulation' },
      { pattern: /your (computer|pc|device|system) (is|has been) (infected|hacked|compromised)/i, score: 55, msg: 'Fake security alert' },
      { pattern: /call (microsoft|apple|google|amazon|support).*\d{3}[-.\s]\d{3}/i, score: 60, msg: 'Tech support scam phone number' },
      { pattern: /send (bitcoin|btc|ethereum|eth|crypto|usdt)/i, score: 65, msg: 'Cryptocurrency scam' },
      { pattern: /wire transfer|western union|moneygram.*urgent/i, score: 55, msg: 'Wire transfer scam' },
      { pattern: /irs|tax (refund|return).*click|government.*grant.*apply/i, score: 45, msg: 'Government impersonation' },
      { pattern: /your (paypal|amazon|netflix|bank|apple id).*suspended/i, score: 40, msg: 'Brand impersonation' },
    ];

    for (const { pattern, score: s, msg } of PHISHING_PATTERNS) {
      if (pattern.test(text)) {
        findings.push({ rule: 'page_content', message: msg, score: s });
        score += s;
        if (findings.length >= 3) break; // cap at 3 findings
      }
    }

    // ── Form field analysis ──────────────────────────────────────────────
    const inputs = document.querySelectorAll('input[type="password"], input[name*="card"], input[name*="ssn"], input[name*="pin"]');
    const sensitiveInputCount = inputs.length;
    if (sensitiveInputCount > 0 && !_isTrustedDomain(location.hostname)) {
      findings.push({ rule: 'sensitive_form', message: `Page has ${sensitiveInputCount} sensitive input field(s) on untrusted domain`, score: 25 });
      score += 25;
    }

    score = Math.min(score, 100);
    if (score < 25 || findings.length === 0) return;

    // Send to background for display decision
    try {
      chrome.runtime.sendMessage({
        type: 'PAGE_THREAT_DETECTED',
        data: {
          url: location.href,
          score,
          level: score >= 70 ? 'high' : score >= 35 ? 'medium' : 'low',
          findings,
          source: 'page_content_scan',
        },
      });

      // Show warning for medium+ threats
      if (score >= 35) {
        showWarning({ score, findings, level: score >= 70 ? 'high' : 'medium' });
      }
    } catch (_) { /* extension context may be gone */ }
  };

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(run, 1500); // slight delay so page text is rendered
  } else {
    document.addEventListener('DOMContentLoaded', () => setTimeout(run, 1500));
  }
})();

function _isTrustedDomain(hostname) {
  const TRUSTED = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'github.com', 'paypal.com', 'netflix.com',
    'linkedin.com', 'twitter.com', 'instagram.com', 'youtube.com',
    'stackoverflow.com', 'wikipedia.org', 'reddit.com',
  ];
  return TRUSTED.some(d => hostname === d || hostname.endsWith('.' + d));
}



function showWarning(result) {
  const existing = document.getElementById("ai-scam-protection-warning");
  if (existing) {
    existing.remove();
  }

  const box = document.createElement("div");
  box.id = "ai-scam-protection-warning";
  box.setAttribute("role", "alert");
  
  const threatLevel = result.score >= 70 ? "High Risk" : result.score >= 35 ? "Medium Risk" : "Low Risk";
  const threatColor = result.score >= 70 ? "#dc2626" : result.score >= 35 ? "#f59e0b" : "#3b82f6";
  
  box.innerHTML = `
    <div class="asp-title">⚠️ AI Scam Protection Warning</div>
    <div class="asp-body">
      <div class="asp-threat-level" style="color: ${threatColor}; font-weight: 600; margin-bottom: 6px;">
        ${threatLevel} (Score: ${result.score}/100)
      </div>
      <div class="asp-findings">
        ${result.findings.slice(0, 2).map(f => `<div class="asp-finding">• ${escapeHtml(f.message)}</div>`).join('')}
      </div>
    </div>
    <button class="asp-close" type="button" aria-label="Close warning">✕</button>
  `;

  const style = document.createElement("style");
  style.textContent = `
    #ai-scam-protection-warning {
      position: fixed;
      top: 16px;
      right: 16px;
      z-index: 2147483647;
      width: min(380px, calc(100vw - 32px));
      box-sizing: border-box;
      padding: 14px 16px;
      color: #171717;
      background: #fff7ed;
      border: 2px solid #fdba74;
      border-radius: 8px;
      box-shadow: 0 12px 28px rgba(15, 23, 42, 0.22);
      font-family: Arial, sans-serif;
      font-size: 13px;
      line-height: 1.4;
      animation: slideIn 0.3s ease;
    }
    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateX(400px);
      }
      to {
        opacity: 1;
        transform: translateX(0);
      }
    }
    #ai-scam-protection-warning .asp-title {
      font-weight: 700;
      margin-bottom: 8px;
      font-size: 14px;
    }
    #ai-scam-protection-warning .asp-body {
      margin-right: 36px;
    }
    #ai-scam-protection-warning .asp-findings {
      font-size: 12px;
      color: #5a5a5a;
    }
    #ai-scam-protection-warning .asp-finding {
      margin-bottom: 4px;
    }
    #ai-scam-protection-warning .asp-close {
      position: absolute;
      top: 8px;
      right: 8px;
      height: 24px;
      width: 24px;
      padding: 0;
      border: none;
      border-radius: 4px;
      color: #7c2d12;
      background: transparent;
      cursor: pointer;
      font: inherit;
      font-size: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background 0.2s;
    }
    #ai-scam-protection-warning .asp-close:hover {
      background: rgba(124, 45, 18, 0.1);
    }
  `;

  document.documentElement.appendChild(style);
  document.documentElement.appendChild(box);
  
  box.querySelector(".asp-close").addEventListener("click", () => {
    box.remove();
    style.remove();
  });

  // Auto-remove after 8 seconds
  setTimeout(() => {
    if (box.parentElement) {
      box.remove();
      style.remove();
    }
  }, 8000);
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => {
    const map = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    };
    return map[char];
  });
}

