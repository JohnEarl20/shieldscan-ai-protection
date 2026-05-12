// ═══════════════════════════════════════════════════════════════════════════════
// ADVANCED THREAT DETECTION ENGINE
// Real-time detection for: Trojans, Viruses, Malware, Scams, Phishing
// ═══════════════════════════════════════════════════════════════════════════════════════

class ThreatDetector {
  constructor() {
    this.threatDatabase = {
      trojans: [],
      viruses: [],
      malware: [],
      phishing: [],
      scams: [],
    };

    // Precompiled regexes / helpers
    this.compiledThreatsByCategory = null;

    // Evasion defenses
    this.homographConfusables = this.buildHomographConfusables();
    this.rloChar = '\u202E';
    this.commonObfuscationHints = [
      // Base64-ish blobs (not perfect, but useful)
      { pattern: /(?:[A-Za-z0-9+/]{40,}={0,2})/g, score: 20, name: 'Base64-like Obfuscation' },
      // Common JS obfuscation / loader patterns
      { pattern: /\beval\s*\(/i, score: 35, name: 'eval() Obfuscation' },
      { pattern: /\bfromCharCode\s*\(/i, score: 25, name: 'fromCharCode() Obfuscation' },
      { pattern: /\batob\s*\(/i, score: 20, name: 'atob() Obfuscation' },
      { pattern: /\bdocument\.write\s*\(/i, score: 25, name: 'document.write() Obfuscation' },
      { pattern: /\bnew\s+Function\s*\(/i, score: 35, name: 'new Function() Obfuscation' },
      // Self-defending patterns
      { pattern: /\b(?:while\s*\(true\)|setInterval\s*\(|String\.fromCharCode)\b/i, score: 15, name: 'Possible Obfuscated Execution' },
    ];

    // Patterns used by initializeThreatPatterns
    this.initializeThreatPatterns();
  }

  buildHomographConfusables() {
    // Basic Cyrillic->Latin confusable mapping (partial by design).
    // Goal: catch obvious lookalikes like "pаypal.com" (a is Cyrillic 'а' U+0430).
    // If you want this stronger later, expand this map.
    return new Map([
      ['а', 'a'], // Cyrillic a
      ['е', 'e'], // Cyrillic e
      ['о', 'o'], // Cyrillic o
      ['р', 'p'], // Cyrillic p
      ['с', 'c'], // Cyrillic es
      ['у', 'y'], // Cyrillic u
      ['х', 'x'], // Cyrillic ha
      ['к', 'k'], // Cyrillic ka
      ['в', 'b'], // Cyrillic ve
      ['т', 't'], // Cyrillic te
      ['м', 'm'], // Cyrillic em
      ['н', 'n'], // Cyrillic en
      ['д', 'd'], // Cyrillic de
      ['г', 'r'], // Cyrillic ge (often confusable with r in scams)
      ['i', 'i'], // keep ASCII
    ]);
  }

  normalizeInput(input) {
    if (typeof input !== 'string') return '';
    return input.trim().replace(/\s+/g, ' ');
  }

  // Replace obvious Cyrillic confusables with Latin equivalents to help detect lookalike domains.
  // (We don't do full IDN/punycode normalization here; this is targeted hardening.)
  normalizeHomograph(text) {
    if (typeof text !== 'string') return '';
    let out = '';
    for (const ch of text) {
      if (this.homographConfusables.has(ch)) out += this.homographConfusables.get(ch);
      else out += ch;
    }
    return out;
  }

  hasRLO(text) {
    if (typeof text !== 'string') return false;
    return text.includes(this.rloChar);
  }

  // Shannon entropy (rough). Works for text/byte-ish strings.
  shannonEntropy(str) {
    if (typeof str !== 'string') return 0;
    if (!str.length) return 0;

    const freq = new Map();
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      freq.set(ch, (freq.get(ch) || 0) + 1);
    }

    const len = str.length;
    let entropy = 0;

    for (const [, count] of freq.entries()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  initializeThreatPatterns() {
    // Helper: compile patterns
    const compile = (pattern) => {
      if (pattern instanceof RegExp) {
        // Ensure case-insensitive where needed; most patterns already have /i
        // Preserve flags but avoid global "g" for repeated test usage.
        const flags = pattern.flags.replace('g', '');
        return new RegExp(pattern.source, flags);
      }
      return new RegExp(String(pattern), 'i');
    };

    const make = (pattern, score, name) => ({
      pattern: compile(pattern),
      score,
      name,
      patternSource: pattern instanceof RegExp ? pattern.source : String(pattern),
    });

    // TROJAN DETECTION PATTERNS
    this.threatDatabase.trojans = [
      // Banking trojans
      make(/banking|bank-login|secure-banking|verify-account/i, 85, 'Banking Trojan'),
      make(/credential|password|login-verify|account-verify/i, 80, 'Credential Stealer'),
      make(/keylogger|keystroke|monitor|spy/i, 90, 'Keylogger/Spyware'),

      // Remote access trojans
      make(/remote-access|rat|backdoor|shell|command-control/i, 95, 'Remote Access Trojan'),
      make(/c2|command-and-control|botnet|zombie/i, 95, 'Botnet/C2'),

      // Trojan downloaders
      make(/downloader|dropper|loader|injector/i, 85, 'Trojan Downloader'),
      make(/payload|exploit-kit|drive-by/i, 90, 'Exploit Kit'),
    ];

    // VIRUS DETECTION PATTERNS
    this.threatDatabase.viruses = [
      // File infectors
      make(/virus|worm|propagate|replicate|infect/i, 90, 'File Virus'),
      make(/boot-sector|mbr|master-boot|system-virus/i, 95, 'Boot Virus'),

      // Macro viruses
      make(/macro|vba|office-macro|document-virus/i, 80, 'Macro Virus'),

      // Polymorphic viruses
      make(/polymorphic|metamorphic|encrypted-virus|obfuscated/i, 95, 'Polymorphic Virus'),
    ];

    // MALWARE DETECTION PATTERNS
    this.threatDatabase.malware = [
      // Ransomware
      make(/ransomware|encrypt|locked|decrypt|payment|bitcoin|ransom/i, 100, 'Ransomware'),
      make(/wannacry|petya|notpetya|cryptolocker|locky/i, 100, 'Known Ransomware'),

      // Adware/PUP
      make(/adware|pup|unwanted|toolbar|browser-hijacker/i, 60, 'Adware/PUP'),

      // Rootkit
      make(/rootkit|kernel-mode|privilege-escalation|system-access/i, 95, 'Rootkit'),

      // Wiper
      make(/wiper|data-destruction|disk-wipe|format/i, 100, 'Wiper Malware'),
    ];

    // PHISHING DETECTION PATTERNS
    this.threatDatabase.phishing = [
      // Email phishing
      make(/verify-email|confirm-email|update-email|email-verification/i, 85, 'Email Phishing'),

      // Banking phishing
      make(/bank|paypal|amazon|apple|microsoft|google/i, 80, 'Banking Phishing'),
      make(/update-payment|verify-payment|confirm-card|card-verification/i, 85, 'Payment Phishing'),

      // Credential phishing
      make(/login|signin|authenticate|password-reset|account-recovery/i, 75, 'Credential Phishing'),

      // Clone phishing
      make(/clone|duplicate|mirror|fake-site|lookalike/i, 80, 'Clone Phishing'),
    ];

    // SCAM DETECTION PATTERNS
    this.threatDatabase.scams = [
      // Prize/Lottery scams
      make(/congratulations|won|prize|lottery|claim-prize|free-money/i, 85, 'Prize Scam'),
      make(/click-here|claim-now|act-now|limited-time|hurry/i, 70, 'Urgency Scam'),

      // Romance/Dating scams
      make(/dating|romance|love|relationship|meet-singles/i, 65, 'Romance Scam'),

      // Tech support scams
      make(/tech-support|call-now|error-detected|virus-found|system-alert/i, 80, 'Tech Support Scam'),
      make(/windows-defender|antivirus-alert|security-warning|malware-detected/i, 85, 'Fake Antivirus'),

      // Investment scams
      make(/invest|crypto|bitcoin|forex|trading|guaranteed-return/i, 75, 'Investment Scam'),

      // Job scams
      make(/work-from-home|easy-money|quick-cash|no-experience/i, 70, 'Job Scam'),

      // Advance fee scams
      make(/advance-fee|upfront-payment|processing-fee|transfer-fee/i, 85, 'Advance Fee Scam'),
    ];

    // Precompile patterns for faster scan:
    // - Keep per-category compiled regex lists (so we can still map matches -> which threat)
    // - Also add an optional "category mega-regex" for early existence checks if needed later.
    this.compiledThreatsByCategory = {};

    for (const [category, patterns] of Object.entries(this.threatDatabase)) {
      // Ensure no global regexes and precompile are already done.
      this.compiledThreatsByCategory[category] = patterns;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // COMPREHENSIVE THREAT ANALYSIS
  // ─────────────────────────────────────────────────────────────────────────────

  analyzeURL(url) {
    const input = this.normalizeInput(url);
    if (!input) {
      return {
        url,
        host: '',
        score: 0,
        type: 'safe',
        threats: [],
        timestamp: new Date().toISOString(),
        error: 'Empty input',
      };
    }

    try {
      const parsed = new URL(input);
      const host = parsed.hostname.toLowerCase();
      const path = decodeURIComponent(parsed.pathname).toLowerCase();
      const query = decodeURIComponent(parsed.search).toLowerCase();
      const full = `${host}${path}${query}`;

      const threats = [];
      let maxScore = 0;
      let threatType = 'safe';

      // Evasion hardening: RLO detection on raw hostname/path/query
      if (this.hasRLO(input) || this.hasRLO(full) || this.hasRLO(host)) {
        threats.push({
          category: 'evasion',
          name: 'Right-to-Left Override (RLO) detected',
          score: 95,
          pattern: 'RLO',
        });
        maxScore = Math.max(maxScore, 95);
      }

      // Homograph attack detection (Cyrillic->Latin normalization)
      const normalizedHost = this.normalizeHomograph(host);
      if (normalizedHost !== host) {
        // If normalization changed something, it's suspicious; then apply threat patterns
        threats.push({
          category: 'evasion',
          name: 'Potential homograph (confusable characters) in domain',
          score: 75,
          pattern: 'homograph',
        });
        maxScore = Math.max(maxScore, 75);
      }

      // Fast scan: early exit when reaching max threat
      // We still preserve which rule matched by testing each compiled regex in each category.
      for (const [category, patterns] of Object.entries(this.compiledThreatsByCategory)) {
        for (const patternObj of patterns) {
          // Early exit for performance
          if (maxScore >= 100) break;

          if (patternObj.pattern.test(full) || patternObj.pattern.test(normalizedHost)) {
            threats.push({
              category,
              name: patternObj.name,
              score: patternObj.score,
              pattern: patternObj.pattern.source,
            });
            maxScore = Math.max(maxScore, patternObj.score);
          }
        }
        if (maxScore >= 100) break;
      }

      // Determine threat type
      if (maxScore >= 85) threatType = 'malicious';
      else if (maxScore >= 60) threatType = 'suspicious';
      else if (maxScore > 0) threatType = 'warning';

      return {
        url: input,
        host: host,
        score: maxScore,
        type: threatType,
        threats: threats,
        timestamp: new Date().toISOString(),
        // Keep normalizedHost to help debugging (optional, but helpful)
        normalizedHost,
      };
    } catch (err) {
      return {
        url,
        score: 0,
        type: 'safe',
        threats: [],
        timestamp: new Date().toISOString(),
        error: err && err.message ? err.message : 'Invalid URL',
      };
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // FILE ANALYSIS
  // ─────────────────────────────────────────────────────────────────────────────

  analyzeFile(filename, filesize) {
    const name = this.normalizeInput(filename);
    const sizeNum = Number(filesize);
    const threats = [];
    let score = 0;

    // Dangerous file extensions (case-insensitive via normalization)
    const dangerousExtensions = {
      '.exe': 95,
      '.bat': 90,
      '.cmd': 90,
      '.com': 90,
      '.scr': 95,
      '.vbs': 90,
      '.js': 70,
      '.jse': 90,
      '.hta': 95,
      '.msi': 85,
      '.dll': 80,
      '.sys': 95,
      '.drv': 95,
      '.iso': 85,
      '.img': 85,
      '.zip': 50,
      '.rar': 50,
      '.7z': 50,
      '.apk': 80,
      '.deb': 70,
      '.rpm': 70,
    };

    // Normalize ext (case-insensitive)
    const lowerName = name.toLowerCase();
    const lastDot = lowerName.lastIndexOf('.');
    const ext = lastDot >= 0 ? lowerName.substring(lastDot) : '';

    if (ext && dangerousExtensions[ext]) {
      score = Math.max(score, dangerousExtensions[ext]);
      threats.push({
        type: 'dangerous_extension',
        name: `Dangerous file type: ${ext}`,
        score: dangerousExtensions[ext],
      });
    }

    // Check for double extensions (e.g., document.pdf.exe)
    const parts = lowerName.split('.');
    if (parts.length > 2) {
      const secondExt = '.' + parts[parts.length - 2];
      const dangerousNow = ext && dangerousExtensions[ext];
      const dangerousSecond = secondExt && dangerousExtensions[secondExt];

      if (dangerousNow && !dangerousSecond) {
        // If last ext is dangerous but "penultimate" doesn't also scream dangerous,
        // it's a common deceptive pattern.
        score = Math.max(score, 90);
        threats.push({
          type: 'double_extension',
          name: 'Suspicious double extension detected',
          score: 90,
        });
      }
    }

    // Check filename patterns
    if (/virus|trojan|malware|ransomware|worm|backdoor/i.test(name)) {
      score = Math.max(score, 95);
      threats.push({
        type: 'malicious_name',
        name: 'Filename contains malicious keywords',
        score: 95,
      });
    }

    // Entropy scoring:
    // We can’t read actual bytes here (no binary content provided),
    // but we can still use a filename-based proxy: if filename includes long encoded-looking parts.
    // If filesize is provided and filename is long/opaque, treat as suspicious.
    const filenameEntropy = this.shannonEntropy(lowerName);
    if (filenameEntropy >= 4.5) {
      const entropyScore = 50 + Math.min(50, Math.round((filenameEntropy - 4.5) * 20)); // ~50-100
      score = Math.max(score, entropyScore);
      threats.push({
        type: 'entropy',
        name: `High entropy filename (proxy): H=${filenameEntropy.toFixed(2)}`,
        score: entropyScore,
      });
    }

    // Small additional heuristic: very small size with dangerous ext can be suspicious too
    if (ext && dangerousExtensions[ext] && Number.isFinite(sizeNum) && sizeNum > 0 && sizeNum < 1024 * 20) {
      score = Math.max(score, 80);
      threats.push({
        type: 'size_suspicious',
        name: 'Dangerous extension with very small file size',
        score: 80,
      });
    }

    // Determine threat type
    let threatType = 'safe';
    if (score >= 85) threatType = 'malicious';
    else if (score >= 60) threatType = 'suspicious';
    else if (score > 0) threatType = 'warning';

    return {
      filename: name,
      filesize: Number.isFinite(sizeNum) ? sizeNum : filesize,
      score,
      type: threatType,
      threats,
      timestamp: new Date().toISOString(),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // CONTENT ANALYSIS
  // ─────────────────────────────────────────────────────────────────────────────

  analyzeContent(text) {
    const input = typeof text === 'string' ? text : '';
    const normalized = input.trim().replace(/\s+/g, ' ');

    const threats = [];
    let score = 0;

    // Defensive checks against RLO in content too
    if (this.hasRLO(normalized)) {
      score = Math.max(score, 95);
      threats.push({
        type: 'evasion',
        name: 'Right-to-Left Override (RLO) detected in content',
        score: 95,
      });
    }

    // Phishing indicators
    const phishingIndicators = [
      { pattern: /verify.*account|confirm.*identity|update.*information/i, score: 80, name: 'Account Verification Request' },
      { pattern: /click.*link|click.*here|verify.*now|confirm.*now/i, score: 75, name: 'Urgent Action Request' },
      { pattern: /suspended|locked|disabled|compromised|unauthorized/i, score: 80, name: 'Account Status Alert' },
      { pattern: /re-enter.*password|confirm.*password|update.*password/i, score: 85, name: 'Password Request' },
    ];

    // Scam indicators
    const scamIndicators = [
      { pattern: /congratulations.*won|you.*won.*prize|claim.*prize/i, score: 90, name: 'Prize Scam' },
      { pattern: /free.*money|easy.*money|quick.*cash|guaranteed.*income/i, score: 85, name: 'Money Scam' },
      { pattern: /act.*now|limited.*time|hurry|expires.*today/i, score: 70, name: 'Urgency Tactic' },
      { pattern: /wire.*money|send.*payment|transfer.*funds|bitcoin/i, score: 85, name: 'Payment Request' },
    ];

    // Obfuscation indicators (Base64/eval/etc.)
    for (const hint of this.commonObfuscationHints) {
      try {
        if (hint.pattern.test(normalized)) {
          const prev = score;
          score = Math.max(score, hint.score);
          if (score !== prev) {
            threats.push({
              type: 'obfuscation',
              name: hint.name,
              score: hint.score,
            });
          }
        }
      } finally {
        // reset lastIndex if hint pattern might have /g
        if (hint.pattern && hint.pattern.global) hint.pattern.lastIndex = 0;
      }
    }

    // Check phishing
    for (const indicator of phishingIndicators) {
      if (indicator.pattern.test(normalized)) {
        score = Math.max(score, indicator.score);
        threats.push({
          type: 'phishing',
          name: indicator.name,
          score: indicator.score,
        });
      }
    }

    // Check scams
    for (const indicator of scamIndicators) {
      if (indicator.pattern.test(normalized)) {
        score = Math.max(score, indicator.score);
        threats.push({
          type: 'scam',
          name: indicator.name,
          score: indicator.score,
        });
      }
    }

    // Determine threat type
    let threatType = 'safe';
    if (score >= 85) threatType = 'malicious';
    else if (score >= 60) threatType = 'suspicious';
    else if (score > 0) threatType = 'warning';

    // If no explicit threats but entropy is high, treat as suspicious obfuscation proxy
    const entropy = this.shannonEntropy(normalized);
    if (entropy >= 4.2 && score < 60) {
      const entropyScore = 60 + Math.min(20, Math.round((entropy - 4.2) * 25));
      score = Math.max(score, entropyScore);
      threats.push({
        type: 'entropy',
        name: `High entropy content (proxy): H=${entropy.toFixed(2)}`,
        score: entropyScore,
      });
    }

    return {
      score: Math.min(100, score),
      type: threatType,
      threats,
      timestamp: new Date().toISOString(),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // REPUTATION CHECK (Simulated - can integrate with real APIs)
  // ─────────────────────────────────────────────────────────────────────────────

  checkReputation(host) {
    const h = String(host || '').toLowerCase();

    // Known malicious domains (simulated database)
    const knownMalicious = [
      'malware-site.com',
      'phishing-bank.com',
      'trojan-download.com',
      'ransomware-pay.com',
      'fake-antivirus.com',
    ];

    // Known safe domains
    const knownSafe = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'stackoverflow.com'];

    if (knownMalicious.some((d) => h.includes(d))) {
      return { reputation: 'malicious', score: 95 };
    }

    if (knownSafe.some((d) => h.includes(d))) {
      return { reputation: 'safe', score: 0 };
    }

    return { reputation: 'unknown', score: 0 };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // COMPREHENSIVE ANALYSIS
  // ─────────────────────────────────────────────────────────────────────────────

  analyze(input, type = 'url') {
    let result;

    if (type === 'url') {
      result = this.analyzeURL(input);
    } else if (type === 'file') {
      const normalized = this.normalizeInput(String(input));
      const [filename, filesize] = normalized.split('|');
      result = this.analyzeFile(filename || '', filesize);
    } else if (type === 'content') {
      result = this.analyzeContent(input);
    } else {
      return {
        score: 0,
        type: 'safe',
        threats: [],
        timestamp: new Date().toISOString(),
        error: `Unknown analyze type: ${type}`,
      };
    }

    // Add reputation check for URLs
    if (type === 'url' && result && result.host) {
      const reputation = this.checkReputation(result.host);
      result.reputation = reputation.reputation;
      result.score = Math.max(result.score, reputation.score);
    }

    // Clamp score to [0..100]
    if (result && typeof result.score === 'number') {
      result.score = Math.max(0, Math.min(100, result.score));
    }

    return result;
  }
}

// Expose for MV3 service worker (background.js expects a global ThreatDetector)
try {
  globalThis.ThreatDetector = ThreatDetector;
} catch (_) {
  // no-op
}

// Also support CommonJS environments (if used elsewhere)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ThreatDetector;
}
