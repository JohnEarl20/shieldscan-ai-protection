# AI Scam Protection Platform — ShieldScan

A full-stack Windows security platform combining a Python protection engine, a local REST API, and a Chrome/Edge browser extension. Detects and blocks scams, malware, ransomware, and trackers in real time.

---

## What's included

### Python protection engine (`ai_scam_protection/`)

| Module | What it does |
| --- | --- |
| `scanner.py` | File scanner — hash, entropy, extension, magic byte, zone identifier |
| `heuristics.py` | 14 YARA-style rules — ransomware, credential theft, process injection, UAC bypass, rootkit indicators, obfuscation, and more |
| `sandbox.py` | Static behavioral sandbox — 20+ behavior patterns across filesystem, network, process, registry, anti-analysis, privilege, and data theft categories |
| `ml_engine.py` | AI/ML scoring engine — weighted feature vector → 0–100 threat score with confidence rating |
| `watcher.py` | Real-time file watcher — polls Downloads/Desktop/Temp for new or changed files |
| `quarantine.py` | Quarantine and restore manager |
| `rootkit_detector.py` | Rootkit scanner — hidden processes, suspicious drivers/services, named pipes, ADS, loaded hook modules |
| `system_audit.py` | Startup entry audit (registry Run keys + startup folders) and installed app audit |
| `process_monitor.py` | **NEW** — Live process scanner, scores 300+ running processes for suspicious names, paths, parent→child spawn chains (Office/browser spawning PowerShell), and cryptominer patterns |
| `ransomware_monitor.py` | **NEW** — Live ransomware behavior monitor, detects mass file renames, 41 known ransomware extensions, ransom note files, runs as background thread |
| `threat_intel.py` | **NEW** — Threat intelligence feed aggregator — URLhaus URLs/domains, MalwareBazaar hashes, Emerging Threats IPs, all cached locally with TTL refresh |
| `autonomous_response.py` | **NEW** — Autonomous response system — kill process, block network via Windows Firewall, create/restore VSS shadow copy snapshots for ransomware rollback |
| `cloud_intel.py` | Cloud threat intelligence — OTX AlienVault (free), MalwareBazaar, URLhaus, VirusTotal |
| `api_server.py` | Threaded local REST API on port 8765, serves real data to the browser extension |
| `cli.py` | Full CLI with 12 commands |
| `service.py` | Windows Task Scheduler integration for always-on protection |
| `notification.py` | Windows toast notifications |

### Browser extension (`browser_extension/`)

| Feature | Details |
| --- | --- |
| Popup dashboard | Live stats — threats blocked, protection score, scans today |
| Browser phishing (page content) | **NEW** — `content.js` now scans visible page text for 12 phishing patterns (credential harvesting, tech support scams, crypto scams, brand impersonation, sensitive form fields on untrusted domains) |
| Live telemetry | **NEW** — `/api/events/stream` SSE endpoint streams detections in real time |
| Attack timeline | **NEW** — `/api/attack-timeline` chronological view of all event types |
| EDR dashboard | **NEW** — `/api/edr/summary` unified endpoint; process tree data available via `/api/processes` |
| Threat intelligence API | **NEW** — `threat_intel.py` aggregates URLhaus, MalwareBazaar, Emerging Threats feeds |
| Autonomous response | **NEW** — `autonomous_response.py` — process kill, firewall block, VSS snapshot, rollback |
| Ransomware rollback | **NEW** — VSS shadow copy creation + restore via `autonomous_response.py` |
| URL inspection | Scans every page load for phishing, suspicious TLDs, risky keywords, IP-based hosts, punycode domains |
| Blocked page | Redirects high-risk URLs to a blocked.html warning page |
| Warning banner | Shows in-page warning for medium-risk URLs |
| Real-time integration | Content script polls the local API for new detections and broadcasts to popup/dashboard |
| VPN manager | Proxy-based VPN with 8 server locations |
| AI Scanner | Scan any URL or text through the full Python engine via the API |
| Full dashboard | Multi-page dashboard with Scanner, Detection History, Real-Time Protection, VPN, Privacy, Identity, Tools, Settings, Account pages |
| CSP compliant | **FIXED** — Zero inline scripts or event handlers. All handlers use event delegation via `data-action` attributes |

---

## Quick start

### 1. Initialize

```powershell
python -m ai_scam_protection.cli init
```

### 2. Start the API server (required for browser extension)

```powershell
.venv\Scripts\python.exe -m ai_scam_protection.cli api-server
```

Keep this running. The browser extension connects to `http://localhost:8765`.

### 3. Start real-time protection

```powershell
python -m ai_scam_protectionpython -m ai_scam_protection.cli protect.cli protect
```

Or use the PowerShell launcher:

```powershell
.\protect.ps1 protect
```

### 4. Load the browser extension

Go to `chrome://extensions` (or `edge://extensions`), enable Developer mode, click **Load unpacked**, and select the `browser_extension` folder.

---

## API endpoints

The API server exposes these endpoints at `http://localhost:8765`:

| Endpoint | Method | Description |
| --- | --- | --- |
| `/api/health` | GET | Server uptime check |
| `/api/stats` | GET | Threats blocked, protection score, scans today, uptime |
| `/api/status` | GET | Protection service running status |
| `/api/detections` | GET | Recent detections from events.jsonl |
| `/api/quarantine` | GET | Quarantined items list |
| `/api/checkup` | GET | Latest checkup report |
| `/api/rootkit` | GET | Cached rootkit scan result |
| `/api/processes` | GET | **NEW** — Live process scan (cached 30s) |
| `/api/ransomware` | GET | **NEW** — Live ransomware monitor status |
| `/api/startup` | GET | **NEW** — Startup entry audit (cached 5min) |
| `/api/scan` | POST | Scan a URL or text with the full engine |
| `/api/cloud-lookup` | POST | Cloud intel lookup (hash or URL) |
| `/api/rootkit/scan` | POST | Trigger a fresh rootkit scan |
| `/api/processes/scan` | POST | **NEW** — Force a fresh process scan |
| `/api/threat-intel` | POST | **NEW** — Look up indicator across URLhaus, MalwareBazaar, Emerging Threats feeds |
| `/api/threat-intel/status` | GET | **NEW** — Feed status (last update, record count, staleness) |
| `/api/threat-intel/refresh` | POST | **NEW** — Force refresh all threat intel feeds |
| `/api/attack-timeline` | GET | **NEW** — Chronological attack timeline from all event types |
| `/api/edr/summary` | GET | **NEW** — Unified EDR summary (processes + startup + ransomware + rootkit) |
| `/api/events/stream` | GET | **NEW** — Server-Sent Events live telemetry stream |
| `/api/autonomous-response` | POST | **NEW** — Execute response actions (kill process, block network, VSS snapshot, restore) |

---

## CLI commands

```powershell
# One-time checkup (scans Downloads/Desktop/Temp, stops automatically)
python -m ai_scam_protection.cli checkup --defender

# Real-time protection (runs until Ctrl+C)
python -m ai_scam_protection.cli protect

# Strict mode (also quarantines medium-risk files)
python -m ai_scam_protection.cli protect --strict

# Scan specific paths
python -m ai_scam_protection.cli scan "C:\Users\...\Downloads" --recursive --quarantine

# Rootkit scan
python -m ai_scam_protection.cli rootkit-scan

# Cloud lookup (hash or URL)
python -m ai_scam_protection.cli cloud-lookup <sha256-or-url>

# Save API keys for cloud intel
python -m ai_scam_protection.cli cloud-key virustotal YOUR_KEY
python -m ai_scam_protection.cli cloud-key abusech YOUR_KEY

# View recent detections
python -m ai_scam_protection.cli detections
python -m ai_scam_protection.cli detections --all

# Quarantine management
python -m ai_scam_protection.cli quarantine list
python -m ai_scam_protection.cli quarantine restore <item-id>

# Always-on background service
python -m ai_scam_protection.cli service install
python -m ai_scam_protection.cli service start
python -m ai_scam_protection.cli service stop
python -m ai_scam_protection.cli service status

# API server
python -m ai_scam_protection.cli api-server
python -m ai_scam_protection.cli api-server --port 8765
```

---

## Cloud threat intelligence

Three sources are supported. OTX AlienVault works with no key. The others require free registration:

| Source | Key required | What it checks |
| --- | --- | --- |
| OTX AlienVault | No | File hashes + URLs |
| MalwareBazaar | Yes — [auth.abuse.ch](https://auth.abuse.ch/) | File hashes |
| URLhaus | Yes — [auth.abuse.ch](https://auth.abuse.ch/) | URLs |
| VirusTotal | Yes — [virustotal.com](https://www.virustotal.com/gui/join-us) | File hashes + URLs (70+ engines) |

Save keys once:

```powershell
python -m ai_scam_protection.cli cloud-key virustotal YOUR_VT_KEY
python -m ai_scam_protection.cli cloud-key abusech YOUR_ABUSECH_KEY
```

---

## State files

All state is stored in `.protection_state/` in the project root:

```
.protection_state/
  config.json          — configuration and API keys
  bad_hashes.txt       — local SHA-256 blocklist
  events.jsonl         — all detection events (append-only log)
  latest_detection.json
  latest_checkup.json
  quarantine/          — quarantined files
  cloud_cache/         — cloud intel response cache (1h TTL)
  protection_service.out.log
  protection_service.err.log
```

---

## Safety model

- Scan and watch commands **report only** by default — no files are moved without `--quarantine` or `--block`
- Files scoring ≥ 70 are "high risk" and eligible for quarantine
- Files scoring 35–69 are "medium risk" — alerted but not quarantined unless `--strict` is used
- Quarantined files are encrypted and stored in `.protection_state/quarantine/` and can be restored at any time
- The API server binds to `127.0.0.1` only — not accessible from the network

---

## Architecture

```
Browser Extension (Chrome/Edge)
  └── popup.js / dashboard.js / background.js
        └── fetch → localhost:8765 (API server)
                      └── api_server.py (ThreadedHTTPServer)
                            ├── scanner.py + heuristics.py + sandbox.py + ml_engine.py
                            ├── process_monitor.py  (live process scan)
                            ├── ransomware_monitor.py  (live file behavior)
                            ├── rootkit_detector.py
                            ├── system_audit.py  (startup entries)
                            └── cloud_intel.py  (OTX / VT / abuse.ch)

Protection Service (background)
  └── cli.py protect → watcher.py → scanner.py → quarantine.py
```