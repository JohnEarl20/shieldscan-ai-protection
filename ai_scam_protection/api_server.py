"""
Local REST API server for ShieldScan dashboard integration.

Runs on http://localhost:8765 and exposes real data from the
protection service to the browser extension and web dashboard.

Endpoints:
  GET  /api/stats          — live threat counts, protection score, uptime
  GET  /api/status         — protection service running status
  GET  /api/detections     — recent detections from events.jsonl
  GET  /api/quarantine     — quarantined items
  GET  /api/checkup        — latest checkup report
  POST /api/scan           — scan a URL or text with the AI engine
  POST /api/cloud-lookup   — cloud intel lookup (hash or URL)
  GET  /api/rootkit        — latest rootkit scan result (cached)
  POST /api/rootkit/scan   — trigger a fresh rootkit scan
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

# ── Resolve project root ───────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from ai_scam_protection.config import load_config, ensure_state
from ai_scam_protection.logging_utils import utc_now
from ai_scam_protection.quarantine import QuarantineManager
from ai_scam_protection.cloud_intel import CloudIntel, load_api_keys

PORT = 8765
_start_time = time.time()
_rootkit_cache: dict[str, Any] = {}
_rootkit_lock = threading.Lock()


# ── CORS + JSON helpers ────────────────────────────────────────────────────────

def _json_response(handler: BaseHTTPRequestHandler, data: Any, status: int = 200) -> None:
    body = json.dumps(data, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)


def _read_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", 0))
    if not length:
        return {}
    try:
        return json.loads(handler.rfile.read(length).decode("utf-8"))
    except Exception:
        return {}


# ── Request handler ────────────────────────────────────────────────────────────

class ShieldScanAPIHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Suppress default access log noise

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        config = load_config(_ROOT)

        if path == "/api/stats":
            _json_response(self, _get_stats(config))
        elif path == "/api/status":
            _json_response(self, _get_status(config))
        elif path == "/api/detections":
            limit = int(params.get("limit", ["20"])[0])
            include_all = params.get("all", ["false"])[0].lower() == "true"
            _json_response(self, _get_detections(config, limit, include_all))
        elif path == "/api/quarantine":
            _json_response(self, _get_quarantine(config))
        elif path == "/api/checkup":
            _json_response(self, _get_checkup(config))
        elif path == "/api/rootkit":
            _json_response(self, _get_rootkit_result())
        elif path == "/api/processes":
            _json_response(self, _get_processes())
        elif path == "/api/ransomware":
            _json_response(self, _get_ransomware_status(config))
        elif path == "/api/startup":
            _json_response(self, _get_startup_entries())
        elif path == "/api/health":
            _json_response(self, {"ok": True, "uptime": int(time.time() - _start_time)})
        elif path == "/api/threat-intel/status":
            _json_response(self, _get_threat_intel_status(config))
        elif path == "/api/attack-timeline":
            limit = int(params.get("limit", ["50"])[0])
            _json_response(self, _get_attack_timeline(config, limit))
        elif path == "/api/edr/summary":
            _json_response(self, _get_edr_summary(config))
        elif path == "/api/realtime/status":
            _json_response(self, _do_realtime_status(config))
        elif path == "/api/events/stream":
            _sse_stream(self, config)
            return
        else:
            _json_response(self, {"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        body = _read_body(self)
        config = load_config(_ROOT)

        if path == "/api/scan":
            _json_response(self, _do_scan(body, config))
        elif path == "/api/cloud-lookup":
            _json_response(self, _do_cloud_lookup(body, config))
        elif path == "/api/rootkit/scan":
            _json_response(self, _do_rootkit_scan(config))
        elif path == "/api/processes/scan":
            _json_response(self, _do_process_scan())
        elif path == "/api/threat-intel":
            _json_response(self, _do_threat_intel_lookup(body, config))
        elif path == "/api/autonomous-response":
            _json_response(self, _do_autonomous_response(body, config))
        elif path == "/api/threat-intel/refresh":
            _json_response(self, _do_threat_intel_refresh(config))
        elif path == "/api/realtime/enable":
            _json_response(self, _do_realtime_enable(config))
        elif path == "/api/realtime/disable":
            _json_response(self, _do_realtime_disable(config))
        elif path == "/api/realtime/status":
            _json_response(self, _do_realtime_status(config))
        else:
            _json_response(self, {"error": "Not found"}, 404)


# ── Endpoint implementations ───────────────────────────────────────────────────

def _get_stats(config) -> dict:
    """Real stats from events.jsonl."""
    ensure_state(config)
    events = _load_events(config)

    threats_blocked = sum(
        1 for e in events
        if e.get("type") in {"watch_detection", "scan"}
        and isinstance(e.get("payload"), dict)
        and e["payload"].get("level") in {"high"}
    )
    quarantine_count = sum(
        1 for e in events
        if e.get("type") in {"quarantine"}
    )
    scans_today = sum(
        1 for e in events
        if e.get("type") == "scan"
        and _is_today(e.get("timestamp", ""))
    )

    # Protection score: base 70 + bonuses
    score = 70
    if _is_service_running():
        score += 15
    if threats_blocked == 0:
        score += 5
    if scans_today > 0:
        score += 5
    score = min(score, 100)

    uptime_seconds = int(time.time() - _start_time)

    return {
        "threats_blocked": threats_blocked,
        "quarantine_count": quarantine_count,
        "scans_today": scans_today,
        "protection_score": score,
        "uptime_seconds": uptime_seconds,
        "uptime_hours": round(uptime_seconds / 3600, 1),
        "timestamp": utc_now(),
    }


def _get_status(config) -> dict:
    """Real protection service status."""
    service_running = _is_service_running()
    latest_detection = _load_latest_detection(config)
    latest_checkup = _load_latest_checkup(config)

    return {
        "protection_active": service_running,
        "service_running": service_running,
        "real_time_shield": service_running,
        "ai_scam_protection": True,
        "identity_protection": True,
        "vpn_enabled": False,
        "latest_detection": latest_detection,
        "last_checkup": latest_checkup.get("timestamp") if latest_checkup else None,
        "platform": platform.system(),
        "timestamp": utc_now(),
    }


def _get_detections(config, limit: int, include_all: bool) -> dict:
    """Recent detections from events.jsonl."""
    ensure_state(config)
    events = _load_events(config)
    detections = []

    for event in reversed(events):
        if len(detections) >= limit:
            break
        etype = event.get("type", "")
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            continue
        if etype not in {"scan", "watch_detection", "quarantine"}:
            continue
        level = payload.get("level", "")
        if not include_all and level not in {"high"} and "quarantine_item" not in payload:
            continue

        detections.append({
            "timestamp": event.get("timestamp", ""),
            "type": etype,
            "level": level,
            "path": payload.get("path") or payload.get("original_path", ""),
            "score": payload.get("score", 0),
            "sha256": payload.get("sha256"),
            "findings": payload.get("findings", [])[:3],
            "quarantined": "quarantine_item" in payload,
            "ai_score": payload.get("ai_score"),
            "sandbox_verdict": payload.get("sandbox", {}).get("verdict") if payload.get("sandbox") else None,
        })

    return {
        "detections": detections,
        "total": len(detections),
        "timestamp": utc_now(),
    }


def _get_quarantine(config) -> dict:
    """List quarantined items."""
    try:
        manager = QuarantineManager(config)
        items = manager.list_items()
        return {
            "items": [item.to_dict() for item in items],
            "count": len(items),
            "timestamp": utc_now(),
        }
    except Exception as exc:
        return {"items": [], "count": 0, "error": str(exc)}


def _get_checkup(config) -> dict:
    """Latest checkup report."""
    data = _load_latest_checkup(config)
    if not data:
        return {"available": False, "timestamp": utc_now()}
    return {"available": True, "report": data, "timestamp": utc_now()}


def _do_scan(body: dict, config) -> dict:
    """Scan a URL or text snippet using the full engine."""
    target = body.get("target", "").strip()
    if not target:
        return {"error": "No target provided"}

    try:
        from ai_scam_protection.heuristics import analyze_heuristics
        from ai_scam_protection.sandbox import run_sandbox

        data = target.encode("utf-8", errors="ignore")
        heuristic = analyze_heuristics(data, filename="input")
        sandbox = run_sandbox(data, filename="input")

        # Simple URL pattern check
        url_score = 0
        url_findings = []
        lower = target.lower()
        risky_patterns = [
            ("secure-verify", 40), ("verify-account", 40), ("claim-prize", 50),
            ("free-money", 50), ("urgent-update", 35), ("bank-login", 45),
            (".xyz", 15), (".top", 15), (".tk", 20), (".ml", 20),
        ]
        for pattern, score in risky_patterns:
            if pattern in lower:
                url_score += score
                url_findings.append({"rule": "url_pattern", "message": f"Contains: {pattern}", "score": score})

        total_score = min(url_score + heuristic.total_score + sandbox.total_score, 100)
        level = "high" if total_score >= 70 else "medium" if total_score >= 35 else "low" if total_score > 0 else "clean"

        return {
            "target": target,
            "score": total_score,
            "level": level,
            "result": "malicious" if level == "high" else "suspicious" if level == "medium" else "safe",
            "url_findings": url_findings,
            "heuristic": heuristic.to_dict(),
            "sandbox": sandbox.to_dict(),
            "timestamp": utc_now(),
        }
    except Exception as exc:
        return {"error": str(exc), "target": target}


def _do_cloud_lookup(body: dict, config) -> dict:
    """Cloud intel lookup for a hash or URL."""
    target = body.get("target", "").strip()
    if not target:
        return {"error": "No target provided"}

    try:
        keys = load_api_keys(config.state_dir)
        cache_dir = config.state_dir / "cloud_cache"
        intel = CloudIntel(
            vt_api_key=keys.get("virustotal"),
            abusech_key=keys.get("abusech"),
            cache_dir=cache_dir,
        )

        if target.startswith("http://") or target.startswith("https://"):
            summary = intel.lookup_url(target)
        elif len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target):
            summary = intel.lookup_hash(target)
        else:
            return {"error": "Target must be a URL or SHA-256 hash"}

        return summary.to_dict()
    except Exception as exc:
        return {"error": str(exc), "target": target}


def _do_rootkit_scan(config) -> dict:
    """Trigger a rootkit scan (runs in background, returns cached result)."""
    def _run():
        from ai_scam_protection.rootkit_detector import scan_for_rootkits
        result = scan_for_rootkits(timeout=30)
        with _rootkit_lock:
            _rootkit_cache["result"] = result.to_dict()
            _rootkit_cache["timestamp"] = utc_now()

    with _rootkit_lock:
        already_running = _rootkit_cache.get("running", False)

    if not already_running:
        with _rootkit_lock:
            _rootkit_cache["running"] = True
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return {"status": "scanning", "message": "Rootkit scan started. Poll /api/rootkit for results."}

    return _get_rootkit_result()


def _get_rootkit_result() -> dict:
    with _rootkit_lock:
        if "result" in _rootkit_cache:
            return {
                "status": "complete",
                "result": _rootkit_cache["result"],
                "timestamp": _rootkit_cache.get("timestamp"),
            }
    return {"status": "not_run", "message": "No rootkit scan has been run yet. POST /api/rootkit/scan to start."}


# ── Process monitor ────────────────────────────────────────────────────────────

_process_cache: dict = {}
_process_lock = threading.Lock()


def _get_processes() -> dict:
    """Return cached process scan result (refreshed every 30s)."""
    with _process_lock:
        cached = _process_cache.get("result")
        cached_ts = _process_cache.get("ts", 0)
        if cached and (time.time() - cached_ts) < 30:
            return cached
    # Cache miss — run a fresh scan in background, return stale or empty
    threading.Thread(target=_refresh_process_cache, daemon=True).start()
    with _process_lock:
        return _process_cache.get("result") or {
            "status": "scanning",
            "message": "Process scan in progress. Poll /api/processes again in a few seconds.",
        }


def _refresh_process_cache() -> None:
    from ai_scam_protection.process_monitor import scan_processes
    result = scan_processes(timeout=20)
    with _process_lock:
        _process_cache["result"] = {
            "status": "complete",
            **result.to_dict(),
            "timestamp": utc_now(),
        }
        _process_cache["ts"] = time.time()


def _do_process_scan() -> dict:
    """Force a fresh process scan."""
    with _process_lock:
        _process_cache.clear()
    _refresh_process_cache()
    with _process_lock:
        return _process_cache.get("result") or {"status": "error"}


# ── Ransomware monitor ─────────────────────────────────────────────────────────

def _get_ransomware_status(config) -> dict:
    """Return current ransomware monitor status."""
    from ai_scam_protection.ransomware_monitor import get_monitor, start_monitor
    from ai_scam_protection.config import default_watch_paths

    monitor = get_monitor()
    if monitor is None:
        # Auto-start monitor on first request
        paths = default_watch_paths()
        if paths:
            monitor = start_monitor(paths)
        else:
            return {"status": "unavailable", "message": "No watch paths configured"}

    status = monitor.get_status()
    return {
        "status": "active" if status.is_active else "stopped",
        **status.to_dict(),
        "timestamp": utc_now(),
    }


# ── Startup entries ────────────────────────────────────────────────────────────

_startup_cache: dict = {}
_startup_lock = threading.Lock()


def _get_startup_entries() -> dict:
    """Return startup audit results (cached for 5 minutes)."""
    with _startup_lock:
        cached = _startup_cache.get("result")
        cached_ts = _startup_cache.get("ts", 0)
        if cached and (time.time() - cached_ts) < 300:
            return cached

    try:
        from ai_scam_protection.system_audit import audit_startup_entries, suspicious_startup_entries
        entries = audit_startup_entries()
        suspicious = suspicious_startup_entries(entries)
        result = {
            "status": "complete",
            "total": len(entries),
            "suspicious_count": len(suspicious),
            "entries": [e.to_dict() for e in entries[:50]],
            "suspicious": [e.to_dict() for e in suspicious],
            "timestamp": utc_now(),
        }
        with _startup_lock:
            _startup_cache["result"] = result
            _startup_cache["ts"] = time.time()
        return result
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_events(config) -> list[dict]:
    try:
        lines = config.log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except Exception:
                continue
        return events
    except Exception:
        return []


def _load_latest_detection(config) -> dict | None:
    path = config.state_dir / "latest_detection.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_latest_checkup(config) -> dict | None:
    path = config.state_dir / "latest_checkup.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _is_service_running() -> bool:
    """Check if the Python protection service process is running."""
    if platform.system().lower() != "windows":
        return False
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*' -and $_.CommandLine -like '*ai_scam_protection.cli protect*' } | Measure-Object | Select-Object -ExpandProperty Count"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return int(result.stdout.strip() or "0") > 0
    except Exception:
        return False


def _is_today(timestamp: str) -> bool:
    if not timestamp:
        return False
    try:
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).date()
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.date() == today
    except Exception:
        return False


# ── Threat intelligence feed ───────────────────────────────────────────────────

_threat_intel_feed = None
_threat_intel_lock = threading.Lock()


def _get_threat_intel_feed(config):
    global _threat_intel_feed
    with _threat_intel_lock:
        if _threat_intel_feed is None:
            from ai_scam_protection.threat_intel import ThreatIntelFeed
            cache_dir = config.state_dir / "threat_intel"
            _threat_intel_feed = ThreatIntelFeed(cache_dir=cache_dir)
    return _threat_intel_feed


def _do_threat_intel_lookup(body: dict, config) -> dict:
    """Look up an indicator across all threat intel feeds."""
    indicator = body.get("indicator", "").strip()
    if not indicator:
        return {"error": "No indicator provided. Send {\"indicator\": \"url/ip/hash/domain\"}"}
    try:
        feed = _get_threat_intel_feed(config)
        result = feed.lookup(indicator)
        return result.to_dict()
    except Exception as exc:
        return {"error": str(exc), "indicator": indicator}


def _get_threat_intel_status(config) -> dict:
    """Return status of all threat intel feeds."""
    try:
        feed = _get_threat_intel_feed(config)
        return {
            "status": "ok",
            "feeds": feed.get_feed_status(),
            "timestamp": utc_now(),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def _do_threat_intel_refresh(config) -> dict:
    """Force refresh all threat intel feeds."""
    try:
        feed = _get_threat_intel_feed(config)
        results = feed.refresh_all()
        return {
            "status": "complete",
            "results": results,
            "timestamp": utc_now(),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


# ── Attack timeline ────────────────────────────────────────────────────────────

def _get_attack_timeline(config, limit: int = 50) -> dict:
    """
    Build a chronological attack timeline from all event types.
    Includes detections, quarantine, rootkit, process, ransomware events.
    """
    ensure_state(config)
    events = _load_events(config)

    timeline = []
    for event in events:
        etype = event.get("type", "")
        payload = event.get("payload", {})
        ts = event.get("timestamp", "")
        if not ts:
            continue

        if not isinstance(payload, dict):
            continue

        entry = None

        if etype in {"watch_detection", "scan"}:
            level = payload.get("level", "clean")
            if level in {"low", "medium", "high"}:
                path = payload.get("path") or payload.get("original_path", "")
                entry = {
                    "timestamp": ts,
                    "event_type": "detection",
                    "severity": level,
                    "title": f"{'Threat blocked' if level == 'high' else 'Suspicious file'}: {Path(path).name if path else 'unknown'}",
                    "detail": path,
                    "score": payload.get("score", 0),
                    "category": "file",
                    "icon": "🔴" if level == "high" else "⚡",
                }

        elif etype == "quarantine":
            path = payload.get("original_path", "")
            entry = {
                "timestamp": ts,
                "event_type": "quarantine",
                "severity": "high",
                "title": f"Quarantined: {Path(path).name if path else 'unknown'}",
                "detail": path,
                "score": payload.get("score", 0),
                "category": "quarantine",
                "icon": "🔒",
            }

        elif etype == "rootkit_scan":
            score = payload.get("total_score", 0)
            if score > 0:
                entry = {
                    "timestamp": ts,
                    "event_type": "rootkit",
                    "severity": "high" if score >= 60 else "medium",
                    "title": f"Rootkit indicators found (score {score})",
                    "detail": f"{len(payload.get('indicators', []))} indicators",
                    "score": score,
                    "category": "rootkit",
                    "icon": "☠️",
                }

        elif etype == "autonomous_response":
            actions = payload.get("actions", [])
            successful = [a for a in actions if a.get("success")]
            entry = {
                "timestamp": ts,
                "event_type": "response",
                "severity": "medium",
                "title": f"Autonomous response: {len(successful)}/{len(actions)} actions succeeded",
                "detail": payload.get("threat_description", ""),
                "score": 0,
                "category": "response",
                "icon": "🛡️",
            }

        elif etype == "restore":
            entry = {
                "timestamp": ts,
                "event_type": "restore",
                "severity": "low",
                "title": f"File restored from quarantine",
                "detail": payload.get("restored_to", ""),
                "score": 0,
                "category": "quarantine",
                "icon": "↩️",
            }

        if entry:
            timeline.append(entry)

    # Sort newest first, limit
    timeline.sort(key=lambda e: e["timestamp"], reverse=True)
    timeline = timeline[:limit]

    return {
        "timeline": timeline,
        "total": len(timeline),
        "timestamp": utc_now(),
    }


# ── EDR summary ────────────────────────────────────────────────────────────────

def _get_edr_summary(config) -> dict:
    """
    Unified EDR summary combining processes, startup, ransomware, rootkit, and detections.
    """
    summary: dict = {"timestamp": utc_now()}

    # Process scan (use cache)
    proc = _get_processes()
    summary["processes"] = {
        "total": proc.get("total_scanned", 0),
        "suspicious": proc.get("suspicious_count", 0),
        "high_risk": proc.get("high_risk_count", 0),
        "top_risks": [p for p in proc.get("processes", []) if p.get("score", 0) >= 40][:5],
    }

    # Startup entries (use cache)
    startup = _get_startup_entries()
    summary["startup"] = {
        "total": startup.get("total", 0),
        "suspicious": startup.get("suspicious_count", 0),
        "entries": startup.get("suspicious", [])[:5],
    }

    # Ransomware monitor
    try:
        from ai_scam_protection.ransomware_monitor import get_monitor
        monitor = get_monitor()
        if monitor:
            rs = monitor.get_status()
            summary["ransomware"] = {
                "active": rs.is_active,
                "risk_score": rs.risk_score,
                "rename_count_30s": rs.rename_count_last_30s,
                "ransom_extensions": rs.ransom_extensions_seen,
                "recent_events": len(rs.events),
            }
        else:
            summary["ransomware"] = {"active": False, "risk_score": 0}
    except Exception:
        summary["ransomware"] = {"active": False, "risk_score": 0}

    # Rootkit (use cache)
    rootkit = _get_rootkit_result()
    if rootkit.get("status") == "complete":
        rk = rootkit.get("result", {})
        summary["rootkit"] = {
            "score": rk.get("total_score", 0),
            "clean": rk.get("clean", True),
            "indicator_count": len(rk.get("indicators", [])),
        }
    else:
        summary["rootkit"] = {"score": 0, "clean": True, "indicator_count": 0}

    # Recent detections count
    events = _load_events(config)
    high_count = sum(
        1 for e in events
        if e.get("type") in {"watch_detection", "scan"}
        and isinstance(e.get("payload"), dict)
        and e["payload"].get("level") == "high"
    )
    summary["detections"] = {"high_risk_total": high_count}

    # Overall EDR risk score
    risk = 0
    if summary["processes"]["high_risk"] > 0:
        risk += 30
    if summary["startup"]["suspicious"] > 0:
        risk += 20
    if summary["ransomware"]["risk_score"] > 0:
        risk += summary["ransomware"]["risk_score"] // 2
    if not summary["rootkit"]["clean"]:
        risk += 30
    summary["overall_risk_score"] = min(risk, 100)
    summary["overall_risk_level"] = (
        "high" if risk >= 70 else "medium" if risk >= 35 else "low" if risk > 0 else "clean"
    )

    return summary


# ── Autonomous response ────────────────────────────────────────────────────────

def _do_autonomous_response(body: dict, config) -> dict:
    """
    Execute an autonomous response action.
    Body: {
        "action": "kill_process" | "block_network" | "create_snapshot" | "restore_snapshot",
        "pid": int (for kill_process),
        "process_name": str (for block_network),
        "drive": str (for create_snapshot, default "C:"),
        "shadow_id": str (for restore_snapshot),
        "target_path": str (for restore_snapshot),
        "threat_description": str
    }
    """
    from ai_scam_protection.autonomous_response import AutonomousResponder

    action = body.get("action", "")
    threat_desc = body.get("threat_description", "Manual response action")

    responder = AutonomousResponder(
        log_file=config.log_file,
        allow_process_kill=body.get("allow_kill", False),
        allow_network_block=True,
        allow_snapshot=True,
    )

    if action == "kill_process":
        pid = body.get("pid")
        if not pid:
            return {"error": "pid required for kill_process"}
        result = responder.kill_process(int(pid))
        return result.to_dict()

    elif action == "block_network":
        process_name = body.get("process_name", "")
        if not process_name:
            return {"error": "process_name required for block_network"}
        result = responder.block_process_network(process_name)
        return result.to_dict()

    elif action == "create_snapshot":
        drive = body.get("drive", "C:")
        result = responder.create_vss_snapshot(drive)
        return result.to_dict()

    elif action == "restore_snapshot":
        shadow_id = body.get("shadow_id", "")
        target_path = body.get("target_path", "")
        if not shadow_id or not target_path:
            return {"error": "shadow_id and target_path required for restore_snapshot"}
        result = responder.restore_from_snapshot(shadow_id, Path(target_path))
        return result.to_dict()

    elif action == "auto":
        # Full automated response
        file_path = Path(body["file_path"]) if body.get("file_path") else None
        result = responder.respond_to_threat(
            threat_description=threat_desc,
            file_path=file_path,
            pid=body.get("pid"),
            process_name=body.get("process_name"),
            auto_quarantine=body.get("auto_quarantine", False),
        )
        return result.to_dict()

    return {"error": f"Unknown action: {action}. Use: kill_process, block_network, create_snapshot, restore_snapshot, auto"}


# ── Realtime engine enable/disable ───────────────────────────────────────────────

def _do_realtime_enable(config) -> dict:
    """Enable and start the in-process realtime engine."""
    try:
        from ai_scam_protection.realtime_engine import get_engine

        engine = get_engine(config)
        engine.start()
        status = engine.get_status()
        return {
            "ok": True,
            "enabled": status.enabled,
            "running": status.running,
            "started_at": status.started_at,
            "last_error": status.last_error,
            "watched_paths": status.watched_paths,
            "timestamp": utc_now(),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "timestamp": utc_now()}


def _do_realtime_disable(config) -> dict:
    """Disable and stop the in-process realtime engine."""
    try:
        from ai_scam_protection.realtime_engine import get_engine

        engine = get_engine(config)
        engine.stop()
        status = engine.get_status()
        return {
            "ok": True,
            "enabled": status.enabled,
            "running": status.running,
            "started_at": status.started_at,
            "last_error": status.last_error,
            "watched_paths": status.watched_paths,
            "timestamp": utc_now(),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "timestamp": utc_now()}


def _do_realtime_status(config) -> dict:
    """Get current realtime engine status."""
    try:
        from ai_scam_protection.realtime_engine import get_engine

        engine = get_engine(config)
        status = engine.get_status()
        return {
            "ok": True,
            "enabled": status.enabled,
            "running": status.running,
            "started_at": status.started_at,
            "last_error": status.last_error,
            "watched_paths": status.watched_paths,
            "timestamp": utc_now(),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "timestamp": utc_now()}


# ── SSE live telemetry stream ──────────────────────────────────────────────────

def _sse_stream(handler: BaseHTTPRequestHandler, config) -> None:
    """
    Server-Sent Events stream for live telemetry.
    Clients connect to GET /api/events/stream and receive real-time events.
    """
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.send_header("Connection", "keep-alive")
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()

    last_event_count = [0]

    def _send(data: dict) -> bool:
        try:
            msg = f"data: {json.dumps(data, default=str)}\n\n"
            handler.wfile.write(msg.encode("utf-8"))
            handler.wfile.flush()
            return True
        except Exception:
            return False

    # Send initial connection event
    if not _send({"type": "connected", "timestamp": utc_now(), "message": "ShieldScan telemetry stream connected"}):
        return

    try:
        while True:
            time.sleep(2)

            # Check for new events in events.jsonl
            events = _load_events(config)
            if len(events) > last_event_count[0]:
                new_events = events[last_event_count[0]:]
                last_event_count[0] = len(events)
                for event in new_events[-10:]:  # max 10 at once
                    payload = event.get("payload", {})
                    if not isinstance(payload, dict):
                        continue
                    if not _send({
                        "type": "detection",
                        "event_type": event.get("type"),
                        "timestamp": event.get("timestamp"),
                        "level": payload.get("level", "info"),
                        "path": payload.get("path") or payload.get("original_path", ""),
                        "score": payload.get("score", 0),
                    }):
                        return

            # Send heartbeat every 10 seconds
            if not _send({"type": "heartbeat", "timestamp": utc_now(), "uptime": int(time.time() - _start_time)}):
                return

    except Exception:
        pass


# ── Server startup ─────────────────────────────────────────────────────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle each request in a separate thread to avoid connection backlog."""
    daemon_threads = True
    allow_reuse_address = True


def run_server(port: int = PORT, quiet: bool = False) -> None:
    # Start WireGuard VPN REST API in background thread
    try:
        from ai_scam_protection.wireguard_vpn import start_vpn_server
        wg_thread = threading.Thread(
            target=start_vpn_server,
            daemon=True,
            name="WireGuardVPN"
        )
        wg_thread.start()
        if not quiet:
            print("🔒 WireGuard VPN API running on http://127.0.0.1:51821")
    except Exception as e:
        if not quiet:
            print(f"⚠️  WireGuard VPN API not started: {e}")

    server = ThreadedHTTPServer(("127.0.0.1", port), ShieldScanAPIHandler)
    if not quiet:
        print(f"🛡️  ShieldScan API server running on http://localhost:{port}")
        print(f"   Endpoints: /api/stats  /api/status  /api/detections  /api/scan")
        print(f"              /api/processes  /api/ransomware  /api/startup  /api/rootkit")
        print(f"   Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if not quiet:
            print("\nAPI server stopped.")


if __name__ == "__main__":
    run_server()
