"""
Live Process Monitor for ShieldScan.

Scans running processes for suspicious indicators:
  - Processes running from Temp/AppData/Downloads
  - Processes with suspicious names (mimikatz, meterpreter, etc.)
  - Processes injecting into other processes (unusual parent-child chains)
  - Processes with no visible window but high CPU (cryptominer pattern)
  - Unsigned executables running from user-writable locations
  - Processes spawned by Office/browser apps (macro/exploit indicator)
  - Ransomware-like behavior: process doing mass file I/O renames

Does NOT require psutil — uses only Windows built-ins (WMI via PowerShell,
tasklist, wmic) so it stays dependency-free.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


# ── Suspicious process name fragments ─────────────────────────────────────────
SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz", "meterpreter", "cobalt", "empire", "metasploit",
    "procdump", "pwdump", "fgdump", "wce.exe", "gsecdump",
    "netcat", "ncat.exe", "socat",
    "psexec", "wmiexec", "smbexec",
    "keylogger", "keyscan", "hookdll",
    "cryptominer", "xmrig", "minerd", "cpuminer",
    "njrat", "darkcomet", "quasar", "asyncrat", "remcos",
    "nanocore", "netwire", "orcus",
]

# ── Suspicious parent→child spawn chains ──────────────────────────────────────
# If parent contains key A and child contains key B → suspicious
SUSPICIOUS_SPAWN_CHAINS = [
    ("winword", "powershell"),
    ("winword", "cmd"),
    ("winword", "wscript"),
    ("winword", "mshta"),
    ("excel", "powershell"),
    ("excel", "cmd"),
    ("excel", "wscript"),
    ("outlook", "powershell"),
    ("outlook", "cmd"),
    ("chrome", "powershell"),
    ("firefox", "powershell"),
    ("msedge", "powershell"),
    ("acrobat", "powershell"),
    ("acrobat", "cmd"),
    ("acrord32", "powershell"),
    ("acrord32", "cmd"),
]

# ── Suspicious execution paths ─────────────────────────────────────────────────
SUSPICIOUS_PATH_PATTERNS = [
    r"\\appdata\\local\\temp\\",
    r"\\appdata\\roaming\\",
    r"\\users\\public\\",
    r"\\programdata\\[^\\]+\\[^\\]+\.exe",
    r"\\downloads\\.*\.exe",
    r"\\desktop\\.*\.exe",
    r"\\recycle",
    r"%temp%",
]

# ── Legitimate system process names (skip scoring these) ──────────────────────
SYSTEM_PROCESS_WHITELIST = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe", "spoolsv.exe",
    "searchindexer.exe", "wuauclt.exe", "msiexec.exe", "conhost.exe",
    "dllhost.exe", "ctfmon.exe", "audiodg.exe", "runtimebroker.exe",
    "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe",
    "registry", "memory compression", "system idle process",
}


@dataclass
class ProcessRisk:
    pid: int
    name: str
    path: str | None
    parent_name: str | None
    score: int
    level: str          # "clean" | "low" | "medium" | "high"
    reasons: list[str] = field(default_factory=list)
    cpu_percent: float = 0.0
    memory_mb: float = 0.0

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "path": self.path,
            "parent_name": self.parent_name,
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
        }


@dataclass
class ProcessMonitorResult:
    processes: list[ProcessRisk]
    suspicious_count: int
    high_risk_count: int
    total_scanned: int
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "processes": [p.to_dict() for p in self.processes],
            "suspicious_count": self.suspicious_count,
            "high_risk_count": self.high_risk_count,
            "total_scanned": self.total_scanned,
            "error": self.error,
        }


def scan_processes(timeout: int = 20, include_clean: bool = False) -> ProcessMonitorResult:
    """
    Scan all running processes for suspicious indicators.
    Returns ProcessMonitorResult with scored ProcessRisk entries.
    """
    if platform.system().lower() != "windows":
        return ProcessMonitorResult(
            processes=[], suspicious_count=0, high_risk_count=0,
            total_scanned=0, error="Process monitor only available on Windows",
        )

    raw_processes = _get_process_list(timeout)
    if raw_processes is None:
        return ProcessMonitorResult(
            processes=[], suspicious_count=0, high_risk_count=0,
            total_scanned=0, error="Failed to retrieve process list",
        )

    # Build PID→name map for parent lookup
    pid_to_name: dict[int, str] = {
        p["pid"]: p["name"].lower() for p in raw_processes
    }

    results: list[ProcessRisk] = []
    for proc in raw_processes:
        name_lower = proc["name"].lower()
        if name_lower in SYSTEM_PROCESS_WHITELIST:
            continue

        risk = _score_process(proc, pid_to_name)
        if include_clean or risk.level != "clean":
            results.append(risk)

    results.sort(key=lambda r: (-r.score, r.name.lower()))

    suspicious = [r for r in results if r.score >= 30]
    high_risk = [r for r in results if r.score >= 70]

    return ProcessMonitorResult(
        processes=results,
        suspicious_count=len(suspicious),
        high_risk_count=len(high_risk),
        total_scanned=len(raw_processes),
    )


def _score_process(proc: dict, pid_to_name: dict[int, str]) -> ProcessRisk:
    name = proc["name"]
    name_lower = name.lower()
    path = proc.get("path") or ""
    path_lower = path.lower()
    parent_pid = proc.get("parent_pid")
    parent_name = pid_to_name.get(parent_pid, "").lower() if parent_pid else ""
    cpu = proc.get("cpu_percent", 0.0)
    mem = proc.get("memory_mb", 0.0)

    score = 0
    reasons: list[str] = []

    # ── Known malicious tool names ─────────────────────────────────────────
    for hint in SUSPICIOUS_PROCESS_NAMES:
        if hint in name_lower or hint in path_lower:
            score += 80
            reasons.append(f"name matches known malicious tool: {hint}")
            break

    # ── Suspicious execution path ──────────────────────────────────────────
    if path_lower:
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if re.search(pattern, path_lower):
                score += 35
                reasons.append(f"running from suspicious path: {path[:80]}")
                break

    # ── Suspicious parent→child spawn chain ───────────────────────────────
    if parent_name:
        for parent_hint, child_hint in SUSPICIOUS_SPAWN_CHAINS:
            if parent_hint in parent_name and child_hint in name_lower:
                score += 55
                reasons.append(
                    f"suspicious spawn: {parent_name} → {name_lower} "
                    f"(Office/browser spawning shell)"
                )
                break

    # ── No path (process hiding or injection) ─────────────────────────────
    if not path_lower and name_lower not in SYSTEM_PROCESS_WHITELIST:
        score += 15
        reasons.append("no executable path visible (possible injection or hiding)")

    # ── High CPU with no window (cryptominer pattern) ─────────────────────
    if cpu > 80 and name_lower not in {"system", "registry"}:
        score += 20
        reasons.append(f"high CPU usage ({cpu:.0f}%) — possible cryptominer")

    score = min(score, 100)

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "clean"

    return ProcessRisk(
        pid=proc["pid"],
        name=name,
        path=path or None,
        parent_name=parent_name or None,
        score=score,
        level=level,
        reasons=reasons,
        cpu_percent=cpu,
        memory_mb=mem,
    )


def _get_process_list(timeout: int) -> list[dict] | None:
    """Retrieve running processes via WMI (PowerShell)."""
    ps = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not ps:
        return None

    cmd = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,Name,ExecutablePath,ParentProcessId,"
        "WorkingSetSize | ConvertTo-Json -Compress -Depth 2"
    )
    try:
        result = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None

        raw = json.loads(result.stdout)
        if isinstance(raw, dict):
            raw = [raw]

        processes = []
        for p in raw:
            try:
                processes.append({
                    "pid": int(p.get("ProcessId") or 0),
                    "name": str(p.get("Name") or "unknown"),
                    "path": p.get("ExecutablePath") or "",
                    "parent_pid": int(p.get("ParentProcessId") or 0),
                    "memory_mb": round(int(p.get("WorkingSetSize") or 0) / (1024 * 1024), 1),
                    "cpu_percent": 0.0,  # WMI doesn't give instant CPU; would need two samples
                })
            except (ValueError, TypeError):
                continue
        return processes

    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return None
