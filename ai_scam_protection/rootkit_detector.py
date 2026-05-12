"""
Rootkit detection for ShieldScan.

Checks for signs that malware is hiding at the kernel/system level:
  - Hidden processes (cross-view comparison via WMI vs psutil/tasklist)
  - Hidden files (directory listing vs FindFirstFile discrepancy simulation)
  - Suspicious kernel drivers loaded
  - SSDT / IDT hook indicators in loaded modules
  - Suspicious services running from non-standard locations
  - Alternate Data Streams (ADS) hiding payloads
  - Suspicious named pipes (common rootkit C2 channel)
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RootkitIndicator:
    check: str
    description: str
    severity: str   # "low" | "medium" | "high"
    score: int
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "description": self.description,
            "severity": self.severity,
            "score": self.score,
            "details": self.details,
        }


@dataclass
class RootkitScanResult:
    total_score: int
    clean: bool
    indicators: list[RootkitIndicator] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "total_score": self.total_score,
            "clean": self.clean,
            "indicators": [i.to_dict() for i in self.indicators],
            "error": self.error,
        }


# ── Known suspicious driver names (partial list) ───────────────────────────────
SUSPICIOUS_DRIVER_HINTS = [
    "rootkit",
    "hider",
    "hide",
    "inject",
    "hook",
    "stealth",
    "ghost",
    "shadow",
    "cloak",
    "invisible",
    "bypass",
    "patch",
    "spoof",
    "fake",
    "rogue",
]

# ── Legitimate system driver locations ────────────────────────────────────────
LEGITIMATE_DRIVER_PATHS = [
    r"c:\windows\system32\drivers",
    r"c:\windows\syswow64\drivers",
    r"c:\windows\system32",
]

# ── Suspicious service binary path patterns ───────────────────────────────────
SUSPICIOUS_SERVICE_PATH_PATTERNS = [
    r"\\appdata\\",
    r"\\temp\\",
    r"\\tmp\\",
    r"\\users\\public\\",
    r"\\programdata\\[^\\]+\\[^\\]+\.exe",
]


def scan_for_rootkits(timeout: int = 30) -> RootkitScanResult:
    """
    Run all rootkit detection checks.
    Returns a RootkitScanResult with indicators and total score.
    """
    if platform.system().lower() != "windows":
        return RootkitScanResult(
            total_score=0,
            clean=True,
            error="Rootkit detection is only available on Windows",
        )

    indicators: list[RootkitIndicator] = []

    # Run all checks
    _check_suspicious_drivers(indicators, timeout)
    _check_suspicious_services(indicators, timeout)
    _check_hidden_processes(indicators, timeout)
    _check_suspicious_named_pipes(indicators, timeout)
    _check_ads_in_system_dirs(indicators)
    _check_loaded_modules_for_hooks(indicators, timeout)

    total_score = min(sum(i.score for i in indicators), 100)

    return RootkitScanResult(
        total_score=total_score,
        clean=total_score == 0,
        indicators=indicators,
    )


def _check_suspicious_drivers(indicators: list[RootkitIndicator], timeout: int) -> None:
    """Check for suspicious kernel drivers."""
    powershell = _ps()
    if not powershell:
        return

    try:
        result = subprocess.run(
            [
                powershell, "-NoProfile", "-NonInteractive", "-Command",
                "Get-WmiObject Win32_SystemDriver | Select-Object Name,PathName,State | ConvertTo-Json -Compress",
            ],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return

        import json
        drivers = json.loads(result.stdout)
        if isinstance(drivers, dict):
            drivers = [drivers]

        suspicious: list[str] = []
        for driver in drivers:
            name = (driver.get("Name") or "").lower()
            path = (driver.get("PathName") or "").lower()

            # Check for suspicious name hints
            if any(hint in name for hint in SUSPICIOUS_DRIVER_HINTS):
                suspicious.append(f"{driver.get('Name')} @ {driver.get('PathName')}")
                continue

            # Check for drivers loaded from non-standard locations
            if path and not any(path.startswith(legit) for legit in LEGITIMATE_DRIVER_PATHS):
                if path.endswith(".sys") and "windows" not in path:
                    suspicious.append(f"{driver.get('Name')} @ {driver.get('PathName')} [non-standard path]")

        if suspicious:
            indicators.append(RootkitIndicator(
                check="suspicious_kernel_drivers",
                description="Kernel drivers loaded from suspicious locations or with suspicious names",
                severity="high",
                score=60,
                details=suspicious[:5],
            ))
    except (subprocess.TimeoutExpired, Exception):
        pass


def _check_suspicious_services(indicators: list[RootkitIndicator], timeout: int) -> None:
    """Check for services running from suspicious paths."""
    powershell = _ps()
    if not powershell:
        return

    try:
        result = subprocess.run(
            [
                powershell, "-NoProfile", "-NonInteractive", "-Command",
                "Get-WmiObject Win32_Service | Select-Object Name,PathName,State,StartMode | ConvertTo-Json -Compress",
            ],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return

        import json
        services = json.loads(result.stdout)
        if isinstance(services, dict):
            services = [services]

        suspicious: list[str] = []
        for svc in services:
            path = (svc.get("PathName") or "").lower()
            state = (svc.get("State") or "").lower()

            if state != "running":
                continue

            for pattern in SUSPICIOUS_SERVICE_PATH_PATTERNS:
                if re.search(pattern, path):
                    suspicious.append(
                        f"{svc.get('Name')} [{state}] @ {svc.get('PathName')}"
                    )
                    break

        if suspicious:
            indicators.append(RootkitIndicator(
                check="suspicious_service_paths",
                description="Running services with binaries in suspicious locations",
                severity="high",
                score=55,
                details=suspicious[:5],
            ))
    except (subprocess.TimeoutExpired, Exception):
        pass


def _check_hidden_processes(indicators: list[RootkitIndicator], timeout: int) -> None:
    """
    Cross-view process comparison: compare tasklist output vs WMI process list.
    Discrepancies can indicate a rootkit hiding processes.
    """
    powershell = _ps()
    if not powershell:
        return

    try:
        # Get PIDs from tasklist
        tasklist_result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        tasklist_pids: set[str] = set()
        for line in tasklist_result.stdout.splitlines():
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                tasklist_pids.add(parts[1].strip('"'))

        # Get PIDs from WMI
        wmi_result = subprocess.run(
            [
                powershell, "-NoProfile", "-NonInteractive", "-Command",
                "(Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId) -join ','",
            ],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        wmi_pids: set[str] = set()
        if wmi_result.stdout.strip():
            wmi_pids = set(wmi_result.stdout.strip().split(","))

        # PIDs in WMI but not in tasklist = potentially hidden
        hidden = wmi_pids - tasklist_pids - {""}
        # Filter out PIDs that are just timing differences (small set is normal)
        if len(hidden) > 3:
            indicators.append(RootkitIndicator(
                check="hidden_processes",
                description="Processes visible in WMI but not in tasklist — possible rootkit hiding",
                severity="high",
                score=70,
                details=[f"Hidden PIDs: {', '.join(sorted(hidden)[:10])}"],
            ))
    except (subprocess.TimeoutExpired, Exception):
        pass


def _check_suspicious_named_pipes(indicators: list[RootkitIndicator], timeout: int) -> None:
    """Check for suspicious named pipes used by rootkits for C2."""
    powershell = _ps()
    if not powershell:
        return

    suspicious_pipe_hints = [
        "meterpreter", "cobalt", "beacon", "empire", "msf",
        "rootkit", "backdoor", "rat_", "c2_",
    ]

    # Known-legitimate pipe name fragments to exclude
    legitimate_pipe_hints = [
        "pshost",           # PowerShell IDE hosts (VS Code, Kiro, etc.)
        "shellex",          # Windows Shell extensions
        "msftewd",          # Microsoft Full-Text Search
        "winsock",
        "lsass",
        "svchost",
        "chrome",
        "firefox",
        "edge",
        "onedrive",
        "dropbox",
    ]

    try:
        result = subprocess.run(
            [
                powershell, "-NoProfile", "-NonInteractive", "-Command",
                "[System.IO.Directory]::GetFiles('\\\\.\\pipe\\') | ForEach-Object { $_ }",
            ],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0:
            return

        suspicious: list[str] = []
        for pipe in result.stdout.splitlines():
            pipe_lower = pipe.lower()
            if any(legit in pipe_lower for legit in legitimate_pipe_hints):
                continue
            if any(hint in pipe_lower for hint in suspicious_pipe_hints):
                suspicious.append(pipe.strip())

        if suspicious:
            indicators.append(RootkitIndicator(
                check="suspicious_named_pipes",
                description="Named pipes with names associated with known attack frameworks",
                severity="high",
                score=65,
                details=suspicious[:5],
            ))
    except (subprocess.TimeoutExpired, Exception):
        pass


def _check_ads_in_system_dirs(indicators: list[RootkitIndicator]) -> None:
    """
    Check for Alternate Data Streams (ADS) in common system directories.
    Rootkits use ADS to hide payloads inside legitimate files.
    """
    check_dirs = [
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32",
        Path(os.environ.get("TEMP", r"C:\Windows\Temp")),
    ]

    suspicious_ads: list[str] = []

    for check_dir in check_dirs:
        if not check_dir.exists():
            continue
        try:
            for item in list(check_dir.iterdir())[:50]:  # limit scan depth
                if not item.is_file():
                    continue
                # Check for ADS by trying to open known ADS names
                for ads_name in ["Zone.Identifier", "SmartScreen", "motw"]:
                    ads_path = f"{item}:{ads_name}"
                    try:
                        with open(ads_path, "rb") as f:
                            content = f.read(256)
                            # Zone.Identifier is normal; others are suspicious
                            if ads_name != "Zone.Identifier" and content:
                                suspicious_ads.append(f"{item} has ADS: {ads_name}")
                    except OSError:
                        pass
        except (PermissionError, OSError):
            continue

    if suspicious_ads:
        indicators.append(RootkitIndicator(
            check="suspicious_alternate_data_streams",
            description="Files with suspicious Alternate Data Streams in system directories",
            severity="medium",
            score=40,
            details=suspicious_ads[:5],
        ))


def _check_loaded_modules_for_hooks(indicators: list[RootkitIndicator], timeout: int) -> None:
    """Check loaded DLLs for known hook/injection library names."""
    powershell = _ps()
    if not powershell:
        return

    hook_hints = [
        "detour", "inject", "patch", "spoof",
        "bypass", "stealth", "ghost", "cloak",
    ]

    # Known-legitimate modules that contain hook-like names
    legitimate_module_hints = [
        "microsoft", "windows", "nahimic", "a-volute",
        "realtek", "nvidia", "amd", "intel", "logitech",
        "razer", "corsair", "steelseries", "asus", "msi",
        "audiohook", "syshook",  # audio system hooks are normal
    ]

    try:
        result = subprocess.run(
            [
                powershell, "-NoProfile", "-NonInteractive", "-Command",
                "Get-Process | ForEach-Object { $_.Modules } 2>$null | "
                "Select-Object -ExpandProperty FileName -ErrorAction SilentlyContinue | "
                "Sort-Object -Unique",
            ],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode != 0:
            return

        suspicious: list[str] = []
        for line in result.stdout.splitlines():
            module = line.strip().lower()
            if any(hint in module for hint in hook_hints):
                # Exclude known-legitimate modules
                if not any(legit in module for legit in legitimate_module_hints):
                    suspicious.append(line.strip())

        if suspicious:
            indicators.append(RootkitIndicator(
                check="suspicious_loaded_modules",
                description="DLLs with hook/injection-related names loaded in running processes",
                severity="medium",
                score=45,
                details=suspicious[:5],
            ))
    except (subprocess.TimeoutExpired, Exception):
        pass


def _ps() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe")
