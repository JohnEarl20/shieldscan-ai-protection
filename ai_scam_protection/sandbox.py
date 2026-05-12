"""
Sandbox / behavior simulation for ShieldScan.

Since running a true kernel-level sandbox requires a hypervisor, this module
implements a *static behavioral sandbox*: it inspects the file's content for
behaviors that would be observed if the file were executed in an isolated VM.

Checks performed:
  - File system manipulation (system file writes, mass-rename patterns)
  - Network activity (C2 beacons, DNS lookups, raw socket usage)
  - Process spawning (cmd, powershell, wscript, mshta child processes)
  - Registry manipulation (run keys, security policy changes)
  - Anti-analysis tricks (VM detection, debugger detection, sleep loops)
  - Privilege escalation (token impersonation, UAC bypass)
  - Data exfiltration (clipboard access, screenshot, keylogging)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BehaviorIndicator:
    category: str
    name: str
    description: str
    severity: str   # "low" | "medium" | "high"
    score: int
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "score": self.score,
            "evidence": self.evidence,
        }


@dataclass
class SandboxResult:
    total_score: int
    verdict: str                    # "clean" | "suspicious" | "malicious"
    indicators: list[BehaviorIndicator] = field(default_factory=list)
    categories_hit: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_score": self.total_score,
            "verdict": self.verdict,
            "indicators": [i.to_dict() for i in self.indicators],
            "categories_hit": self.categories_hit,
        }


# ── Behavior pattern definitions ───────────────────────────────────────────────

_BEHAVIOR_PATTERNS: list[dict] = [
    # ── File system ──────────────────────────────────────────────────────────
    {
        "category": "filesystem",
        "name": "system_file_write",
        "description": "Writes to protected system directories",
        "severity": "high",
        "score": 55,
        "patterns": [
            r"\\windows\\system32",
            r"\\windows\\syswow64",
            r"\\windows\\winsxs",
            r"c:\\windows\\",
        ],
    },
    {
        "category": "filesystem",
        "name": "mass_file_rename",
        "description": "Renames many files — ransomware-like behavior",
        "severity": "high",
        "score": 65,
        "patterns": [
            r"rename.*\.\w{3,6}",
            r"move-item.*\.\w{3,6}",
            r"\.locked",
            r"\.encrypted",
            r"\.crypted",
            r"\.enc\b",
        ],
    },
    {
        "category": "filesystem",
        "name": "shadow_copy_deletion",
        "description": "Deletes Volume Shadow Copies (ransomware tactic)",
        "severity": "high",
        "score": 80,
        "patterns": [
            r"vssadmin.*delete.*shadows",
            r"wmic.*shadowcopy.*delete",
            r"wbadmin.*delete.*catalog",
            r"bcdedit.*recoveryenabled.*no",
        ],
    },
    {
        "category": "filesystem",
        "name": "temp_execution",
        "description": "Drops and executes files from Temp directory",
        "severity": "medium",
        "score": 35,
        "patterns": [
            r"\\appdata\\local\\temp\\.*\.(exe|bat|ps1|vbs|cmd)",
            r"\\temp\\.*\.(exe|bat|ps1|vbs|cmd)",
            r"%temp%.*\.(exe|bat|ps1|vbs|cmd)",
        ],
    },

    # ── Network ──────────────────────────────────────────────────────────────
    {
        "category": "network",
        "name": "raw_socket",
        "description": "Creates raw network sockets (port scanning / C2)",
        "severity": "medium",
        "score": 40,
        "patterns": [
            r"socket\(",
            r"wsasocket",
            r"raw socket",
            r"sock_raw",
        ],
    },
    {
        "category": "network",
        "name": "dns_lookup_suspicious",
        "description": "Resolves suspicious or dynamic DNS domains",
        "severity": "medium",
        "score": 35,
        "patterns": [
            r"\.duckdns\.org",
            r"\.no-ip\.com",
            r"\.ddns\.net",
            r"\.hopto\.org",
            r"\.zapto\.org",
            r"\.servebeer\.com",
        ],
    },
    {
        "category": "network",
        "name": "c2_beacon",
        "description": "Periodic HTTP/S beacon to remote server",
        "severity": "high",
        "score": 60,
        "patterns": [
            r"while.*true.*sleep.*http",
            r"invoke-restmethod.*loop",
            r"webclient.*downloadstring.*loop",
            r"start-sleep.*invoke-webrequest",
        ],
    },
    {
        "category": "network",
        "name": "data_exfiltration",
        "description": "Sends local data to remote server",
        "severity": "high",
        "score": 65,
        "patterns": [
            r"uploadfile\(",
            r"uploadstring\(",
            r"invoke-webrequest.*-method.*post",
            r"ftp.*put",
            r"smtp.*send",
        ],
    },

    # ── Process spawning ─────────────────────────────────────────────────────
    {
        "category": "process",
        "name": "suspicious_child_process",
        "description": "Spawns suspicious child processes",
        "severity": "medium",
        "score": 40,
        "patterns": [
            r"start-process.*powershell",
            r"start-process.*cmd",
            r"start-process.*wscript",
            r"start-process.*mshta",
            r"createprocess.*cmd\.exe",
            r"shellexecute.*powershell",
        ],
    },
    {
        "category": "process",
        "name": "process_hollowing",
        "description": "Hollows a legitimate process to hide malicious code",
        "severity": "high",
        "score": 75,
        "patterns": [
            r"createprocess.*suspended",
            r"ntunmapviewofsection",
            r"zwunmapviewofsection",
            r"process hollowing",
            r"virtualallocex.*writeprocessmemory.*resumethread",
        ],
    },
    {
        "category": "process",
        "name": "self_deletion",
        "description": "Deletes itself after execution (anti-forensics)",
        "severity": "medium",
        "score": 45,
        "patterns": [
            r"del.*%0",
            r"remove-item.*\$myinvocation",
            r"self.delete",
            r"deleteself",
        ],
    },

    # ── Registry ─────────────────────────────────────────────────────────────
    {
        "category": "registry",
        "name": "disable_security_policy",
        "description": "Modifies security policy registry keys",
        "severity": "high",
        "score": 60,
        "patterns": [
            r"reg.*add.*policies.*system.*disabletaskmgr",
            r"reg.*add.*policies.*system.*disableregistrytools",
            r"reg.*add.*policies.*system.*disablecmd",
            r"reg.*add.*winlogon.*shell",
        ],
    },
    {
        "category": "registry",
        "name": "persistence_run_key",
        "description": "Adds entry to registry Run key for persistence",
        "severity": "high",
        "score": 55,
        "patterns": [
            r"reg.*add.*\\run\b",
            r"new-itemproperty.*\\run\b",
            r"set-itemproperty.*\\run\b",
            r"\\currentversion\\run",
        ],
    },

    # ── Anti-analysis ────────────────────────────────────────────────────────
    {
        "category": "anti_analysis",
        "name": "vm_detection",
        "description": "Checks for virtual machine environment",
        "severity": "medium",
        "score": 35,
        "patterns": [
            r"vmware",
            r"virtualbox",
            r"vbox",
            r"qemu",
            r"sandboxie",
            r"cuckoo",
            r"win32_computersystem.*manufacturer.*vmware",
            r"cpuid.*hypervisor",
        ],
    },
    {
        "category": "anti_analysis",
        "name": "debugger_detection",
        "description": "Checks if a debugger is attached",
        "severity": "medium",
        "score": 30,
        "patterns": [
            r"isdebuggerpresent",
            r"checkremotedebuggerpresent",
            r"ntqueryinformationprocess.*processdebugport",
            r"outputdebugstring",
        ],
    },
    {
        "category": "anti_analysis",
        "name": "sleep_evasion",
        "description": "Uses long sleep to evade sandbox time limits",
        "severity": "low",
        "score": 15,
        "patterns": [
            r"start-sleep\s+-seconds\s+[3-9]\d{2,}",
            r"sleep\(\s*[3-9]\d{5,}\s*\)",
            r"thread\.sleep\(\s*[3-9]\d{5,}\s*\)",
        ],
    },

    # ── Privilege escalation ─────────────────────────────────────────────────
    {
        "category": "privilege",
        "name": "token_impersonation",
        "description": "Impersonates another user's security token",
        "severity": "high",
        "score": 60,
        "patterns": [
            r"impersonateloggedonuser",
            r"seimpersonateprivilege",
            r"adjusttokenprivileges",
            r"duplicatetokenex",
            r"createprocesswithtoken",
        ],
    },
    {
        "category": "privilege",
        "name": "uac_bypass",
        "description": "Bypasses User Account Control",
        "severity": "high",
        "score": 65,
        "patterns": [
            r"fodhelper",
            r"eventvwr.*msc",
            r"sdclt",
            r"computerdefaults",
            r"bypassuac",
        ],
    },

    # ── Data theft ───────────────────────────────────────────────────────────
    {
        "category": "data_theft",
        "name": "clipboard_access",
        "description": "Reads clipboard contents",
        "severity": "medium",
        "score": 30,
        "patterns": [
            r"get-clipboard",
            r"openclipboard",
            r"getclipboarddata",
            r"clipboard\.gettext",
        ],
    },
    {
        "category": "data_theft",
        "name": "browser_credential_theft",
        "description": "Accesses browser credential stores",
        "severity": "high",
        "score": 70,
        "patterns": [
            r"login data",
            r"chrome.*cookies",
            r"firefox.*logins\.json",
            r"edge.*login data",
            r"appdata.*chrome.*user data",
            r"appdata.*mozilla.*firefox",
        ],
    },
    {
        "category": "data_theft",
        "name": "crypto_wallet_theft",
        "description": "Targets cryptocurrency wallet files",
        "severity": "high",
        "score": 70,
        "patterns": [
            r"wallet\.dat",
            r"electrum.*wallets",
            r"metamask",
            r"exodus.*wallet",
            r"\.keystore",
            r"seed phrase",
            r"mnemonic",
        ],
    },
]


def run_sandbox(data: bytes, filename: str = "") -> SandboxResult:
    """
    Static behavioral sandbox analysis.
    Inspects file content for behaviors that would be observed at runtime.
    """
    try:
        text = data.decode("utf-8", errors="ignore").lower()
    except Exception:
        text = ""

    indicators: list[BehaviorIndicator] = []
    categories_hit: set[str] = set()

    for bp in _BEHAVIOR_PATTERNS:
        matched_evidence: list[str] = []
        for pattern in bp["patterns"]:
            try:
                matches = re.findall(pattern, text)
                if matches:
                    matched_evidence.append(pattern)
            except re.error:
                if pattern in text:
                    matched_evidence.append(pattern)

        if matched_evidence:
            indicators.append(
                BehaviorIndicator(
                    category=bp["category"],
                    name=bp["name"],
                    description=bp["description"],
                    severity=bp["severity"],
                    score=bp["score"],
                    evidence=matched_evidence[:3],
                )
            )
            categories_hit.add(bp["category"])

    # Deduplicate by name
    seen: set[str] = set()
    unique: list[BehaviorIndicator] = []
    for ind in indicators:
        if ind.name not in seen:
            seen.add(ind.name)
            unique.append(ind)

    total_score = min(sum(i.score for i in unique), 100)

    if total_score >= 60:
        verdict = "malicious"
    elif total_score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return SandboxResult(
        total_score=total_score,
        verdict=verdict,
        indicators=unique,
        categories_hit=sorted(categories_hit),
    )
