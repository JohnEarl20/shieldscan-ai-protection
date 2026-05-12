"""
Heuristic analysis engine for ShieldScan.

Checks suspicious behaviors that indicate malware even when the file
is not in the known-bad hash list:
  - Editing system files / registry run keys
  - Disabling Windows Defender
  - Auto-startup persistence tricks
  - Process injection patterns
  - Ransomware-like file-rename loops
  - Obfuscation / packing indicators
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


# ── YARA-style rule definitions ────────────────────────────────────────────────

@dataclass(frozen=True)
class YaraRule:
    name: str
    description: str
    severity: str          # "low" | "medium" | "high"
    score: int
    patterns: list[str]    # all must match (AND logic within a rule)
    any_of: list[str] = field(default_factory=list)   # at least one must match


# Rules are evaluated against the lowercased decoded text of the file head.
YARA_RULES: list[YaraRule] = [
    # ── Defender / AV disabling ────────────────────────────────────────────
    YaraRule(
        name="disable_defender",
        description="Attempts to disable Windows Defender real-time protection",
        severity="high",
        score=60,
        patterns=[],
        any_of=[
            "set-mppreference -disablerealtimemonitoring",
            "set-mppreference -disableioavprotection",
            "set-mppreference -disablebehaviormonitoring",
            "add-mppreference -exclusionpath",
            "sc stop windefend",
            "sc config windefend start= disabled",
            "net stop windefend",
            "reg add.*windows defender.*disableantispyware",
        ],
    ),
    # ── Registry persistence ───────────────────────────────────────────────
    YaraRule(
        name="registry_autorun",
        description="Writes to registry auto-start locations",
        severity="high",
        score=50,
        patterns=[],
        any_of=[
            r"\\currentversion\\run",
            r"\\currentversion\\runonce",
            r"\\currentversion\\runservices",
            "reg add.*\\\\run",
            "new-itemproperty.*run",
            "set-itemproperty.*run",
        ],
    ),
    # ── Scheduled task persistence ─────────────────────────────────────────
    YaraRule(
        name="scheduled_task_persistence",
        description="Creates a scheduled task for persistence",
        severity="medium",
        score=35,
        patterns=["schtasks"],
        any_of=["/create", "-taskname", "new-scheduledtask"],
    ),
    # ── Process injection ──────────────────────────────────────────────────
    YaraRule(
        name="process_injection",
        description="Injects code into another process",
        severity="high",
        score=65,
        patterns=[],
        any_of=[
            "virtualallocex",
            "writeprocessmemory",
            "createremotethread",
            "ntcreatethreadex",
            "rtlcreateuserthread",
            "queueuserapc",
            "setwindowshookex",
            "reflectivedllinjection",
            "process hollowing",
        ],
    ),
    # ── Ransomware indicators ──────────────────────────────────────────────
    YaraRule(
        name="ransomware_behavior",
        description="Ransomware-like file encryption / rename loop",
        severity="high",
        score=70,
        patterns=[],
        any_of=[
            "cryptoapi",
            "bcryptencrypt",
            "cryptencrypt",
            "vssadmin delete shadows",
            "wbadmin delete catalog",
            "wmic shadowcopy delete",
            "bcdedit /set {default} recoveryenabled no",
            "readme_to_decrypt",
            "your_files_are_encrypted",
            "how_to_recover",
            ".locked",
            ".encrypted",
            ".crypted",
        ],
    ),
    # ── Credential harvesting ──────────────────────────────────────────────
    YaraRule(
        name="credential_harvesting",
        description="Attempts to steal credentials or dump LSASS",
        severity="high",
        score=65,
        patterns=[],
        any_of=[
            "sekurlsa::logonpasswords",
            "lsass.exe",
            "mimikatz",
            "procdump",
            "comsvcs.dll",
            "minidump",
            "ntlm hash",
            "sam database",
            "credential manager",
        ],
    ),
    # ── Lateral movement ──────────────────────────────────────────────────
    YaraRule(
        name="lateral_movement",
        description="Attempts to move laterally across the network",
        severity="high",
        score=55,
        patterns=[],
        any_of=[
            "psexec",
            "wmiexec",
            "invoke-wmimethod",
            "invoke-cimmethod",
            "enter-pssession",
            "new-pssession",
            "net use \\\\",
            "copy.*\\\\.*\\admin$",
        ],
    ),
    # ── Downloader / dropper ───────────────────────────────────────────────
    YaraRule(
        name="downloader_dropper",
        description="Downloads and executes a secondary payload",
        severity="high",
        score=55,
        patterns=[],
        any_of=[
            "downloadfile(",
            "downloadstring(",
            "start-bitstransfer",
            "invoke-webrequest",
            "wget ",
            "curl ",
            "certutil -urlcache",
            "bitsadmin /transfer",
            "xmlhttp",
            "winhttprequest",
        ],
    ),
    # ── Obfuscation / encoding ─────────────────────────────────────────────
    YaraRule(
        name="heavy_obfuscation",
        description="Heavy use of encoding / obfuscation to hide intent",
        severity="medium",
        score=40,
        patterns=[],
        any_of=[
            "frombase64string",
            "convert]::frombase64",
            "[char]",
            "-join",
            "iex(",
            "invoke-expression",
            "-encodedcommand",
            "-enc ",
            "gzip",
            "deflate",
            "decompress",
        ],
    ),
    # ── UAC bypass ────────────────────────────────────────────────────────
    YaraRule(
        name="uac_bypass",
        description="Attempts to bypass User Account Control",
        severity="high",
        score=60,
        patterns=[],
        any_of=[
            "fodhelper",
            "eventvwr",
            "sdclt",
            "computerdefaults",
            "bypassuac",
            "bypass uac",
            "requestedexecutionlevel",
            "highestAvailable",
        ],
    ),
    # ── Keylogger / screen capture ─────────────────────────────────────────
    YaraRule(
        name="keylogger_spyware",
        description="Keylogger or screen-capture spyware patterns",
        severity="high",
        score=60,
        patterns=[],
        any_of=[
            "getasynckeystate",
            "setwinhook",
            "setwindowshookex",
            "keylogger",
            "screencapture",
            "printwindow",
            "bitblt",
            "capturescreenshot",
        ],
    ),
    # ── Rootkit / kernel tampering ─────────────────────────────────────────
    YaraRule(
        name="rootkit_indicators",
        description="Rootkit or kernel-level hiding techniques",
        severity="high",
        score=70,
        patterns=[],
        any_of=[
            "ntquerysysteminformation",
            "zwquerysysteminformation",
            "dkom",
            "direct kernel object manipulation",
            "ssdt hook",
            "idt hook",
            "driverentry",
            "zwsetinformationfile",
            "ntfscontrolfile",
            "\\device\\physicalmemory",
            "\\\\.\\\\.\\physicalmemory",
        ],
    ),
    # ── Suspicious PowerShell execution policy bypass ──────────────────────
    YaraRule(
        name="powershell_bypass",
        description="PowerShell execution policy bypass",
        severity="medium",
        score=30,
        patterns=["powershell"],
        any_of=[
            "executionpolicy bypass",
            "executionpolicy unrestricted",
            "-noprofile",
            "-windowstyle hidden",
            "-noninteractive",
        ],
    ),
    # ── Suspicious network C2 patterns ────────────────────────────────────
    YaraRule(
        name="c2_communication",
        description="Command-and-control communication patterns",
        severity="medium",
        score=40,
        patterns=[],
        any_of=[
            "reverse shell",
            "bind shell",
            "netcat",
            "ncat ",
            "socat ",
            "meterpreter",
            "cobalt strike",
            "beacon",
            "empire",
            "metasploit",
        ],
    ),
]


@dataclass
class HeuristicFinding:
    rule: str
    description: str
    severity: str
    score: int
    matched_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "description": self.description,
            "severity": self.severity,
            "score": self.score,
            "matched_patterns": self.matched_patterns,
        }


@dataclass
class HeuristicResult:
    total_score: int
    findings: list[HeuristicFinding] = field(default_factory=list)
    entropy: float = 0.0
    is_packed: bool = False
    is_obfuscated: bool = False

    def to_dict(self) -> dict:
        return {
            "total_score": self.total_score,
            "entropy": round(self.entropy, 3),
            "is_packed": self.is_packed,
            "is_obfuscated": self.is_obfuscated,
            "findings": [f.to_dict() for f in self.findings],
        }


def analyze_heuristics(data: bytes, filename: str = "") -> HeuristicResult:
    """
    Run all YARA-style heuristic rules against raw file bytes.
    Returns a HeuristicResult with a cumulative score and individual findings.
    """
    findings: list[HeuristicFinding] = []

    # Decode to text for pattern matching
    try:
        text = data.decode("utf-8", errors="ignore").lower()
    except Exception:
        text = ""

    # Run YARA-style rules
    for rule in YARA_RULES:
        matched = _match_rule(rule, text)
        if matched:
            findings.append(
                HeuristicFinding(
                    rule=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    score=rule.score,
                    matched_patterns=matched,
                )
            )

    # Entropy / packing check
    entropy = _shannon_entropy(data)
    is_packed = entropy >= 7.2 and _is_executable_header(data)
    is_obfuscated = _detect_obfuscation(text)

    if is_packed:
        findings.append(
            HeuristicFinding(
                rule="high_entropy_packed",
                description=f"Executable has very high entropy ({entropy:.2f}) — likely packed or encrypted",
                severity="medium",
                score=30,
            )
        )

    if is_obfuscated:
        findings.append(
            HeuristicFinding(
                rule="script_obfuscation",
                description="Script uses heavy character-level obfuscation",
                severity="medium",
                score=25,
            )
        )

    # Deduplicate and cap score
    seen: set[str] = set()
    unique_findings: list[HeuristicFinding] = []
    for f in findings:
        if f.rule not in seen:
            seen.add(f.rule)
            unique_findings.append(f)

    total_score = min(sum(f.score for f in unique_findings), 100)

    return HeuristicResult(
        total_score=total_score,
        findings=unique_findings,
        entropy=entropy,
        is_packed=is_packed,
        is_obfuscated=is_obfuscated,
    )


def _match_rule(rule: YaraRule, text: str) -> list[str]:
    """Returns list of matched pattern strings if the rule fires, else empty list."""
    matched: list[str] = []

    # All required patterns must match
    for pattern in rule.patterns:
        if not _pattern_match(pattern, text):
            return []

    # At least one of any_of must match (if any_of is specified)
    if rule.any_of:
        any_matched = []
        for pattern in rule.any_of:
            if _pattern_match(pattern, text):
                any_matched.append(pattern)
        if not any_matched:
            return []
        matched.extend(any_matched[:3])  # report up to 3 matched patterns
    else:
        matched.extend(rule.patterns[:3])

    return matched


def _pattern_match(pattern: str, text: str) -> bool:
    """Match a pattern (supports simple regex) against text."""
    try:
        return bool(re.search(pattern, text))
    except re.error:
        return pattern in text


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _is_executable_header(data: bytes) -> bool:
    return data[:2] == b"MZ" or data[:4] == b"\x7fELF"


def _detect_obfuscation(text: str) -> bool:
    """Detect character-level obfuscation common in malicious scripts."""
    # High density of [char] casts or chr() calls
    char_cast_count = len(re.findall(r"\[char\]\s*\d+", text))
    chr_call_count = len(re.findall(r"chr\(\s*\d+\s*\)", text))
    if char_cast_count + chr_call_count > 10:
        return True

    # Excessive string concatenation with single chars
    concat_count = len(re.findall(r"['\"][a-z0-9]['\"][\s]*\+[\s]*['\"][a-z0-9]['\"]", text))
    if concat_count > 15:
        return True

    # Very long single-line scripts (common in obfuscated PS1)
    for line in text.splitlines():
        if len(line) > 2000 and ("+" in line or "join" in line):
            return True

    return False
