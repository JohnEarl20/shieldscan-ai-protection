from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
from pathlib import Path
import re
from typing import Iterable

from .config import DOCUMENT_EXTENSIONS, ProtectionConfig, RISKY_NAME_HINTS, load_bad_hashes
from .heuristics import analyze_heuristics, HeuristicResult
from .ml_engine import build_feature_vector, compute_ai_score, AIScore
from .sandbox import run_sandbox, SandboxResult


TEXT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".txt",
}


EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".com",
    ".pif",
    ".msi",
    ".dll",
    ".sys",
}


@dataclass
class Finding:
    rule: str
    severity: str
    score: int
    message: str


@dataclass
class SourceInfo:
    zone_id: str | None = None
    host_url: str | None = None
    referrer_url: str | None = None

    @property
    def is_internet_zone(self) -> bool:
        return self.zone_id in {"3", "4"}

    def to_dict(self) -> dict[str, str | None]:
        return {
            "zone_id": self.zone_id,
            "host_url": self.host_url,
            "referrer_url": self.referrer_url,
        }


@dataclass
class ScanResult:
    path: Path
    sha256: str | None
    size: int
    score: int
    level: str
    should_block: bool
    source: SourceInfo | None = None
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False
    error: str | None = None
    # New: enriched analysis results
    heuristic: HeuristicResult | None = None
    sandbox: SandboxResult | None = None
    ai_score: AIScore | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "path": str(self.path),
            "sha256": self.sha256,
            "size": self.size,
            "score": self.score,
            "level": self.level,
            "should_block": self.should_block,
            "source": self.source.to_dict() if self.source else None,
            "skipped": self.skipped,
            "error": self.error,
            "findings": [finding.__dict__ for finding in self.findings],
        }
        if self.heuristic:
            result["heuristic"] = self.heuristic.to_dict()
        if self.sandbox:
            result["sandbox"] = self.sandbox.to_dict()
        if self.ai_score:
            result["ai_score"] = self.ai_score.to_dict()
        return result


def scan_file(path: Path, config: ProtectionConfig, bad_hashes: set[str] | None = None) -> ScanResult:
    path = path.expanduser().resolve()
    findings: list[Finding] = []
    bad_hashes = bad_hashes if bad_hashes is not None else load_bad_hashes(config)

    try:
        stat = path.stat()
    except OSError as exc:
        return _result(path, None, 0, findings, config, error=str(exc))

    if not path.is_file():
        return _result(path, None, stat.st_size, findings, config, skipped=True, error="Not a file")

    max_size = config.max_file_size_mb * 1024 * 1024
    if stat.st_size > max_size:
        findings.append(
            Finding(
                rule="size_limit",
                severity="info",
                score=0,
                message=f"Skipped because file is larger than {config.max_file_size_mb} MB",
            )
        )
        return _result(path, None, stat.st_size, findings, config, skipped=True)

    try:
        head = _read_head(path, config.entropy_sample_size)
        digest = sha256_file(path)
    except OSError as exc:
        return _result(path, None, stat.st_size, findings, config, error=str(exc))

    suffix = path.suffix.lower()
    lower_name = path.name.lower()
    source = read_zone_identifier(path)

    # ── Signature-based: known bad hash ────────────────────────────────────
    if digest in bad_hashes:
        findings.append(
            Finding(
                rule="known_bad_hash",
                severity="high",
                score=100,
                message="SHA-256 hash matches the local malicious hash list",
            )
        )

    # ── Extension checks ────────────────────────────────────────────────────
    extension_score = config.suspicious_extensions.get(suffix)
    if extension_score:
        findings.append(
            Finding(
                rule="suspicious_extension",
                severity="medium",
                score=extension_score,
                message=f"File uses risky extension {suffix}",
            )
        )

    double_ext = _detect_double_extension(path)
    if double_ext:
        findings.append(
            Finding(
                rule="double_extension",
                severity="high",
                score=35,
                message=f"File name appears to disguise executable type: {double_ext}",
            )
        )

    # ── Source / zone checks ────────────────────────────────────────────────
    if source and source.is_internet_zone:
        findings.append(
            Finding(
                rule="internet_zone",
                severity="low",
                score=10,
                message="Windows marks this file as downloaded from the internet",
            )
        )

    if any(hint in lower_name for hint in RISKY_NAME_HINTS) and suffix in config.suspicious_extensions:
        findings.append(
            Finding(
                rule="risky_name",
                severity="low",
                score=10,
                message="File name contains common scam or malware lure words",
            )
        )

    # ── Magic byte / mismatched extension ───────────────────────────────────
    if _looks_like_windows_executable(head) and suffix not in EXECUTABLE_EXTENSIONS:
        findings.append(
            Finding(
                rule="mismatched_magic",
                severity="high",
                score=45,
                message="File content is a Windows executable but extension does not look executable",
            )
        )

    # ── Entropy / packing check ─────────────────────────────────────────────
    if suffix in EXECUTABLE_EXTENSIONS and head:
        entropy = shannon_entropy(head)
        if entropy >= 7.2:
            findings.append(
                Finding(
                    rule="high_entropy_executable",
                    severity="medium",
                    score=25,
                    message=f"Executable sample has high entropy ({entropy:.2f}), which may indicate packing",
                )
            )
    else:
        entropy = shannon_entropy(head) if head else 0.0

    # ── Script pattern scan ─────────────────────────────────────────────────
    if suffix in TEXT_EXTENSIONS or _looks_textual(head):
        findings.extend(_scan_script_patterns(head, config.script_patterns))

    # ── Heuristic analysis (YARA-style rules) ───────────────────────────────
    heuristic_result: HeuristicResult | None = None
    if head:
        heuristic_result = analyze_heuristics(head, filename=path.name)
        for hf in heuristic_result.findings:
            findings.append(
                Finding(
                    rule=f"heuristic_{hf.rule}",
                    severity=hf.severity,
                    score=hf.score,
                    message=hf.description,
                )
            )

    # ── Static sandbox analysis ─────────────────────────────────────────────
    sandbox_result: SandboxResult | None = None
    if head and (suffix in TEXT_EXTENSIONS or suffix in EXECUTABLE_EXTENSIONS or _looks_textual(head)):
        sandbox_result = run_sandbox(head, filename=path.name)
        for ind in sandbox_result.indicators:
            findings.append(
                Finding(
                    rule=f"sandbox_{ind.name}",
                    severity=ind.severity,
                    score=ind.score,
                    message=f"[Sandbox] {ind.description}",
                )
            )

    # ── AI / ML scoring ─────────────────────────────────────────────────────
    fv = build_feature_vector(
        path=path,
        sha256=digest,
        size=stat.st_size,
        entropy=entropy,
        findings=findings,
        heuristic_result=heuristic_result,
        source=source,
        bad_hashes=bad_hashes,
    )
    ai_score = compute_ai_score(fv)

    return _result(
        path, digest, stat.st_size, findings, config,
        source=source,
        heuristic=heuristic_result,
        sandbox=sandbox_result,
        ai_score=ai_score,
    )


def scan_paths(paths: Iterable[Path], recursive: bool, config: ProtectionConfig) -> list[ScanResult]:
    bad_hashes = load_bad_hashes(config)
    results: list[ScanResult] = []
    for root in paths:
        root = root.expanduser()
        if root.is_file():
            results.append(scan_file(root, config, bad_hashes))
            continue
        if not root.exists():
            results.append(_result(root, None, 0, [], config, error="Path does not exist"))
            continue
        iterator = root.rglob("*") if recursive else root.iterdir()
        for item in iterator:
            if item.is_file():
                results.append(scan_file(item, config, bad_hashes))
    return results


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in frequencies:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def _result(
    path: Path,
    digest: str | None,
    size: int,
    findings: list[Finding],
    config: ProtectionConfig,
    skipped: bool = False,
    error: str | None = None,
    source: SourceInfo | None = None,
    heuristic: HeuristicResult | None = None,
    sandbox: SandboxResult | None = None,
    ai_score: AIScore | None = None,
) -> ScanResult:
    score = min(sum(finding.score for finding in findings), 100)
    if error:
        level = "error"
    elif score >= config.block_threshold:
        level = "high"
    elif score >= config.medium_threshold:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "clean"
    return ScanResult(
        path=path,
        sha256=digest,
        size=size,
        score=score,
        level=level,
        should_block=score >= config.block_threshold,
        source=source,
        findings=findings,
        skipped=skipped,
        error=error,
        heuristic=heuristic,
        sandbox=sandbox,
        ai_score=ai_score,
    )


def _read_head(path: Path, sample_size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(sample_size)


def _detect_double_extension(path: Path) -> str | None:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if len(suffixes) < 2:
        return None
    apparent = suffixes[-2]
    actual = suffixes[-1]
    if apparent in DOCUMENT_EXTENSIONS and actual in EXECUTABLE_EXTENSIONS.union(TEXT_EXTENSIONS):
        return f"{apparent}{actual}"
    return None


def read_zone_identifier(path: Path) -> SourceInfo | None:
    zone_path = f"{path}:Zone.Identifier"
    try:
        with open(zone_path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read(8192)
    except OSError:
        return None
    return parse_zone_identifier(content)


def parse_zone_identifier(content: str) -> SourceInfo | None:
    values: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip()

    if not values:
        return None

    return SourceInfo(
        zone_id=values.get("zoneid"),
        host_url=values.get("hosturl"),
        referrer_url=values.get("referrerurl"),
    )


def _looks_like_windows_executable(data: bytes) -> bool:
    return data.startswith(b"MZ")


def _looks_textual(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        try:
            sample.decode("utf-16")
            return True
        except UnicodeDecodeError:
            return False


def _scan_script_patterns(data: bytes, patterns: list[str]) -> list[Finding]:
    try:
        text = data.decode("utf-8", errors="ignore").lower()
    except UnicodeDecodeError:
        return []

    findings: list[Finding] = []
    for pattern in patterns:
        if pattern.lower() in text:
            findings.append(
                Finding(
                    rule="suspicious_script_pattern",
                    severity="medium",
                    score=20,
                    message=f"Script contains suspicious pattern: {pattern}",
                )
            )

    base64_hits = re.findall(r"[a-z0-9+/]{120,}={0,2}", text)
    if base64_hits:
        findings.append(
            Finding(
                rule="long_base64_blob",
                severity="medium",
                score=20,
                message="Script contains long base64-like encoded content",
            )
        )

    return findings
