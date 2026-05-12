"""
Machine Learning / AI scoring engine for ShieldScan.

Uses a hand-crafted feature vector + weighted scoring model that mimics
what a trained classifier would produce — without requiring external ML
libraries (scikit-learn, torch, etc.) so the project stays dependency-free.

Feature categories:
  1. Structural features  (file size, entropy, header magic)
  2. Extension features   (risky extension, double extension)
  3. Behavioral features  (heuristic rule hits)
  4. Source features      (internet zone, referrer)
  5. Name features        (risky name hints)
  6. Script features      (obfuscation, base64, suspicious patterns)

The final AI score is 0–100 and maps to a threat level:
  0–24   → clean
  25–49  → low
  50–74  → medium
  75–100 → high
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Feature weights (tuned to approximate a trained binary classifier) ─────────

FEATURE_WEIGHTS: dict[str, float] = {
    # Structural
    "is_executable":            0.15,
    "high_entropy":             0.20,
    "very_high_entropy":        0.35,
    "mismatched_magic":         0.40,
    "large_file":               0.05,
    "tiny_executable":          0.10,

    # Extension
    "risky_extension":          0.15,
    "very_risky_extension":     0.30,
    "double_extension":         0.40,

    # Behavioral / heuristic
    "heuristic_low":            0.10,
    "heuristic_medium":         0.25,
    "heuristic_high":           0.55,
    "multiple_heuristics":      0.20,   # bonus for 3+ rule hits

    # Source
    "internet_zone":            0.10,
    "suspicious_referrer":      0.15,

    # Name
    "risky_name":               0.10,

    # Script
    "obfuscated_script":        0.30,
    "base64_blob":              0.20,
    "suspicious_script_pattern":0.15,
    "many_script_patterns":     0.20,   # bonus for 3+ pattern hits

    # Known bad
    "known_bad_hash":           1.00,   # instant max
}

# Very risky extensions (score ≥ 30 in config)
VERY_RISKY_EXTENSIONS = {".scr", ".com", ".pif", ".hta", ".vbe", ".jse", ".wsf"}


@dataclass
class AIFeatureVector:
    """Extracted feature flags for a single file."""
    is_executable: bool = False
    high_entropy: bool = False          # entropy ≥ 6.5
    very_high_entropy: bool = False     # entropy ≥ 7.2
    mismatched_magic: bool = False
    large_file: bool = False            # > 50 MB
    tiny_executable: bool = False       # < 4 KB executable

    risky_extension: bool = False
    very_risky_extension: bool = False
    double_extension: bool = False

    heuristic_low: bool = False
    heuristic_medium: bool = False
    heuristic_high: bool = False
    heuristic_rule_count: int = 0

    internet_zone: bool = False
    suspicious_referrer: bool = False

    risky_name: bool = False

    obfuscated_script: bool = False
    base64_blob: bool = False
    suspicious_script_pattern: bool = False
    script_pattern_count: int = 0

    known_bad_hash: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class AIScore:
    score: int                          # 0–100
    confidence: float                   # 0.0–1.0
    level: str                          # clean / low / medium / high
    top_features: list[str] = field(default_factory=list)
    feature_vector: AIFeatureVector = field(default_factory=AIFeatureVector)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "confidence": round(self.confidence, 3),
            "level": self.level,
            "top_features": self.top_features,
            "feature_vector": self.feature_vector.to_dict(),
        }


def build_feature_vector(
    path: Path,
    sha256: str | None,
    size: int,
    entropy: float,
    findings: list[Any],          # list of scanner.Finding
    heuristic_result: Any | None,  # heuristics.HeuristicResult | None
    source: Any | None,            # scanner.SourceInfo | None
    bad_hashes: set[str] | None = None,
) -> AIFeatureVector:
    """Build a feature vector from already-computed scan data."""
    fv = AIFeatureVector()
    suffix = path.suffix.lower()
    name_lower = path.name.lower()

    # ── Structural ──────────────────────────────────────────────────────────
    fv.is_executable = suffix in {".exe", ".scr", ".com", ".pif", ".msi", ".dll", ".sys"}
    fv.high_entropy = entropy >= 6.5
    fv.very_high_entropy = entropy >= 7.2
    fv.large_file = size > 50 * 1024 * 1024
    fv.tiny_executable = fv.is_executable and 0 < size < 4096

    # ── Extension ───────────────────────────────────────────────────────────
    from .config import SUSPICIOUS_EXTENSIONS
    fv.risky_extension = suffix in SUSPICIOUS_EXTENSIONS
    fv.very_risky_extension = suffix in VERY_RISKY_EXTENSIONS

    # ── Findings from base scanner ──────────────────────────────────────────
    finding_rules = {f.rule for f in findings}
    fv.double_extension = "double_extension" in finding_rules
    fv.mismatched_magic = "mismatched_magic" in finding_rules
    fv.risky_name = "risky_name" in finding_rules
    fv.internet_zone = "internet_zone" in finding_rules
    fv.base64_blob = "long_base64_blob" in finding_rules
    fv.suspicious_script_pattern = "suspicious_script_pattern" in finding_rules
    fv.script_pattern_count = sum(1 for f in findings if f.rule == "suspicious_script_pattern")
    fv.known_bad_hash = "known_bad_hash" in finding_rules

    # ── Source ──────────────────────────────────────────────────────────────
    if source:
        fv.internet_zone = fv.internet_zone or source.is_internet_zone
        referrer = (source.referrer_url or "").lower()
        fv.suspicious_referrer = any(
            kw in referrer
            for kw in ["pastebin", "discord", "telegram", "mega.nz", "anonfiles", "temp.sh"]
        )

    # ── Heuristics ──────────────────────────────────────────────────────────
    if heuristic_result:
        fv.heuristic_rule_count = len(heuristic_result.findings)
        fv.obfuscated_script = heuristic_result.is_obfuscated
        if heuristic_result.total_score >= 60:
            fv.heuristic_high = True
        elif heuristic_result.total_score >= 30:
            fv.heuristic_medium = True
        elif heuristic_result.total_score > 0:
            fv.heuristic_low = True

    # ── Known bad hash ──────────────────────────────────────────────────────
    if bad_hashes and sha256 and sha256.lower() in bad_hashes:
        fv.known_bad_hash = True

    return fv


def compute_ai_score(fv: AIFeatureVector) -> AIScore:
    """
    Compute a 0–100 AI threat score from the feature vector using
    a weighted logistic-style model.
    """
    if fv.known_bad_hash:
        return AIScore(
            score=100,
            confidence=1.0,
            level="high",
            top_features=["known_bad_hash"],
            feature_vector=fv,
        )

    # Accumulate weighted raw score
    raw = 0.0
    active_features: list[tuple[float, str]] = []

    def add(weight: float, name: str, condition: bool) -> None:
        if condition:
            raw_contribution = weight * 100
            active_features.append((raw_contribution, name))

    add(FEATURE_WEIGHTS["is_executable"],            "is_executable",            fv.is_executable)
    add(FEATURE_WEIGHTS["high_entropy"],             "high_entropy",             fv.high_entropy and not fv.very_high_entropy)
    add(FEATURE_WEIGHTS["very_high_entropy"],        "very_high_entropy",        fv.very_high_entropy)
    add(FEATURE_WEIGHTS["mismatched_magic"],         "mismatched_magic",         fv.mismatched_magic)
    add(FEATURE_WEIGHTS["large_file"],               "large_file",               fv.large_file)
    add(FEATURE_WEIGHTS["tiny_executable"],          "tiny_executable",          fv.tiny_executable)
    add(FEATURE_WEIGHTS["risky_extension"],          "risky_extension",          fv.risky_extension and not fv.very_risky_extension)
    add(FEATURE_WEIGHTS["very_risky_extension"],     "very_risky_extension",     fv.very_risky_extension)
    add(FEATURE_WEIGHTS["double_extension"],         "double_extension",         fv.double_extension)
    add(FEATURE_WEIGHTS["heuristic_low"],            "heuristic_low",            fv.heuristic_low)
    add(FEATURE_WEIGHTS["heuristic_medium"],         "heuristic_medium",         fv.heuristic_medium)
    add(FEATURE_WEIGHTS["heuristic_high"],           "heuristic_high",           fv.heuristic_high)
    add(FEATURE_WEIGHTS["multiple_heuristics"],      "multiple_heuristics",      fv.heuristic_rule_count >= 3)
    add(FEATURE_WEIGHTS["internet_zone"],            "internet_zone",            fv.internet_zone)
    add(FEATURE_WEIGHTS["suspicious_referrer"],      "suspicious_referrer",      fv.suspicious_referrer)
    add(FEATURE_WEIGHTS["risky_name"],               "risky_name",               fv.risky_name)
    add(FEATURE_WEIGHTS["obfuscated_script"],        "obfuscated_script",        fv.obfuscated_script)
    add(FEATURE_WEIGHTS["base64_blob"],              "base64_blob",              fv.base64_blob)
    add(FEATURE_WEIGHTS["suspicious_script_pattern"],"suspicious_script_pattern",fv.suspicious_script_pattern)
    add(FEATURE_WEIGHTS["many_script_patterns"],     "many_script_patterns",     fv.script_pattern_count >= 3)

    # Weighted sum → pass through sigmoid to get 0–1 probability
    total_weight = sum(w for w, _ in active_features)
    # Sigmoid: maps total_weight (0–∞) to (0–1)
    probability = _sigmoid(total_weight - 1.0)  # shift so neutral = 0.5

    score = int(round(probability * 100))
    score = max(0, min(100, score))

    # Confidence: how many features fired vs total possible
    confidence = min(len(active_features) / max(len(FEATURE_WEIGHTS), 1), 1.0)
    confidence = round(0.3 + confidence * 0.7, 3)  # floor at 0.3

    # Level
    if score >= 75:
        level = "high"
    elif score >= 50:
        level = "medium"
    elif score >= 25:
        level = "low"
    else:
        level = "clean"

    # Top contributing features (sorted by weight descending)
    top_features = [name for _, name in sorted(active_features, reverse=True)[:5]]

    return AIScore(
        score=score,
        confidence=confidence,
        level=level,
        top_features=top_features,
        feature_vector=fv,
    )


def _sigmoid(x: float) -> float:
    """Standard logistic sigmoid function."""
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0
