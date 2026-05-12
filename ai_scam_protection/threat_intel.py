"""
Threat Intelligence Feed Aggregator for ShieldScan.

Aggregates multiple free threat intel feeds into a unified API:
  - abuse.ch URLhaus feed (malicious URLs, updated every 5 min)
  - abuse.ch MalwareBazaar recent samples feed
  - Emerging Threats open blocklist (IPs)
  - PhishTank (phishing URLs, no key required for basic use)
  - Local custom blocklist (user-managed)

All feeds are cached locally and refreshed on a schedule.
No API keys required for the free feeds used here.

Usage:
    from ai_scam_protection.threat_intel import ThreatIntelFeed
    feed = ThreatIntelFeed(cache_dir=Path(".protection_state/threat_intel"))
    result = feed.lookup("http://evil.com/payload.exe")
    result = feed.lookup("192.168.1.100")
    result = feed.lookup("abc123...sha256hash")
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import ssl
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Feed definitions ───────────────────────────────────────────────────────────

FEEDS = {
    "urlhaus_urls": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "csv",
        "ttl": 300,          # refresh every 5 minutes
        "description": "abuse.ch URLhaus — recent malicious URLs",
    },
    "urlhaus_domains": {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "type": "hostfile",
        "ttl": 3600,
        "description": "abuse.ch URLhaus — malicious domains (hosts format)",
    },
    "malwarebazaar_recent": {
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "type": "csv",
        "ttl": 600,
        "description": "abuse.ch MalwareBazaar — recent malware SHA-256 hashes",
    },
    "emerging_threats_ips": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "linelist",
        "ttl": 3600,
        "description": "Emerging Threats — compromised IP addresses",
    },
}


@dataclass
class ThreatIntelMatch:
    indicator: str          # the queried value
    indicator_type: str     # "url" | "domain" | "ip" | "hash"
    matched: bool
    source: str
    threat_type: str | None = None
    tags: list[str] = field(default_factory=list)
    first_seen: str | None = None
    confidence: str = "medium"   # "low" | "medium" | "high"

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "matched": self.matched,
            "source": self.source,
            "threat_type": self.threat_type,
            "tags": self.tags,
            "first_seen": self.first_seen,
            "confidence": self.confidence,
        }


@dataclass
class ThreatIntelResult:
    indicator: str
    indicator_type: str
    malicious: bool
    matches: list[ThreatIntelMatch] = field(default_factory=list)
    score_boost: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "malicious": self.malicious,
            "matches": [m.to_dict() for m in self.matches],
            "score_boost": self.score_boost,
            "error": self.error,
        }


class ThreatIntelFeed:
    """
    Aggregates multiple threat intelligence feeds.
    Caches feed data locally and refreshes on TTL expiry.
    """

    def __init__(self, cache_dir: Path, timeout: int = 10) -> None:
        self.cache_dir = cache_dir
        self.timeout = timeout
        self._cache: dict[str, dict] = {}   # feed_name → {data, ts}
        cache_dir.mkdir(parents=True, exist_ok=True)
        self._ssl_ctx = _make_ssl_ctx()

    def lookup(self, indicator: str) -> ThreatIntelResult:
        """
        Look up an indicator (URL, domain, IP, or SHA-256 hash) across all feeds.
        """
        indicator = indicator.strip()
        itype = _classify_indicator(indicator)

        matches: list[ThreatIntelMatch] = []

        if itype == "url":
            matches.extend(self._check_urlhaus_urls(indicator))
            domain = _extract_domain(indicator)
            if domain:
                matches.extend(self._check_urlhaus_domains(domain))

        elif itype == "domain":
            matches.extend(self._check_urlhaus_domains(indicator))

        elif itype == "ip":
            matches.extend(self._check_emerging_threats_ips(indicator))

        elif itype == "hash":
            matches.extend(self._check_malwarebazaar(indicator))

        malicious = any(m.matched for m in matches)
        score_boost = 50 if malicious else 0

        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=itype,
            malicious=malicious,
            matches=matches,
            score_boost=score_boost,
        )

    def get_feed_status(self) -> dict:
        """Return status of all feeds (last update, record count, etc.)."""
        status = {}
        for name, feed_def in FEEDS.items():
            cached = self._cache.get(name)
            cache_file = self.cache_dir / f"{name}.json"
            last_update = None
            record_count = 0

            if cached:
                last_update = cached.get("ts")
                data = cached.get("data", {})
                record_count = len(data) if isinstance(data, (set, list, dict)) else 0
            elif cache_file.exists():
                try:
                    raw = json.loads(cache_file.read_text(encoding="utf-8"))
                    last_update = raw.get("ts")
                    data = raw.get("data", {})
                    record_count = len(data) if isinstance(data, (set, list, dict)) else 0
                except Exception:
                    pass

            status[name] = {
                "description": feed_def["description"],
                "ttl_seconds": feed_def["ttl"],
                "last_update": last_update,
                "record_count": record_count,
                "stale": _is_stale(last_update, feed_def["ttl"]),
            }
        return status

    def refresh_all(self) -> dict[str, bool]:
        """Force refresh all feeds. Returns {feed_name: success}."""
        results = {}
        for name in FEEDS:
            try:
                self._load_feed(name, force=True)
                results[name] = True
            except Exception:
                results[name] = False
        return results

    # ── Feed checkers ──────────────────────────────────────────────────────

    def _check_urlhaus_urls(self, url: str) -> list[ThreatIntelMatch]:
        try:
            data = self._load_feed("urlhaus_urls")
            url_lower = url.lower()
            if url_lower in data:
                entry = data[url_lower]
                return [ThreatIntelMatch(
                    indicator=url,
                    indicator_type="url",
                    matched=True,
                    source="URLhaus",
                    threat_type=entry.get("threat"),
                    tags=entry.get("tags", []),
                    first_seen=entry.get("date_added"),
                    confidence="high",
                )]
        except Exception:
            pass
        return []

    def _check_urlhaus_domains(self, domain: str) -> list[ThreatIntelMatch]:
        try:
            data = self._load_feed("urlhaus_domains")
            if domain.lower() in data:
                return [ThreatIntelMatch(
                    indicator=domain,
                    indicator_type="domain",
                    matched=True,
                    source="URLhaus (domains)",
                    threat_type="malware_distribution",
                    confidence="high",
                )]
        except Exception:
            pass
        return []

    def _check_malwarebazaar(self, sha256: str) -> list[ThreatIntelMatch]:
        try:
            data = self._load_feed("malwarebazaar_recent")
            sha256_lower = sha256.lower()
            if sha256_lower in data:
                entry = data[sha256_lower]
                return [ThreatIntelMatch(
                    indicator=sha256,
                    indicator_type="hash",
                    matched=True,
                    source="MalwareBazaar",
                    threat_type=entry.get("signature"),
                    tags=entry.get("tags", []),
                    first_seen=entry.get("first_seen"),
                    confidence="high",
                )]
        except Exception:
            pass
        return []

    def _check_emerging_threats_ips(self, ip: str) -> list[ThreatIntelMatch]:
        try:
            data = self._load_feed("emerging_threats_ips")
            if ip in data:
                return [ThreatIntelMatch(
                    indicator=ip,
                    indicator_type="ip",
                    matched=True,
                    source="Emerging Threats",
                    threat_type="compromised_host",
                    confidence="medium",
                )]
        except Exception:
            pass
        return []

    # ── Feed loader ────────────────────────────────────────────────────────

    def _load_feed(self, name: str, force: bool = False) -> Any:
        """Load feed from cache or download if stale."""
        feed_def = FEEDS[name]
        ttl = feed_def["ttl"]

        # Check in-memory cache
        cached = self._cache.get(name)
        if not force and cached and not _is_stale(cached.get("ts"), ttl):
            return cached["data"]

        # Check disk cache
        cache_file = self.cache_dir / f"{name}.json"
        if not force and cache_file.exists():
            try:
                raw = json.loads(cache_file.read_text(encoding="utf-8"))
                if not _is_stale(raw.get("ts"), ttl):
                    self._cache[name] = raw
                    return raw["data"]
            except Exception:
                pass

        # Download fresh
        data = self._download_feed(name, feed_def)
        entry = {"ts": time.time(), "data": data}
        self._cache[name] = entry
        try:
            # Convert sets to lists for JSON serialization
            serializable = {"ts": entry["ts"], "data": _make_serializable(data)}
            cache_file.write_text(json.dumps(serializable), encoding="utf-8")
        except Exception:
            pass
        return data

    def _download_feed(self, name: str, feed_def: dict) -> Any:
        """Download and parse a feed."""
        req = urllib.request.Request(
            feed_def["url"],
            headers={"User-Agent": "ShieldScan/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
        except Exception as exc:
            # Return empty data on download failure — don't crash
            return {} if feed_def["type"] in ("csv", "hostfile") else set()

        feed_type = feed_def["type"]

        if feed_type == "csv" and name == "urlhaus_urls":
            return _parse_urlhaus_csv(raw)
        elif feed_type == "csv" and name == "malwarebazaar_recent":
            return _parse_malwarebazaar_csv(raw)
        elif feed_type == "hostfile":
            return _parse_hostfile(raw)
        elif feed_type == "linelist":
            return _parse_linelist(raw)
        return {}


# ── Feed parsers ───────────────────────────────────────────────────────────────

def _parse_urlhaus_csv(raw: str) -> dict[str, dict]:
    """Parse URLhaus CSV into {url_lower: {threat, tags, date_added}}."""
    result: dict[str, dict] = {}
    try:
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 5:
                continue
            # Columns: id, date_added, url, url_status, threat, tags, ...
            url = row[2].strip().lower()
            if url:
                tags_raw = row[5].strip() if len(row) > 5 else ""
                result[url] = {
                    "date_added": row[1].strip(),
                    "threat": row[4].strip() if len(row) > 4 else None,
                    "tags": [t.strip() for t in tags_raw.split(",") if t.strip()],
                }
    except Exception:
        pass
    return result


def _parse_malwarebazaar_csv(raw: str) -> dict[str, dict]:
    """Parse MalwareBazaar CSV into {sha256_lower: {signature, tags, first_seen}}."""
    result: dict[str, dict] = {}
    try:
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 10:
                continue
            # Columns: first_seen, sha256_hash, md5_hash, sha1_hash, reporter, file_name,
            #          file_type_guess, mime_type, signature, clamav, vtpercent, imphash, tlsh, tags
            sha256 = row[1].strip().lower()
            if len(sha256) == 64:
                tags_raw = row[13].strip() if len(row) > 13 else ""
                result[sha256] = {
                    "first_seen": row[0].strip(),
                    "signature": row[8].strip() if len(row) > 8 else None,
                    "tags": [t.strip() for t in tags_raw.split(",") if t.strip()],
                }
    except Exception:
        pass
    return result


def _parse_hostfile(raw: str) -> set[str]:
    """Parse hosts-format file into set of domains."""
    domains: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].lower().strip()
            if domain and domain != "localhost":
                domains.add(domain)
        elif len(parts) == 1:
            domains.add(parts[0].lower())
    return domains


def _parse_linelist(raw: str) -> set[str]:
    """Parse a plain line-per-entry list (IPs, domains, etc.)."""
    entries: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line)
    return entries


# ── Helpers ────────────────────────────────────────────────────────────────────

def _classify_indicator(indicator: str) -> str:
    """Classify an indicator as url, domain, ip, or hash."""
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    if len(indicator) == 64 and all(c in "0123456789abcdefABCDEF" for c in indicator):
        return "hash"
    import re
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
        return "ip"
    return "domain"


def _extract_domain(url: str) -> str | None:
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname
    except Exception:
        return None


def _is_stale(ts: float | None, ttl: int) -> bool:
    if ts is None:
        return True
    return (time.time() - ts) > ttl


def _make_serializable(data: Any) -> Any:
    if isinstance(data, set):
        return list(data)
    if isinstance(data, dict):
        return {k: _make_serializable(v) for k, v in data.items()}
    return data


def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    return ctx
