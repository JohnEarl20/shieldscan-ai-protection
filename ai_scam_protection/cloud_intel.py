"""
Cloud Threat Intelligence for ShieldScan.

Sources supported:
  - OTX AlienVault        (free, no key required — hash + URL + IP)
  - MalwareBazaar         (requires free Auth-Key from auth.abuse.ch)
  - URLhaus               (requires free Auth-Key from auth.abuse.ch)
  - VirusTotal            (requires free API key from virustotal.com)
  - Local offline feed    (abuse.ch SHA-256 blocklist, auto-updated daily)

Getting free API keys:
  - abuse.ch (MalwareBazaar + URLhaus): https://auth.abuse.ch/
  - VirusTotal: https://www.virustotal.com/gui/join-us

Keys are stored in .protection_state/config.json under "api_keys":
  {
    "api_keys": {
      "abusech": "YOUR_ABUSE_CH_KEY",
      "virustotal": "YOUR_VT_KEY"
    }
  }

Usage:
    from ai_scam_protection.cloud_intel import CloudIntel
    intel = CloudIntel(abusech_key="...", vt_api_key="...")
    result = intel.lookup_hash("abc123...")
    url_result = intel.lookup_url("https://example.com")
"""
from __future__ import annotations

import hashlib
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class CloudHashResult:
    sha256: str
    found: bool
    malicious: bool
    source: str
    detections: int = 0
    total_engines: int = 0
    threat_names: list[str] = field(default_factory=list)
    permalink: str | None = None
    error: str | None = None

    @property
    def detection_ratio(self) -> str:
        if self.total_engines:
            return f"{self.detections}/{self.total_engines}"
        return "N/A"

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "found": self.found,
            "malicious": self.malicious,
            "source": self.source,
            "detections": self.detections,
            "total_engines": self.total_engines,
            "detection_ratio": self.detection_ratio,
            "threat_names": self.threat_names,
            "permalink": self.permalink,
            "error": self.error,
        }


@dataclass
class CloudURLResult:
    url: str
    found: bool
    malicious: bool
    source: str
    category: str | None = None
    threat: str | None = None
    tags: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "found": self.found,
            "malicious": self.malicious,
            "source": self.source,
            "category": self.category,
            "threat": self.threat,
            "tags": self.tags,
            "error": self.error,
        }


@dataclass
class CloudIntelSummary:
    sha256: str | None = None
    url: str | None = None
    hash_results: list[CloudHashResult] = field(default_factory=list)
    url_results: list[CloudURLResult] = field(default_factory=list)
    overall_malicious: bool = False
    overall_score_boost: int = 0

    def to_dict(self) -> dict:
        def _r(item):
            return item.to_dict() if hasattr(item, 'to_dict') else item
        return {
            "sha256": self.sha256,
            "url": self.url,
            "hash_results": [_r(r) for r in self.hash_results],
            "url_results": [_r(r) for r in self.url_results],
            "overall_malicious": self.overall_malicious,
            "overall_score_boost": self.overall_score_boost,
        }


# ── Main class ─────────────────────────────────────────────────────────────────

class CloudIntel:
    """
    Aggregates multiple threat intelligence sources.
    OTX AlienVault works with no API key.
    abuse.ch and VirusTotal require free registration keys.
    """

    def __init__(
        self,
        vt_api_key: str | None = None,
        abusech_key: str | None = None,
        timeout: int = 10,
        cache_dir: Path | None = None,
    ) -> None:
        self.vt_api_key = vt_api_key
        self.abusech_key = abusech_key
        self.timeout = timeout
        self._cache: dict[str, Any] = {}
        self._cache_dir = cache_dir
        self._ssl_ctx = _make_ssl_context()
        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────

    def lookup_hash(self, sha256: str) -> CloudIntelSummary:
        """Look up a SHA-256 hash across all available threat intel sources."""
        sha256 = sha256.lower().strip()
        summary = CloudIntelSummary(sha256=sha256)

        cached = self._load_cache(f"hash_{sha256}")
        if cached:
            return CloudIntelSummary(**cached)

        # OTX AlienVault — always available, no key needed
        otx = self._otx_hash(sha256)
        summary.hash_results.append(otx)

        # MalwareBazaar — requires abuse.ch Auth-Key
        if self.abusech_key:
            mb = self._malwarebazaar_hash(sha256)
            summary.hash_results.append(mb)
        else:
            summary.hash_results.append(CloudHashResult(
                sha256=sha256, found=False, malicious=False,
                source="MalwareBazaar",
                error="No abuse.ch key — get one free at https://auth.abuse.ch/",
            ))

        # VirusTotal — requires API key
        if self.vt_api_key:
            vt = self._virustotal_hash(sha256)
            summary.hash_results.append(vt)

        summary.overall_malicious = any(r.malicious for r in summary.hash_results)
        if summary.overall_malicious:
            max_det = max((r.detections for r in summary.hash_results if r.malicious), default=1)
            summary.overall_score_boost = min(40, max_det * 2)

        self._save_cache(f"hash_{sha256}", summary.to_dict())
        return summary

    def lookup_url(self, url: str) -> CloudIntelSummary:
        """Look up a URL across all available threat intel sources."""
        summary = CloudIntelSummary(url=url)
        url_key = hashlib.md5(url.encode()).hexdigest()

        cached = self._load_cache(f"url_{url_key}")
        if cached:
            return CloudIntelSummary(**cached)

        # OTX AlienVault — always available, no key needed
        otx = self._otx_url(url)
        summary.url_results.append(otx)

        # URLhaus — requires abuse.ch Auth-Key
        if self.abusech_key:
            uh = self._urlhaus_lookup(url)
            summary.url_results.append(uh)
        else:
            summary.url_results.append(CloudURLResult(
                url=url, found=False, malicious=False,
                source="URLhaus",
                error="No abuse.ch key — get one free at https://auth.abuse.ch/",
            ))

        # VirusTotal — requires API key
        if self.vt_api_key:
            vt = self._virustotal_url(url)
            summary.url_results.append(vt)

        summary.overall_malicious = any(r.malicious for r in summary.url_results)
        if summary.overall_malicious:
            summary.overall_score_boost = 35

        self._save_cache(f"url_{url_key}", summary.to_dict())
        return summary

    def lookup_file(self, path: Path) -> CloudIntelSummary:
        """Compute SHA-256 of a file and look it up in cloud intel."""
        try:
            sha256 = _sha256_file(path)
        except OSError as exc:
            summary = CloudIntelSummary()
            summary.hash_results.append(
                CloudHashResult(sha256="", found=False, malicious=False,
                                source="local", error=str(exc))
            )
            return summary
        return self.lookup_hash(sha256)

    # ── OTX AlienVault (no key required) ──────────────────────────────────

    def _otx_hash(self, sha256: str) -> CloudHashResult:
        """Query OTX AlienVault for a file hash — free, no API key required."""
        try:
            req = urllib.request.Request(
                f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
                headers={
                    "User-Agent": "ShieldScan/1.0",
                    "Accept": "application/json",
                },
            )
            with self._urlopen(req) as resp:
                body = json.loads(resp.read().decode())

            pulse_count = body.get("pulse_info", {}).get("count", 0)
            malicious = pulse_count > 0

            threat_names: list[str] = []
            for pulse in body.get("pulse_info", {}).get("pulses", [])[:3]:
                name = pulse.get("name", "")
                if name:
                    threat_names.append(name)

            return CloudHashResult(
                sha256=sha256,
                found=pulse_count > 0,
                malicious=malicious,
                source="OTX AlienVault",
                detections=pulse_count,
                total_engines=pulse_count,
                threat_names=threat_names,
                permalink=f"https://otx.alienvault.com/indicator/file/{sha256}",
            )

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                       source="OTX AlienVault")
            return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                   source="OTX AlienVault", error=f"HTTP {exc.code}")
        except Exception as exc:
            return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                   source="OTX AlienVault", error=str(exc))

    def _otx_url(self, url: str) -> CloudURLResult:
        """Query OTX AlienVault for a URL — free, no API key required."""
        try:
            encoded = urllib.parse.quote(url, safe="")
            req = urllib.request.Request(
                f"https://otx.alienvault.com/api/v1/indicators/url/{encoded}/general",
                headers={
                    "User-Agent": "ShieldScan/1.0",
                    "Accept": "application/json",
                },
            )
            with self._urlopen(req) as resp:
                body = json.loads(resp.read().decode())

            pulse_count = body.get("pulse_info", {}).get("count", 0)
            malicious = pulse_count > 0

            tags: list[str] = []
            for pulse in body.get("pulse_info", {}).get("pulses", [])[:3]:
                tags.extend(pulse.get("tags", [])[:2])

            return CloudURLResult(
                url=url,
                found=pulse_count > 0,
                malicious=malicious,
                source="OTX AlienVault",
                category="malware" if malicious else None,
                threat=f"{pulse_count} threat pulse(s)" if malicious else None,
                tags=list(set(tags))[:5],
            )

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return CloudURLResult(url=url, found=False, malicious=False,
                                      source="OTX AlienVault")
            return CloudURLResult(url=url, found=False, malicious=False,
                                  source="OTX AlienVault", error=f"HTTP {exc.code}")
        except Exception as exc:
            return CloudURLResult(url=url, found=False, malicious=False,
                                  source="OTX AlienVault", error=str(exc))

    # ── MalwareBazaar (requires abuse.ch Auth-Key) ─────────────────────────

    def _malwarebazaar_hash(self, sha256: str) -> CloudHashResult:
        """Query MalwareBazaar — requires free Auth-Key from auth.abuse.ch"""
        try:
            data = urllib.parse.urlencode({
                "query": "get_info",
                "hash": sha256,
            }).encode()
            req = urllib.request.Request(
                "https://mb-api.abuse.ch/api/v1/",
                data=data,
                headers={
                    "User-Agent": "ShieldScan/1.0",
                    "Auth-Key": self.abusech_key or "",
                },
                method="POST",
            )
            with self._urlopen(req) as resp:
                body = json.loads(resp.read().decode())

            status = body.get("query_status", "")
            if status == "hash_not_found":
                return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                       source="MalwareBazaar")
            if status == "ok":
                entries = body.get("data", [])
                if entries:
                    entry = entries[0]
                    return CloudHashResult(
                        sha256=sha256,
                        found=True,
                        malicious=True,
                        source="MalwareBazaar",
                        detections=1,
                        total_engines=1,
                        threat_names=[entry.get("signature") or "unknown"],
                        permalink=f"https://bazaar.abuse.ch/sample/{sha256}/",
                    )
            return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                   source="MalwareBazaar", error=f"status={status}")
        except Exception as exc:
            return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                   source="MalwareBazaar", error=str(exc))

    # ── URLhaus (requires abuse.ch Auth-Key) ──────────────────────────────

    def _urlhaus_lookup(self, url: str) -> CloudURLResult:
        """Query URLhaus — requires free Auth-Key from auth.abuse.ch"""
        try:
            data = urllib.parse.urlencode({"url": url}).encode()
            req = urllib.request.Request(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data=data,
                headers={
                    "User-Agent": "ShieldScan/1.0",
                    "Auth-Key": self.abusech_key or "",
                },
                method="POST",
            )
            with self._urlopen(req) as resp:
                body = json.loads(resp.read().decode())

            status = body.get("query_status", "")
            if status == "no_results":
                return CloudURLResult(url=url, found=False, malicious=False,
                                      source="URLhaus")
            if status == "is_listed":
                tags = body.get("tags") or []
                return CloudURLResult(
                    url=url, found=True, malicious=True,
                    source="URLhaus",
                    category="malware",
                    threat=body.get("threat"),
                    tags=tags if isinstance(tags, list) else [],
                )
            return CloudURLResult(url=url, found=False, malicious=False,
                                  source="URLhaus", error=f"status={status}")
        except Exception as exc:
            return CloudURLResult(url=url, found=False, malicious=False,
                                  source="URLhaus", error=str(exc))

    # ── VirusTotal (requires API key) ──────────────────────────────────────

    def _virustotal_hash(self, sha256: str) -> CloudHashResult:
        """Query VirusTotal v3 — requires free API key from virustotal.com"""
        try:
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={
                    "x-apikey": self.vt_api_key,
                    "User-Agent": "ShieldScan/1.0",
                },
            )
            with self._urlopen(req) as resp:
                body = json.loads(resp.read().decode())

            attrs = body.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values())
            label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
            threat_names = [p for p in label.split(".") if p]

            return CloudHashResult(
                sha256=sha256,
                found=True,
                malicious=malicious_count > 0,
                source="VirusTotal",
                detections=malicious_count,
                total_engines=total,
                threat_names=threat_names,
                permalink=f"https://www.virustotal.com/gui/file/{sha256}",
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                       source="VirusTotal")
            return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                   source="VirusTotal", error=f"HTTP {exc.code}")
        except Exception as exc:
            return CloudHashResult(sha256=sha256, found=False, malicious=False,
                                   source="VirusTotal", error=str(exc))

    def _virustotal_url(self, url: str) -> CloudURLResult:
        """Query VirusTotal v3 for a URL — requires free API key."""
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={
                    "x-apikey": self.vt_api_key,
                    "User-Agent": "ShieldScan/1.0",
                },
            )
            with self._urlopen(req) as resp:
                body = json.loads(resp.read().decode())

            attrs = body.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            categories = attrs.get("categories", {})
            category = next(iter(categories.values()), None) if categories else None

            return CloudURLResult(
                url=url, found=True,
                malicious=malicious_count > 0,
                source="VirusTotal",
                category=category,
                threat="malicious" if malicious_count > 0 else None,
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return CloudURLResult(url=url, found=False, malicious=False,
                                      source="VirusTotal")
            return CloudURLResult(url=url, found=False, malicious=False,
                                  source="VirusTotal", error=f"HTTP {exc.code}")
        except Exception as exc:
            return CloudURLResult(url=url, found=False, malicious=False,
                                  source="VirusTotal", error=str(exc))

    # ── SSL-aware urlopen ──────────────────────────────────────────────────

    def _urlopen(self, req: urllib.request.Request) -> Any:
        """Open a URL, falling back to no-verify SSL on cert errors."""
        try:
            return urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx)
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(exc):
                no_verify = ssl.create_default_context()
                no_verify.check_hostname = False
                no_verify.verify_mode = ssl.CERT_NONE
                return urllib.request.urlopen(req, timeout=self.timeout, context=no_verify)
            raise

    # ── Cache helpers ──────────────────────────────────────────────────────

    def _load_cache(self, key: str) -> dict | None:
        if key in self._cache:
            entry = self._cache[key]
            if time.time() - entry["_ts"] < 3600:
                return entry["data"]
        if self._cache_dir:
            cache_file = self._cache_dir / f"{key}.json"
            if cache_file.exists():
                try:
                    data = json.loads(cache_file.read_text(encoding="utf-8"))
                    if time.time() - data.get("_ts", 0) < 3600:
                        return data.get("data")
                except Exception:
                    pass
        return None

    def _save_cache(self, key: str, data: dict) -> None:
        entry = {"_ts": time.time(), "data": data}
        self._cache[key] = entry
        if self._cache_dir:
            cache_file = self._cache_dir / f"{key}.json"
            try:
                cache_file.write_text(json.dumps(entry), encoding="utf-8")
            except Exception:
                pass


# ── SSL helper ─────────────────────────────────────────────────────────────────

def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    return ctx


# ── File hash helper ───────────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ── Config key loader ──────────────────────────────────────────────────────────

def load_api_keys(state_dir: Path) -> dict[str, str]:
    """Load API keys from .protection_state/config.json under 'api_keys'."""
    config_path = state_dir / "config.json"
    if not config_path.exists():
        return {}
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        keys = data.get("api_keys", {})
        return {k: str(v) for k, v in keys.items() if v}
    except Exception:
        return {}


def save_api_key(state_dir: Path, service: str, key: str) -> None:
    """Save an API key to .protection_state/config.json."""
    config_path = state_dir / "config.json"
    try:
        data: dict = {}
        if config_path.exists():
            data = json.loads(config_path.read_text(encoding="utf-8"))
        if "api_keys" not in data:
            data["api_keys"] = {}
        data["api_keys"][service] = key
        config_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        pass
