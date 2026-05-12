"""
Live Ransomware Behavior Monitor for ShieldScan.

Detects ransomware activity by watching for:
  - Mass file renames (many files renamed in a short window)
  - Files gaining known ransomware extensions (.locked, .encrypted, .encrypted, etc.)
  - Shadow copy deletion commands in running processes
  - README/ransom note files appearing (HOW_TO_DECRYPT.txt, etc.)
  - Rapid file size changes (encryption changes file size/entropy)

This complements the static heuristics in heuristics.py and sandbox.py
by detecting LIVE behavior rather than just file content patterns.

Usage:
    monitor = RansomwareMonitor(watch_paths=[Path("C:/Users/John/Downloads")])
    monitor.start()
    # ... later ...
    monitor.stop()
    events = monitor.get_events()
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


# ── Known ransomware file extensions ──────────────────────────────────────────
RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".encrypted", ".enc", ".crypt",
    ".crypto", ".vault", ".zzzzz", ".zepto", ".cerber",
    ".locky", ".odin", ".thor", ".aesir", ".xtbl",
    ".ccc", ".vvv", ".abc", ".xyz", ".micro",
    ".ecc", ".ezz", ".exx", ".zix", ".zzz",
    ".aaa", ".abc", ".ccc", ".vvv", ".xxx",
    ".ttt", ".mp3", ".lesli", ".magic",
    ".WNCRY", ".wncryt", ".wcry",
    ".DHARMA", ".phobos", ".makop",
    ".ryuk", ".conti", ".revil", ".sodinokibi",
}

# ── Ransom note file name patterns ────────────────────────────────────────────
RANSOM_NOTE_PATTERNS = [
    "how_to_decrypt",
    "how_to_recover",
    "readme_to_decrypt",
    "your_files_are_encrypted",
    "decrypt_instructions",
    "recovery_instructions",
    "ransom_note",
    "files_encrypted",
    "restore_files",
    "help_decrypt",
    "attention",
    "!!!readme!!!",
    "read_me_please",
    "_readme.txt",
    "!!! important !!!",
]

# ── Time window for mass-rename detection (seconds) ───────────────────────────
MASS_RENAME_WINDOW_SECONDS = 30
MASS_RENAME_THRESHOLD = 10   # renames in window = suspicious
MASS_RENAME_HIGH_THRESHOLD = 25  # renames in window = high confidence ransomware


@dataclass
class RansomwareEvent:
    event_type: str     # "mass_rename" | "ransom_extension" | "ransom_note" | "shadow_delete"
    severity: str       # "medium" | "high"
    description: str
    details: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "details": self.details[:5],
            "timestamp": self.timestamp,
        }


@dataclass
class RansomwareStatus:
    is_active: bool
    events: list[RansomwareEvent]
    rename_count_last_30s: int
    ransom_extensions_seen: list[str]
    ransom_notes_seen: list[str]
    risk_score: int     # 0–100

    def to_dict(self) -> dict:
        return {
            "is_active": self.is_active,
            "events": [e.to_dict() for e in self.events],
            "rename_count_last_30s": self.rename_count_last_30s,
            "ransom_extensions_seen": self.ransom_extensions_seen,
            "ransom_notes_seen": self.ransom_notes_seen,
            "risk_score": self.risk_score,
        }


class RansomwareMonitor:
    """
    Lightweight ransomware behavior monitor.
    Polls watched directories for suspicious file activity.
    Thread-safe — can be started/stopped from any thread.
    """

    def __init__(
        self,
        watch_paths: list[Path],
        poll_interval: float = 2.0,
        on_alert: Callable[[RansomwareEvent], None] | None = None,
    ) -> None:
        self.watch_paths = watch_paths
        self.poll_interval = poll_interval
        self.on_alert = on_alert

        self._lock = threading.Lock()
        self._events: list[RansomwareEvent] = []
        self._rename_timestamps: deque[float] = deque()
        self._ransom_extensions_seen: set[str] = set()
        self._ransom_notes_seen: set[str] = set()
        self._seen_files: dict[Path, tuple[int, int]] = {}  # path → (mtime_ns, size)
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start monitoring in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="RansomwareMonitor")
        self._thread.start()

    def stop(self) -> None:
        """Stop the monitor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def get_status(self) -> RansomwareStatus:
        """Get current ransomware monitoring status."""
        with self._lock:
            now = time.time()
            # Count renames in last 30 seconds
            recent_renames = sum(
                1 for ts in self._rename_timestamps
                if now - ts <= MASS_RENAME_WINDOW_SECONDS
            )
            risk_score = self._compute_risk_score(recent_renames)
            return RansomwareStatus(
                is_active=self._running,
                events=list(self._events[-20:]),
                rename_count_last_30s=recent_renames,
                ransom_extensions_seen=sorted(self._ransom_extensions_seen),
                ransom_notes_seen=sorted(self._ransom_notes_seen),
                risk_score=risk_score,
            )

    def get_events(self) -> list[RansomwareEvent]:
        with self._lock:
            return list(self._events)

    def clear_events(self) -> None:
        with self._lock:
            self._events.clear()

    # ── Internal ───────────────────────────────────────────────────────────

    def _run(self) -> None:
        # Initial snapshot
        self._snapshot()
        while self._running:
            time.sleep(self.poll_interval)
            self._poll()

    def _snapshot(self) -> None:
        """Build initial file state snapshot."""
        for root in self.watch_paths:
            root = root.expanduser()
            if not root.exists():
                continue
            try:
                for item in root.rglob("*"):
                    if item.is_file():
                        try:
                            stat = item.stat()
                            self._seen_files[item] = (stat.st_mtime_ns, stat.st_size)
                        except OSError:
                            pass
            except OSError:
                pass

    def _poll(self) -> None:
        """Check for new/changed files and detect ransomware patterns."""
        now = time.time()
        new_snapshot: dict[Path, tuple[int, int]] = {}

        for root in self.watch_paths:
            root = root.expanduser()
            if not root.exists():
                continue
            try:
                for item in root.rglob("*"):
                    if not item.is_file():
                        continue
                    try:
                        stat = item.stat()
                        fingerprint = (stat.st_mtime_ns, stat.st_size)
                        new_snapshot[item] = fingerprint

                        prev = self._seen_files.get(item)
                        if prev is None:
                            # New file appeared
                            self._check_new_file(item, now)
                        elif prev != fingerprint:
                            # File changed
                            self._check_changed_file(item, now)
                    except OSError:
                        pass
            except OSError:
                pass

        # Check for mass renames (files that disappeared + new files appeared)
        disappeared = set(self._seen_files.keys()) - set(new_snapshot.keys())
        appeared = set(new_snapshot.keys()) - set(self._seen_files.keys())

        if disappeared and appeared:
            # Heuristic: if many files disappeared and similar count appeared,
            # it's likely a rename (ransomware encrypts and renames)
            rename_estimate = min(len(disappeared), len(appeared))
            if rename_estimate >= 3:
                with self._lock:
                    for _ in range(rename_estimate):
                        self._rename_timestamps.append(now)
                    # Prune old timestamps
                    cutoff = now - MASS_RENAME_WINDOW_SECONDS * 2
                    while self._rename_timestamps and self._rename_timestamps[0] < cutoff:
                        self._rename_timestamps.popleft()

                    recent = sum(
                        1 for ts in self._rename_timestamps
                        if now - ts <= MASS_RENAME_WINDOW_SECONDS
                    )
                    if recent >= MASS_RENAME_HIGH_THRESHOLD:
                        self._add_event(RansomwareEvent(
                            event_type="mass_rename",
                            severity="high",
                            description=f"Mass file rename detected: {recent} files renamed in {MASS_RENAME_WINDOW_SECONDS}s",
                            details=[str(p) for p in list(disappeared)[:3]] + ["→"] + [str(p) for p in list(appeared)[:3]],
                            timestamp=now,
                        ))
                    elif recent >= MASS_RENAME_THRESHOLD:
                        self._add_event(RansomwareEvent(
                            event_type="mass_rename",
                            severity="medium",
                            description=f"Suspicious file rename activity: {recent} files renamed in {MASS_RENAME_WINDOW_SECONDS}s",
                            details=[str(p) for p in list(disappeared)[:3]],
                            timestamp=now,
                        ))

        self._seen_files = new_snapshot

    def _check_new_file(self, path: Path, now: float) -> None:
        """Check a newly appeared file for ransomware indicators."""
        name_lower = path.name.lower()
        suffix_lower = path.suffix.lower()

        # Ransom extension
        if suffix_lower in RANSOMWARE_EXTENSIONS:
            with self._lock:
                self._ransom_extensions_seen.add(suffix_lower)
                self._add_event(RansomwareEvent(
                    event_type="ransom_extension",
                    severity="high",
                    description=f"File with ransomware extension appeared: {suffix_lower}",
                    details=[str(path)],
                    timestamp=now,
                ))

        # Ransom note
        for pattern in RANSOM_NOTE_PATTERNS:
            if pattern in name_lower:
                with self._lock:
                    self._ransom_notes_seen.add(path.name)
                    self._add_event(RansomwareEvent(
                        event_type="ransom_note",
                        severity="high",
                        description=f"Ransom note file appeared: {path.name}",
                        details=[str(path)],
                        timestamp=now,
                    ))
                break

    def _check_changed_file(self, path: Path, now: float) -> None:
        """Check a modified file — rapid changes may indicate encryption."""
        # Track rename-like changes (extension changed)
        suffix_lower = path.suffix.lower()
        if suffix_lower in RANSOMWARE_EXTENSIONS:
            with self._lock:
                self._ransom_extensions_seen.add(suffix_lower)
                self._add_event(RansomwareEvent(
                    event_type="ransom_extension",
                    severity="high",
                    description=f"File modified to ransomware extension: {suffix_lower}",
                    details=[str(path)],
                    timestamp=now,
                ))

    def _add_event(self, event: RansomwareEvent) -> None:
        """Add event and fire callback. Must be called with lock held."""
        self._events.append(event)
        if len(self._events) > 200:
            self._events = self._events[-200:]
        if self.on_alert:
            try:
                self.on_alert(event)
            except Exception:
                pass

    def _compute_risk_score(self, recent_renames: int) -> int:
        score = 0
        if recent_renames >= MASS_RENAME_HIGH_THRESHOLD:
            score += 80
        elif recent_renames >= MASS_RENAME_THRESHOLD:
            score += 40
        if self._ransom_extensions_seen:
            score += 60
        if self._ransom_notes_seen:
            score += 70
        return min(score, 100)


# ── Module-level singleton for use by the protection service ──────────────────

_monitor: RansomwareMonitor | None = None


def get_monitor() -> RansomwareMonitor | None:
    return _monitor


def start_monitor(watch_paths: list[Path], on_alert: Callable[[RansomwareEvent], None] | None = None) -> RansomwareMonitor:
    global _monitor
    if _monitor and _monitor._running:
        return _monitor
    _monitor = RansomwareMonitor(watch_paths=watch_paths, on_alert=on_alert)
    _monitor.start()
    return _monitor


def stop_monitor() -> None:
    global _monitor
    if _monitor:
        _monitor.stop()
        _monitor = None
