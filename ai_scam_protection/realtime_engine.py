from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import ProtectionConfig, default_watch_paths
from .logging_utils import append_event, utc_now
from .quarantine import QuarantineManager
from .scanner import ScanResult, scan_file
from .watcher import watch_paths


@dataclass
class EngineStatus:
    enabled: bool
    running: bool
    started_at: str | None
    last_error: str | None
    watched_paths: list[str]


class RealtimeEngine:
    """
    In-process real-time protection engine.

    Uses the existing polling watcher (watcher.py) + scanner.py + quarantine.py.
    This is the backend needed by the dashboard toggle (enable/disable).

    Note: This is not the Windows "Service" itself; service just starts the CLI/service
    process. This engine is what the local API toggles.
    """

    def __init__(self, config: ProtectionConfig, watched_paths: list[Path] | None = None) -> None:
        self.config = config
        self.watched_paths = watched_paths or default_watch_paths()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        self._lock = threading.Lock()
        self._running = False
        self._enabled = False
        self._started_at: str | None = None
        self._last_error: str | None = None

        self._quarantine_manager = QuarantineManager(config)

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._enabled = True
            self._stop_event.clear()
            self._running = True
            self._started_at = utc_now()
            self._last_error = None

        t = threading.Thread(target=self._run_loop, daemon=True, name="RealtimeEngine")
        self._thread = t
        t.start()

    def stop(self) -> None:
        with self._lock:
            self._enabled = False
            self._stop_event.set()

        t = self._thread
        if t and t.is_alive():
            t.join(timeout=5)

        with self._lock:
            self._running = False

    def get_status(self) -> EngineStatus:
        with self._lock:
            return EngineStatus(
                enabled=self._enabled,
                running=self._running,
                started_at=self._started_at,
                last_error=self._last_error,
                watched_paths=[str(p) for p in self.watched_paths],
            )

    # ── Internal ─────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """
        watcher.watch_paths() currently runs a polling loop without stop support.
        To still support enable/disable, we run it in a tight wrapper:
        - start watcher
        - on stop_event, exit by raising and letting thread end
        """

        def _callback(result: ScanResult) -> None:
            # Respect stop request as fast as possible
            if self._stop_event.is_set():
                return

            self._handle_detection(result)

        try:
            append_event(
                self.config.log_file,
                "engine_start",
                {"watched_paths": [str(p) for p in self.watched_paths]},
            )

            # This blocks forever; we rely on stop_event to stop scanning results,
            # and we also attempt to end by returning if stop_event is set.
            # (watch_paths implementation does not take stop_event, so worst case it keeps
            # polling until the thread is force-terminated by process lifecycle.)
            watch_paths(
                paths=self.watched_paths,
                config=self.config,
                callback=_callback,
                interval=2.0,
                stop_event=self._stop_event,
            )
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
            append_event(self.config.log_file, "engine_error", {"error": str(exc)})

    def _handle_detection(self, result: ScanResult) -> None:
        event: dict = result.to_dict()

        # Quarantine logic mirrors CLI protect behavior: quarantine high-risk
        should_quarantine = result.level in {"high"} or (result.score >= self.config.block_threshold)

        if should_quarantine:
            try:
                item = self._quarantine_manager.quarantine(result)
                event["quarantine_item"] = item.to_dict()
                append_event(self.config.log_file, "watch_detection", event)

            except Exception as exc:
                event["quarantine_error"] = str(exc)
                append_event(self.config.log_file, "watch_detection", event)
                return

        else:
            append_event(self.config.log_file, "watch_detection", event)

        # Cache latest detection for UI
        latest_detection_path = self.config.state_dir / "latest_detection.json"
        try:
            latest_detection_path.write_text(
                __import__("json").dumps(event, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception:
            pass


# ── Module-level singleton used by api_server ────────────────────────────────

_engine: RealtimeEngine | None = None
_engine_lock = threading.Lock()


def get_engine(config: ProtectionConfig) -> RealtimeEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = RealtimeEngine(config=config, watched_paths=default_watch_paths())
        return _engine
