from __future__ import annotations

from pathlib import Path
import time
from typing import Callable, Iterable

from .config import ProtectionConfig, load_bad_hashes
from .scanner import ScanResult, scan_file


WatchCallback = Callable[[ScanResult], None]


def watch_paths(
    paths: Iterable[Path],
    config: ProtectionConfig,
    callback: WatchCallback,
    interval: float = 5.0,
    stop_event: object | None = None,
) -> None:
    """
    Polling watcher for new/changed files.

    stop_event:
      - If provided and has is_set(), the watcher will exit when stop_event.is_set() becomes True.
    """
    bad_hashes = load_bad_hashes(config)
    seen: dict[Path, tuple[int, int]] = {}

    for path in paths:
        for file_path in _iter_files(path, config):
            try:
                stat = file_path.stat()
            except OSError:
                continue
            seen[file_path] = (stat.st_mtime_ns, stat.st_size)

    while True:
        if stop_event is not None and getattr(stop_event, "is_set", None) and stop_event.is_set():
            return

        for root in paths:
            if stop_event is not None and getattr(stop_event, "is_set", None) and stop_event.is_set():
                return
            for file_path in _iter_files(root, config):
                try:
                    stat = file_path.stat()
                except OSError:
                    continue

                fingerprint = (stat.st_mtime_ns, stat.st_size)
                previous = seen.get(file_path)
                if previous == fingerprint:
                    continue

                seen[file_path] = fingerprint
                result = scan_file(file_path, config, bad_hashes)
                if result.level in {"low", "medium", "high"}:
                    callback(result)

        time.sleep(interval)


def _iter_files(root: Path, config: ProtectionConfig):
    root = root.expanduser()
    if root.is_file():
        yield root
        return
    if not root.exists():
        return
    quarantine_dir = config.quarantine_dir.resolve()
    try:
        for item in root.rglob("*"):
            try:
                resolved = item.resolve()
            except OSError:
                continue
            if quarantine_dir in resolved.parents or resolved == quarantine_dir:
                continue
            if item.is_file():
                yield item
    except OSError:
        return
