"""
Native Messaging Host for ShieldScan.

Chrome communicates with this process via stdin/stdout using the
Chrome Native Messaging protocol (4-byte length-prefixed JSON messages).

This host bridges the browser extension to the Python protection engine,
enabling capabilities that the REST API can't provide:
  - Direct file system access (scan a file by path without HTTP)
  - Real-time event push (no polling needed)
  - Access to Windows APIs not available in the browser

Protocol:
  - Each message is a JSON object prefixed with a 4-byte little-endian length
  - The host reads from stdin and writes to stdout
  - Messages from extension → host: {"type": "...", "data": {...}}
  - Messages from host → extension: {"type": "...", "data": {...}}

Message types (extension → host):
  scan_file       — scan a file path: {"path": "C:\\..."}
  get_stats       — get protection stats
  get_detections  — get recent detections
  quarantine_list — list quarantine items
  ping            — health check

Message types (host → extension):
  scan_result     — result of a file scan
  stats           — protection stats
  detections      — recent detections
  quarantine      — quarantine list
  pong            — ping response
  error           — error response
  event           — real-time detection event (pushed proactively)
"""
from __future__ import annotations

import json
import struct
import sys
import threading
from pathlib import Path

# ── Resolve project root ───────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))


def _read_message() -> dict | None:
    """Read one native message from stdin."""
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) < 4:
        return None
    length = struct.unpack("<I", raw_length)[0]
    if length == 0 or length > 1024 * 1024:
        return None
    raw = sys.stdin.buffer.read(length)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _send_message(data: dict) -> None:
    """Send one native message to stdout."""
    encoded = json.dumps(data, default=str).encode("utf-8")
    length = struct.pack("<I", len(encoded))
    sys.stdout.buffer.write(length + encoded)
    sys.stdout.buffer.flush()


def _handle(message: dict) -> dict:
    """Dispatch a message to the appropriate handler."""
    msg_type = message.get("type", "")
    data = message.get("data", {})

    if msg_type == "ping":
        return {"type": "pong", "data": {"ok": True}}

    if msg_type == "scan_file":
        return _handle_scan_file(data)

    if msg_type == "get_stats":
        return _handle_get_stats()

    if msg_type == "get_detections":
        return _handle_get_detections(data)

    if msg_type == "quarantine_list":
        return _handle_quarantine_list()

    return {"type": "error", "data": {"message": f"Unknown message type: {msg_type}"}}


def _handle_scan_file(data: dict) -> dict:
    path_str = data.get("path", "")
    if not path_str:
        return {"type": "error", "data": {"message": "No path provided"}}
    try:
        from ai_scam_protection.config import load_config
        from ai_scam_protection.scanner import scan_file
        config = load_config(_ROOT)
        result = scan_file(Path(path_str), config)
        return {"type": "scan_result", "data": result.to_dict()}
    except Exception as exc:
        return {"type": "error", "data": {"message": str(exc), "path": path_str}}


def _handle_get_stats() -> dict:
    try:
        from ai_scam_protection.config import load_config, ensure_state
        from ai_scam_protection.logging_utils import utc_now
        import json as _json
        config = load_config(_ROOT)
        ensure_state(config)
        events = []
        if config.log_file.exists():
            for line in config.log_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    events.append(_json.loads(line))
                except Exception:
                    pass
        threats = sum(
            1 for e in events
            if e.get("type") in {"watch_detection", "scan"}
            and isinstance(e.get("payload"), dict)
            and e["payload"].get("level") == "high"
        )
        return {"type": "stats", "data": {
            "threats_blocked": threats,
            "total_events": len(events),
            "timestamp": utc_now(),
        }}
    except Exception as exc:
        return {"type": "error", "data": {"message": str(exc)}}


def _handle_get_detections(data: dict) -> dict:
    limit = int(data.get("limit", 10))
    try:
        from ai_scam_protection.config import load_config
        import json as _json
        config = load_config(_ROOT)
        events = []
        if config.log_file.exists():
            for line in config.log_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    events.append(_json.loads(line))
                except Exception:
                    pass
        detections = []
        for e in reversed(events):
            if len(detections) >= limit:
                break
            if e.get("type") in {"watch_detection", "scan", "quarantine"}:
                payload = e.get("payload", {})
                if isinstance(payload, dict) and payload.get("level") in {"medium", "high"}:
                    detections.append({
                        "timestamp": e.get("timestamp"),
                        "level": payload.get("level"),
                        "path": payload.get("path") or payload.get("original_path", ""),
                        "score": payload.get("score", 0),
                    })
        return {"type": "detections", "data": {"detections": detections}}
    except Exception as exc:
        return {"type": "error", "data": {"message": str(exc)}}


def _handle_quarantine_list() -> dict:
    try:
        from ai_scam_protection.config import load_config
        from ai_scam_protection.quarantine import QuarantineManager
        config = load_config(_ROOT)
        manager = QuarantineManager(config)
        items = manager.list_items()
        return {"type": "quarantine", "data": {
            "items": [item.to_dict() for item in items],
            "count": len(items),
        }}
    except Exception as exc:
        return {"type": "error", "data": {"message": str(exc)}}


def main() -> None:
    """Main loop — read messages from Chrome and respond."""
    while True:
        message = _read_message()
        if message is None:
            break
        try:
            response = _handle(message)
        except Exception as exc:
            response = {"type": "error", "data": {"message": str(exc)}}
        _send_message(response)


if __name__ == "__main__":
    main()
