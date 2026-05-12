from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any


STATE_DIR_NAME = ".protection_state"


DEFAULT_SCRIPT_PATTERNS = [
    "frombase64string",
    "invoke-expression",
    "iex ",
    "downloadstring",
    "start-bitstransfer",
    "windowstyle hidden",
    "executionpolicy bypass",
    "encodedcommand",
    " -enc ",
    "reg add",
    "\\currentversion\\run",
    "schtasks /create",
    "rundll32",
    "mshta",
    "wscript.shell",
    "createobject(",
]


SUSPICIOUS_EXTENSIONS = {
    ".exe": 20,
    ".scr": 35,
    ".com": 35,
    ".pif": 35,
    ".msi": 20,
    ".bat": 25,
    ".cmd": 25,
    ".ps1": 30,
    ".vbs": 30,
    ".vbe": 30,
    ".js": 25,
    ".jse": 30,
    ".wsf": 30,
    ".hta": 35,
    ".jar": 20,
    ".lnk": 25,
    ".iso": 15,
    ".img": 15,
}


DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".jpg",
    ".jpeg",
    ".png",
}


RISKY_NAME_HINTS = [
    "crack",
    "keygen",
    "activator",
    "invoice",
    "receipt",
    "payment",
    "bank",
    "urgent",
    "update",
    "setup",
    "installer",
    "security",
    "account",
    "verify",
]


@dataclass(frozen=True)
class ProtectionConfig:
    state_dir: Path
    quarantine_dir: Path
    bad_hashes_file: Path
    log_file: Path
    suspicious_extensions: dict[str, int] = field(default_factory=lambda: dict(SUSPICIOUS_EXTENSIONS))
    script_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_SCRIPT_PATTERNS))
    max_file_size_mb: int = 250
    entropy_sample_size: int = 1024 * 1024
    block_threshold: int = 70
    medium_threshold: int = 35

    @classmethod
    def default(cls, root: Path | None = None) -> "ProtectionConfig":
        base = (root or Path.cwd()) / STATE_DIR_NAME
        return cls(
            state_dir=base,
            quarantine_dir=base / "quarantine",
            bad_hashes_file=base / "bad_hashes.txt",
            log_file=base / "events.jsonl",
        )


def default_watch_paths() -> list[Path]:
    home = Path.home()
    paths = [
        home / "Downloads",
        home / "Desktop",
        Path(os.environ.get("TEMP", str(home / "AppData" / "Local" / "Temp"))),
    ]
    return [path for path in paths if path.exists()]


def ensure_state(config: ProtectionConfig) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.quarantine_dir.mkdir(parents=True, exist_ok=True)
    if not config.bad_hashes_file.exists():
        config.bad_hashes_file.write_text(
            "# One lowercase SHA-256 hash per line. Lines beginning with # are ignored.\n",
            encoding="utf-8",
        )
    config.log_file.touch(exist_ok=True)


def load_config(root: Path | None = None) -> ProtectionConfig:
    config = ProtectionConfig.default(root)
    config_path = config.state_dir / "config.json"
    if not config_path.exists():
        return config

    data = json.loads(config_path.read_text(encoding="utf-8"))
    return ProtectionConfig(
        state_dir=config.state_dir,
        quarantine_dir=config.quarantine_dir,
        bad_hashes_file=config.bad_hashes_file,
        log_file=config.log_file,
        suspicious_extensions=_string_int_dict(data.get("suspicious_extensions"), config.suspicious_extensions),
        script_patterns=_string_list(data.get("script_patterns"), config.script_patterns),
        max_file_size_mb=int(data.get("max_file_size_mb", config.max_file_size_mb)),
        entropy_sample_size=int(data.get("entropy_sample_size", config.entropy_sample_size)),
        block_threshold=int(data.get("block_threshold", config.block_threshold)),
        medium_threshold=int(data.get("medium_threshold", config.medium_threshold)),
    )


def write_default_config(config: ProtectionConfig) -> Path:
    ensure_state(config)
    config_path = config.state_dir / "config.json"
    if not config_path.exists():
        data: dict[str, Any] = {
            "max_file_size_mb": config.max_file_size_mb,
            "entropy_sample_size": config.entropy_sample_size,
            "block_threshold": config.block_threshold,
            "medium_threshold": config.medium_threshold,
            "suspicious_extensions": config.suspicious_extensions,
            "script_patterns": config.script_patterns,
        }
        config_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return config_path


def load_bad_hashes(config: ProtectionConfig) -> set[str]:
    ensure_state(config)
    hashes: set[str] = set()
    for line in config.bad_hashes_file.read_text(encoding="utf-8").splitlines():
        value = line.strip().lower()
        if not value or value.startswith("#"):
            continue
        if len(value) == 64:
            hashes.add(value)
    return hashes


def _string_int_dict(value: Any, fallback: dict[str, int]) -> dict[str, int]:
    if not isinstance(value, dict):
        return dict(fallback)
    output: dict[str, int] = {}
    for key, item in value.items():
        if isinstance(key, str):
            try:
                output[key.lower()] = int(item)
            except (TypeError, ValueError):
                continue
    return output or dict(fallback)


def _string_list(value: Any, fallback: list[str]) -> list[str]:
    if not isinstance(value, list):
        return list(fallback)
    output = [item.lower() for item in value if isinstance(item, str) and item.strip()]
    return output or list(fallback)
