from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import platform
import shlex
from typing import Any

SUSPICIOUS_APP_HINTS = [
    "activator",
    "adware",
    "cleaner",
    "coupon",
    "crack",
    "driver updater",
    "free vpn",
    "keygen",
    "optimizer",
    "pc repair",
    "registry cleaner",
    "remote access",
    "search manager",
    "toolbar",
    "ultraviewer",
    "unknown publisher",
]


SUSPICIOUS_COMMAND_HINTS = [
    "appdata\\local\\temp",
    "\\temp\\",
    "encodedcommand",
    "executionpolicy bypass",
    "frombase64string",
    "invoke-expression",
    "mshta",
    "powershell",
    "rundll32",
    "schtasks",
    "wscript",
]


@dataclass
class AppAuditResult:
    name: str
    publisher: str | None = None
    version: str | None = None
    install_date: str | None = None
    install_location: str | None = None
    uninstall_string: str | None = None
    source: str | None = None
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def level(self) -> str:
        if self.score >= 60:
            return "high"
        if self.score >= 30:
            return "medium"
        if self.score > 0:
            return "low"
        return "clean"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "publisher": self.publisher,
            "version": self.version,
            "install_date": self.install_date,
            "install_location": self.install_location,
            "uninstall_string": self.uninstall_string,
            "source": self.source,
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
        }


@dataclass
class StartupAuditResult:
    name: str
    command: str
    source: str
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def level(self) -> str:
        if self.score >= 60:
            return "high"
        if self.score >= 30:
            return "medium"
        if self.score > 0:
            return "low"
        return "clean"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "command": self.command,
            "source": self.source,
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
        }


def audit_installed_apps() -> list[AppAuditResult]:
    if platform.system().lower() != "windows":
        return []

    try:
        import winreg
    except ImportError:
        return []

    roots = [
        (winreg.HKEY_CURRENT_USER, "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
    ]
    uninstall_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    views = [0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)]

    apps: dict[tuple[str, str | None], AppAuditResult] = {}
    for root, root_name in roots:
        for uninstall_path in uninstall_paths:
            for view in views:
                access = winreg.KEY_READ | view
                try:
                    with winreg.OpenKey(root, uninstall_path, 0, access) as key:
                        count = winreg.QueryInfoKey(key)[0]
                        for index in range(count):
                            try:
                                subkey_name = winreg.EnumKey(key, index)
                                app = _read_uninstall_subkey(winreg, key, subkey_name, f"{root_name}\\{uninstall_path}")
                            except OSError:
                                continue
                            if not app:
                                continue
                            apps.setdefault((app.name.lower(), app.install_location), app)
                except OSError:
                    continue

    return sorted((_score_app(app) for app in apps.values()), key=lambda item: (-item.score, item.name.lower()))


def audit_startup_entries() -> list[StartupAuditResult]:
    entries: list[StartupAuditResult] = []
    if platform.system().lower() == "windows":
        entries.extend(_registry_startup_entries())
        entries.extend(_startup_folder_entries())
    return sorted((_score_startup(entry) for entry in entries), key=lambda item: (-item.score, item.name.lower()))


def suspicious_apps(apps: list[AppAuditResult]) -> list[AppAuditResult]:
    return [app for app in apps if app.score >= 30]


def suspicious_startup_entries(entries: list[StartupAuditResult]) -> list[StartupAuditResult]:
    return [entry for entry in entries if entry.score >= 30]


def _read_uninstall_subkey(winreg: Any, parent_key: Any, subkey_name: str, source: str) -> AppAuditResult | None:
    with winreg.OpenKey(parent_key, subkey_name) as subkey:
        name = _reg_value(winreg, subkey, "DisplayName")
        if not name:
            return None
        system_component = _reg_value(winreg, subkey, "SystemComponent")
        if system_component == 1:
            return None
        return AppAuditResult(
            name=str(name),
            publisher=_optional_str(_reg_value(winreg, subkey, "Publisher")),
            version=_optional_str(_reg_value(winreg, subkey, "DisplayVersion")),
            install_date=_optional_str(_reg_value(winreg, subkey, "InstallDate")),
            install_location=_optional_str(_reg_value(winreg, subkey, "InstallLocation")),
            uninstall_string=_optional_str(_reg_value(winreg, subkey, "UninstallString")),
            source=f"{source}\\{subkey_name}",
        )


def _registry_startup_entries() -> list[StartupAuditResult]:
    try:
        import winreg
    except ImportError:
        return []

    entries: list[StartupAuditResult] = []
    roots = [
        (winreg.HKEY_CURRENT_USER, "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
    ]
    run_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    views = [0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)]

    for root, root_name in roots:
        for run_path in run_paths:
            for view in views:
                access = winreg.KEY_READ | view
                try:
                    with winreg.OpenKey(root, run_path, 0, access) as key:
                        count = winreg.QueryInfoKey(key)[1]
                        for index in range(count):
                            try:
                                name, command, _ = winreg.EnumValue(key, index)
                            except OSError:
                                continue
                            entries.append(
                                StartupAuditResult(
                                    name=str(name),
                                    command=str(command),
                                    source=f"{root_name}\\{run_path}",
                                )
                            )
                except OSError:
                    continue

    return _dedupe_startup(entries)


def _startup_folder_entries() -> list[StartupAuditResult]:
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    folders = []
    if appdata:
        folders.append(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
    if programdata:
        folders.append(Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\StartUp")

    entries: list[StartupAuditResult] = []
    for folder in folders:
        if not folder.exists():
            continue
        for item in folder.iterdir():
            if item.name.lower() == "desktop.ini":
                continue
            if item.is_file():
                entries.append(StartupAuditResult(name=item.name, command=str(item), source=str(folder)))
    return entries


def _score_app(app: AppAuditResult) -> AppAuditResult:
    haystack = " ".join(
        value.lower()
        for value in [
            app.name,
            app.publisher or "",
            app.install_location or "",
            app.uninstall_string or "",
        ]
    )

    for hint in SUSPICIOUS_APP_HINTS:
        if hint in haystack:
            app.score += 20
            app.reasons.append(f"contains risky app hint: {hint}")

    missing_publisher = not app.publisher
    if missing_publisher:
        app.score += 10
        app.reasons.append("missing publisher")

    location = (app.install_location or "").lower()
    if "\\appdata\\local\\temp" in location or "\\temp\\" in location:
        app.score += 20
        app.reasons.append("installed under Temp")
    elif "\\appdata\\" in location and missing_publisher:
        app.score += 20
        app.reasons.append("installed under AppData without a publisher")

    if app.uninstall_string:
        command = app.uninstall_string.lower()
        for hint in SUSPICIOUS_COMMAND_HINTS:
            if hint in command:
                app.score += 15
                app.reasons.append(f"uninstall command contains suspicious token: {hint}")
                break

    app.score = min(app.score, 100)
    return app


def _score_startup(entry: StartupAuditResult) -> StartupAuditResult:
    command = entry.command.lower()

    for hint in SUSPICIOUS_COMMAND_HINTS:
        if hint in command:
            entry.score += 25
            entry.reasons.append(f"startup command contains suspicious token: {hint}")

    if "\\appdata\\" in command or "\\temp\\" in command:
        if any(hint in command for hint in SUSPICIOUS_COMMAND_HINTS) or _command_has_missing_publisher_shape(command):
            entry.score += 20
            entry.reasons.append("startup target runs from AppData or Temp")

    target = _extract_command_path(entry.command)
    if target and not target.exists():
        entry.score += 10
        entry.reasons.append("startup target path does not exist")

    entry.score = min(entry.score, 100)
    return entry


def _extract_command_path(command: str) -> Path | None:
    try:
        parts = shlex.split(command, posix=False)
    except ValueError:
        return None
    if not parts:
        return None
    first = parts[0].strip('"')
    if not first or first.startswith("-"):
        return None
    if first.lower() in {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        return None
    return Path(os.path.expandvars(first))


def _command_has_missing_publisher_shape(command: str) -> bool:
    lower = command.lower()
    return "\\appdata\\" in lower and not any(
        known in lower
        for known in [
            "microsoft",
            "onedrive",
            "opera",
            "ecosiabrowser",
            "warthunder",
            "ollama",
        ]
    )


def _reg_value(winreg: Any, key: Any, name: str) -> object | None:
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def _optional_str(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _dedupe_startup(entries: list[StartupAuditResult]) -> list[StartupAuditResult]:
    deduped: dict[tuple[str, str], StartupAuditResult] = {}
    for entry in entries:
        deduped.setdefault((entry.name.lower(), entry.command.lower()), entry)
    return list(deduped.values())
