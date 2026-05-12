from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys

from .config import ProtectionConfig, ensure_state


TASK_NAME = "AI Scam Protection Realtime"
DAILY_SCAN_TASK_NAME = "AI Scam Protection Daily Scan"
BACKGROUND_SCRIPT = "run_protection_background.ps1"
STARTUP_SCRIPT = "AI Scam Protection.vbs"
SERVICE_STDOUT = "protection_service.out.log"
SERVICE_STDERR = "protection_service.err.log"


@dataclass
class ServiceCommandResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str

    def message(self) -> str:
        return (self.stdout or self.stderr).strip()


def install_service(
    config: ProtectionConfig,
    strict: bool = False,
    defender: bool = True,
    interval: float = 2.0,
    defender_timeout: int = 30,
) -> ServiceCommandResult:
    if not _is_windows():
        return _unsupported()

    ensure_state(config)
    script_path = write_background_script(
        config,
        strict=strict,
        defender=defender,
        interval=interval,
        defender_timeout=defender_timeout,
    )

    powershell = _powershell_path()
    if not powershell:
        return ServiceCommandResult(False, 1, "", "PowerShell was not found")

    task_run = (
        f'"{powershell}" -NoProfile -ExecutionPolicy Bypass '
        f'-WindowStyle Hidden -File "{script_path}"'
    )
    result = _run_schtasks(
        [
            "/Create",
            "/TN",
            TASK_NAME,
            "/TR",
            task_run,
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
            "/F",
        ]
    )
    if not result.ok and "access is denied" in result.message().lower():
        startup_path = install_startup_file(script_path)
        return ServiceCommandResult(
            True,
            0,
            f"Task Scheduler was denied, so installed no-admin startup launcher instead: {startup_path}",
            "",
        )
    return result


def uninstall_service() -> ServiceCommandResult:
    if not _is_windows():
        return _unsupported()
    task_result = _run_schtasks(["/Delete", "/TN", TASK_NAME, "/F"])
    _run_schtasks(["/Delete", "/TN", DAILY_SCAN_TASK_NAME, "/F"])
    startup_path = startup_file_path()
    removed_startup = False
    if startup_path and startup_path.exists():
        startup_path.unlink()
        removed_startup = True

    if task_result.ok or removed_startup:
        message = task_result.message()
        if removed_startup:
            message = f"{message}\nRemoved startup launcher: {startup_path}".strip()
        return ServiceCommandResult(True, 0, message, "")
    return task_result


def start_service(config: ProtectionConfig | None = None) -> ServiceCommandResult:
    if not _is_windows():
        return _unsupported()
    task_result = _run_schtasks(["/Run", "/TN", TASK_NAME])
    if task_result.ok:
        return task_result

    script_path = (config.state_dir / BACKGROUND_SCRIPT) if config else default_background_script_path()
    if script_path.exists():
        powershell = _powershell_path()
        if not powershell:
            return ServiceCommandResult(False, 1, "", "PowerShell was not found")
        try:
            subprocess.Popen(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-WindowStyle",
                    "Hidden",
                    "-File",
                    str(script_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            return ServiceCommandResult(False, 1, "", str(exc))
        return ServiceCommandResult(True, 0, f"Started startup launcher: {script_path}", "")

    return task_result


def stop_service() -> ServiceCommandResult:
    if not _is_windows():
        return _unsupported()
    task_result = _run_schtasks(["/End", "/TN", TASK_NAME])
    process_result = stop_running_protection_processes()
    if task_result.ok or process_result.ok:
        return ServiceCommandResult(
            True,
            0,
            f"{task_result.message()}\n{process_result.message()}".strip(),
            "",
        )
    return task_result


def install_daily_scan(time_str: str = "10:00") -> ServiceCommandResult:
    if not _is_windows():
        return _unsupported()

    python_path = Path(sys.executable).resolve()
    # This schedules the 'checkup' command which scans Downloads, Desktop, and Temp by default
    task_run = f'"{python_path}" -m ai_scam_protection.cli checkup --defender'

    return _run_schtasks(
        [
            "/Create",
            "/TN",
            DAILY_SCAN_TASK_NAME,
            "/TR",
            task_run,
            "/SC",
            "DAILY",
            "/ST",
            time_str,
            "/RL",
            "LIMITED",
            "/F",
        ]
    )


def service_status() -> ServiceCommandResult:
    if not _is_windows():
        return _unsupported()
    task_result = _run_schtasks(["/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"])
    task_status = task_result.message() if task_result.ok else "not installed"
    startup_path = startup_file_path()
    startup_status = "not installed"
    if startup_path and startup_path.exists():
        startup_status = f"installed: {startup_path}"
    process_status = running_protection_status().message()
    message = (
        f"Scheduled task:\n{task_status}\n\n"
        f"Startup launcher: {startup_status}\n\n"
        f"Running process:\n{process_status or 'not running'}"
    )
    return ServiceCommandResult(True, 0, message, "")


def write_background_script(
    config: ProtectionConfig,
    strict: bool,
    defender: bool,
    interval: float,
    defender_timeout: int,
) -> Path:
    ensure_state(config)
    script_path = config.state_dir / BACKGROUND_SCRIPT
    project_root = config.state_dir.parent.resolve()
    python_path = Path(sys.executable).resolve()
    args = [
        "-u",
        "-m",
        "ai_scam_protection.cli",
        "protect",
        "--interval",
        str(interval),
        "--defender-timeout",
        str(defender_timeout),
    ]
    if strict:
        args.append("--strict")
    if not defender:
        args.append("--no-defender")

    ps_args = ", ".join(_ps_quote(arg) for arg in args)
    script = f"""$ErrorActionPreference = "Continue"
$projectRoot = {_ps_quote(str(project_root))}
$python = {_ps_quote(str(python_path))}
$stdout = Join-Path $PSScriptRoot {_ps_quote(SERVICE_STDOUT)}
$stderr = Join-Path $PSScriptRoot {_ps_quote(SERVICE_STDERR)}
$env:PYTHONUNBUFFERED = "1"
Set-Location -LiteralPath $projectRoot
& $python @({ps_args}) >> $stdout 2>> $stderr
"""
    script_path.write_text(script, encoding="utf-8")
    return script_path


def install_startup_file(background_script_path: Path) -> Path:
    startup_path = startup_file_path()
    if startup_path is None:
        raise OSError("Windows startup folder could not be resolved")

    startup_path.parent.mkdir(parents=True, exist_ok=True)
    powershell = _powershell_path()
    if not powershell:
        raise OSError("PowerShell was not found")

    command = (
        f'"{powershell}" -NoProfile -ExecutionPolicy Bypass '
        f'-WindowStyle Hidden -File "{background_script_path}"'
    )
    content = (
        'Set WshShell = CreateObject("WScript.Shell")\n'
        f'WshShell.Run "{command.replace(chr(34), chr(34) + chr(34))}", 0, False\n'
    )
    startup_path.write_text(content, encoding="utf-8")
    return startup_path


def startup_file_path() -> Path | None:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / STARTUP_SCRIPT


def default_background_script_path() -> Path:
    return Path.cwd() / ".protection_state" / BACKGROUND_SCRIPT


def service_log_paths(config: ProtectionConfig) -> tuple[Path, Path]:
    return config.state_dir / SERVICE_STDOUT, config.state_dir / SERVICE_STDERR


def running_protection_status(exclude_self: bool = False) -> ServiceCommandResult:
    powershell = _powershell_path() or "powershell.exe"
    pid_filter = f"-and $_.ProcessId -ne {os.getpid()}" if exclude_self else ""
    command = [
        powershell,
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-CimInstance Win32_Process | "
            f"Where-Object {{ $_.Name -like 'python*' -and $_.CommandLine -like '*ai_scam_protection.cli protect*' {pid_filter} }} | "
            "Select-Object ProcessId,Name,CommandLine | Format-List"
        ),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return ServiceCommandResult(completed.returncode == 0, completed.returncode, completed.stdout.strip(), completed.stderr.strip())


def stop_running_protection_processes() -> ServiceCommandResult:
    powershell = _powershell_path() or "powershell.exe"
    command = [
        powershell,
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "$processes = Get-CimInstance Win32_Process | "
            "Where-Object { $_.Name -like 'python*' -and $_.CommandLine -like '*ai_scam_protection.cli protect*' }; "
            "if (-not $processes) { 'No protection process was running.'; exit 0 }; "
            "$processes | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; "
            "$processes | Select-Object ProcessId,CommandLine | Format-List"
        ),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return ServiceCommandResult(completed.returncode == 0, completed.returncode, completed.stdout.strip(), completed.stderr.strip())


def _run_schtasks(args: list[str]) -> ServiceCommandResult:
    command = ["schtasks", *args]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return ServiceCommandResult(
        ok=completed.returncode == 0,
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _powershell_path() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe")


def _unsupported() -> ServiceCommandResult:
    return ServiceCommandResult(False, 1, "", "Service install is only supported on Windows")


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"
