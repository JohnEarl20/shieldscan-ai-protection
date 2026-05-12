from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform
import shutil
import subprocess


@dataclass
class DefenderResult:
    available: bool
    returncode: int | None
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.available and self.returncode == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "ok": self.ok,
        }


def scan_with_defender(path: Path, timeout: int = 300) -> DefenderResult:
    if platform.system().lower() != "windows":
        return DefenderResult(False, None, "", "Microsoft Defender integration is only available on Windows")

    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not powershell:
        return DefenderResult(False, None, "", "PowerShell was not found")

    quoted_path = powershell_single_quoted(str(path))
    command = [
        powershell,
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"Start-MpScan -ScanType CustomScan -ScanPath {quoted_path}",
    ]
    return _run_command(command, timeout)


def defender_status(timeout: int = 60) -> DefenderResult:
    if platform.system().lower() != "windows":
        return DefenderResult(False, None, "", "Microsoft Defender integration is only available on Windows")

    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not powershell:
        return DefenderResult(False, None, "", "PowerShell was not found")

    command = [
        powershell,
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,NISEnabled | ConvertTo-Json",
    ]
    return _run_command(command, timeout)


def _run_command(command: list[str], timeout: int) -> DefenderResult:
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return DefenderResult(True, None, "", str(exc))

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return DefenderResult(
            True,
            None,
            stdout.strip(),
            f"Microsoft Defender scan timed out after {timeout} seconds. {stderr.strip()}".strip(),
        )
    except KeyboardInterrupt:
        process.kill()
        process.communicate()
        raise

    return DefenderResult(True, process.returncode, stdout.strip(), stderr.strip())


def powershell_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"
