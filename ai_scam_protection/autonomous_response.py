"""
Autonomous Response System for ShieldScan.

When a high-confidence threat is detected, this module can automatically:
  1. Kill the malicious process (if a PID is known)
  2. Quarantine the file (delegates to QuarantineManager)
  3. Block outbound network connections from a process (Windows Firewall rule)
  4. Create a VSS shadow copy snapshot before quarantine (ransomware rollback)
  5. Restore files from shadow copy (ransomware rollback)
  6. Log all response actions to events.jsonl

All actions are logged and reversible where possible.
Network blocking uses named Windows Firewall rules that can be removed.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .logging_utils import append_event, utc_now


# ── Response action types ──────────────────────────────────────────────────────

ACTION_KILL_PROCESS = "kill_process"
ACTION_QUARANTINE_FILE = "quarantine_file"
ACTION_BLOCK_NETWORK = "block_network"
ACTION_CREATE_SNAPSHOT = "create_snapshot"
ACTION_RESTORE_SNAPSHOT = "restore_snapshot"
ACTION_REMOVE_FIREWALL_RULE = "remove_firewall_rule"


@dataclass
class ResponseAction:
    action_type: str
    target: str          # PID, file path, process name, or snapshot ID
    success: bool
    message: str
    timestamp: str = field(default_factory=utc_now)
    reversible: bool = True
    undo_command: str | None = None

    def to_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "success": self.success,
            "message": self.message,
            "timestamp": self.timestamp,
            "reversible": self.reversible,
            "undo_command": self.undo_command,
        }


@dataclass
class ResponseResult:
    threat_description: str
    actions: list[ResponseAction] = field(default_factory=list)
    overall_success: bool = False

    def to_dict(self) -> dict:
        return {
            "threat_description": self.threat_description,
            "actions": [a.to_dict() for a in self.actions],
            "overall_success": self.overall_success,
            "timestamp": utc_now(),
        }


class AutonomousResponder:
    """
    Executes automated response actions against detected threats.
    All actions are logged. Destructive actions require explicit enable flags.
    """

    def __init__(
        self,
        log_file: Path,
        allow_process_kill: bool = False,
        allow_network_block: bool = True,
        allow_snapshot: bool = True,
    ) -> None:
        self.log_file = log_file
        self.allow_process_kill = allow_process_kill
        self.allow_network_block = allow_network_block
        self.allow_snapshot = allow_snapshot
        self._firewall_rules: list[str] = []   # track rules we created

    def respond_to_threat(
        self,
        threat_description: str,
        file_path: Path | None = None,
        pid: int | None = None,
        process_name: str | None = None,
        auto_quarantine: bool = False,
    ) -> ResponseResult:
        """
        Execute appropriate response actions for a detected threat.
        Returns a ResponseResult with all actions taken.
        """
        result = ResponseResult(threat_description=threat_description)

        # 1. Create snapshot before any file changes (ransomware rollback prep)
        if self.allow_snapshot and file_path:
            snap = self.create_vss_snapshot(file_path.drive or "C:")
            result.actions.append(snap)

        # 2. Kill the process if PID known and kill is enabled
        if pid and self.allow_process_kill:
            kill = self.kill_process(pid)
            result.actions.append(kill)

        # 3. Block network for the process
        if process_name and self.allow_network_block:
            block = self.block_process_network(process_name)
            result.actions.append(block)

        # 4. Quarantine the file
        if file_path and auto_quarantine and file_path.exists():
            quarantine = self.quarantine_file(file_path)
            result.actions.append(quarantine)

        result.overall_success = any(a.success for a in result.actions)

        # Log to events.jsonl
        append_event(self.log_file, "autonomous_response", result.to_dict())

        return result

    def kill_process(self, pid: int) -> ResponseAction:
        """Kill a process by PID using taskkill."""
        if not _is_windows():
            return ResponseAction(
                action_type=ACTION_KILL_PROCESS,
                target=str(pid),
                success=False,
                message="Process kill only supported on Windows",
                reversible=False,
            )
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            success = result.returncode == 0
            return ResponseAction(
                action_type=ACTION_KILL_PROCESS,
                target=str(pid),
                success=success,
                message=result.stdout.strip() or result.stderr.strip() or f"PID {pid} terminated",
                reversible=False,
            )
        except Exception as exc:
            return ResponseAction(
                action_type=ACTION_KILL_PROCESS,
                target=str(pid),
                success=False,
                message=str(exc),
                reversible=False,
            )

    def block_process_network(self, process_name: str) -> ResponseAction:
        """
        Add a Windows Firewall outbound block rule for a process name.
        Rule name: ShieldScan_Block_{process_name}
        """
        if not _is_windows():
            return ResponseAction(
                action_type=ACTION_BLOCK_NETWORK,
                target=process_name,
                success=False,
                message="Firewall rules only supported on Windows",
            )

        rule_name = f"ShieldScan_Block_{process_name.replace('.', '_')}"
        ps = _ps()
        if not ps:
            return ResponseAction(
                action_type=ACTION_BLOCK_NETWORK,
                target=process_name,
                success=False,
                message="PowerShell not found",
            )

        try:
            cmd = (
                f"New-NetFirewallRule -DisplayName '{rule_name}' "
                f"-Direction Outbound -Action Block "
                f"-Program '%SystemRoot%\\System32\\{process_name}' "
                f"-Enabled True -Profile Any"
            )
            result = subprocess.run(
                [ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=15, check=False,
            )
            success = result.returncode == 0
            if success:
                self._firewall_rules.append(rule_name)
            undo = f"Remove-NetFirewallRule -DisplayName '{rule_name}'"
            return ResponseAction(
                action_type=ACTION_BLOCK_NETWORK,
                target=process_name,
                success=success,
                message=f"Firewall rule '{rule_name}' {'created' if success else 'failed: ' + result.stderr.strip()}",
                reversible=True,
                undo_command=undo,
            )
        except Exception as exc:
            return ResponseAction(
                action_type=ACTION_BLOCK_NETWORK,
                target=process_name,
                success=False,
                message=str(exc),
            )

    def remove_firewall_rule(self, rule_name: str) -> ResponseAction:
        """Remove a firewall rule created by block_process_network."""
        ps = _ps()
        if not ps:
            return ResponseAction(
                action_type=ACTION_REMOVE_FIREWALL_RULE,
                target=rule_name,
                success=False,
                message="PowerShell not found",
            )
        try:
            cmd = f"Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"
            result = subprocess.run(
                [ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if rule_name in self._firewall_rules:
                self._firewall_rules.remove(rule_name)
            return ResponseAction(
                action_type=ACTION_REMOVE_FIREWALL_RULE,
                target=rule_name,
                success=result.returncode == 0,
                message=f"Firewall rule '{rule_name}' removed",
                reversible=False,
            )
        except Exception as exc:
            return ResponseAction(
                action_type=ACTION_REMOVE_FIREWALL_RULE,
                target=rule_name,
                success=False,
                message=str(exc),
            )

    def create_vss_snapshot(self, drive: str = "C:") -> ResponseAction:
        """
        Create a VSS (Volume Shadow Copy) snapshot for ransomware rollback.
        Requires elevation. Returns the snapshot ID on success.
        """
        if not _is_windows():
            return ResponseAction(
                action_type=ACTION_CREATE_SNAPSHOT,
                target=drive,
                success=False,
                message="VSS snapshots only supported on Windows",
            )
        ps = _ps()
        if not ps:
            return ResponseAction(
                action_type=ACTION_CREATE_SNAPSHOT,
                target=drive,
                success=False,
                message="PowerShell not found",
            )
        try:
            cmd = (
                f"$s = (Get-WmiObject -List Win32_ShadowCopy).Create('{drive}\\\\', 'ClientAccessible'); "
                f"$s.ShadowID"
            )
            result = subprocess.run(
                [ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=30, check=False,
            )
            shadow_id = result.stdout.strip()
            success = result.returncode == 0 and shadow_id
            undo = f"Get-WmiObject Win32_ShadowCopy | Where-Object {{$_.ID -eq '{shadow_id}'}} | Remove-WmiObject"
            return ResponseAction(
                action_type=ACTION_CREATE_SNAPSHOT,
                target=drive,
                success=bool(success),
                message=f"VSS snapshot created: {shadow_id}" if success else f"VSS failed: {result.stderr.strip()}",
                reversible=True,
                undo_command=undo,
            )
        except Exception as exc:
            return ResponseAction(
                action_type=ACTION_CREATE_SNAPSHOT,
                target=drive,
                success=False,
                message=str(exc),
            )

    def restore_from_snapshot(self, shadow_id: str, target_path: Path) -> ResponseAction:
        """
        Restore a file or directory from a VSS shadow copy.
        shadow_id: the VSS snapshot ID (from create_vss_snapshot)
        target_path: the path to restore
        """
        if not _is_windows():
            return ResponseAction(
                action_type=ACTION_RESTORE_SNAPSHOT,
                target=str(target_path),
                success=False,
                message="VSS restore only supported on Windows",
            )
        ps = _ps()
        if not ps:
            return ResponseAction(
                action_type=ACTION_RESTORE_SNAPSHOT,
                target=str(target_path),
                success=False,
                message="PowerShell not found",
            )
        try:
            # Get the shadow copy device path
            cmd = (
                f"$sc = Get-WmiObject Win32_ShadowCopy | Where-Object {{$_.ID -eq '{shadow_id}'}}; "
                f"if ($sc) {{ $sc.DeviceObject }} else {{ '' }}"
            )
            result = subprocess.run(
                [ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=15, check=False,
            )
            device = result.stdout.strip()
            if not device:
                return ResponseAction(
                    action_type=ACTION_RESTORE_SNAPSHOT,
                    target=str(target_path),
                    success=False,
                    message=f"Shadow copy {shadow_id} not found",
                )

            # Build the shadow path: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\path\to\file
            drive = str(target_path.drive)  # e.g. "C:"
            rel_path = str(target_path).replace(drive, "").lstrip("\\")
            shadow_path = f"{device}\\{rel_path}"

            # Copy from shadow to original location
            copy_cmd = f"Copy-Item -Path '{shadow_path}' -Destination '{target_path}' -Force -Recurse"
            copy_result = subprocess.run(
                [ps, "-NoProfile", "-NonInteractive", "-Command", copy_cmd],
                capture_output=True, text=True, timeout=30, check=False,
            )
            success = copy_result.returncode == 0
            return ResponseAction(
                action_type=ACTION_RESTORE_SNAPSHOT,
                target=str(target_path),
                success=success,
                message=f"Restored from snapshot {shadow_id}" if success else copy_result.stderr.strip(),
                reversible=False,
            )
        except Exception as exc:
            return ResponseAction(
                action_type=ACTION_RESTORE_SNAPSHOT,
                target=str(target_path),
                success=False,
                message=str(exc),
            )

    def quarantine_file(self, file_path: Path) -> ResponseAction:
        """Move a file to a safe quarantine location."""
        try:
            quarantine_dir = self.log_file.parent / "quarantine"
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            dest = quarantine_dir / f"{file_path.name}.quarantine_auto"
            shutil.move(str(file_path), str(dest))
            return ResponseAction(
                action_type=ACTION_QUARANTINE_FILE,
                target=str(file_path),
                success=True,
                message=f"Moved to {dest}",
                reversible=True,
                undo_command=f"Move-Item '{dest}' '{file_path}'",
            )
        except Exception as exc:
            return ResponseAction(
                action_type=ACTION_QUARANTINE_FILE,
                target=str(file_path),
                success=False,
                message=str(exc),
            )

    def list_active_firewall_rules(self) -> list[str]:
        """Return list of firewall rules created by this responder."""
        return list(self._firewall_rules)

    def cleanup_all_rules(self) -> list[ResponseAction]:
        """Remove all firewall rules created by this session."""
        actions = []
        for rule in list(self._firewall_rules):
            actions.append(self.remove_firewall_rule(rule))
        return actions


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _ps() -> str | None:
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe")
