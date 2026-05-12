from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .config import default_watch_paths, ensure_state, load_config, write_default_config
from .defender import defender_status, scan_with_defender
from .logging_utils import append_event
from .notification import show_alert
from .quarantine import QuarantineManager
from .rootkit_detector import scan_for_rootkits
from .cloud_intel import CloudIntel, load_api_keys, save_api_key
from .scanner import ScanResult, scan_paths
from .service import (
    install_daily_scan,
    install_service,
    service_log_paths,
    service_status,
    start_service,
    running_protection_status,
    stop_service,
    uninstall_service,
)
from .system_audit import (
    audit_installed_apps,
    audit_startup_entries,
    suspicious_apps,
    suspicious_startup_entries,
)
from .watcher import watch_paths


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config()
    ensure_state(config)

    try:
        if args.command == "init":
            return _cmd_init(config)
        if args.command == "scan":
            return _cmd_scan(args, config)
        if args.command == "checkup":
            return _cmd_checkup(args, config)
        if args.command == "protect":
            return _cmd_protect(args, config)
        if args.command == "watch":
            return _cmd_watch(args, config)
        if args.command == "quarantine":
            return _cmd_quarantine(args, config)
        if args.command == "service":
            return _cmd_service(args, config)
        if args.command == "detections":
            return _cmd_detections(args, config)
        if args.command == "checkup-reports":
            return _cmd_checkup_reports(args, config)
        if args.command == "status":
            return _cmd_status(config)
        if args.command == "rootkit-scan":
            return _cmd_rootkit_scan(args, config)
        if args.command == "cloud-lookup":
            return _cmd_cloud_lookup(args, config)
        if args.command == "cloud-key":
            return _cmd_cloud_key(args, config)
        if args.command == "api-server":
            return _cmd_api_server(args)
    except KeyboardInterrupt:
        print("\nStopped by user.", file=sys.stderr)
        return 130

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-scam-protect",
        description="Defensive file scanner, watcher, and quarantine MVP.",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Create local config, hash list, log, and quarantine folders.")

    scan_parser = subparsers.add_parser("scan", help="Scan one or more files or folders.")
    scan_parser.add_argument("paths", nargs="+", type=Path)
    scan_parser.add_argument("--recursive", action="store_true", help="Scan folders recursively.")
    scan_parser.add_argument("--quarantine", action="store_true", help="Move high-risk detections to quarantine.")
    scan_parser.add_argument("--defender", action="store_true", help="Ask Microsoft Defender to scan suspicious files.")
    scan_parser.add_argument("--defender-timeout", type=int, default=60, help="Seconds to wait per Defender scan.")
    scan_parser.add_argument("--json", action="store_true", help="Print JSON results.")

    checkup_parser = subparsers.add_parser(
        "checkup",
        help="Run a one-time protection check, print a report, and stop automatically.",
    )
    checkup_parser.add_argument("paths", nargs="*", type=Path, help="Folders to scan. Defaults to Downloads, Desktop, and Temp.")
    checkup_parser.add_argument("--no-recursive", action="store_true", help="Do not scan folders recursively.")
    checkup_parser.add_argument("--quarantine", action="store_true", help="Move high-risk detections to quarantine.")
    checkup_parser.add_argument("--defender", action="store_true", help="Ask Microsoft Defender to scan suspicious files.")
    checkup_parser.add_argument("--defender-timeout", type=int, default=30, help="Seconds to wait per Defender scan.")
    checkup_parser.add_argument("--json", action="store_true", help="Print JSON report.")

    protect_parser = subparsers.add_parser(
        "protect",
        help="Run real-time protection that alerts immediately and blocks high-risk detections.",
    )
    protect_parser.add_argument("paths", nargs="*", type=Path, help="Folders to protect. Defaults to Downloads, Desktop, and Temp.")
    protect_parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds.")
    protect_parser.add_argument("--strict", action="store_true", help="Also quarantine medium-risk detections. This can block legitimate installers.")
    protect_parser.add_argument("--no-defender", action="store_true", help="Do not ask Microsoft Defender to scan suspicious files.")
    protect_parser.add_argument("--defender-timeout", type=int, default=30, help="Seconds to wait per Defender scan.")

    watch_parser = subparsers.add_parser("watch", help="Watch folders for new or changed suspicious files.")
    watch_parser.add_argument("paths", nargs="*", type=Path, help="Folders to watch. Defaults to Downloads, Desktop, and Temp.")
    watch_parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds.")
    watch_parser.add_argument("--block", action="store_true", help="Quarantine high-risk detections.")
    watch_parser.add_argument("--strict", action="store_true", help="Also quarantine medium-risk detections when --block is used.")
    watch_parser.add_argument("--defender", action="store_true", help="Ask Microsoft Defender to scan suspicious files.")
    watch_parser.add_argument("--defender-timeout", type=int, default=60, help="Seconds to wait per Defender scan.")

    quarantine_parser = subparsers.add_parser("quarantine", help="Manage quarantine.")
    quarantine_subparsers = quarantine_parser.add_subparsers(dest="quarantine_command")
    quarantine_subparsers.add_parser("list", help="List quarantine items.")
    restore_parser = quarantine_subparsers.add_parser("restore", help="Restore a quarantine item.")
    restore_parser.add_argument("item_id")
    restore_parser.add_argument("--destination", type=Path)
    restore_parser.add_argument("--overwrite", action="store_true")

    service_parser = subparsers.add_parser("service", help="Install and manage always-on background protection.")
    service_subparsers = service_parser.add_subparsers(dest="service_command")
    service_install = service_subparsers.add_parser("install", help="Install auto-start protection at Windows logon.")
    service_install.add_argument("--strict", action="store_true", help="Also quarantine medium-risk detections.")
    service_install.add_argument("--no-defender", action="store_true", help="Do not ask Microsoft Defender to scan suspicious files.")
    service_install.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds.")
    service_install.add_argument("--defender-timeout", type=int, default=30, help="Seconds to wait per Defender scan.")
    service_subparsers.add_parser("uninstall", help="Remove auto-start protection.")
    service_subparsers.add_parser("start", help="Start background protection now.")
    service_subparsers.add_parser("stop", help="Stop background protection.")
    service_daily = service_subparsers.add_parser("daily-scan", help="Schedule a daily full scan of Downloads at a specific time.")
    service_daily.add_argument("--time", default="10:00", help="Time to run in 24h format HH:mm (default: 10:00).")
    service_subparsers.add_parser("status", help="Show background protection task status.")
    service_subparsers.add_parser("logs", help="Show background protection log paths.")

    detections_parser = subparsers.add_parser("detections", help="Show recent suspicious or blocked detections.")
    detections_parser.add_argument("--limit", type=int, default=20, help="Maximum number of detections to show.")
    detections_parser.add_argument("--all", action="store_true", help="Include medium-risk warnings from scans.")
    detections_parser.add_argument("--json", action="store_true", help="Print JSON detections.")

    checkup_reports_parser = subparsers.add_parser("checkup-reports", help="Show recent daily scan (checkup) reports.")
    checkup_reports_parser.add_argument("--limit", type=int, default=5, help="Maximum number of reports to show.")
    checkup_reports_parser.add_argument("--json", action="store_true", help="Print JSON reports.")

    subparsers.add_parser("status", help="Show local protection and Defender status.")

    rootkit_parser = subparsers.add_parser("rootkit-scan", help="Scan for rootkits, hidden processes, and kernel-level threats.")
    rootkit_parser.add_argument("--timeout", type=int, default=30, help="Seconds per check (default: 30).")
    rootkit_parser.add_argument("--json", action="store_true", help="Print JSON results.")

    cloud_parser = subparsers.add_parser("cloud-lookup", help="Look up a file hash or URL in cloud threat intelligence databases.")
    cloud_parser.add_argument("target", help="SHA-256 hash, file path, or URL to look up.")
    cloud_parser.add_argument("--vt-key", default=None, help="VirusTotal API key (overrides saved key).")
    cloud_parser.add_argument("--abusech-key", default=None, help="abuse.ch Auth-Key (overrides saved key).")
    cloud_parser.add_argument("--json", action="store_true", help="Print JSON results.")

    cloud_key_parser = subparsers.add_parser("cloud-key", help="Save a cloud threat intelligence API key.")
    cloud_key_parser.add_argument("service", choices=["virustotal", "abusech"],
                                  help="Service to configure: 'virustotal' or 'abusech'.")
    cloud_key_parser.add_argument("key", help="The API key / Auth-Key to save.")

    api_server_parser = subparsers.add_parser("api-server", help="Start the local REST API server for dashboard integration (port 8765).")
    api_server_parser.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765).")

    return parser


def _cmd_init(config) -> int:
    config_path = write_default_config(config)
    print(f"Created state directory: {config.state_dir}")
    print(f"Config: {config_path}")
    print(f"Bad hashes: {config.bad_hashes_file}")
    print(f"Quarantine: {config.quarantine_dir}")
    
    extension_path = config.state_dir.parent / "browser_extension"
    print(f"\nBrowser Extension path (for Edge/Chrome): {extension_path}")
    return 0


def _cmd_scan(args, config) -> int:
    manager = QuarantineManager(config)
    results = scan_paths(args.paths, args.recursive, config)
    output: list[dict[str, object]] = []

    for result in results:
        event = result.to_dict()

        if args.defender and result.level in {"medium", "high"}:
            if not args.json:
                print(f"Defender scan: {result.path}")
            defender_result = scan_with_defender(result.path, timeout=args.defender_timeout)
            event["defender"] = defender_result.to_dict()
            if not args.json and not defender_result.ok and defender_result.stderr:
                print(f"Defender scan warning: {defender_result.stderr}", file=sys.stderr)

        if args.quarantine and result.should_block and result.path.exists():
            try:
                item = manager.quarantine(result)
                event["quarantine_item"] = item.to_dict()
            except OSError as exc:
                event["quarantine_error"] = str(exc)

        append_event(config.log_file, "scan", event)
        output.append(event)

    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        _print_scan_summary(results)

    return 1 if any(result.should_block for result in results) else 0


def _cmd_checkup(args, config) -> int:
    paths = args.paths or default_watch_paths()
    if not paths:
        print("No default checkup paths exist. Provide one or more paths.", file=sys.stderr)
        return 2

    manager = QuarantineManager(config)
    print("Running one-time protection check...")
    print("Scanning:")
    for path in paths:
        print(f"  {path}")

    results = scan_paths(paths, recursive=not args.no_recursive, config=config)
    scan_events = _process_scan_results(args, config, manager, results)
    apps = audit_installed_apps()
    startup_entries = audit_startup_entries()
    app_findings = suspicious_apps(apps)
    startup_findings = suspicious_startup_entries(startup_entries)

    report = {
        "scan_results": scan_events,
        "installed_app_count": len(apps),
        "suspicious_installed_apps": [app.to_dict() for app in app_findings],
        "startup_entry_count": len(startup_entries),
        "suspicious_startup_entries": [entry.to_dict() for entry in startup_findings],
    }
    latest_report_path = config.state_dir / "latest_checkup.json"
    latest_report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    append_event(config.log_file, "checkup", report)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_checkup_summary(results, apps, app_findings, startup_entries, startup_findings, latest_report_path)

    has_high_scan = any(result.should_block for result in results)
    has_high_app = any(app.level == "high" for app in app_findings)
    has_high_startup = any(entry.level == "high" for entry in startup_findings)
    return 1 if has_high_scan or has_high_app or has_high_startup else 0


def _cmd_watch(args, config) -> int:
    return _run_realtime(args, config, command_name="watch", block=args.block, defender=args.defender)


def _cmd_protect(args, config) -> int:
    defender = not args.no_defender
    return _run_realtime(args, config, command_name="protect", block=True, defender=defender)


def _run_realtime(args, config, command_name: str, block: bool, defender: bool) -> int:
    manager = QuarantineManager(config)
    paths = args.paths or default_watch_paths()
    if not paths:
        print("No default protection paths exist. Provide one or more paths.", file=sys.stderr)
        return 2

    strict = getattr(args, "strict", False)
    print("Real-time protection:")
    for path in paths:
        print(f"  {path}")
    if block:
        policy = "block high-risk and medium-risk files" if strict else "block high-risk files"
    else:
        policy = "report only"
    print(f"Mode: {policy}")
    print(f"Microsoft Defender: {'enabled' if defender else 'disabled'}")
    print("\n[✔] Real-time Shield is active and monitoring...")
    if command_name == "protect":
        print("Press Ctrl+C to stop protection.")

    # Quality improvement: detect redundant instances
    existing = running_protection_status(exclude_self=True)
    if existing.stdout:
        print("\n[!] WARNING: Another protection instance is already running.")
        print("Running multiple instances can cause duplicate logs and performance issues.")
        print("Existing processes found:")
        print(existing.stdout, "\n")

    def on_detection(result: ScanResult) -> None:
        event = result.to_dict()
        print("\nImmediate detection:")
        print_result(result)

        if defender and result.level in {"medium", "high"}:
            defender_result = scan_with_defender(result.path, timeout=args.defender_timeout)
            event["defender"] = defender_result.to_dict()
            print(f"  Invoking Microsoft Defender for {result.path.name}...")
            if defender_result.stdout:
                print(f"    Defender reported: {defender_result.stdout.strip()}")
            if defender_result.stderr and not defender_result.ok:
                print(f"    Defender warning/error: {defender_result.stderr.strip()}")
            if not defender_result.stdout and not defender_result.stderr:
                print(f"    Defender completed with no specific findings.")

        # Automatic block for Viruses (Score 100) even in watch-only mode
        is_virus = result.score >= 100
        should_quarantine = (block and _should_quarantine(result, strict=strict)) or is_virus
        if should_quarantine and result.path.exists():
            try:
                item = manager.quarantine(result)
                event["quarantine_item"] = item.to_dict()
                print(f"Action: quarantined ({item.item_id})")
                show_alert("Threat Blocked", f"Quarantined: {result.path.name}")
            except OSError as exc:
                event["quarantine_error"] = str(exc)
                print(f"Quarantine failed: {exc}", file=sys.stderr)
        elif result.level in {"medium", "high"}:
            if block:
                print("Action: alerted only, below blocking threshold")
            show_alert("Suspicious File Detected", f"Warning: {result.path.name}\nLevel: {result.level.upper()}")

        latest_detection_path = config.state_dir / "latest_detection.json"
        latest_detection_path.write_text(json.dumps(event, indent=2, sort_keys=True), encoding="utf-8")
        append_event(config.log_file, "watch_detection", event)

    try:
        watch_paths(paths, config, on_detection, interval=args.interval)
    except KeyboardInterrupt:
        print("\nStopped real-time protection.")
        return 0


def _cmd_quarantine(args, config) -> int:
    manager = QuarantineManager(config)
    if args.quarantine_command == "list":
        items = manager.list_items()
        if not items:
            print("Quarantine is empty.")
            return 0
        for item in items:
            print(f"{item.item_id} | {item.level} | score={item.score} | {item.original_path}")
        return 0

    if args.quarantine_command == "restore":
        restored = manager.restore(args.item_id, destination=args.destination, overwrite=args.overwrite)
        print(f"Restored to: {restored}")
        return 0

    print("Specify a quarantine command: list or restore", file=sys.stderr)
    return 2


def _cmd_service(args, config) -> int:
    if args.service_command == "install":
        defender = not args.no_defender
        result = install_service(
            config,
            strict=args.strict,
            defender=defender,
            interval=args.interval,
            defender_timeout=args.defender_timeout,
        )
        _print_service_result("Install", result)
        if result.ok:
            stdout, stderr = service_log_paths(config)
            print("Auto-start protection installed.")
            print("Start it now with:")
            print("  .\\protect.ps1 service start")
            print(f"Logs: {stdout} | {stderr}")
        return 0 if result.ok else result.returncode

    if args.service_command == "uninstall":
        result = uninstall_service()
        _print_service_result("Uninstall", result)
        return 0 if result.ok else result.returncode

    if args.service_command == "start":
        result = start_service(config)
        _print_service_result("Start", result)
        return 0 if result.ok else result.returncode

    if args.service_command == "stop":
        result = stop_service()
        _print_service_result("Stop", result)
        return 0 if result.ok else result.returncode

    if args.service_command == "daily-scan":
        result = install_daily_scan(time_str=args.time)
        _print_service_result("Daily Scan Schedule", result)
        return 0 if result.ok else result.returncode

    if args.service_command == "status":
        result = service_status()
        _print_service_result("Status", result)
        return 0 if result.ok else result.returncode

    if args.service_command == "logs":
        stdout, stderr = service_log_paths(config)
        print(f"stdout: {stdout}")
        print(f"stderr: {stderr}")
        print(f"events: {config.log_file}")
        return 0

    print("Specify a service command: install, uninstall, start, stop, status, or logs", file=sys.stderr)
    return 2


def _cmd_status(config) -> int:
    print("--- Platform Status ---")
    print(f"Directory: {config.state_dir}")
    print(f"Quarantine directory: {config.quarantine_dir}")
    print(f"Logs: {config.log_file}")
    
    print("\n--- Background Application ---")
    service_res = service_status()
    print(service_res.message())

    print("\n--- Microsoft Defender ---")
    result = defender_status()
    if result.available:
        print(result.stdout or result.stderr or "No status output")
    else:
        print(f"Unavailable: {result.stderr}")
    return 0


def _cmd_detections(args, config) -> int:
    detections = _recent_detections(config.log_file, limit=args.limit, include_warnings=args.all)
    if args.json:
        print(json.dumps(detections, indent=2, sort_keys=True))
        return 0

    if not detections:
        if args.all:
            print("No recent suspicious detections found.")
        else:
            print("No recent blocked or high-risk detections found.")
            print("Use .\\protect.ps1 detections --all to include medium-risk warnings.")
        return 0

    for item in detections:
        payload = item["payload"]
        path = payload.get("path") or payload.get("original_path")
        print(f"[{str(payload.get('level', 'unknown')).upper()}] score={payload.get('score')} {path}")
        source = payload.get("source")
        if isinstance(source, dict):
            if source.get("host_url"):
                print(f"  source: {source['host_url']}")
            if source.get("referrer_url"):
                print(f"  referrer: {source['referrer_url']}")
        quarantine_item = payload.get("quarantine_item")
        if isinstance(quarantine_item, dict):
            print(f"  action: quarantined ({quarantine_item.get('item_id')})")
        findings = payload.get("findings")
        if isinstance(findings, list):
            for finding in findings[:3]:
                if isinstance(finding, dict):
                    print(f"  - {finding.get('rule')}: {finding.get('message')}")
        print(f"  time: {item.get('timestamp')}")
    return 0


def _cmd_checkup_reports(args, config) -> int:
    reports = _recent_checkup_reports(config.log_file, limit=args.limit)
    if args.json:
        print(json.dumps(reports, indent=2, sort_keys=True))
        return 0

    if not reports:
        print("No recent daily scan (checkup) reports found.")
        print("Run 'python -m ai_scam_protection.cli service daily-scan' to schedule one.")
        return 0

    for i, item in enumerate(reports):
        payload = item["payload"]
        print(f"\n--- Checkup Report {i + 1} ({item.get('timestamp')}) ---")
        print(f"Files scanned: {len(payload.get('scan_results', []))}")
        print(f"Suspicious files: {sum(1 for r in payload.get('scan_results', []) if r.get('level') in ['medium', 'high'])}")
        print(f"Suspicious apps: {len(payload.get('suspicious_installed_apps', []))}")
        print(f"Suspicious startup entries: {len(payload.get('suspicious_startup_entries', []))}")
        
        if payload.get('suspicious_installed_apps'):
            print("  Top suspicious apps:")
            for app in payload['suspicious_installed_apps'][:3]:
                print(f"    [{app['level'].upper()}] score={app['score']} {app['name']} | {app.get('publisher', 'unknown')}")

    return 0


def _recent_detections(log_file: Path, limit: int, include_warnings: bool) -> list[dict[str, object]]:
    if not log_file.exists():
        return []
    records: list[dict[str, object]] = []
    for line in reversed(log_file.read_text(encoding="utf-8", errors="ignore").splitlines()):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue
        if record.get("type") not in {"scan", "watch_detection"}:
            continue
        level = payload.get("level")
        if include_warnings:
            if level not in {"medium", "high"} and "quarantine_item" not in payload:
                continue
        elif level != "high" and "quarantine_item" not in payload:
            continue
        records.append(record)
        if len(records) >= limit:
            break
    return records


def _recent_checkup_reports(log_file: Path, limit: int) -> list[dict[str, object]]:
    if not log_file.exists():
        return []
    reports: list[dict[str, object]] = []
    for line in reversed(log_file.read_text(encoding="utf-8", errors="ignore").splitlines()):
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("type") == "checkup":
            reports.append(record)
            if len(reports) >= limit:
                break
    return reports


def _print_service_result(action: str, result) -> None:
    status = "OK" if result.ok else "FAILED"
    print(f"{action}: {status}")
    message = result.message()
    if message:
        print(message)


def _process_scan_results(args, config, manager: QuarantineManager, results: list[ScanResult]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for result in results:
        event = result.to_dict()

        if args.defender and result.level in {"medium", "high"}:
            if not args.json:
                print(f"Defender scan: {result.path}")
            defender_result = scan_with_defender(result.path, timeout=args.defender_timeout)
            event["defender"] = defender_result.to_dict()
            if not args.json and not defender_result.ok and defender_result.stderr:
                print(f"Defender scan warning: {defender_result.stderr}", file=sys.stderr)

        if args.quarantine and result.should_block and result.path.exists():
            try:
                item = manager.quarantine(result)
                event["quarantine_item"] = item.to_dict()
            except OSError as exc:
                event["quarantine_error"] = str(exc)

        append_event(config.log_file, "scan", event)
        output.append(event)
    return output


def _print_scan_summary(results: list[ScanResult]) -> None:
    for result in results:
        print_result(result)

    total = len(results)
    risky = sum(1 for result in results if result.level in {"medium", "high"})
    high = sum(1 for result in results if result.level == "high")
    print(f"\nScanned: {total} | risky: {risky} | high-risk: {high}")


def _print_checkup_summary(
    results: list[ScanResult],
    apps,
    app_findings,
    startup_entries,
    startup_findings,
    latest_report_path: Path,
) -> None:
    print("\nFile scan results:")
    risky_results = [result for result in results if result.level in {"medium", "high"}]
    if risky_results:
        for result in risky_results[:20]:
            print_result(result)
        if len(risky_results) > 20:
            print(f"... {len(risky_results) - 20} more risky file entries saved in the report")
    else:
        print("No risky files detected by local rules.")

    total = len(results)
    risky = len(risky_results)
    high = sum(1 for result in results if result.level == "high")
    print(f"Scanned: {total} | risky: {risky} | high-risk: {high}")

    print("\nInstalled app audit:")
    print(f"Installed apps checked: {len(apps)}")
    if app_findings:
        for app in app_findings[:20]:
            publisher = app.publisher or "unknown publisher"
            print(f"[{app.level.upper()}] score={app.score} {app.name} | {publisher}")
            for reason in app.reasons[:3]:
                print(f"  - {reason}")
        if len(app_findings) > 20:
            print(f"... {len(app_findings) - 20} more suspicious app entries omitted")
    else:
        print("No suspicious installed apps flagged by audit rules.")

    print("\nStartup audit:")
    print(f"Startup entries checked: {len(startup_entries)}")
    if startup_findings:
        for entry in startup_findings[:20]:
            print(f"[{entry.level.upper()}] score={entry.score} {entry.name}")
            print(f"  command: {entry.command}")
            for reason in entry.reasons[:3]:
                print(f"  - {reason}")
        if len(startup_findings) > 20:
            print(f"... {len(startup_findings) - 20} more suspicious startup entries omitted")
    else:
        print("No suspicious startup entries flagged by audit rules.")

    print(f"\nReport saved: {latest_report_path}")
    print("Checkup complete. The command stopped automatically.")


def _should_quarantine(result: ScanResult, strict: bool) -> bool:
    if result.should_block:
        return True
    if strict and result.level in {"medium", "high"}:
        return True
    return False


def _cmd_rootkit_scan(args, config) -> int:
    print("🔍 Running rootkit and kernel-level threat scan...")
    print("   Checking: hidden processes, suspicious drivers, services, named pipes, ADS...\n")

    result = scan_for_rootkits(timeout=args.timeout)

    if getattr(args, "json", False):
        import json
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 1 if not result.clean else 0

    if result.error:
        print(f"⚠️  {result.error}")
        return 2

    if result.clean:
        print("✅ No rootkit indicators found. System appears clean.")
        return 0

    print(f"⚠️  Rootkit scan score: {result.total_score}/100\n")
    for ind in result.indicators:
        print(f"  [{ind.severity.upper()}] {ind.check} (+{ind.score})")
        print(f"    {ind.description}")
        for detail in ind.details[:3]:
            print(f"    → {detail}")
    print(f"\nTotal indicators: {len(result.indicators)}")
    append_event(config.log_file, "rootkit_scan", result.to_dict())
    return 1 if result.total_score >= 50 else 0


def _cmd_cloud_lookup(args, config) -> int:
    import json as _json
    target = args.target

    # Load saved keys, allow CLI overrides
    saved_keys = load_api_keys(config.state_dir)
    vt_key = getattr(args, "vt_key", None) or saved_keys.get("virustotal")
    abusech_key = getattr(args, "abusech_key", None) or saved_keys.get("abusech")

    cache_dir = config.state_dir / "cloud_cache"
    intel = CloudIntel(vt_api_key=vt_key, abusech_key=abusech_key, cache_dir=cache_dir)

    # Determine if target is a URL, file path, or raw hash
    if target.startswith("http://") or target.startswith("https://"):
        print(f"🌐 Looking up URL in cloud threat intelligence: {target}")
        summary = intel.lookup_url(target)
    elif len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target):
        print(f"🔑 Looking up hash in cloud threat intelligence: {target}")
        summary = intel.lookup_hash(target)
    else:
        path = Path(target)
        if path.exists() and path.is_file():
            print(f"📄 Computing SHA-256 and looking up file: {path}")
            summary = intel.lookup_file(path)
        else:
            print(f"❌ Target is not a valid URL, SHA-256 hash, or existing file path: {target}", file=sys.stderr)
            return 2

    if getattr(args, "json", False):
        print(_json.dumps(summary.to_dict(), indent=2, sort_keys=True))
        return 1 if summary.overall_malicious else 0

    # Human-readable output
    def _get(obj, attr, default=None):
        return getattr(obj, attr, None) if hasattr(obj, attr) else obj.get(attr, default)

    if summary.hash_results:
        for r in summary.hash_results:
            malicious = _get(r, 'malicious', False)
            found = _get(r, 'found', False)
            source = _get(r, 'source', '?')
            detection_ratio = _get(r, 'detection_ratio', 'N/A')
            threat_names = _get(r, 'threat_names', [])
            permalink = _get(r, 'permalink')
            error = _get(r, 'error')
            status = "🔴 MALICIOUS" if malicious else ("🟡 Found (clean)" if found else "⚪ Not found")
            print(f"  [{source}] {status}", end="")
            if malicious:
                print(f" — {detection_ratio} pulses/engines", end="")
                if threat_names:
                    print(f" — {', '.join(threat_names[:3])}", end="")
                if permalink:
                    print(f"\n    🔗 {permalink}", end="")
            if error:
                print(f" (⚠ {error})", end="")
            print()

    if summary.url_results:
        for r in summary.url_results:
            malicious = _get(r, 'malicious', False)
            found = _get(r, 'found', False)
            source = _get(r, 'source', '?')
            threat = _get(r, 'threat')
            error = _get(r, 'error')
            status = "🔴 MALICIOUS" if malicious else ("🟡 Found (clean)" if found else "⚪ Not found")
            print(f"  [{source}] {status}", end="")
            if malicious and threat:
                print(f" — {threat}", end="")
            if error:
                print(f" (⚠ {error})", end="")
            print()

    if summary.overall_malicious:
        print(f"\n🚨 VERDICT: MALICIOUS (score boost: +{summary.overall_score_boost})")
        append_event(config.log_file, "cloud_lookup", summary.to_dict())
        return 1
    else:
        print("\n✅ VERDICT: No cloud threats detected")
        return 0


def _cmd_cloud_key(args, config) -> int:
    """Save a cloud threat intelligence API key to config."""
    ensure_state(config)
    save_api_key(config.state_dir, args.service, args.key)
    print(f"✅ Saved {args.service} API key to {config.state_dir / 'config.json'}")
    if args.service == "abusech":
        print("   Enables: MalwareBazaar hash lookups + URLhaus URL lookups")
        print("   Get your free key at: https://auth.abuse.ch/")
    elif args.service == "virustotal":
        print("   Enables: VirusTotal hash + URL lookups (70+ AV engines)")
        print("   Get your free key at: https://www.virustotal.com/gui/join-us")
    return 0


def _cmd_api_server(args) -> int:
    """Start the local REST API server for dashboard integration."""
    from ai_scam_protection.api_server import run_server
    port = getattr(args, "port", 8765)
    print(f"🛡️  Starting ShieldScan API server on http://localhost:{port}")
    print(f"   Dashboard will now show REAL data from the protection service.")
    print(f"   Keep this running alongside 'protect' for live dashboard updates.")
    print(f"   Press Ctrl+C to stop.\n")
    run_server(port=port)
    return 0
def print_result(result: ScanResult) -> None:
    status = result.level.upper()
    print(f"[{status}] score={result.score} {result.path}")
    if result.source:
        if result.source.host_url:
            print(f"  source: {result.source.host_url}")
        if result.source.referrer_url:
            print(f"  referrer: {result.source.referrer_url}")
    if result.error:
        print(f"  error: {result.error}")
    for finding in result.findings:
        print(f"  - {finding.rule}: {finding.message} (+{finding.score})")
    if result.ai_score:
        ai = result.ai_score
        print(f"  AI score: {ai.score}/100 [{ai.level}] confidence={ai.confidence:.0%}", end="")
        if ai.top_features:
            print(f" | top features: {', '.join(ai.top_features[:3])}", end="")
        print()
    if result.heuristic and result.heuristic.findings:
        print(f"  Heuristics: {len(result.heuristic.findings)} rule(s) fired, entropy={result.heuristic.entropy:.2f}")
    if result.sandbox and result.sandbox.verdict != "clean":
        print(f"  Sandbox verdict: {result.sandbox.verdict} ({len(result.sandbox.indicators)} behavior(s))")


if __name__ == "__main__":
    raise SystemExit(main())
