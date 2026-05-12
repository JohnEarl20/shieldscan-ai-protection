@echo off
REM ShieldScan Native Messaging Host launcher
REM This script is called by Chrome when the extension uses nativeMessaging.
REM It launches the Python native host bridge.
cd /d "%~dp0.."
.venv\Scripts\python.exe -m ai_scam_protection.native_host
