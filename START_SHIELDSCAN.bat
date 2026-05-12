@echo off
title ShieldScan - Starting All Services
color 0A
echo.
echo  ============================================================
echo   ShieldScan - Starting All Services
echo  ============================================================
echo.

:: Kill any leftover Python processes on our ports
echo [1/3] Cleaning up old processes...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8080 " 2^>nul') do taskkill /PID %%a /F >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8765 " 2^>nul') do taskkill /PID %%a /F >nul 2>&1
timeout /t 1 /nobreak >nul

:: Start protection service
echo [2/3] Starting real-time protection service...
start "ShieldScan Protection" /MIN cmd /c "cd /d "%~dp0" && python -m ai_scam_protection.cli protect >> .protection_state\protection_service.out.log 2>&1"
timeout /t 2 /nobreak >nul

:: Start API server
echo [3/3] Starting API server (port 8765)...
start "ShieldScan API" /MIN cmd /c "cd /d "%~dp0" && python -m ai_scam_protection.cli api-server >> .protection_state\api_server.log 2>&1"
timeout /t 2 /nobreak >nul

:: Start web server and open dashboard
echo [4/4] Starting web server (port 8080)...
start "ShieldScan Web" /MIN cmd /c "cd /d "%~dp0" && python web_server.py >> .protection_state\web_server.log 2>&1"
timeout /t 3 /nobreak >nul

:: Open dashboard
echo.
echo  ============================================================
echo   All services started!
echo   Opening dashboard...
echo  ============================================================
echo.
start "" "http://localhost:8080/dashboard.html"

echo  Services running in background:
echo    Protection service  ^(real-time file monitoring^)
echo    API server          http://localhost:8765
echo    Web dashboard       http://localhost:8080/dashboard.html
echo.
echo  Close this window to keep services running.
echo  To stop all services, close the minimized windows.
pause
