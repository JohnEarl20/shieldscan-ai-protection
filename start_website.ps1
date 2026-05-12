#!/usr/bin/env powershell

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   ShieldScan Web Dashboard Launcher" -ForegroundColor Cyan  
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "🚀 Starting ShieldScan web server..." -ForegroundColor Green
Write-Host ""

try {
    # Start the web server
    python web_server.py
}
catch {
    Write-Host "❌ Error starting web server: $_" -ForegroundColor Red
}
finally {
    Write-Host ""
    Write-Host "Web server stopped." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
}