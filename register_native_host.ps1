# Register ShieldScan Native Messaging Host in Windows Registry
# Run this once after installing the extension.
# Requires no elevation — registers under HKCU (current user only).

$hostName = "com.shieldscan.protection"
$manifestPath = Join-Path $PSScriptRoot "browser_extension\shieldscan_native_host.json"
$manifestPath = (Resolve-Path $manifestPath).Path

# Update the manifest to use the absolute path to the .bat launcher
$manifest = Get-Content $manifestPath | ConvertFrom-Json
$batPath = Join-Path $PSScriptRoot "browser_extension\shieldscan_native_host.bat"
$batPath = (Resolve-Path $batPath).Path
$manifest.path = $batPath
$manifest | ConvertTo-Json -Depth 5 | Set-Content $manifestPath -Encoding UTF8

# Register for Chrome
$chromePath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"
New-Item -Path $chromePath -Force | Out-Null
Set-ItemProperty -Path $chromePath -Name "(Default)" -Value $manifestPath

# Register for Edge
$edgePath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$hostName"
New-Item -Path $edgePath -Force | Out-Null
Set-ItemProperty -Path $edgePath -Name "(Default)" -Value $manifestPath

Write-Host "✅ Native messaging host registered for Chrome and Edge"
Write-Host "   Host name: $hostName"
Write-Host "   Manifest:  $manifestPath"
Write-Host "   Launcher:  $batPath"
Write-Host ""
Write-Host "Reload the extension in chrome://extensions to activate."
