from __future__ import annotations
import os
import shutil
import subprocess

def show_alert(title: str, message: str) -> None:
    """Displays a Windows Toast Notification to the user."""
    if os.name != "nt":
        return

    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not powershell:
        return

    # Escape single quotes for PowerShell string literals
    safe_title = title.replace("'", "''")
    safe_message = message.replace("'", "''")

    # Script to trigger a Toast notification via Windows Runtime APIs
    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastType]::ToastText02)
$textNodes = $template.GetElementsByTagName('text')
$textNodes.Item(0).AppendChild($template.CreateTextNode('{safe_title}')) | Out-Null
$textNodes.Item(1).AppendChild($template.CreateTextNode('{safe_message}')) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AI Scam Protection').Show($toast)
"""

    try:
        subprocess.run(
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=10
        )
    except Exception:
        pass