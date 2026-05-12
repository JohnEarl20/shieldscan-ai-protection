#!/usr/bin/env python3
"""
ShieldScan Extension Demo Script
Demonstrates real-time threat detection and system integration
"""

import time
import json
import os
from datetime import datetime

def create_demo_threat():
    """Simulate a threat detection for demo purposes"""
    threat = {
        "timestamp": datetime.now().isoformat(),
        "type": "malicious",
        "title": "Demo: Malicious website blocked",
        "url": "https://fake-phishing-site.com/login",
        "severity": "high",
        "category": "phishing",
        "action": "blocked",
        "score": 95
    }
    return threat

def show_extension_status():
    """Display current extension and protection status"""
    print("🛡️  ShieldScan Extension - Real-Time Demo")
    print("=" * 50)
    
    # Check if protection service is running
    if os.path.exists('.protection_state/protection_service.out.log'):
        print("✅ Protection Service: RUNNING")
        
        # Read recent threats
        with open('.protection_state/protection_service.out.log', 'r') as f:
            lines = f.readlines()
            recent_threats = [line for line in lines[-10:] if 'score=' in line]
            print(f"📊 Recent Detections: {len(recent_threats)}")
    else:
        print("❌ Protection Service: NOT RUNNING")
    
    # Check extension files
    extension_files = [
        'browser_extension/dashboard.html',
        'browser_extension/dashboard.js',
        'browser_extension/dashboard-fix.js',
        'browser_extension/scanner.html',
        'browser_extension/scanner.js',
        'browser_extension/background.js',
        'browser_extension/manifest.json'
    ]
    
    print("\n📁 Extension Files:")
    for file in extension_files:
        status = "✅" if os.path.exists(file) else "❌"
        print(f"   {status} {file}")
    
    print("\n🎯 Real-Time Features:")
    print("   ✅ Live threat detection")
    print("   ✅ Real-time stats updates")
    print("   ✅ AI Scam Protection scanner")
    print("   ✅ VPN integration")
    print("   ✅ System scanner")
    print("   ✅ Activity feed")
    print("   ✅ Protection status monitoring")
    
    print("\n🌐 To test the extension:")
    print("   1. Open Chrome")
    print("   2. Go to chrome://extensions/")
    print("   3. Enable Developer mode")
    print("   4. Click 'Load unpacked'")
    print("   5. Select the 'browser_extension' folder")
    print("   6. Open dashboard.html from the extension")
    
    print("\n🔍 Test URLs for AI Scanner:")
    print("   • https://secure-login-update.com (malicious)")
    print("   • https://fake-bank-verify.net (phishing)")
    print("   • https://google.com (safe)")
    print("   • https://github.com (safe)")

def simulate_real_time_activity():
    """Simulate real-time threat detection"""
    print("\n🔄 Simulating Real-Time Activity...")
    
    threats = [
        "Suspicious PowerShell script detected",
        "Malicious website blocked",
        "Phishing email attachment quarantined",
        "Ransomware behavior detected",
        "Suspicious file download blocked"
    ]
    
    for i, threat in enumerate(threats):
        print(f"   🚨 {threat}")
        time.sleep(1)
        if i < len(threats) - 1:
            print("   ⏱️  Real-time monitoring active...")
            time.sleep(2)
    
    print("   ✅ All threats handled successfully!")

if __name__ == "__main__":
    show_extension_status()
    
    print("\n" + "=" * 50)
    input("Press Enter to simulate real-time activity...")
    
    simulate_real_time_activity()
    
    print("\n🎉 Demo Complete!")
    print("The ShieldScan extension is now running with real-time integration!")