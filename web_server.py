#!/usr/bin/env python3
"""
ShieldScan Web Server
Hosts the dashboard as a local website for easy access
"""

import http.server
import socketserver
import webbrowser
import os
import sys
from pathlib import Path

# Configuration
PORT = 8080
HOST = "localhost"
DASHBOARD_DIR = "browser_extension"

class ShieldScanHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom handler for ShieldScan web server"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)
    
    def end_headers(self):
        # Add CORS headers for local development
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        # Add CSP header that allows our external scripts
        self.send_header('Content-Security-Policy', 
                        "default-src 'self'; "
                        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                        "font-src 'self' https://fonts.gstatic.com; "
                        "connect-src 'self' http://localhost:*")
        super().end_headers()
    
    def log_message(self, format, *args):
        """Custom logging"""
        print(f"🌐 {self.address_string()} - {format % args}")

def main():
    """Start the ShieldScan web server"""
    
    # Check if dashboard directory exists
    if not os.path.exists(DASHBOARD_DIR):
        print(f"❌ Error: {DASHBOARD_DIR} directory not found!")
        print("Make sure you're running this from the AI Scam Protection Platform directory.")
        sys.exit(1)
    
    # Check if dashboard.html exists
    dashboard_path = Path(DASHBOARD_DIR) / "dashboard.html"
    if not dashboard_path.exists():
        print(f"❌ Error: dashboard.html not found in {DASHBOARD_DIR}!")
        sys.exit(1)
    
    print("🚀 Starting ShieldScan Web Server...")
    print(f"📁 Serving files from: {os.path.abspath(DASHBOARD_DIR)}")
    print(f"🌐 Server URL: http://{HOST}:{PORT}")
    print(f"📊 Dashboard URL: http://{HOST}:{PORT}/dashboard.html")
    print("=" * 60)
    
    try:
        # Create server
        with socketserver.TCPServer((HOST, PORT), ShieldScanHTTPRequestHandler) as httpd:
            print(f"✅ Server started successfully on http://{HOST}:{PORT}")
            print("🔗 Opening dashboard in your default browser...")
            
            # Open dashboard in browser
            dashboard_url = f"http://{HOST}:{PORT}/dashboard.html"
            webbrowser.open(dashboard_url)
            
            print("\n📋 Available URLs:")
            print(f"   • Dashboard: http://{HOST}:{PORT}/dashboard.html")
            print(f"   • Test Page: http://{HOST}:{PORT}/test_buttons.html")
            print(f"   • CSP Test:  http://{HOST}:{PORT}/test_csp_compliance.html")
            print("\n🛑 Press Ctrl+C to stop the server")
            print("=" * 60)
            
            # Start serving
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except OSError as e:
        if e.errno == 10048:  # Port already in use
            print(f"❌ Error: Port {PORT} is already in use!")
            print("Try using a different port or stop the existing server.")
        else:
            print(f"❌ Error starting server: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()