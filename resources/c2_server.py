#!/usr/bin/env python3
"""
C2 Server Simulator for SOC Lab Testing
Run this on Kali Linux (192.168.88.134)
Receives beacons from Windows 10 victim (192.168.88.128)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import datetime
import json

class C2Handler(BaseHTTPRequestHandler):
    """Handler for C2 beaconing traffic"""
    
    def do_GET(self):
        """Handle GET requests (beacon check-ins)"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Log the beacon
        print("=" * 60)
        print(f"[{timestamp}] ✓ BEACON RECEIVED (GET)")
        print(f"  Source IP    : {self.client_address[0]}:{self.client_address[1]}")
        print(f"  Path         : {self.path}")
        print(f"  User-Agent   : {self.headers.get('User-Agent', 'N/A')}")
        print(f"  Host         : {self.headers.get('Host', 'N/A')}")
        print("=" * 60)
        
        # Send response (simulating C2 server acknowledgment)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        # Send tasking (empty for now)
        response = json.dumps({
            "status": "ok",
            "tasking": [],
            "timestamp": timestamp
        })
        self.wfile.write(response.encode())
    
    def do_POST(self):
        """Handle POST requests (beacon data exfiltration)"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        # Log the beacon
        print("=" * 60)
        print(f"[{timestamp}] ✓ BEACON RECEIVED (POST)")
        print(f"  Source IP    : {self.client_address[0]}:{self.client_address[1]}")
        print(f"  Path         : {self.path}")
        print(f"  Content-Type : {self.headers.get('Content-Type', 'N/A')}")
        print(f"  Data Length  : {content_length} bytes")
        
        # Try to parse JSON data
        try:
            data = json.loads(post_data.decode('utf-8'))
            print(f"  Beacon Data  :")
            for key, value in data.items():
                print(f"    - {key}: {value}")
        except:
            print(f"  Raw Data     : {post_data.decode('utf-8', errors='ignore')[:200]}")
        
        print("=" * 60)
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = json.dumps({"status": "received", "timestamp": timestamp})
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        """Suppress default HTTP server logging"""
        pass


def main():
    """Start the C2 server"""
    HOST = '0.0.0.0'  # Listen on all interfaces
    PORT = 8080
    
    print("\n" + "=" * 60)
    print("  C2 SERVER - SOC LAB TESTING")
    print("=" * 60)
    print(f"  Kali IP      : 192.168.88.134")
    print(f"  Victim IP    : 192.168.88.128")
    print(f"  Listening on : {HOST}:{PORT}")
    print(f"  Started at   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print("\n[*] Waiting for beacons from Windows victim...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        server = HTTPServer((HOST, PORT), C2Handler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[!] Shutting down C2 server...")
        server.shutdown()
        print("[✓] Server stopped\n")
    except Exception as e:
        print(f"\n[!] Error: {e}\n")


if __name__ == '__main__':
    main()
