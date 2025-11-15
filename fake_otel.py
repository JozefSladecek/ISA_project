#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys

PORT = 4318
PATH = "/v1/metrics"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def do_POST(self):
        if self.path != PATH:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b''

        print("\n=== RECEIVED POST ===")
        print(f"Path: {self.path}")
        print(f"Content-Type: {self.headers.get('Content-Type')}")
        print(f"Content-Length: {length}")

        # Try to parse and validate JSON
        try:
            data = json.loads(body.decode('utf-8'))
            print("\n✅ Valid JSON received")
            print(json.dumps(data, indent=2))

            # Basic OTLP validation
            if 'resourceMetrics' in data:
                metrics_count = 0
                for rm in data['resourceMetrics']:
                    for sm in rm.get('scopeMetrics', []):
                        metrics_count += len(sm.get('metrics', []))
                print(f"\n📊 Metrics received: {metrics_count}")
            else:
                print("⚠️  Warning: Missing 'resourceMetrics' field")

            # Reply with 200 OK
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success"}).encode())

        except json.JSONDecodeError as e:
            print(f"\n❌ Invalid JSON: {e}")
            print("Raw body:")
            print(body.decode('utf-8', errors='replace'))

            # Reply with 400 Bad Request
            self.send_response(400)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Invalid JSON")

        print("=" * 50)

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), Handler)
    print(f"🚀 Fake OTEL endpoint listening on http://0.0.0.0:{PORT}{PATH}")
    print(f"📝 Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping server...")
        server.server_close()
        sys.exit(0)