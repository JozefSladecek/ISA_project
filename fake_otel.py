#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

PORT = 4318
PATH = "/v1/metrics"

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != PATH:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        print("=== RECEIVED POST ===")
        print("Path:", self.path)
        print("Headers:", self.headers)
        print("Body:")
        try:
            print(body.decode('utf-8'))
        except:
            print(body)
        print("=====================")
        # reply with 200 OK
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), Handler)
    print(f"Fake OTEL endpoint listening on http://0.0.0.0:{PORT}{PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping")
        server.server_close()
        sys.exit(0)
