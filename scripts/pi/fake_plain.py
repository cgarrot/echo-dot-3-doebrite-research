#!/usr/bin/env python3
"""Serveur HTTP clair : capte les canaux non chiffrés du device."""
import http.server, socketserver, time, json, os

LOG = "/tmp/fakeap/fake_plain.log"
COUNTER = {"n": 0}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _log(self, body=b""):
        COUNTER["n"] += 1
        with open(LOG, "a") as f:
            f.write(f"\n=== {time.strftime('%H:%M:%S')} #{COUNTER['n']} ===\n")
            f.write(f"{self.command} {self.path}\n")
            f.write(f"Host: {self.headers.get('Host')}\n")
            for k, v in self.headers.items():
                if k.lower() in ("host",): continue
                f.write(f"{k}: {v}\n")
            if body:
                f.write(f"--- body ({len(body)}o) ---\n{body[:800].decode(errors='replace')}\n")
    def do_GET(self):
        self._log()
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else b""
        self._log(body)
        out = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    srv = S(("0.0.0.0", 80), H)
    print("serveur HTTP clair sur :80")
    srv.serve_forever()
