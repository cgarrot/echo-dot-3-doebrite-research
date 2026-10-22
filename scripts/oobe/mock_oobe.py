#!/usr/bin/env python3
"""Faux serveur /OOBE pour valider shoot_priority.py hors device.
Simule : connectToAP -> NO_ERROR, puis getKnownList contient le SSID.
"""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = {"saved": False, "ssid": None, "posts": 0, "connect": 0}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        STATE["posts"] += 1
        try: env = json.loads(body)
        except Exception: env = [0, "?", 0, 0, {}]
        method = env[1] if len(env) > 1 else "?"
        out = ""
        if method == "connectToAP":
            STATE["connect"] += 1
            # on "sauvegarde" seulement au 2e tir (pour tester l'échec du 1er)
            if STATE["connect"] >= 2:
                STATE["saved"] = True
                ap = env[4].get("1", {})
                STATE["ssid"] = ap.get("1", "TEST")
            out = '[1,"connectToAP",2,1,{"0":{"i32":0}}]'
        elif method == "getKnownList":
            if STATE["saved"]:
                out = '[1,"getKnownList",2,1,{"0":{"lst":[{"rec":{"1":{"str":"%s"},"2":{"i32":-29}}}]}}]' % STATE["ssid"]
            else:
                out = '[1,"getKnownList",2,1,{"0":{"lst":[]}}]'
        else:
            out = '[1,"%s",2,1,{"0":{"i32":0}}]' % method
        b = out.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-thrift")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

HTTPServer(("127.0.0.1", 18080), H).serve_forever()
