#!/usr/bin/env python3
"""Tente des requêtes LOGIN sur le port 4070 (Spotify Connect login server).
Le firewall dit '# ...login server.' — ce n'est PAS un serveur HTTP générique.
Il faut des POST avec des credentials, pas des GET de chemins."""
import socket, json, time, sys

IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.25"
PORT = 4070

def send(path, body, method="POST", content_type="application/json", timeout=5):
    req = (f"{method} {path} HTTP/1.1\r\n"
           f"Host: {IP}:{PORT}\r\n"
           f"Content-Type: {content_type}\r\n"
           f"Content-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n{body}")
    try:
        s = socket.create_connection((IP, PORT), timeout=timeout)
        s.sendall(req.encode())
        buf = b""
        while True:
            d = s.recv(4096)
            if not d: break
            buf += d
        s.close()
        return buf.decode("utf-8", "replace")
    except Exception as e:
        return f"ERR:{type(e).__name__}"

# Schémas de login à essayer
cases = [
    # Spotify Connect (le firewall mentionne Spotify)
    ("/login", json.dumps({"username":"test","password":"test"}), "POST"),
    ("/login", json.dumps({"deviceId":"G0914705XXXXXXX","token":"test"}), "POST"),
    ("/login", json.dumps({"type":"spotify","user":"test","auth":"test"}), "POST"),
    ("/api/login", json.dumps({"username":"test","password":"test"}), "POST"),
    # Thrift JSON (le device utilise Thrift partout)
    ("/login", '[1,"login",1,1,{"1":{"str":"test"},"2":{"str":"test"}}]', "POST"),
    # CBL (Code Based Linking — le flux d'enregistrement Echo)
    ("/cbl", json.dumps({"code":"test","dsn":"G0914705XXXXXXX"}), "POST"),
    # Spotify zeroconf
    ("/spotify/connect", json.dumps({"action":"getInfo","version":"1.0"}), "POST"),
    # OAuth/token
    ("/token", json.dumps({"grant_type":"password","username":"test","password":"test"}), "POST"),
    ("/oauth/token", json.dumps({"grant_type":"client_credentials"}), "POST"),
    # Amazon auth
    ("/auth", json.dumps({"email":"test@test.com","password":"test"}), "POST"),
    ("/register", json.dumps({"deviceId":"G0914705XXXXXXX"}), "POST"),
    # Chemins génériques
    ("/", json.dumps({"action":"login"}), "POST"),
    ("/v1/login", json.dumps({"user":"test","pass":"test"}), "POST"),
    ("/v2/login", json.dumps({"user":"test","pass":"test"}), "POST"),
]

print(f"=== LOGIN fuzz 4070 sur {IP} ===")
for path, body, method in cases:
    r = send(path, body, method)
    status = r.split("\n")[0] if r else "NO_RESPONSE"
    body_start = r.find("\r\n\r\n")
    content = r[body_start:body_start+80] if body_start > 0 else ""
    if "404" not in status:
        print(f"  ★ {method} {path}: {status} — {content}")
    else:
        print(f"    {method} {path}: 404")
    time.sleep(0.3)

# OPTIONS pour voir les méthodes autorisées
r = send("/", "", "OPTIONS")
print(f"\n  OPTIONS /: {r[:200]}")
