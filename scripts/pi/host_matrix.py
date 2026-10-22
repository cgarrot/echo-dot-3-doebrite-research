#!/usr/bin/env python3
"""
host_matrix.py — angles NEUFS sur 4070 et 6543 : vhost, protocoles, h2c/gRPC.

POURQUOI
  Tout ce qu'on a tiré jusqu'ici utilisait l'**IP** comme `Host:` et supposait du
  HTTP/1.1 nu. Or :
    • 6543 est annoncé en mDNS comme `avs-ffreg-1765549357.local` (§ version=1) —
      un serveur peut **router sur le Host** (vhost) ou attendre ce nom ;
    • le nom d'instance contient le **device id `1765549357`**, et le device a un
      **DSN `G091470502330EBE`** → chemins plausibles jamais essayés ;
    • 4070 répond `403` sur `/` mais `404` ailleurs, et renvoie `DAV: 1` +
      `Allow: GET, POST, …, PROPFIND, MKCOL` — signature d'un **routeur Go**
      (peut-être gRPC/h2c derrière) ;
    • 6543 renvoie du HTML `BaseHTTPServer` sur 404/501 — on n'a jamais testé s'il
      parle **Thrift** (l'app utilise `avs-ffreg`, et le reste du device est Thrift).

CE QUE ÇA TESTE
  1. **Host:** IP · `avs-ffreg-1765549357.local` · `device.local` · DSN · `localhost`
  2. **méthodes** : GET, POST, PUT, OPTIONS, TRACE, PATCH
  3. **corps** : TJSON `[1,"ping",1,1,{}]` · JSON-RPC · JSON vide
  4. **chemins dérivés** : `/1765549357`, `/G091470502330EBE`, `/ffs/1765549357`,
     `/avs-ffreg`, `/v1/<dsn>`, `/register`, `/*`
  5. **h2c / gRPC** : tentative HTTP/2 prior-knowledge (préface + SETTINGS) sur 4070
     et chemin `/grpc.health.v1.Health/Check`

ORACLE
  Tout ce qui n'est **pas** le 404 habituel (HTML Python sur 6543, `Error 404` Go
  sur 4070). Un `Invalid method name`, un 400 différent, un 405, un 501 inattendu,
  une réponse HTTP/2 : **route ou protocole identifié**.

USAGE
  python3 host_matrix.py --list
  python3 host_matrix.py --run --ip 192.168.1.24
"""
import argparse
import itertools
import json
import socket
import struct

HOSTS = ["{ip}", "avs-ffreg-1765549357.local", "avs-ffreg-1765549357",
         "device.local", "G091470502330EBE", "localhost", "127.0.0.1"]
PATHS = ["/", "/*", "/1765549357", "/G091470502330EBE", "/ffs/1765549357",
         "/avs-ffreg", "/v1/G091470502330EBE", "/register", "/ffs"]
METHODS = ["GET", "POST", "PUT", "OPTIONS", "TRACE", "PATCH"]
BODIES = {
    "tjson": ('[1,"ping",1,1,{}]', "application/x-thrift"),
    "jsonrpc": ('{"jsonrpc":"2.0","method":"ping","id":1}', "application/json"),
    "empty": ("", "application/json"),
}


def send(ip, port, method, path, host, body="", ctype="application/json", timeout=3):
    raw = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Accept: */*\r\nContent-Type: {ctype}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}").encode()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(raw)
        d = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            d += c
        s.close()
        t = d.decode("utf-8", "replace")
        head, _, pl = t.partition("\r\n\r\n")
        st = head.split(" ")[1] if head.startswith("HTTP/") else "?"
        return st, pl[:160]
    except Exception as e:
        return "ERR", type(e).__name__


def h2c_probe(ip, port, path="/grpc.health.v1.Health/Check", timeout=3):
    """HTTP/2 prior knowledge : préface + SETTINGS vide, puis HEADERS minimal.
    Un serveur h2c/gRPC répond SETTINGS + éventuellement un RST_STREAM/GOAWAY,
    là où un serveur HTTP/1.1 renvoie une erreur de parsing."""
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"          # SETTINGS, len 0
    # HEADERS minimal (type 0x01, flags END_HEADERS|END_STREAM, stream 1) — vide,
    # volontairement invalide : ce qui compte est la RÉPONSE du serveur.
    headers = struct.pack("!I", 0x00000005)[1:] + b"\x01\x05" + b"\x00\x00\x00\x01"
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(preface + settings + headers)
        d = s.recv(256)
        s.close()
        return d[:40].hex()
    except Exception as e:
        return f"ERR {type(e).__name__}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.1.24")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--max", type=int, default=0)
    a = ap.parse_args()

    cases = []
    for port in (4070, 6543):
        for path in PATHS:
            for host_t in HOSTS[:5]:
                host = host_t.format(ip=a.ip)
                for method in ("GET", "POST"):
                    for bname, (body, ctype) in BODIES.items():
                        cases.append((port, method, path, host, bname, body, ctype))
            for method in METHODS:
                host = a.ip
                cases.append((port, method, path, host, "-", "", "application/json"))
    if a.max:
        cases = cases[:a.max]

    if a.list or not a.run:
        print(f"{len(cases)} cas :")
        for c in cases[:8]:
            print(f"  {c[0]} {c[1]:7s} {c[2]:22s} Host={c[3][:32]:32s} body={c[4]}")
        print(f"  ... + h2c/gRPC sur 4070")
        print("\n(relancer avec --run)")
        return

    hits = []
    for i, (port, method, path, host, bname, body, ctype) in enumerate(cases, 1):
        st, pl = send(a.ip, port, method, path, host, body, ctype)
        # les 404 attendus : Go "Error 404: Not Found" (4070) et HTML Python (6543)
        known404 = ("Not Found" in pl) or ("not found on this server" in pl)
        if not known404:
            hits.append((port, method, path, host, bname, st, pl))
            print(f"[{i}] ⚠ {port} {method:7s} {path[:20]:20s} Host={host[:28]:28s} "
                  f"{bname:8s} → {st} {pl[:80]!r}")
    print(f"\n=== {len(hits)} réponse(s) hors-404 sur {len(cases)} ===")
    for h in hits:
        print("  ", h[:6])
    print("\n=== h2c/gRPC ===")
    for port in (4070, 6543):
        print(f"  {port}: {h2c_probe(a.ip, port)}  (attendu 00000004… = SETTINGS si h2c)")
    if not hits:
        print("\n  Aucun vhost, aucune méthode, aucun protocole alternatif détecté.")


if __name__ == "__main__":
    main()
