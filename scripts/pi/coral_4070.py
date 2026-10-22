#!/usr/bin/env python3
"""
coral_4070.py — attaquer 4070 avec le VRAI format Coral (et les vrais noms d'opérations).

POURQUOI CE SCRIPT EXISTE
  On avait fuzzé 4070 avec des chemins génériques (2 × 1229 × GET/POST → 404 partout,
  `CONNECT` → « Invalid URI »). Le format manquait. Il est maintenant connu, extrait
  du dex de l'APK Alexa :

    opération Coral = "<namespace>#<Operation>"
    ex.  com.amazon.devicesetup.common.v1#RegisterDevice
    services versionnés présents dans l'app :
      com.amazon.devicesetup.common.v1        com.amazon.devicesetupservice.v1
      com.amazon.devicesetupservice.pwsync.v1 com.amazon.devicesetupservice.scap.v1
      com.amazon.alexa.notifications.llmapi.resource.v1   com.amazon.tv.settings.v2

  Et **les noms d'opérations du domaine device-setup, on les a déjà** — ce sont
  exactement les 6 du service FFS/DSS documentés dans FFS_SDK.md / FFS_PROTOCOL.md :
      startProvisioningSession · computeConfigurationData · getWifiCredentials
      postWifiScanData · report · startPinBasedSetup
  Plus les variantes en PascalCase et les verbes du domaine (Register/Provision/…).

ORACLE (le seul signal qui compte)
  404 / 400 nu        → pas cette route
  **`UnknownOperationException`** (ou tout JSON Coral) → **la route vit** ⇒ on
  itère sur les opérations. C'est le même oracle que `Invalid method name` sur
  /OOBE : une erreur *applicative* prouve que le parseur nous a lus.

USAGE
  python3 coral_4070.py --ip 192.168.1.24 --list
  python3 coral_4070.py --ip 192.168.1.24 --run
"""
import argparse
import itertools
import json
import socket
import time

NS = ["com.amazon.devicesetup.common.v1", "com.amazon.devicesetupservice.v1",
      "com.amazon.devicesetupservice.pwsync.v1", "com.amazon.devicesetupservice.scap.v1",
      "com.amazon.devicesetup.common", "com.amazon.devicesetupservice.lts",
      "com.amazon.devicesetupservice.wififfs", "com.amazon.devicesetupservice.smarthome"]

OPS = ["startProvisioningSession", "computeConfigurationData", "getWifiCredentials",
       "postWifiScanData", "report", "startPinBasedSetup",
       "registerDevice", "getDeviceDetails", "provisionDevice", "discoverDevices",
       "getKnownList", "getScanList", "connectToAP", "setupComplete",
       "ping", "Ping", "GetDeviceDetails", "RegisterDevice", "StartProvisioningSession",
       "GetWifiCredentials", "ComputeConfigurationData", "PostWifiScanData",
       "StartPinBasedSetup", "Report", "Ping"]

PATHS = ["/", "/api", "/coral", "/rpc", "/v1", "/Coral", "/operation", "/invoke"]


def req(ip, port, path, body, timeout=4):
    raw = (f"POST {path} HTTP/1.1\r\nHost: {ip}:{port}\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n{body}").encode()
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
        return st, pl[:200]
    except Exception as e:
        return "ERR", type(e).__name__


def bodies(ns, op):
    """Les deux formes d'enveloppe Coral plausibles."""
    return [
        json.dumps({"operation": f"{ns}#{op}", "clientContext": {"clientId": "probe"},
                    "parameters": {}}, separators=(",", ":")),
        json.dumps({"operation": {"serviceName": ns, "operationName": op},
                    "clientContext": {"clientId": "probe"}, "parameters": {}},
                   separators=(",", ":")),
        json.dumps({"operation": op, "service": ns, "clientContext": {}, "parameters": {}},
                   separators=(",", ":")),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="192.168.1.24")
    ap.add_argument("--port", type=int, default=4070)
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--max", type=int, default=0)
    ap.add_argument("--workers", type=int, default=6,
                    help="parallélisme (4070 = Go, gère la concurrence ; 6 = prudent)")
    a = ap.parse_args()

    cases = []
    # 1) chemins nus (contrôle : on doit retrouver 404)
    for p in PATHS:
        cases.append((f"path{p}", p, json.dumps({})))
    # 2) chemin Coral dérivé du namespace + enveloppe avec opération
    for ns, op in itertools.product(NS, OPS):
        for p in (f"/coral/{ns}/", f"/{ns}/", f"/coral/{ns}/{op}", f"/{ns}/{op}"):
            cases.append((f"{ns}#{op} via {p}", p, bodies(ns, op)[0]))
    # 3) une seule enveloppe par couple ns/op (utile si le chemin est fixe)
    for ns, op in itertools.product(NS, OPS):
        for i, b in enumerate(bodies(ns, op)):
            cases.append((f"{ns}#{op} body{i}", "/", b))
    if a.max:
        cases = cases[:a.max]

    if a.list or not a.run:
        print(f"{len(cases)} cas — exemples :")
        for n, p, b in cases[:12]:
            print(f"  {n[:70]:70s} POST {p[:40]}")
        print("\n(relancer avec --run)")
        return

    hits = []
    from concurrent.futures import ThreadPoolExecutor
    lock_print = __import__('threading').Lock()
    counter = [0]

    def one(case):
        name, path, body = case
        st, pl = req(a.ip, a.port, path, body)
        interesting = st not in ("404", "ERR") and "Not Found" not in pl
        with lock_print:
            counter[0] += 1
            i = counter[0]
            if interesting or i % 40 == 0:
                tag = "  ⚠ HIT" if interesting else ""
                print(f"[{i}/{len(cases)}] {name[:60]:60s} {st:>4s} {pl[:90]!r}{tag}", flush=True)
        if interesting:
            return (name, path, body, st, pl)
        return None

    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for r in ex.map(one, cases):
            if r:
                hits.append(r)
        time.sleep(0.15)

    print(f"\n=== {len(hits)} réponse(s) ≠ 404 ===")
    for n, p, b, st, pl in hits:
        print(f"  {n}\n    POST {p} → {st} {pl[:120]}")
    if not hits:
        print("  Aucune : 4070 ne répond pas au format Coral, ou le service est arrêté.")


if __name__ == "__main__":
    main()
