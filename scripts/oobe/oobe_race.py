#!/usr/bin/env python3
"""Race conditions sur /OOBE :8080 — deux connexions TCP simultanées avec
séquences entremêlées. Cible : l'état partagé du service mono-thread
(crypto door, mutex, seqid).
"""
import socket, threading, time, json, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.201.126.241"
PORT = 8080
LOG = "/tmp/fakeap/oobe_race.log"

def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    with open(LOG, "a") as f: f.write(line + "\n")
    print(line, flush=True)

def call(method, seq, args="{}", timeout=8):
    body = '[1,"%s",1,%d,%s]' % (method, seq, args)
    req = ("POST /OOBE HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: application/x-thrift\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n%s"
           ) % (TARGET, PORT, len(body), body)
    try:
        s = socket.create_connection((TARGET, PORT), timeout=timeout)
        s.sendall(req.encode())
        buf = b""
        while True:
            d = s.recv(65536)
            if not d: break
            buf += d
        s.close()
        return buf.decode("utf-8", "replace")
    except Exception as e:
        return "ERR:%s" % type(e).__name__

def race_pair(method1, method2, args1="{}", args2="{}"):
    """Lance deux appels SIMULTANÉS (le service est mono-thread → l'un doit
    attendre). Si les deux passent en parallèle = état partagé cassé."""
    results = [None, None]
    def t1(): results[0] = call(method1, 1, args1)
    def t2(): results[1] = call(method2, 2, args2)
    th1 = threading.Thread(target=t1)
    th2 = threading.Thread(target=t2)
    th1.start(); th2.start()
    th1.join(timeout=30); th2.join(timeout=30)
    return results

# Test 1 : deux pings simultanés (baseline : les deux doivent répondre)
log("=== TEST 1 : 2x ping simultanés (baseline) ===")
r = race_pair("ping", "ping")
log("  r1=%s" % r[0][:80] if r[0] else "  r1=TIMEOUT")
log("  r2=%s" % r[1][:80] if r[1] else "  r2=TIMEOUT")

# Test 2 : getDeviceDetails + ping (l'un doit bloquer l'autre ?)
log("=== TEST 2 : getDeviceDetails + ping simultanés ===")
r = race_pair("getDeviceDetails", "ping")
log("  r1=%s" % (r[0][:80] if r[0] else "TIMEOUT"))
log("  r2=%s" % (r[1][:80] if r[1] else "TIMEOUT"))

# Test 3 : deux connectToAP avec des SSID différents (état partagé du WiFi)
log("=== TEST 3 : 2x connectToAP simultanés (SSID différents) ===")
args1 = '{"1":{"rec":{"1":{"str":"RACE-A"},"3":{"i32":1}}}}'  # ouvert
args2 = '{"1":{"rec":{"1":{"str":"RACE-B"},"3":{"i32":1}}}}'
r = race_pair("connectToAP", "connectToAP", args1, args2, timeout=35)
log("  r1=%s" % (r[0][:120] if r[0] else "TIMEOUT"))
log("  r2=%s" % (r[1][:120] if r[1] else "TIMEOUT"))

# Test 4 : ping + setupComplete simultanés (le destructeur contre un ping)
log("=== TEST 4 : ping + setupComplete simultanés ===")
r = race_pair("ping", "setupComplete")
log("  r1=%s" % (r[0][:80] if r[0] else "TIMEOUT"))
log("  r2=%s" % (r[1][:80] if r[1] else "TIMEOUT"))

# Test 5 : 5 connexions simultanées de ping (surcharge de la boucle)
log("=== TEST 5 : 5x ping simultanés ===")
threads = []
results = [None] * 5
def tp(i): results[i] = call("ping", 1)
for i in range(5):
    t = threading.Thread(target=tp, args=(i,))
    threads.append(t); t.start()
for t in threads: t.join(timeout=15)
for i, r in enumerate(results):
    log("  r%d=%s" % (i+1, (r[:60] if r else "TIMEOUT")))

# Test 6 : connexion TCP sans envoyer de données (le service gèle-t-il ?)
log("=== TEST 6 : connexion TCP vide + ping (concurrence de sockets) ===")
try:
    dead = socket.create_connection((TARGET, PORT), timeout=3)
    # NE RIEN ENVOYER — garder la connexion ouverte
    time.sleep(1)
    r = call("ping", 1, timeout=5)
    log("  ping pendant connexion vide : %s" % (r[:60] if r else "TIMEOUT"))
    dead.close()
except Exception as e:
    log("  connexion vide : %s" % e)

log("=== FIN DES TESTS RACE ===")
