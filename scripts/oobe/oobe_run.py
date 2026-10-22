import socket, threading, time, json, sys

TARGET = "10.201.126.241"
PORT = 8080
LOG = "/tmp/oobe_fresh.log"
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
        return "ERR:%s" % type(e).__name__, 0

r, dt = call("ping", timeout=5)
log("PING: %s (%.1fs)" % (r[:60], dt))
if "tf" not in r:
    log("DEVICE PAS VIVANT — abandon"); sys.exit(1)

log("=== T1 : setLocaleAndEndpoints → TOUS endpoints vers 192.168.50.1 ===")
our_ip = "192.168.50.1"
args = {"1": {"rec": {
    "1": {"str": "en-US"}, "2": {"str": "US"},
    "4": {"str": our_ip + ":8080"}, "5": {"i32": 8080},
    "6": {"str": our_ip + ":8080"}, "7": {"i32": 8080},
    "8": {"str": our_ip + ":8080"}, "9": {"str": our_ip + ":8080"},
    "10": {"str": our_ip + ":8080"},
    "11": {"str": "http://" + our_ip + ":8080/captive"}
}}}
r, dt = call("setLocaleAndEndpoints", args, timeout=15)
log("  → (%.1fs) %s" % (dt, r[:300]))
if '"i32":0' in r:
    log("  ★★★ ACCEPTÉ — le device a NOS endpoints !")

log("=== T2 : connectToAPEx → config IP hostile ===")
args2 = {"1": {"rec": {"1": {"str": "TEST"}, "3": {"i32": 1}}},
        "2": {"rec": {
            "1": {"str": "192.168.50.1"}, "2": {"str": "255.255.255.255"},
            "3": {"str": "192.168.50.254"}, "4": {"str": "192.168.50.1"}}}}
r, dt = call("connectToAPEx", args2, timeout=40)
log("  → (%.1fs) %s" % (dt, r[:300]))

log("=== T3 : getOTADetails (compact, 90s) ===")
r, dt = call("getOTADetails", "{}", timeout=90)
log("  → (%.1fs) %s" % (dt, r[:300]))

log("=== T4 : getLinkCode (compact) ===")
r, dt = call("getLinkCode", "{}", timeout=90)
log("  → (%.1fs) %s" % (dt, r[:300]))

if 1:
    log("=== T5a : 2 ping simultanés ===")
    results = [None, None]
    def t1(): results[0] = call("ping", seq=100)
    def t2(): results[1] = call("ping", seq=101)
    th1 = threading.Thread(target=t1); th2 = threading.Thread(target=t2)
    th1.start(); th2.start(); th1.join(15); th2.join(15)
    log("  r1=%s" % (results[0][0][:60] if results[0] else "TIMEOUT"))
    log("  r2=%s" % (results[1][0][:60] if results[1] else "TIMEOUT"))

    log("=== T5b : getDeviceDetails + ping // ===")
    results = [None, None]
    def t3(): results[0] = call("getDeviceDetails", seq=200)
    def t4(): results[1] = call("ping", seq=201)
    th1 = threading.Thread(target=t3); th2 = threading.Thread(target=t4)
    th1.start(); th2.start(); th1.join(20); th2.join(20)
    log("  r1=%s" % (results[0][0][:60] if results[0] else "TIMEOUT"))
    log("  r2=%s" % (results[1][0][:60] if results[1] else "TIMEOUT"))

    log("=== T5c : TCP vide + ping ===")
    try:
        dead = socket.create_connection((TARGET, PORT), timeout=3)
        time.sleep(1)
        r, dt = call("ping", timeout=8, seq=300)
        log("  ping pendant vide : %s (%.1fs)" % (r[:60], dt))
        dead.close()
    except Exception as e:
        log("  erreur : %s" % e)

    log("=== T5d : 5 ping // ===")
    results5 = [None] * 5
    def tp(i): results5[i] = call("ping", timeout=15, seq=400+i)
    threads = [threading.Thread(target=tp, args=(i,)) for i in range(5)]
    for t in threads: t.start()
    for t in threads: t.join(20)
    for i, rr in enumerate(results5):
        log("  r%d=%s" % (i+1, (rr[0][:60] if rr else "TIMEOUT")))

    log("=== T6 : disconnectFromAP SSID malformés ===")
    for label, ssid in [("253c","A"*253), ("ctrl","\x01\x02\x03"), ("utf8","test\xFF"), ("nul","a"*50+"\x00"+"b"*50)]:
        args6 = {"1": {"str": ssid[:200]}}
        r, dt = call("disconnectFromAP", args6, timeout=10)
        log("  %s → %s" % (label, r[:60]))

log("=== FIN ===")
