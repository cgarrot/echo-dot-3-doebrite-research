#!/usr/bin/env python3
"""Probe avahi 0.6.31 (mDNS) sur le device — accessible SANS enregistrement."""
import socket, struct, time, sys

IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.25"
LOG = "/tmp/avahi_probe.log"

def log(m):
    print(f"{time.strftime('%H:%M:%S')} {m}", flush=True)

def nm(name):
    out = b""
    for l in name.strip(b".").split(b"."):
        out += bytes([len(l)]) + l
    return out + b"\x00"

# Requêtes mDNS standard vers le device
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)

queries = [
    ("_amzn-alexa._tcp.local", 12),      # PTR — le service FFS
    ("_services._dns-sd._udp.local", 12), # PTR — énumération
    ("_spotify-connect._tcp.local", 12),  # PTR — Spotify Connect
    ("_googlecast._tcp.local", 12),       # PTR — Chromecast-like
    ("octave.local", 1),                   # A — hostname
    ("_http._tcp.local", 12),              # PTR — serveur web
    ("_ipp._tcp.local", 12),               # PTR — imprimante
    ("_sftp-ssh._tcp.local", 12),          # PTR — SFTP
]

log(f"=== PROBE AVAHI 5353 sur {IP} ===")
for name, qtype in queries:
    q = nm(name.encode())
    pkt = struct.pack("!HHHHHH", 0x4142, 0, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)
    s.sendto(pkt, (IP, 5353))
    try:
        data, addr = s.recvfrom(4096)
        log(f"  ★ {name}: RÉPONSE ({len(data)} o) — hex: {data[:60].hex()}")
    except socket.timeout:
        log(f"  {name}: silence")

# Maintenant via multicast
log(f"=== PROBE AVAHI MULTICAST ===")
sm = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sm.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sm.bind(("", 5353))
mreq = socket.inet_aton("224.0.0.251") + socket.inet_aton("0.0.0.0")
sm.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
sm.settimeout(3)

for name, qtype in queries:
    q = nm(name.encode())
    pkt = struct.pack("!HHHHHH", 0x4143, 0, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)
    sm.sendto(pkt, ("224.0.0.251", 5353))
    time.sleep(0.2)

t0 = time.time()
seen = set()
while time.time() - t0 < 5:
    try:
        data, addr = sm.recvfrom(4096)
        if addr[0] == IP:
            key = data[:20].hex()
            if key not in seen:
                seen.add(key)
                log(f"  ★ MULTICAST RÉPONSE de {addr[0]} ({len(data)} o)")
    except socket.timeout:
        break

if not seen:
    log("  aucun répondant multicast")

log("=== FIN ===")
