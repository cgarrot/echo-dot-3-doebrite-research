#!/usr/bin/env python3
"""Fuzzer SOCKS5 du service root de l'Echo (1080)."""
import socket, struct, time, sys, random

H=("192.168.1.24",1080)

def alive():
    try:
        s=socket.create_connection(H,timeout=3)
        s.sendall(b"\x05\x01\x00"); s.settimeout(3)
        d=s.recv(2); s.close(); return d==b"\x05\x00"
    except: return False

def probe(payload, label, follow=None, timeout=4):
    """envoie payload ; si follow, envoie apres la reponse au greeting"""
    try:
        s=socket.create_connection(H,timeout=timeout); s.settimeout(timeout)
        s.sendall(payload)
        try: d=s.recv(256)
        except socket.timeout: d=b"<TO>"
        out=d
        if follow:
            try:
                s.sendall(follow); s.settimeout(timeout)
                out2=s.recv(256)
                out = d + b" | " + out2
            except socket.timeout: out = d + b" | <TO>"
            except Exception as e: out = d + b" | EXC:" + type(e).__name__.encode()
        s.close()
        return out
    except Exception as e:
        return f"EXC:{type(e).__name__}".encode()

print("baseline:", alive())
if not alive(): sys.exit("serveur SOCKS injoignable")

T=[]
# --- greetings malformes
for nm in [0,1,2,3,10,255]:
    T.append((f"greet nmethods={nm}", b"\x05"+bytes([nm])))
T.append(("greet v4", b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00"))
T.append(("greet v0", b"\x00"*3))
T.append(("greet tronque 1o", b"\x05"))
# --- methods dangereuses
T.append(("method 0xff", b"\x05\x01\xff"))
T.append(("method 0x02 (userpass)", b"\x05\x01\x02"))
T.append(("255 methods", b"\x05\xff"+b"\x02"*255))
# --- CONNECT atyp varies
for atyp,addr,lab in [
    (1, socket.inet_aton("127.0.0.1"), "ipv4 loopback"),
    (1, socket.inet_aton("0.0.0.0"), "ipv4 0.0.0.0"),
    (1, socket.inet_aton("255.255.255.255"), "ipv4 broadcast"),
    (3, b"\x00a", "domain len=0"),
    (3, b"\xff" + b"a"*255, "domain len=255"),
    (3, b"\x01\x00", "domain NUL"),
    (4, b"\x00"*16, "ipv6 zeros"),
    (4, b"\xff"*16, "ipv6 ff"),
    (0, b"", "atyp 0"),
    (5, b"AAAA", "atyp 5"),
    (255, b"", "atyp 255"),
]:
    req = b"\x05\x01\x00"+bytes([atyp])+addr+struct.pack(">H",80)
    T.append((f"connect {lab}", None, req))
# --- commandes invalides
for cmd in [0,2,3,4,255]:
    T.append((f"cmd={cmd}", None, b"\x05"+bytes([cmd])+b"\x00\x01"+socket.inet_aton("127.0.0.1")+struct.pack(">H",80)))
# --- ports extremes
for port in [0,1,65535]:
    T.append((f"port={port}", None, b"\x05\x01\x00\x01"+socket.inet_aton("127.0.0.1")+struct.pack(">H",port)))

GREET=b"\x05\x01\x00"
for item in T:
    if len(item)==3:
        label,_,follow = item
        r=probe(GREET, label, follow=follow)
    else:
        label,payload = item
        r=probe(payload, label)
    ok=alive()
    print(f"{label:28} -> {r[:60]!r} alive={ok}")
    if not ok:
        print(f"  ★★★★ MORT sur: {label}  payload={r[:80]!r}")
        break
    time.sleep(0.25)
