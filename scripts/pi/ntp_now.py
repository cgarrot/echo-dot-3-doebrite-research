#!/usr/bin/env python3
"""Serveur NTP qui sert l'HEURE EXACTE du Pi (pas minuit)."""
import socket, struct, time
def ntp_ts(t):
    sec = int(t) + 2208988800
    frac = int((t - int(t)) * (1 << 32)) & 0xFFFFFFFF
    return struct.pack("!II", sec & 0xFFFFFFFF, frac)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 123))
print(f"[ntp_now] sert l'heure exacte, démarre à {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
with open("/tmp/fakeap/ntp_now.log","a",buffering=1) as logf:
    while True:
        data, addr = s.recvfrom(1024)
        if len(data) < 48: continue
        now = time.time()
        r = bytearray(48)
        r[0]=0x24; r[1]=2; r[2]=4; r[3]=0xEC
        r[4:8]=struct.pack("!I",1<<16); r[8:12]=struct.pack("!I",1<<16)
        r[12:16]=b"LOCL"
        r[16:24]=ntp_ts(now); r[24:32]=data[40:48]
        r[32:40]=ntp_ts(now); r[40:48]=ntp_ts(now)
        s.sendto(bytes(r), addr)
        logf.write(f"{time.strftime('%H:%M:%S')} {addr[0]}:{addr[1]} -> {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
