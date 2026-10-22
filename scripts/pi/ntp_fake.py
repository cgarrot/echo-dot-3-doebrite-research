#!/usr/bin/env python3
"""
ntp_fake.py — serveur NTP minimal qui LOGGE chaque requête.

Pourquoi : l'Echo a besoin d'une horloge à peu près juste pour valider les
certificats TLS. Le Pi est synchronisé (systemd-timesyncd) -> on lui sert
notre heure. Bonus : un hit NTP = jalon du bootstrap (juste après le DHCP,
avant les premiers TLS).

Usage: sudo ./ntp_fake.py [--log /tmp/fakeap/ntp.log]
"""
import argparse
import socket
import struct
import time


def ntp_ts(t):
    """Timestamp NTP 64 bits (secondes depuis 1900 + fraction)."""
    sec = int(t) + 2208988800
    frac = int((t - int(t)) * (1 << 32)) & 0xFFFFFFFF
    return struct.pack("!II", sec & 0xFFFFFFFF, frac)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/tmp/fakeap/ntp.log")
    ap.add_argument("--port", type=int, default=123)
    a = ap.parse_args()
    logf = open(a.log, "a", buffering=1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", a.port))
    print(f"[ntp] écoute udp/{a.port} -> {a.log}", flush=True)

    while True:
        data, addr = s.recvfrom(1024)
        now = time.time()
        if len(data) < 48:
            continue
        client_tx = data[40:48]          # transmit timestamp du client
        li_vn_mode = 0x24                # LI=0 VN=4 Mode=4 (server)
        resp = bytearray(48)
        resp[0] = li_vn_mode
        resp[1] = 2                      # stratum
        resp[2] = 4                      # poll
        resp[3] = 0xEC                   # precision -20
        resp[4:8] = struct.pack("!I", 1 << 16)   # root delay
        resp[8:12] = struct.pack("!I", 1 << 16)  # root dispersion
        resp[12:16] = b"FAKE"
        resp[16:24] = ntp_ts(now - 1)    # reference
        resp[24:32] = client_tx          # originate = echo du client
        resp[32:40] = ntp_ts(now)        # receive
        resp[40:48] = ntp_ts(now)        # transmit
        s.sendto(bytes(resp), addr)
        # --- attribution de l'implémentation cliente -------------------------
        # LI/VN/Mode du 1er octet, puis les champs qui trahissent un client donné
        b0 = data[0]
        li, vn, mode = b0 >> 6, (b0 >> 3) & 7, b0 & 7
        stratum, poll, prec = data[1], data[2], data[3]
        root_delay = struct.unpack("!I", data[4:8])[0]
        root_disp = struct.unpack("!I", data[8:12])[0]
        refid = data[12:16]
        ref_ts = data[16:24]
        orig_ts = data[24:32]
        recv_ts = data[32:40]
        tx = data[40:48]
        logf.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} NTP-REQ from "
                   f"{addr[0]}:{addr[1]} len={len(data)}\n")
        logf.write(f"    li={li} vn={vn} mode={mode} stratum={stratum} "
                   f"poll={poll} precision={prec} (0x{prec & 0xff:02x})\n")
        logf.write(f"    root_delay={root_delay} root_disp={root_disp} "
                   f"refid={refid.hex()} ({refid!r})\n")
        logf.write(f"    ref_ts={ref_ts.hex()} /*=0*/{ref_ts == bytes(8)}  "
                   f"orig_ts={orig_ts.hex()} /*=0*/{orig_ts == bytes(8)}\n")
        logf.write(f"    recv_ts={recv_ts.hex()} /*=0*/{recv_ts == bytes(8)}  "
                   f"tx_ts={tx.hex()} /*=0*/{tx == bytes(8)}\n")
        logf.write(f"    hex={data.hex()}\n")


if __name__ == "__main__":
    main()
