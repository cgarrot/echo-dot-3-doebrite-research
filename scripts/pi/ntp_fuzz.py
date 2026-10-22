#!/usr/bin/env python3
"""ntp_fuzz — serveur NTP mutant + FINGERPRINT du client Echo.

Le bootstrap DNS montre des requêtes vers ntp-g7g.amazon.com avec transmit
timestamp à ZÉRO (log ntp_fake). Le 1er octet de la requête (LI/VN/mode) va
identifier le client : VN=3 mode=3 → SntpClient.java (framework, sûr) ;
VN=4 → client natif type ntpd/chrony/minimal C (surface mémoire possible) ;
autre → client maison Amazon (à documenter).

Usage :
  sudo python3 ntp_fuzz.py                     # cas ctrl_ok (réponse saine + fingerprint)
  sudo python3 ntp_fuzz.py --case stratum0
  sudo python3 ntp_fuzz.py --list
Fingerprint dans /tmp/fakeap/ntp_fingerprint.log (hex des 16 1ers octets de
chaque requête + interpretation).
"""
import argparse
import socket
import struct
import time

FPLOG = "/tmp/fakeap/ntp_fingerprint.log"
LOGF = "/tmp/fakeap/ntp_fuzz.log"


def ntp_ts(t):
    sec = int(t) + 2208988800
    frac = int((t - int(t)) * (1 << 32)) & 0xFFFFFFFF
    return struct.pack("!II", sec & 0xFFFFFFFF, frac)


def base_resp(req, now):
    resp = bytearray(48)
    resp[0] = 0x24                     # LI=0 VN=4 mode=4 (server)
    resp[1] = 2                        # stratum
    resp[2] = 4                        # poll
    resp[3] = 0xEC                     # precision
    resp[4:8] = struct.pack("!I", 1 << 16)
    resp[8:12] = struct.pack("!I", 1 << 16)
    resp[12:16] = b"FAKE"
    resp[16:24] = ntp_ts(now - 1)      # reference
    resp[24:32] = req[40:48]           # originate = echo transmit client
    resp[32:40] = ntp_ts(now)          # receive
    resp[40:48] = ntp_ts(now)          # transmit
    return resp


def apply_case(r, case, now):
    if case == "ctrl_ok":
        pass
    elif case == "stratum0":           # kiss-of-death → RFC: client doit ignorer l'heure
        r[1] = 0; r[12:16] = b"RATE"
    elif case == "stratum255":
        r[1] = 255
    elif case == "li_alarm":
        r[0] = (r[0] & 0x3F) | 0xC0    # LI=3 (alarme d'horloge)
    elif case == "vn0":
        r[0] = (r[0] & 0x38) | 0x04    # VN=0
    elif case == "mode2":
        r[0] = (r[0] & 0xC7) | 0x10    # mode=2 (symmetric passive, pas server)
    elif case == "rootdelay_max":
        r[4:8] = b"\xff\xff\xff\xff"
    elif case == "rootdisp_max":
        r[8:12] = b"\xff\xff\xff\xff"
    elif case == "originate_zero":     # négatif : le client doit REJETER
        r[24:32] = b"\x00" * 8
    elif case == "tx_zero":
        r[40:48] = b"\x00" * 8
    elif case == "old_time":           # heure de 1970 → casse la validation TLS ?
        t = 1
        r[16:24] = ntp_ts(t); r[32:40] = ntp_ts(t); r[40:48] = ntp_ts(t)
    elif case == "future_time":
        t = 2 ** 31
        r[16:24] = ntp_ts(t); r[32:40] = ntp_ts(t); r[40:48] = ntp_ts(t)
    elif case == "short":              # réponse < 48 o
        return bytes(r[:37])
    elif case == "ext_field":          # RFC 7822 : champ d'extension avec len menteuse
        ext = bytearray(28)
        ext[0:2] = struct.pack("!H", 0x0104)      # type 0x0104, len déclarée
        ext[2:4] = struct.pack("!H", 0xFFFF)      # 65535 mensonger
        return bytes(r) + bytes(ext)
    elif case == "ext_field_short":
        ext = bytearray(8)
        ext[0:2] = struct.pack("!H", 0x0104)
        ext[2:4] = b"\x00\x03"         # len < 8 = malformé
        return bytes(r) + bytes(ext)
    return bytes(r)


CASES = ["ctrl_ok", "stratum0", "stratum255", "li_alarm", "vn0", "mode2",
         "rootdelay_max", "rootdisp_max", "originate_zero", "tx_zero",
         "old_time", "future_time", "short", "ext_field", "ext_field_short"]


def fingerprint(req, addr):
    if len(req) < 1:
        return
    b0 = req[0]
    li, vn, mode = b0 >> 6, (b0 >> 3) & 7, b0 & 7
    tx = req[40:48].hex() if len(req) >= 48 else "?"
    with open(FPLOG, "a") as f:
        f.write("%s req %s len=%d LI=%d VN=%d mode=%d tx=%s hex=%s\n" % (
            time.strftime("%H:%M:%S"), addr, len(req), li, vn, mode, tx,
            req[:16].hex()))
    interp = {3: "SntpClient.java (framework, Java sûr)",
              4: "client natif (ntpd/chrony/minimal C — SURFACE MÉMOIRE)"}.get(vn,
              "inconnu")
    if mode != 3 and mode != 0:
        interp += " [mode inattendu %d]" % mode
    with open(FPLOG, "a") as f:
        f.write("  → VN=%d : %s\n" % (vn, interp))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="ctrl_ok")
    ap.add_argument("--port", type=int, default=123)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        print("\n".join(CASES))
        return
    if a.case not in CASES:
        print("cas inconnu %s" % a.case)
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", a.port))
    print("[ntp_fuzz] cas=%s udp/%d" % (a.case, a.port), flush=True)
    logf = open(LOGF, "a", buffering=1)
    logf.write("%s === ntp_fuzz case=%s ===\n" % (time.strftime("%F %T"), a.case))
    while True:
        data, addr = s.recvfrom(2048)
        now = time.time()
        if len(data) < 48:
            logf.write("%s req trop courte %d o de %s\n" % (time.strftime("%T"), len(data), addr))
            continue
        fingerprint(data, addr)
        resp = apply_case(base_resp(data, now), a.case, now)
        s.sendto(resp, addr)
        logf.write("%s → %s (%d o) cas=%s\n" % (time.strftime("%T"), addr, len(resp), a.case))


if __name__ == "__main__":
    main()
