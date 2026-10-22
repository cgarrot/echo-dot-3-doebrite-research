#!/usr/bin/env python3
"""
Fuzz du CLIENT DNS de l'Echo : on est son serveur DNS et on lui renvoie
des reponses MALFORMEES. Objectif : parseur (resolver) qui casse.
"""
import socket, struct, time, sys, os

LOG = "/tmp/fakeap/dns_fuzz_client.log"
COUNT_FILE = "/tmp/fakeap/dns_fuzz_count"
STATE = {"i": 0}

def log(msg):
    with open(LOG, "a", buffering=1) as f:
        f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")

def parse_q(data):
    """Extrait qid, qname, qtype, et l'offset de fin de la question."""
    if len(data) < 12: return None
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    off = 12
    labels = []
    while off < len(data) and data[off] != 0:
        l = data[off]
        if l & 0xC0: break
        labels.append(data[off+1:off+1+l])
        off += 1 + l
    off += 1
    qtype, qclass = struct.unpack("!HH", data[off:off+4]) if off+4 <= len(data) else (1,1)
    return qid, b".".join(labels), qtype, off+4

def hdr(qid, flags=0x8180, qd=1, an=1, ns=0, ar=0):
    return struct.pack("!HHHHHH", qid, flags, qd, an, ns, ar)

# ---------- CAS MALFORMES ----------
def c_compress_loop(qid, qname, qtype, qend):
    """Pointeur de compression qui boucle sur lui-meme."""
    q = qname + b"\x00" if qname else b"\x00"
    qsec = b"\x03www" + b"\x00" + struct.pack("!HH", 1, 1)
    # answer: name = pointeur vers 0x0c+len(qsec) -> lui-meme
    an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return hdr(qid) + qsec + an

def c_ptr_oob(qid, qname, qtype, qend):
    """Pointeur de compression hors paquet."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    an = b"\xc0\xff" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return hdr(qid) + qsec + an

def c_rr_len_huge(qid, qname, qtype, qend):
    """RDLENGTH enorme mais pas de donnees."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 60000)
    return hdr(qid) + qsec + an

def c_cname_loop(qid, qname, qtype, qend):
    """CNAME qui pointe vers lui-meme."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    rd = b"\xc0" + bytes([12 + len(qsec)])   # pointe sur le CNAME lui-meme
    an = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(rd)) + rd
    return hdr(qid) + qsec + an

def c_label_too_long(qid, qname, qtype, qend):
    """Label de longueur 100 (max legal = 63)."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    an = b"\x64" + b"A"*100 + b"\x00" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return hdr(qid) + qsec + an

def c_name_too_long(qid, qname, qtype, qend):
    """Nom > 255 octets (labels de 63)."""
    name = (b"\x3f" + b"B"*63) * 5 + b"\x00"
    qsec = b"\x03www" + b"\x00" + struct.pack("!HH", 1, 1)
    an = name + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return hdr(qid) + qsec + an

def c_ancount_lies(qid, qname, qtype, qend):
    """ANCOUNT=5 mais une seule reponse."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return hdr(qid, an=5) + qsec + an

def c_truncated_rr(qid, qname, qtype, qend):
    """RR tronque en plein milieu."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02"
    return hdr(qid) + qsec + an

def c_edns_bad(qid, qname, qtype, qend):
    """OPT malforme (ARCOUNT=1, RDLEN gigantesque)."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0x8000, 5000)
    return hdr(qid, ar=1) + qsec + opt

def c_qd_zero(qid, qname, qtype, qend):
    """QDCOUNT=0 mais une reponse presente."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return hdr(qid, qd=0) + qsec + an

def c_self_ptr_answer(qid, qname, qtype, qend):
    """Pointeur qui pointe vers la reponse elle-meme (boucle profonde)."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    off = 12 + len(qsec)
    an = struct.pack("!H", 0xC000 | (off + 2)) + struct.pack("!HHIH", 1, 1, 60, 2) + struct.pack("!H", 0xC000 | (off))
    return hdr(qid) + qsec + an

def c_over_512(qid, qname, qtype, qend):
    """Reponse > 512 octets sans EDNS (fragmentation)."""
    qsec = qname + b"\x00" + struct.pack("!HH", 1, 1)
    an = b""
    for i in range(40):
        an += b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, 20) + b"\x14" + b"X"*19
    return hdr(qid, an=40) + qsec + an

CASES = [
    ("ctrl_valid", None),
    ("compress_loop", c_compress_loop),
    ("ptr_oob", c_ptr_oob),
    ("rr_len_huge", c_rr_len_huge),
    ("cname_loop", c_cname_loop),
    ("label_too_long", c_label_too_long),
    ("name_too_long", c_name_too_long),
    ("ancount_lies", c_ancount_lies),
    ("truncated_rr", c_truncated_rr),
    ("edns_bad", c_edns_bad),
    ("qd_zero", c_qd_zero),
    ("self_ptr", c_self_ptr_answer),
    ("over_512", c_over_512),
]

def valid_response(qid, qname, qtype, qend, data):
    """Reponse valide : renvoie une IP de notre Pi."""
    qsec = data[12:qend]
    an = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + socket.inet_aton("192.168.50.1")
    return hdr(qid) + qsec + an

def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "compress_loop"
    gen = dict(CASES).get(name)
    log(f"=== DEMARRAGE case={name} ===")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 53))
    n = 0
    while True:
        try:
            data, addr = s.recvfrom(2048)
        except KeyboardInterrupt:
            break
        p = parse_q(data)
        if not p:
            continue
        qid, qname, qtype, qend = p
        n += 1
        try:
            if gen is None:
                resp = valid_response(qid, qname, qtype, qend, data)
            else:
                resp = gen(qid, qname, qtype, qend)
            s.sendto(resp, addr)
            log(f"#{n} {addr[0]} q={qname.decode(errors='replace')[:40]} type={qtype} -> {name} ({len(resp)}o)")
        except Exception as e:
            log(f"#{n} ERREUR generation: {e}")
        with open(COUNT_FILE, "w") as f:
            f.write(str(n))

if __name__ == "__main__":
    main()
