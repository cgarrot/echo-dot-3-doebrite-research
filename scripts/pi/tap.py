#!/usr/bin/env python3
"""
tap.py — proxy transparent L7 "log-only" pour observer le bootstrap de l'Echo.

On NE termine PAS le TLS : on relaie les octets tels quels vers la vraie
destination (retrouvée via SO_ORIGINAL_DST), donc pas de problème de pinning
de certificat. Ce qu'on récupère quand même :

  - HTTPS/443 : SNI (en clair dans le ClientHello), ALPN, versions TLS,
                tailles/durées de flux (=> on repère le téléchargement OTA),
                et pour TLS<=1.2 les domaines présents dans le certificat
                serveur (le cert est en clair dans le handshake).
  - HTTP/80   : requête complète (méthode + host + chemin) => URL entières.

Sorties (JSONL, une ligne par flux) : /tmp/fakeap/tap.jsonl
Dump optionnel des N premiers octets : --dump

Usage:
    sudo ./tap.py                       # 443->8443, 80->8080
    sudo ./tap.py --https-port 8443 --http-port 8080 --dump 2048
"""
import argparse
import asyncio
import json
import os
import re
import socket
import struct
import time

SO_ORIGINAL_DST = 80
DOMAIN_RE = re.compile(rb"[a-z0-9][a-z0-9._-]{3,60}\.(?:com|net|org|io|cn|co\.uk|de|fr|eu|amazonaws\.com)")
LOG = None
ARGS = None
NL = 0


def log(event, **kw):
    global NL
    NL += 1
    rec = {"i": NL, "t": time.strftime("%Y-%m-%dT%H:%M:%S"), "ev": event, **kw}
    line = json.dumps(rec, ensure_ascii=False)
    LOG.write(line + "\n")
    LOG.flush()
    if ARGS.verbose:
        print(line, flush=True)


def original_dst(sock):
    """Destination d'origine d'une connexion REDIRECTée (iptables NAT)."""
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    except OSError:
        return None
    port = struct.unpack("!H", raw[2:4])[0]
    ip = socket.inet_ntoa(raw[4:8])
    return ip, port


# ---------------------------------------------------------------- TLS parsing
def parse_client_hello(buf):
    """Retourne (sni, alpn, versions) depuis les premiers octets client."""
    if len(buf) < 6 or buf[0] != 0x16:          # handshake record
        return None
    rec_len = int.from_bytes(buf[3:5], "big")
    body = buf[5:5 + rec_len]
    if not body or body[0] != 0x01:             # ClientHello
        return None
    try:
        p = 4                                    # type(1) + len(3)
        p += 2                                   # legacy_version
        p += 32                                  # random
        p += 1 + body[p]                         # session_id
        p += 2 + int.from_bytes(body[p:p + 2], "big")   # cipher_suites
        p += 1 + body[p]                         # compression
        ext_end = p + 2 + int.from_bytes(body[p:p + 2], "big")
        p += 2
        sni, alpn, vers = None, None, []
        while p + 4 <= min(ext_end, len(body)):
            etype = int.from_bytes(body[p:p + 2], "big")
            elen = int.from_bytes(body[p + 2:p + 4], "big")
            ed = body[p + 4:p + 4 + elen]
            p += 4 + elen
            if etype == 0 and len(ed) >= 5:                       # server_name
                n = int.from_bytes(ed[3:5], "big")
                sni = ed[5:5 + n].decode("utf-8", "replace")
            elif etype == 16 and len(ed) >= 3:                    # ALPN
                out, q = [], 2
                while q < len(ed):
                    ln = ed[q]
                    out.append(ed[q + 1:q + 1 + ln].decode("latin1"))
                    q += 1 + ln
                alpn = out
            elif etype == 43 and len(ed) >= 3:                    # supported_versions
                vers = [f"0x{int.from_bytes(ed[q:q + 2], 'big'):04x}"
                        for q in range(1, len(ed) - 1, 2)]
        return sni, alpn, vers
    except Exception:
        return None


def domains_in(buf):
    """Domaines lisibles dans un blob (cert TLS1.2 en clair, SAN/CN)."""
    return sorted({m.decode() for m in DOMAIN_RE.findall(buf.lower())})


def parse_http_request(buf):
    try:
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1")
    except Exception:
        return None
    lines = head.split("\r\n")
    if not lines or " " not in lines[0]:
        return None
    method, path = lines[0].split(" ")[0], lines[0].split(" ")[1]
    host = ""
    for ln in lines[1:]:
        if ln.lower().startswith("host:"):
            host = ln.split(":", 1)[1].strip()
    return {"method": method, "path": path, "host": host,
            "headers": lines[1:]}


# ------------------------------------------------------------------ le relais
async def pump(reader, writer, stats, key):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            stats[key] += len(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(reader, writer, kind):
    t0 = time.time()
    sock = writer.get_extra_info("socket")
    dst = original_dst(sock)
    if not dst:
        writer.close()
        return
    peer = writer.get_extra_info("peername")
    flow = {"kind": kind, "peer": f"{peer[0]}:{peer[1]}",
            "dst": f"{dst[0]}:{dst[1]}", "conntrack": f"{peer[0]} -> {dst[0]}:{dst[1]}"}
    # 1er vol client : SNI ou requête HTTP
    try:
        first = await asyncio.wait_for(reader.read(8192), timeout=3.0)
    except asyncio.TimeoutError:
        first = b""
    if not first:
        log("flow_empty", **flow)
        writer.close()
        return
    if kind == "https":
        # ClientHello parfois tronqué par le 1er read (session ticket) -> compléter
        if len(first) >= 5 and first[0] == 0x16:
            need = 5 + int.from_bytes(first[3:5], "big")
            while len(first) < need and len(first) < 32768:
                try:
                    more = await asyncio.wait_for(reader.read(need - len(first)), timeout=2.0)
                except asyncio.TimeoutError:
                    break
                if not more:
                    break
                first += more
        ch = parse_client_hello(first)
        if ch:
            sni, alpn, vers = ch
            flow.update(sni=sni, alpn=alpn, tls_versions=vers)
    else:
        req = parse_http_request(first)
        if req:
            flow.update(http=req)
    log("flow_start", **flow)

    try:
        up = await asyncio.open_connection(dst[0], dst[1])
    except OSError as e:
        log("upstream_fail", err=str(e), **flow)
        writer.close()
        return
    u_reader, u_writer = up
    stats = {"c2s": 0, "s2c": 0}

    # 1er vol serveur (cert TLS1.2, réponse HTTP)
    s2c_first = b""
    if ARGS.dump:
        os.makedirs(ARGS.dumpdir, exist_ok=True)
        tag = re.sub(r"[^A-Za-z0-9._-]", "_", flow.get("sni") or dst[0])
        stamp = time.strftime("%H%M%S")

    u_writer.write(first)
    await u_writer.drain()
    stats["c2s"] += len(first)

    async def sniff_server():
        nonlocal s2c_first
        try:
            s2c_first = await asyncio.wait_for(u_reader.read(16384), timeout=3.0)
        except asyncio.TimeoutError:
            s2c_first = b""
        return s2c_first

    extra = {}
    first_srv = await sniff_server()
    if first_srv:
        stats["s2c"] += len(first_srv)
        if kind == "https":
            doms = domains_in(first_srv)
            if doms:
                extra["cert_domains"] = doms
            # TLS1.2 = 0x16 en tête ; TLS1.3 = handshake dans ApplicationData
            extra["server_record"] = "handshake" if first_srv[:1] == b"\x16" else "appdata(tls1.3?)"
        else:
            head = first_srv.split(b"\r\n", 1)[0].decode("latin1", "replace")
            extra["http_status"] = head
            extra["http_headers"] = first_srv.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")[:800]
        try:
            writer.write(first_srv)
            await writer.drain()
        except OSError:
            pass
        if ARGS.dump:
            for tag_suffix, blob in (("c2s", first), ("s2c", first_srv)):
                p = os.path.join(ARGS.dumpdir, f"{stamp}_{tag}_{tag_suffix}.bin")
                with open(p, "wb") as f:
                    f.write(blob[:ARGS.dump])

    t = asyncio.create_task(pump(reader, u_writer, stats, "c2s"))
    t2 = asyncio.create_task(pump(u_reader, writer, stats, "s2c"))
    await asyncio.gather(t, t2, return_exceptions=True)
    log("flow_end", c2s=stats["c2s"], s2c=stats["s2c"],
        dur=round(time.time() - t0, 2), **extra, **flow)


async def main():
    global LOG
    ap = argparse.ArgumentParser()
    ap.add_argument("--https-port", type=int, default=8443)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--log", default="/tmp/fakeap/tap.jsonl")
    ap.add_argument("--dump", type=int, default=0)
    ap.add_argument("--dumpdir", default="/tmp/fakeap/flows")
    ap.add_argument("--verbose", action="store_true")
    global ARGS
    ARGS = ap.parse_args()
    os.makedirs(os.path.dirname(ARGS.log), exist_ok=True)
    LOG = open(ARGS.log, "a", buffering=1)

    servers = []
    for port, kind in ((ARGS.https_port, "https"), (ARGS.http_port, "http")):
        s = await asyncio.start_server(
            lambda r, w, k=kind: handle(r, w, k), "0.0.0.0", port)
        servers.append(s)
        print(f"[tap] {kind} : 0.0.0.0:{port}", flush=True)
    print(f"[tap] log -> {ARGS.log}", flush=True)
    async with servers[0], servers[1]:
        await asyncio.gather(servers[0].serve_forever(),
                             servers[1].serve_forever())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
