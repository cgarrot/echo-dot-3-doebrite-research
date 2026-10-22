#!/usr/bin/env python3
"""
socks5_probe.py — sonde du listener SOCKS5 sans auth (port 1080 de l'Echo).

État connu (LOCAL_SURFACE.md) :
  offre \\x05\\x01\\x00            -> \\x05\\x00     (no-auth accepté)
  offre \\x05\\x02\\x00\\x02        -> \\x05\\x00     (no-auth choisi même si non proposé)
  CONNECT (IPv4 ou domaine)     -> \\x05\\x09     (REP hors RFC 1928 : refus applicatif)
  BIND / UDP ASSOCIATE          -> \\x05\\x07
  SOCKS4/4a                     -> \\x05\\xff

LA QUESTION OUVERTE : REP 0x09 n'existe pas dans la RFC. C'est donc un refus
*applicatif* — la pile SOCKS est présente, la redirection est bloquée « tant
qu'aucune session de diagnostic n'est autorisée ». La sonde cherche **ce qui
débloque** : méthode d'auth, type d'adresse, variantes de trame.

Sonde en LECTURE SEULE : elle n'envoie que des poignées de main SOCKS5 et lit la
réponse. Aucun paquet malformé au-delà de ce que la RFC autorise, aucune tentative
d'exploitation. Elle signale toute réponse différente de 0x09 — c'est là que
serait la faille.

Usage :
  python3 socks5_probe.py --host 192.168.1.24
  python3 socks5_probe.py --host 192.168.1.24 --port 1080 --verbose
  python3 socks5_probe.py --host 127.0.0.1 --selftest   # valide la sonde sur un faux serveur
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time

REP = {
    0x00: "succeeded",
    0x01: "general failure",
    0x02: "not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
    0x09: "*** HORS RFC — refus applicatif (connu) ***",
}
AUTH = {0x00: "no-auth", 0x01: "GSSAPI", 0x02: "user/pass", 0xFF: "aucune acceptée"}


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            break
        buf += c
    return buf


def attempt(host: str, port: int, methods: list[int], cmd: int, atyp: int,
            target: tuple, auth: tuple[str, str] | None = None,
            timeout: float = 5.0) -> dict:
    """Une tentative. Retourne {ok, auth_reply, rep, note}."""
    res = {"methods": methods, "cmd": cmd, "atyp": atyp, "auth": auth,
           "auth_reply": None, "rep": None, "note": ""}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        res["note"] = f"connexion impossible: {type(e).__name__}"
        return res
    try:
        s.settimeout(timeout)
        s.sendall(bytes([0x05, len(methods)]) + bytes(methods))
        rep = _recv_exact(s, 2)
        if len(rep) < 2:
            res["note"] = "pas de réponse à la poignée de main"
            return res
        res["auth_reply"] = rep[1]
        if rep[1] == 0xFF:
            res["note"] = "aucune méthode acceptée"
            return res
        if rep[1] == 0x02:
            u, p = (auth or ("", ""))
            ub, pb = u.encode()[:255], p.encode()[:255]
            s.sendall(bytes([0x01, len(ub)]) + ub + bytes([len(pb)]) + pb)
            ar = _recv_exact(s, 2)
            if len(ar) < 2 or ar[1] != 0x00:
                res["note"] = f"auth user/pass refusée ({ar.hex() if ar else 'vide'})"
                return res
            res["note"] = "auth user/pass ACCEPTÉE"
        # requête
        if atyp == 0x01:
            addr = socket.inet_aton(target[0])
        elif atyp == 0x04:
            addr = socket.inet_pton(socket.AF_INET6, target[0])
        else:
            d = target[0].encode()
            addr = bytes([len(d)]) + d
        req = bytes([0x05, cmd, 0x00, atyp]) + addr + target[1].to_bytes(2, "big")
        s.sendall(req)
        head = _recv_exact(s, 4)
        if len(head) < 4:
            res["note"] = (res["note"] + " | pas de réponse à la requête").strip(" |")
            return res
        res["rep"] = head[1]
        # consommer l'adresse de réponse si présente
        if head[3] == 0x01:
            _recv_exact(s, 4 + 2)
        elif head[3] == 0x03:
            ln = _recv_exact(s, 1)
            if ln: _recv_exact(s, ln[0] + 2)
        elif head[3] == 0x04:
            _recv_exact(s, 16 + 2)
    except Exception as e:
        res["note"] = (res["note"] + f" | {type(e).__name__}: {e}").strip(" |")
    finally:
        try: s.close()
        except Exception: pass
    return res


def matrix(host: str, port: int, verbose: bool) -> int:
    targets = [
        ("127.0.0.1", 8080), ("127.0.0.1", 4070), ("127.0.0.1", 6543),
        ("192.168.1.1", 80), ("example.com", 80),
    ]
    interesting = 0
    total = 0

    print(f"=== sonde SOCKS5 {host}:{port} ===\n")
    combos = [
        ("no-auth", [0x00], None),
        ("user/pass proposé", [0x02], ("", "")),
        ("no-auth + user/pass", [0x00, 0x02], None),
        ("GSSAPI + no-auth", [0x01, 0x00], None),
    ]
    for label, methods, auth in combos:
        for ip, tport in targets[:2]:
            for cmd, cmdname in ((0x01, "CONNECT"), (0x03, "UDP")):
                total += 1
                r = attempt(host, port, methods, cmd, 0x01, (ip, tport), auth)
                a = AUTH.get(r["auth_reply"], f"0x{r['auth_reply']:02x}") if r["auth_reply"] is not None else "—"
                rep = REP.get(r["rep"], f"0x{r['rep']:02x}") if r["rep"] is not None else "—"
                flag = ""
                if r["rep"] is not None and r["rep"] != 0x09:
                    flag = "  <<<< DIFFÉRENT"
                    interesting += 1
                if verbose or flag or r["auth_reply"] not in (0x00, None):
                    print(f"  {label:20s} {cmdname:7s} {ip}:{tport:<5d} "
                          f"auth={a:16s} rep={rep}{flag}")
                if r["note"] and (verbose or flag):
                    print(f"      note: {r['note']}")
    # variantes d'ATYP sur un CONNECT no-auth
    for atyp, tgt, name in ((0x03, ("localhost", 8080), "domaine"),
                            (0x04, ("::1", 8080), "IPv6"),
                            (0x01, ("127.0.0.1", 0), "port 0")):
        total += 1
        r = attempt(host, port, [0x00], 0x01, atyp, tgt)
        rep = REP.get(r["rep"], f"0x{r['rep']:02x}") if r["rep"] is not None else "—"
        flag = ""
        if r["rep"] is not None and r["rep"] != 0x09:
            flag = "  <<<< DIFFÉRENT"
            interesting += 1
        print(f"  {'no-auth':20s} CONNECT {name:12s} rep={rep}{flag}")
        if r["note"] and verbose:
            print(f"      note: {r['note']}")

    print(f"\n{total} tentatives, {interesting} réponse(s) hors 0x09.")
    if interesting:
        print("==> quelque chose se comporte différemment : à creuser en priorité.")
        return 0
    print("==> tout est refusé en 0x09 : le verrou n'est pas dans la trame SOCKS,")
    print("    il est en amont (une « session de diagnostic » doit être autorisée).")
    print("    Prochaine piste : ce qui autorise la session (directive cloud ? état")
    print("    du device ? appairage ?) — pas la couche SOCKS elle-même.")
    return 1


# ------------------------------------------------------------------ selftest --
def selftest() -> None:
    """Faux serveur SOCKS5 : refuse tout en 0x09 SAUF le domaine (0x03),
    où il répond 0x00 — pour vérifier que la sonde distingue bien."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 19080))
    srv.listen(32)
    stop = threading.Event()

    def handle(c):
        try:
            c.settimeout(3)
            h = _recv_exact(c, 2)
            if len(h) < 2: return
            _recv_exact(c, h[1])
            if 0x02 in []: pass
            c.sendall(bytes([0x05, 0x00]))          # toujours no-auth
            r = _recv_exact(c, 4)
            if len(r) < 4: return
            atyp = r[3]
            if atyp == 0x01: _recv_exact(c, 4 + 2)
            elif atyp == 0x04: _recv_exact(c, 16 + 2)
            else:
                ln = _recv_exact(c, 1)
                _recv_exact(c, ln[0] + 2)
            rep = 0x00 if atyp == 0x03 else 0x09    # le domaine passe !
            c.sendall(bytes([0x05, rep, 0x00, 0x01]) + b"\x00" * 4 + b"\x00\x00")
        except Exception:
            pass
        finally:
            try: c.close()
            except Exception: pass

    def loop():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except Exception:
                break
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    t = threading.Thread(target=loop, daemon=True); t.start()
    time.sleep(0.4)
    rc = matrix("127.0.0.1", 19080, verbose=False)
    stop.set(); srv.close()
    print(f"\nselftest: la sonde a bien détecté la variante 'domaine' comme différente "
          f"(code retour {rc}, attendu 0).")
    sys.exit(0 if rc == 0 else 3)


def main() -> None:
    ap = argparse.ArgumentParser(description="Sonde du SOCKS5 sans auth (port 1080)")
    ap.add_argument("--host", required=False, help="IP de l'Echo")
    ap.add_argument("--port", type=int, default=1080)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        selftest()
        return
    if not args.host:
        ap.error("--host requis (ou --selftest)")
    sys.exit(matrix(args.host, args.port, args.verbose))


if __name__ == "__main__":
    main()
