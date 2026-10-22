#!/usr/bin/env python3
"""
fake_ota.py — IMPERSONNER LE SERVEUR OTA : l'expérience qui tranche (a) et (b).

CE QU'ON SAIT DÉJÀ (mesuré, pas supposé)
  • Dans la capture réelle du bootstrap, `softwareupdates.amazon.com` est joint en
    **HTTPS** (1 flux, SNI + certificat Amazon en clair) et **tous** les gros
    téléchargements (3,46 / 2,08 / 0,68 Mo) sont des CloudFront en **HTTPS**.
    Les seuls flux en clair sont le portail captif, Spotify apresolve, un
    diagnostic AWS et un check Google → **aucun OTA en HTTP**. (b) est donc
    tranché par les données : pas de passe-droit via HTTP.
  • Le SDK FFS d'Amazon **épingle une CA** pour authentifier le serveur :
    `pCaCert = STARFIELD_CLASS_2_CERTIFICATION_AUTHORITY` = **Starfield Services
    Root Certificate Authority - G2** (empreinte SHA-256 28:68:9B:30:…).
    ⇒ Amazon vérifie les certificats serveur dans ses piles embarquées. Indice
    fort, mais l'OTA handler est un autre composant : **à tester**.

CE QUE FAIT CE SCRIPT
  Il répond en TLS (ou en clair) à la place de l'hôte OTA, avec un certificat
  **auto-signé**, et journalise TOUT ce que le device fait :

    • le SNI du ClientHello (sait-il au moins quel hôte il demande ?)
    • la version TLS et les suites proposées
    • si un **certificat client** est présenté (mTLS) et son sujet
    • si la poignée de main **aboutit** ou si le device **coupe** (et avec quel
      code d'alerte : 42 bad_certificate, 48 unknown_ca, 46 certificate_unknown…)
    • s'il aboutit : la **requête HTTP exacte** (méthode, chemin, en-têtes) — donc
      le **chemin réel du manifeste**, ce que le TLS nous cachait jusqu'ici

  Codes d'alerte utiles : 42 = bad_certificate, 43 = unsupported_certificate,
  46 = certificate_unknown, 48 = unknown_ca. Une alerte 42/46/48 ⇒ **le device
  valide** et l'usurpation HTTPS est morte. Une requête qui arrive ⇒ **il ne
  valide pas** ⇒ tout devient possible.

MISE EN PLACE (sur piveil, l'Echo étant sur notre AP)
  1) détourner les noms OTA dans dnsmasq :
       address=/softwareupdates.amazon.com/192.168.50.1
       address=/updates.amazon.com/192.168.50.1
       address=/tp.ef6ac5c69-frontier.amazon.com/192.168.50.1
     puis `sudo systemctl restart dnsmasq` (ou `kill -HUP`)
  2) lancer :  sudo python3 fake_ota.py --serve
  3) déclencher une vérification OTA côté device (reboot, ou attente du cycle)
  4) lire `fake_ota_out/events.jsonl`

USAGE
  python3 fake_ota.py --make-cert                       # crée cert+clé auto-signés
  sudo python3 fake_ota.py --serve --port 443 --body manifest.json
  sudo python3 fake_ota.py --serve --port 80 --plain    # teste un repli HTTP
  python3 fake_ota.py --dns-help                        # affiche les lignes dnsmasq
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

OUT = "fake_ota_out"


def log(**kw):
    os.makedirs(OUT, exist_ok=True)
    kw["t"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    line = json.dumps(kw, ensure_ascii=False, default=str)
    with open(os.path.join(OUT, "events.jsonl"), "a", buffering=1) as f:
        f.write(line + "\n")
    print("  " + line[:300], flush=True)


def make_cert(cn="softwareupdates.amazon.com"):
    os.makedirs(OUT, exist_ok=True)
    key, crt = os.path.join(OUT, "ota.key"), os.path.join(OUT, "ota.pem")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "30",
                        "-subj", f"/C=US/ST=WA/L=Seattle/O=Amazon/CN={cn}",
                        "-addext", f"subjectAltName=DNS:{cn},DNS:*.amazon.com"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print(f"certificat créé : {crt}\n  sujet : CN={cn} (auto-signé, NON validable)")
        return crt, key
    print("échec openssl :", r.stderr[:200])
    return None, None


def handle(conn, addr, ctx, body, plain):
    peer = f"{addr[0]}:{addr[1]}"
    try:
        if not plain:
            try:
                conn = ctx.wrap_socket(conn, server_side=True)
                slog = {"peer": peer, "handshake": "OK",
                        "tls": conn.version(), "cipher": (conn.cipher()[0] if conn.cipher() else None),
                        "sni": getattr(conn, "server_hostname", None)}
                pc = conn.getpeercert()
                slog["client_cert"] = bool(pc)
                if pc:
                    slog["client_cert_subject"] = str(pc.get("subject"))
                log(ev="tls", **slog)
            except ssl.SSLError as e:
                # c'est ICI qu'on lit la réponse à (a)
                log(ev="tls_abort", peer=peer, reason=getattr(e, "reason", None),
                    code=e.args[0] if e.args else None, detail=str(e)[:200],
                    lecture=("le device REFUSE notre certificat ⇒ il valide"
                             if getattr(e, "reason", "") else ""))
                return
            except Exception as e:
                log(ev="tls_error", peer=peer, err=type(e).__name__, detail=str(e)[:150])
                return
        else:
            log(ev="plain_connect", peer=peer)

        conn.settimeout(10)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                ch = conn.recv(4096)
                if not ch:
                    break
                data += ch
        except Exception:
            pass
        head = data.decode("latin1", "replace")
        if head:
            lines = head.split("\r\n")
            log(ev="http_request", peer=peer, request_line=lines[0],
                headers=lines[1:25], plain=plain)
        else:
            log(ev="no_http", peer=peer, note="poignée de main OK mais aucune requête")
            return
        payload = body.encode() if isinstance(body, str) else body
        resp = (f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n").encode() + payload
        conn.sendall(resp)
        log(ev="served", peer=peer, bytes=len(payload))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve(port, cert, key, body, plain, once=False):
    os.makedirs(OUT, exist_ok=True)
    ctx = None
    if not plain:
        if not (cert and key and os.path.exists(cert) and os.path.exists(key)):
            cert, key = make_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        # on NE demande PAS de certificat client : on veut voir s'il en envoie
        print(f"[fake_ota] TLS sur :{port} avec {cert} (auto-signé)\n")
    else:
        print(f"[fake_ota] HTTP en clair sur :{port}\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    print(f"en écoute — les événements vont dans {OUT}/events.jsonl\n")
    try:
        while True:
            c, a = s.accept()
            threading.Thread(target=handle, args=(c, a, ctx, body, plain), daemon=True).start()
            if once:
                time.sleep(20)
                break
    except KeyboardInterrupt:
        print("\narrêt.")
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--make-cert", action="store_true")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--plain", action="store_true", help="servir en HTTP clair")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--body", default='{"Output":{"__type":"ok"}}',
                    help="corps servi en 200 (fichier ou littéral)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dns-help", action="store_true")
    a = ap.parse_args()

    if a.dns_help:
        print("""Détournement DNS sur piveil (à ajouter à ~/fakeap/dnsmasq.conf) :
  address=/softwareupdates.amazon.com/192.168.50.1
  address=/updates.amazon.com/192.168.50.1
  address=/tp.ef6ac5c69-frontier.amazon.com/192.168.50.1
  address=/amzdigitaldownloads.edgesuite.net/192.168.50.1
  address=/d1fazkmcmqzwfk.cloudfront.net/192.168.50.1   # etc. pour chaque CDN vu
puis :  sudo pkill -HUP dnsmasq   (ou systemctl restart dnsmasq)
vérif :  dig +short softwareupdates.amazon.com @192.168.50.1   → 192.168.50.1""")
        return
    if a.make_cert:
        make_cert()
        return
    body = a.body
    if os.path.exists(body):
        body = open(body, "rb").read()
    if a.serve:
        serve(a.port, a.cert, a.key, body, a.plain, a.once)
        return
    ap.print_help()


if __name__ == "__main__":
    main()
