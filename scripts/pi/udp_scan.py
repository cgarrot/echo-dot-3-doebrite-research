#!/usr/bin/env python3
"""Scan UDP rapide de la plage 16384-32767 sur le device Echo."""
import socket, sys, time
from concurrent.futures import ThreadPoolExecutor

IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.25"
LO = int(sys.argv[2]) if len(sys.argv) > 2 else 16384
HI = int(sys.argv[3]) if len(sys.argv) > 3 else 32767

# Payload: un M-SEARCH SSDP minimal (certains services répondent à ça)
PAYLOAD = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"

def probe(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    try:
        s.sendto(PAYLOAD, (IP, port))
        try:
            data, addr = s.recvfrom(2048)
            return port, len(data), data[:40]
        except socket.timeout:
            # Un port UDP "ouvert" qui ne répond pas ne peut pas être distingué
            # d'un port fermé (ICMP type 3) — on regarde l'ICMP
            return None
        except ConnectionRefusedError:
            return None  # ICMP port unreachable = fermé
    except Exception:
        return None
    finally:
        s.close()

print(f"Scan UDP {LO}-{HI} sur {IP}...", flush=True)
hits = []
with ThreadPoolExecutor(max_workers=200) as ex:
    for r in ex.map(probe, range(LO, HI + 1)):
        if r:
            hits.append(r)
            print(f"  ★ UDP {r[0]}: {r[1]} o — {r[2].hex()[:60]}", flush=True)
if not hits:
    print("Aucun port UDP répondant (les ports UDP ouverts ne répondent pas forcément)")
