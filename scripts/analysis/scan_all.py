import socket, concurrent.futures, sys
HOST="192.168.1.24"
def probe(p):
    try:
        s=socket.create_connection((HOST,p),timeout=1.2); s.close(); return p
    except: return None
print("=== balayage 1-65535 de l Echo (TCP) ===")
open_ports=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=400) as ex:
    for r in ex.map(probe, range(1,65536)):
        if r: open_ports.append(r)
print(f"OUVERTS ({len(open_ports)}) : {open_ports}")
