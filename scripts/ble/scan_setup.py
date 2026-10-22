import socket, concurrent.futures
H="10.201.126.241"
def p(port):
    try:
        s=socket.create_connection((H,port),timeout=1.5); s.close(); return port
    except: return None
open_p=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=300) as ex:
    for r in ex.map(p, range(1,65536)):
        if r: open_p.append(r)
print("PORTS OUVERTS EN MODE SETUP:", open_p)
