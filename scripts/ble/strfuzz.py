import socket, time, urllib.request, urllib.error
DEV="10.201.126.241"
def send(body, tmo=30):
    r=urllib.request.Request(f"http://{DEV}:8080/OOBE", data=body,
        headers={"Content-Type":"application/x-thrift"})
    try:
        return 200, urllib.request.urlopen(r,timeout=tmo).read()[:100]
    except urllib.error.HTTPError as e: return e.code, e.read()[:120]
    except Exception as e: return -1, type(e).__name__.encode()
def alive():
    try: s=socket.create_connection((DEV,8080),timeout=4); s.close(); return True
    except: return False
def run(name, body):
    st,b=send(body); ok=alive()
    print(f"{name:34} len={len(body):8} -> {st!s:5} alive={ok}  {b[:60]!r}")
    return ok
print("baseline:", alive())
tests=[]
for n in [1024, 65536, 262144, 1048576]:
    tests.append((f"str simple {n}", b"[1,\"ping\",1,1,{\"0\":{\"str\":\"" + b"A"*n + b"\"}}]"))
for n in [1024, 65536, 262144]:
    tests.append((f"utf8 invalide {n}", b"[1,\"ping\",1,1,{\"0\":{\"str\":\"" + b"\\xff\\xfe"*(n//8) + b"\"}}]"))
tests.append(("surrogates isoles", b"[1,\"ping\",1,1,{\"0\":{\"str\":\"" + b"\\ud800"*2000 + b"\"}}]"))
tests.append(("echappements profonds", b"[1,\"ping\",1,1,{\"0\":{\"str\":\"" + b"\\\\"*50000 + b"\"}}]"))
tests.append(("nombre enorme", b"[1,\"ping\",1,1,{\"0\":{\"i64\":1" + b"0"*5000 + b"}}]"))
for name,body in tests:
    if not run(name, body):
        print(f"  ★★★ MORT: {name}"); break
    time.sleep(0.5)
