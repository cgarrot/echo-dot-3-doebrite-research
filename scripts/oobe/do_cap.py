#!/usr/bin/env python3
"""connectToAP avec parametres valides (JSON COMPACT) — la transition de l'experience 1.5"""
import json, subprocess, urllib.request, sys
DEV="10.201.126.241"
def post(payload):
    req=urllib.request.Request(f"http://{DEV}:8080/OOBE",
        data=json.dumps(payload,separators=(',',':')).encode(),
        headers={"Content-Type":"application/x-thrift"})
    return urllib.request.urlopen(req,timeout=25).read()
# 1. cert frais
d=json.loads(post([1,"getDeviceDetails",1,1,{}]))
cert=d[4]['0']['rec']['5']['rec']['1']['str']
open("/tmp/c15.pem","w").write(cert)
# 2. chiffrer le mot de passe avec le cert du device
enc=subprocess.run(["openssl","smime","-encrypt","-aes256","-binary","-outform","PEM",
                    "/tmp/c15.pem"], input=b"testing1234", capture_output=True).stdout.decode()
# 3. connectToAP en COMPACT
p=[1,"connectToAP",1,1,{"1":{"rec":{"1":{"str":"TEST"},"2":{"i32":3},"3":{"rec":{"1":{"str":enc}}}}}}]
r=post(p)
print(r[:200].decode(errors="replace"))
