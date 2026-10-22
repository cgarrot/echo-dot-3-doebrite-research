#!/usr/bin/env python3
import asyncio, random
from bleak import BleakScanner, BleakClient
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"; REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"; CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"
NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
def varint(n):
    n&=0xFFFFFFFFFFFFFFFF; o=bytearray()
    while True:
        b=n&0x7F; n>>=7; o.append(b|0x80 if n else b)
        if not n: break
    return bytes(o)
def zz(v): return (v<<1)^(v>>31)
def dv(b,i):
    r=0;s=0
    while True:
        x=b[i];i+=1;r|=(x&0x7F)<<s;s+=7
        if not(x&0x80):break
    return r,i
def prs(d):
    i=0;rid=st=None
    while i<len(d):
        try: t,i=dv(d,i)
        except: break
        fn,wt=t>>3,t&7
        if wt==0:
            v,i=dv(d,i)
            if fn==1: rid=(v>>1)^-(v&1)
            elif fn==2: st=(v>>1)^-(v&1)
        elif wt==2:
            ln,i=dv(d,i); i+=ln
        else: break
    return rid,st
N=[]
def mk(n):
    def cb(ch,d):
        b=bytes(d); N.append((n,b)); print(f"   ★[{n}] {b.hex(' ')}",flush=True)
        if n=="START_RSP":
            rid,st=prs(b); nm={0:"GRANTED",1:"DENIED_ALREADY",2:"DENIED_ERROR"}
            print(f"      → reqID={rid} status={st} ({nm.get(st,'?')})",flush=True)
    return cb
async def attempt(dev):
    async with BleakClient(dev,timeout=25) as c:
        print(f"  connecte={c.is_connected}",flush=True)
        for ch,n in ((STA,"STATUS"),(RSP,"START_RSP"),(CRS,"CMD_RSP"),(NTF,"NOTIF")):
            try: await c.start_notify(ch,mk(n))
            except Exception as e: print(f"  notify {n}: {e}",flush=True)
        await asyncio.sleep(1)
        rid=random.randint(1,0x7FFFFFFF)
        p=bytes([0x08])+varint(zz(rid))
        print(f"  → requestId={rid} payload={p.hex(' ')}",flush=True)
        await c.write_gatt_char(REQ,p,response=True)
        for i in range(25):
            await asyncio.sleep(1)
            if any(n=="START_RSP" for n,_ in N): break
        print(f"  === notifs: {len(N)} ===",flush=True)
        return bool(N)
async def main():
    for r in range(12):
        print(f"[passe {r}] scan 10s...",flush=True)
        found=await BleakScanner.discover(timeout=10,return_adv=True)
        for a,(d,ad) in found.items():
            if FE00 in [str(u).lower() for u in (ad.service_uuids or [])]:
                print(f"  ★★★ {a} {d.name!r} rssi={ad.rssi}",flush=True)
                try:
                    if await attempt(d): return
                except Exception as e: print(f"  connexion: {type(e).__name__}: {e}",flush=True)
    print("non trouve apres 12 passes",flush=True)
asyncio.run(main())
