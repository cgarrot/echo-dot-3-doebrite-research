#!/usr/bin/env python3
"""ONE-SHOT: START + all commands in a single BLE connection."""
import asyncio, random, sys, uuid as U
from bleak import BleakScanner, BleakClient
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"; REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"; CMD="cf011dfa-07ee-40b7-a71d-3f2eb6e0d040"
CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"; NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
CMDS=[
 ("RETRIEVE_SUPPORTED_COMMANDS","22947d92-c4bb-47dc-9c00-23679575b5a5"),
 ("GET_DEVICE_DETAILS","bfae2d87-3937-42ec-8016-7ea13542c397"),
 ("RETRIEVE_SUPPORTED_EVENTS","22947d93-c4bb-47dc-9c00-23679575b5a5"),
 ("GET_VISIBLE_NETWORKS","c95ec711-f36f-4cd9-9879-1fa22f7eb110"),
 ("GET_CONFIGURATION","dd7ad30e-4a09-4252-98c5-bc159f6bd2f2"),
]
def vi(n):
    n&=0xFFFFFFFFFFFFFFFF;o=bytearray()
    while True:
        b=n&0x7F;n>>=7;o.append(b|0x80 if n else b)
        if not n:break
    return bytes(o)
def zz(v): return (v<<1)^(v>>31)
def dv(b,i):
    r=0;s=0
    while True:
        x=b[i];i+=1;r|=(x&0x7F)<<s;s+=7
        if not(x&0x80):break
    return r,i
def uuid_le(s):
    u=U.UUID(s); i=u.int
    return (i & 0xFFFFFFFFFFFFFFFF).to_bytes(8,"little") + ((i >> 64) & 0xFFFFFFFFFFFFFFFF).to_bytes(8,"little")
def pbb(f,d): return bytes([(f<<3)|2])+vi(len(d))+d
def pbi(f,v): return bytes([(f<<3)|0])+vi(v)
def pkt(payload,key=None):
    if key is None: key=random.getrandbits(31)
    return pbi(1,key)+pbi(2,0)+pbi(3,0)+pbb(4,payload)
def pp(b):
    i=0;d={}
    while i<len(b):
        try:t,i=dv(b,i)
        except:break
        fn,wt=t>>3,t&7
        if wt==0:
            v,i=dv(b,i);d[fn]=v
        elif wt==2:
            ln,i=dv(b,i);d[fn]=b[i:i+ln];i+=ln
        else:break
    return d
INBOX=[]
def mk(n):
    def cb(ch,data):
        INBOX.append((n,bytes(data)))
        print(f"   ★[{n}] {bytes(data).hex(' ')[:160]}",flush=True)
    return cb
async def wait_for(name,timeout):
    for i in range(timeout*2):
        for k,(n,b) in enumerate(INBOX):
            if n==name:
                INBOX.pop(k); return b
        await asyncio.sleep(0.5)
    return None
async def main():
    print("=== scan ===",flush=True)
    dev=None
    for r in range(20):
        found=await BleakScanner.discover(timeout=6,return_adv=True)
        for a,(d,ad) in found.items():
            if FE00 in [str(u).lower() for u in (ad.service_uuids or [])]:
                print(f"  ★ {a} {d.name!r} rssi={ad.rssi}",flush=True); dev=d; break
        if dev: break
        print(f"  passe {r}",flush=True)
    if not dev: print("ABANDON: FE00 absent"); return
    async with BleakClient(dev,timeout=30) as c:
        print(f"  connecte={c.is_connected}",flush=True)
        _ = c.services  # trigger discovery
        for ch,n in ((STA,"STATUS"),(RSP,"START_RSP"),(CRS,"CMD_RSP"),(NTF,"NOTIF")):
            await c.start_notify(ch,mk(n))
        print("  abonnements OK",flush=True)
        await asyncio.sleep(0.8)
        rid=random.randint(1,0x7FFFFFFF)
        await c.write_gatt_char(REQ,bytes([0x08])+vi(zz(rid)),response=True)
        r=await wait_for("START_RSP",8)
        print(f"  START_RSP={r.hex(' ') if r else None}",flush=True)
        if not r or r[-1]!=0: print("NON ACCORDE"); return
        print("  ✅ GRANTED — envoi des commandes",flush=True)
        for name,u in CMDS:
            inner=pbb(1,uuid_le(u))
            p=pkt(inner)
            print(f"\n  → {name}",flush=True)
            print(f"    bytes={p.hex(' ')}",flush=True)
            try:
                await c.write_gatt_char(CMD,p,response=True)
            except Exception as e:
                print(f"    write: {e}",flush=True); continue
            rsp=await wait_for("CMD_RSP",12)
            if rsp:
                print(f"    RSP={rsp.hex(' ')}",flush=True)
                p2=pp(rsp)
                if 4 in p2:
                    inner2=p2[4]; print(f"    payload={inner2.hex(' ')}",flush=True)
                    f=pp(inner2)
                    for k,v in f.items():
                        print(f"      f{k}: {v.hex(' ') if isinstance(v,bytes) else v}",flush=True)
            else:
                print("    (pas de reponse)",flush=True)
            await asyncio.sleep(0.5)
        print("\n=== FIN ===",flush=True)
asyncio.run(main())
