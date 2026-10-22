#!/usr/bin/env python3
import asyncio, random, sys, uuid as U
from bleak import BleakScanner, BleakClient
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"; REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"; CMD="cf011dfa-07ee-40b7-a71d-3f2eb6e0d040"
CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"; NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
CMDS=[("RETRIEVE_SUPPORTED_COMMANDS","22947d92-c4bb-47dc-9c00-23679575b5a5"),
      ("GET_DEVICE_DETAILS","bfae2d87-3937-42ec-8016-7ea13542c397"),
      ("GET_VISIBLE_NETWORKS","c95ec711-f36f-4cd9-9879-1fa22f7eb110"),
      ("GET_CONFIGURATION","dd7ad30e-4a09-4252-98c5-bc159f6bd2f2")]
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
    i=U.UUID(s).int
    return (i&0xFFFFFFFFFFFFFFFF).to_bytes(8,'little')+((i>>64)&0xFFFFFFFFFFFFFFFF).to_bytes(8,'little')
def pbb(f,d): return bytes([(f<<3)|2])+vi(len(d))+d
def pbi(f,v): return bytes([(f<<3)|0])+vi(v)
def pp(b):
    i=0;d={}
    try:
        while i<len(b):
            t,i=dv(b,i);fn,wt=t>>3,t&7
            if wt==0:
                v,i=dv(b,i);d[fn]=v
            elif wt==2:
                ln,i=dv(b,i)
                if i+ln>len(b): d[fn]=b[i:]; break
                d[fn]=b[i:i+ln];i+=ln
            elif wt==5: i+=4
            elif wt==1: i+=8
            else: break
    except Exception: pass
    return d
INB=[]
def mk(n):
    def cb(ch,data):
        INB.append((n,bytes(data))); print(f"   ★[{n}] {bytes(data).hex(' ')[:120]}",flush=True)
    return cb
async def wf(name,t=8):
    for _ in range(t*2):
        for k,(n,b) in enumerate(INB):
            if n==name: INB.pop(k); return b
        await asyncio.sleep(0.5)
    return None
async def read_all(c,ch,rounds=6):
    """lit la caracteristique, avec suite si additionalChunks"""
    out=bytearray(); last=None
    for r in range(rounds):
        try: raw=await c.read_gatt_char(ch)
        except Exception as e: print(f"      read ERR {e}",flush=True); break
        p=pp(bytes(raw))
        payload=p.get(4,b"")
        out+=payload
        print(f"      [read {r}] len={len(raw)} key={p.get(1)} chunk={p.get(2)} more={p.get(3)} paylen={len(payload)}",flush=True)
        if len(payload)>0: print(f"        pay={payload.hex(' ')[:180]}",flush=True)
        if not p.get(3): break
        # demande le chunk suivant
        nxt=pbi(1,p.get(1,0))+pbi(2,p.get(2,0))+pbi(3,1)+pbb(4,b"\x00")
        try: await c.write_gatt_char(ch,nxt,response=True)
        except Exception as e: print(f"      next ERR {e}",flush=True); break
        await asyncio.sleep(0.6)
    return bytes(out)
async def main():
    dev=None
    for r in range(25):
        found=await BleakScanner.discover(timeout=6,return_adv=True)
        for a,(d,ad) in found.items():
            if FE00 in [str(u).lower() for u in (ad.service_uuids or [])]:
                print(f"  ★ {a} {d.name!r} rssi={ad.rssi}",flush=True); dev=d; break
        if dev: break
    if not dev: print("ABANDON"); return
    async with BleakClient(dev,timeout=30) as c:
        print(f"  connecte={c.is_connected}",flush=True); _=c.services
        for ch,n in ((STA,"STATUS"),(RSP,"START_RSP"),(CRS,"CMD_RSP"),(NTF,"NOTIF")):
            try: await c.start_notify(ch,mk(n))
            except: pass
        await asyncio.sleep(0.6)
        await c.write_gatt_char(REQ,bytes([0x08])+vi(zz(random.randint(1,0x7FFFFFFF))),response=True)
        r=await wf("START_RSP",8)
        print(f"  START_RSP={r.hex(' ') if r else None}",flush=True)
        if not r or r[-1]!=0: print("NON ACCORDE"); return
        print("  ✅ GRANTED",flush=True)
        for name,u in CMDS:
            print(f"\n  → {name}",flush=True)
            p=pbi(1,random.getrandbits(31))+pbi(2,0)+pbi(3,0)+pbb(4,pbb(1,uuid_le(u)))
            try: await c.write_gatt_char(CMD,p,response=True)
            except Exception as e: print(f"    write: {e}",flush=True); continue
            await asyncio.sleep(1.5)
            data=await read_all(c,CRS)
            print(f"    TOTAL payload ({len(data)} o): {data.hex(' ')[:250]}",flush=True)
            await asyncio.sleep(0.5)
        print("\n=== FIN ===",flush=True)
asyncio.run(main())
