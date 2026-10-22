#!/usr/bin/env python3
"""WhisperJoin — correct protobuf encoding (SInt32 zigzag + varint)."""
import asyncio, random, sys
from bleak import BleakScanner, BleakClient
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"
REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"
CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"
NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"

def varint(n):
    n &= 0xFFFFFFFFFFFFFFFF
    out=bytearray()
    while True:
        b=n&0x7F; n>>=7
        out.append(b|0x80 if n else b)
        if not n: break
    return bytes(out)

def zigzag32(v):
    return (v << 1) ^ (v >> 31)

def dec_varint(b,i):
    r=0;s=0
    while True:
        x=b[i]; i+=1; r |= (x&0x7F)<<s; s+=7
        if not (x&0x80): break
    return r,i

def parse_resp(data):
    i=0; rid=None; st=None
    while i < len(data):
        try:
            tag,i = dec_varint(data,i)
        except Exception: break
        fn, wt = tag>>3, tag&7
        if wt==0:
            v,i = dec_varint(data,i)
            if fn==1: rid = (v>>1) ^ -(v&1)   # sint32 zigzag
            elif fn==2: st = (v>>1) ^ -(v&1)
        elif wt==2:
            ln,i = dec_varint(data,i); i+=ln
        else: break
    return rid, st

N=[]
def mk(n):
    def cb(ch,d):
        b=bytes(d); N.append((n,b))
        print(f"   ★[NOTIF {n}] {b.hex(' ')}", flush=True)
        if n=="START_RSP":
            rid,st=parse_resp(b)
            nm={0:"GRANTED ✓",1:"DENIED_ALREADY_PROVISIONING",2:"DENIED_INTERNAL_ERROR"}
            print(f"      → reqID={rid} status={st} ({nm.get(st,'?')})", flush=True)
    return cb

async def main():
    found=await BleakScanner.discover(timeout=30,return_adv=True)
    tgt=None
    for a,(d,ad) in found.items():
        if FE00 in [str(u).lower() for u in (ad.service_uuids or [])]:
            print(f"  ★ {a} {d.name!r} rssi={ad.rssi}"); tgt=tgt or d
    if not tgt: print("FE00 absent"); return
    async with BleakClient(tgt,timeout=30) as c:
        print(f"  connecte={c.is_connected}")
        for ch,n in ((STA,"STATUS"),(RSP,"START_RSP"),(CRS,"CMD_RSP"),(NTF,"NOTIF")):
            try: await c.start_notify(ch,mk(n))
            except Exception as e: print(f"  notify {n}: {e}")
        await asyncio.sleep(1)
        rid=random.randint(1,0x7FFFFFFF)
        payload=bytes([0x08])+varint(zigzag32(rid))
        print(f"  → envoi requestId={rid} payload={payload.hex(' ')}")
        await c.write_gatt_char(REQ,payload,response=True)
        for i in range(20):
            await asyncio.sleep(1)
            if any(n=="START_RSP" for n,_ in N): break
        print(f"  === notifications: {len(N)} ===")
asyncio.run(main())
