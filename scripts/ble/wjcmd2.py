#!/usr/bin/env python3
import asyncio, random, sys, uuid as U
from bleak import BleakScanner, BleakClient
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"; REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"; CMD="cf011dfa-07ee-40b7-a71d-3f2eb6e0d040"
CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"; NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
CMDS={
 "GET_DEVICE_DETAILS":"bfae2d87-3937-42ec-8016-7ea13542c397",
 "RETRIEVE_SUPPORTED_COMMANDS":"22947d92-c4bb-47dc-9c00-23679575b5a5",
 "RETRIEVE_SUPPORTED_EVENTS":"22947d93-c4bb-47dc-9c00-23679575b5a5",
 "GET_VISIBLE_NETWORKS":"c95ec711-f36f-4cd9-9879-1fa22f7eb110",
 "INITIATE_VISIBLE_NETWORK_SCAN":"c95ec710-f36f-4cd9-9879-1fa22f7eb110",
 "GET_CONFIGURATION":"dd7ad30e-4a09-4252-98c5-bc159f6bd2f2",
 "UNAUTHENTICATED_ECDHE":"cc6ad206-b8a2-4710-bf23-e9d7ae3e2d0b",
 "AUTHENTICATED_ECDHE":"2caff8db-7767-448c-b12b-eac29589e12b",
}
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
    u=U.UUID(s);return u.least_significant_bits.to_bytes(8,'little')+u.most_significant_bits.to_bytes(8,'little')
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
NOT=[]
def mk(n):
    def cb(ch,data):
        b=bytes(data);NOT.append((n,b));print(f"   ★[{n}] {b.hex(' ')[:170]}",flush=True)
        if n=="CMD_RSP" and len(b)>0:
            p=pp(b)
            if 4 in p:
                print(f"      payload={p[4].hex(' ')[:200]}",flush=True)
                ip=pp(p[4])
                for k,v in ip.items():
                    print(f"        f{k}: {v.hex(' ') if isinstance(v,bytes) else v}",flush=True)
    return cb

async def session(dev,cmdname):
    def disc(c): print(f"   [deconnecte]",flush=True)
    async with BleakClient(dev,timeout=30,disconnected_callback=disc) as c:
        if not c.is_connected: print("  pas connecte",flush=True); return False
        await asyncio.sleep(1.5)
        try: await c.get_services()
        except Exception as e: print(f"  discovery: {e}",flush=True); return False
        print(f"  services OK, connecte={c.is_connected}",flush=True)
        for ch,n in ((STA,"STATUS"),(RSP,"START_RSP"),(CRS,"CMD_RSP"),(NTF,"NOTIF")):
            try: await c.start_notify(ch,mk(n))
            except Exception as e: print(f"  notify {n}: {e}",flush=True)
        await asyncio.sleep(1.2)
        rid=random.randint(1,0x7FFFFFFF)
        try:
            await c.write_gatt_char(REQ,bytes([0x08])+vi(zz(rid)),response=True)
        except Exception as e:
            print(f"  START write: {e}",flush=True); return False
        print(f"  → START rid={rid}",flush=True)
        for i in range(10):
            await asyncio.sleep(1)
            if any(n=="START_RSP" for n,_ in NOT): break
        g=any(n=="START_RSP" and len(b)>=2 and b[-1]==0 for n,b in NOT)
        print(f"  granted={g}",flush=True)
        if not g: return False
        uu=uuid_le(CMDS[cmdname]); inner=pbb(1,uu); p=pkt(inner)
        print(f"  → CMD {cmdname}",flush=True)
        print(f"    inner={inner.hex(' ')}",flush=True)
        print(f"    packet={p.hex(' ')}",flush=True)
        try: await c.write_gatt_char(CMD,p,response=True)
        except Exception as e: print(f"  CMD write: {e}",flush=True); return False
        for i in range(18):
            await asyncio.sleep(1)
            if any(n=="CMD_RSP" for n,_ in NOT): break
        print(f"  === notifs: {len(NOT)} ===",flush=True)
        return True

async def main():
    cmd=sys.argv[1] if len(sys.argv)>1 else "GET_DEVICE_DETAILS"
    for attempt in range(6):
        print(f"--- tentative {attempt+1} ---",flush=True)
        dev=None
        found=await BleakScanner.discover(timeout=8,return_adv=True)
        for a,(d,ad) in found.items():
            if FE00 in [str(u).lower() for u in (ad.service_uuids or [])]:
                print(f"  ★ {a} {d.name!r} rssi={ad.rssi}",flush=True); dev=d; break
        if not dev:
            print("  FE00 absent, nouvelle passe",flush=True); continue
        try:
            if await session(dev,cmd): return
        except Exception as e:
            print(f"  erreur: {type(e).__name__}: {e}",flush=True)
        NOT.clear(); await asyncio.sleep(2)
asyncio.run(main())
