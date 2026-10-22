#!/usr/bin/env python3
import asyncio, random, sys, uuid as U
from bleak import BleakScanner, BleakClient
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"; REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"; CMD="cf011dfa-07ee-40b7-a71d-3f2eb6e0d040"
CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"; NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
T=[
 ("RETRIEVE_SUPPORTED_COMMANDS","22947d92-c4bb-47dc-9c00-23679575b5a5"),
 ("RETRIEVE_SUPPORTED_EVENTS","22947d93-c4bb-47dc-9c00-23679575b5a5"),
 ("RETRIEVE_EVENT_OBJECT","22947d94-c4bb-47dc-9c00-23679575b5a5"),
 ("STOP_PROVISIONING","22947d95-c4bb-47dc-9c00-23679575b5a5"),
 ("PROVISIONING_COMPLETE","6cd1d7e1-c37b-46d7-b268-635186f9aca1"),
 ("INITIATE_VISIBLE_NETWORK_SCAN","c95ec710-f36f-4cd9-9879-1fa22f7eb110"),
 ("GET_VISIBLE_NETWORKS","c95ec711-f36f-4cd9-9879-1fa22f7eb110"),
 ("SAVE_CONFIGURED_NETWORK","c95ec713-f36f-4cd9-9879-1fa22f7eb110"),
 ("CONNECT_TO_CONFIGURED_NETWORK","c95ec714-f36f-4cd9-9879-1fa22f7eb110"),
 ("DELETE_CONFIGURED_NETWORK","c95ec715-f36f-4cd9-9879-1fa22f7eb110"),
 ("DELETE_ALL_CONFIGURED_NETWORKS","c95ec716-f36f-4cd9-9879-1fa22f7eb110"),
 ("REFRESH_WIFI_CONNECTION","c95ec717-f36f-4cd9-9879-1fa22f7eb110"),
 ("GET_DEVICE_DETAILS","bfae2d87-3937-42ec-8016-7ea13542c397"),
 ("GET_CONFIGURATION","dd7ad30e-4a09-4252-98c5-bc159f6bd2f2"),
 ("SET_CONFIGURATION","ac796df3-dd27-4459-a753-44efb4a9f195"),
 ("DELETE_CONFIGURATION","f8747782-c7e8-4314-a086-aee78ad8b0e7"),
 ("DELETE_CONFIGURATION_SET","93fd9191-8382-4c10-aedf-6092c6154651"),
]
STR={0:"SUCCESS",1:"internal error",2:"UNKNOWN COMMAND",3:"serialization error",
     4:"packet verification error",5:"UNAUTHORIZED PROVISIONER",
     -10:"specific -10",-11:"specific -11",-12:"-12",-13:"-13",-14:"-14"}
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
def pp(b,zig=False):
    i=0;d={}
    try:
        while i<len(b):
            t,i=dv(b,i);fn,wt=t>>3,t&7
            if wt==0:
                v,i=dv(b,i); d[fn]=zz(v) if zig else v
            elif wt==2:
                ln,i=dv(b,i)
                if i+ln>len(b): d[fn]=b[i:];break
                d[fn]=b[i:i+ln];i+=ln
            elif wt==5: i+=4
            elif wt==1: i+=8
            else: break
    except Exception: pass
    return d
INB=[]
def mk(n):
    def cb(ch,data): INB.append((n,bytes(data)))
    return cb
async def wf(name,t=10):
    for _ in range(t*2):
        for k,(n,b) in enumerate(INB):
            if n==name: INB.pop(k); return b
        await asyncio.sleep(0.5)
    return None
async def rd(c,ch,rounds=6):
    out=bytearray()
    for r in range(rounds):
        try: raw=bytes(await c.read_gatt_char(ch))
        except Exception as e: return out,b"ERR"
        p=pp(raw); pl=p.get(4,b""); out+=pl
        if not p.get(3): break
        nxt=pbi(1,p.get(1,0))+pbi(2,p.get(2,0))+pbi(3,1)+pbb(4,b"\x00")
        try: await c.write_gatt_char(ch,nxt,response=True)
        except: break
        await asyncio.sleep(0.4)
    return bytes(out),b""
async def main():
    dev=None
    for r in range(25):
        f=await BleakScanner.discover(timeout=6,return_adv=True)
        for a,(d,ad) in f.items():
            if FE00 in [str(u).lower() for u in (ad.service_uuids or [])]:
                print(f"  ★ {a} {d.name!r}",flush=True); dev=d; break
        if dev: break
    if not dev: print("ABANDON"); return
    async with BleakClient(dev,timeout=30) as c:
        _=c.services
        for ch,n in ((STA,"STATUS"),(RSP,"START_RSP"),(CRS,"CMD_RSP"),(NTF,"NOTIF")):
            try: await c.start_notify(ch,mk(n))
            except: pass
        await asyncio.sleep(0.6)
        await c.write_gatt_char(REQ,bytes([0x08])+vi(zz(random.randint(1,0x7FFFFFFF))),response=True)
        r=await wf("START_RSP",8)
        if not r or r[-1]!=0: print("NON ACCORDE",r); return
        print("  ✅ GRANTED\n",flush=True)
        print(f"{'COMMANDE':36} {'STATUT':30} DATA",flush=True)
        print("-"*95,flush=True)
        for name,u in T:
            p=pbi(1,random.getrandbits(31))+pbi(2,0)+pbi(3,0)+pbb(4,pbb(1,uuid_le(u)))
            try: await c.write_gatt_char(CMD,p,response=True)
            except Exception as e: print(f"{name:36} WRITE-ERR {e}",flush=True); continue
            await asyncio.sleep(1.2)
            out,err=await rd(c,CRS)
            d=pp(out,zig=True) if out else {}
            st=d.get(2); data=d.get(3,b"")
            lab=STR.get(st,f"?{st}")
            print(f"{name:36} {st:>4} {lab:26} {data.hex(' ')[:40] if isinstance(data,bytes) else data}",flush=True)
            await asyncio.sleep(0.3)
        print("\n=== FIN ===",flush=True)
asyncio.run(main())
