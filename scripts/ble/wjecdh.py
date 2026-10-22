#!/usr/bin/env python3
import asyncio, random, sys, uuid as U
from bleak import BleakScanner, BleakClient
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"; REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"; CMD="cf011dfa-07ee-40b7-a71d-3f2eb6e0d040"
CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"; NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
UECDHE="cc6ad206-b8a2-4710-bf23-e9d7ae3e2d0b"
GETDET="bfae2d87-3937-42ec-8016-7ea13542c397"
GETNET="c95ec711-f36f-4cd9-9879-1fa22f7eb110"
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
            if wt==0: v,i=dv(b,i);d[fn]=v
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
    def cb(ch,data):
        INB.append((n,bytes(data))); print(f"   ★[{n}] {bytes(data).hex(' ')[:100]}",flush=True)
    return cb
async def wf(name,t=8):
    for _ in range(t*2):
        for k,(n,b) in enumerate(INB):
            if n==name: INB.pop(k); return b
        await asyncio.sleep(0.5)
    return None
async def rd(c,ch,rounds=8):
    out=bytearray()
    for r in range(rounds):
        try: raw=bytes(await c.read_gatt_char(ch))
        except Exception as e: print(f"      read ERR {e}",flush=True); break
        p=pp(raw); pl=p.get(4,b""); out+=pl
        print(f"      [rd{r}] key={p.get(1)} more={p.get(3)} len={len(pl)}",flush=True)
        if pl: print(f"        {pl.hex(' ')[:200]}",flush=True)
        if not p.get(3): break
        nxt=pbi(1,p.get(1,0))+pbi(2,p.get(2,0))+pbi(3,1)+pbb(4,b"\x00")
        try: await c.write_gatt_char(ch,nxt,response=True)
        except Exception as e: print(f"      nxt ERR {e}",flush=True); break
        await asyncio.sleep(0.5)
    return bytes(out)
async def main():
    dev=None
    for r in range(25):
        f=await BleakScanner.discover(timeout=6,return_adv=True)
        for a,(d,ad) in f.items():
            if FE00 in [str(u).lower() for u in (ad.service_uuids or [])]:
                print(f"  ★ {a} {d.name!r} rssi={ad.rssi}",flush=True); dev=d; break
        if dev: break
    if not dev: print("ABANDON"); return
    # cle ECDHE P-256
    priv=ec.generate_private_key(ec.SECP256R1())
    der=priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    print(f"  notre cle ECDHE: {len(der)} o DER",flush=True)
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
        # --- ECDHE non authentifie ---
        print("\n  → UNAUTHENTICATED_ECDHE",flush=True)
        # ProvisioningCommand{uuid=UECDHE, data=UnauthEcdheRequest{derECDHEPublicKey=1}}
        data=pbb(1,der)
        cmd=pbb(1,uuid_le(UECDHE))+pbb(2,data)
        p=pbi(1,random.getrandbits(31))+pbi(2,0)+pbi(3,0)+pbb(4,cmd)
        print(f"    tx={p.hex(' ')[:120]}",flush=True)
        await c.write_gatt_char(CMD,p,response=True)
        await asyncio.sleep(2)
        out=await rd(c,CRS)
        print(f"    ECDHE resp ({len(out)} o): {out.hex(' ')[:220]}",flush=True)
        f2=pp(out)
        for k,v in f2.items():
            print(f"      f{k}: {v.hex(' ')[:120] if isinstance(v,bytes) else v}",flush=True)
        # extrait la cle publique du device si presente
        devkey=None
        for k,v in f2.items():
            if isinstance(v,bytes) and v.startswith(b'\x30'):
                devkey=v; break
        if devkey:
            print(f"\n  ★ cle device trouvee ({len(devkey)} o)",flush=True)
            try:
                pub=serialization.load_der_public_key(devkey)
                shared=priv.exchange(ec.ECDH(),pub)
                print(f"  ★★ secret partage = {shared.hex()}",flush=True)
                aeskey=shared[:16]
                print(f"  ★★★ CLE AES-128 = {aeskey.hex()}",flush=True)
            except Exception as e: print(f"  echange: {e}",flush=True)
        else:
            print("  (pas de cle device dans la reponse)",flush=True)
        # --- retente GET_DEVICE_DETAILS ---
        print("\n  → GET_DEVICE_DETAILS (apres ECDHE)",flush=True)
        cmd=pbb(1,uuid_le(GETDET))
        p=pbi(1,random.getrandbits(31))+pbi(2,0)+pbi(3,0)+pbb(4,cmd)
        await c.write_gatt_char(CMD,p,response=True)
        await asyncio.sleep(2)
        out2=await rd(c,CRS)
        print(f"    resp ({len(out2)} o): {out2.hex(' ')[:250]}",flush=True)
        print("\n=== FIN ===",flush=True)
asyncio.run(main())
