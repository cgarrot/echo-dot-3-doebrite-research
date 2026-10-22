#!/usr/bin/env python3
import asyncio, struct, random, sys
from bleak import BleakClient
ADDR=sys.argv[1] if len(sys.argv)>1 else "4C:2C:F7:73:56:24"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"; REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"; CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"
NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
N=[]
def mk(n):
    def cb(ch,d): N.append((n,bytes(d))); print(f"   ★[NOTIF {n}] {d.hex(' ')}")
    return cb
async def main():
    print(f"=== connexion directe a {ADDR} ===")
    try:
        async with BleakClient(ADDR, timeout=25) as c:
            print(f"  connecte={c.is_connected}")
            for ch,n in ((STA,"STATUS"),(RSP,"START_RSP"),(CRS,"CMD_RSP"),(NTF,"NOTIF")):
                try: await c.start_notify(ch,mk(n)); print(f"  notify {n}")
                except Exception as e: print(f"  notify {n}: {e}")
            await asyncio.sleep(1.5)
            try:
                v=await c.read_gatt_char(STA); print(f"  STATUS = {v.hex(' ')} len={len(v)}")
            except Exception as e: print(f"  STATUS: {e}")
            for i in range(8):
                await asyncio.sleep(1)
                if N: break
            print(f"  === notifications recues: {len(N)} ===")
            for n,d in N:
                print(f"     {n}: {d.hex(' ')}")
                if n=="START_RSP" and len(d)>=5:
                    st=d[4]; nm={0:"GRANTED",1:"DENIED_ALREADY_PROVISIONING",2:"DENIED_INTERNAL_ERROR"}
                    print(f"        reqID={struct.unpack('<I',d[:4])[0]:#x} status={st} → {nm.get(st,'?')}")
    except Exception as e:
        print(f"  ECHEC: {type(e).__name__}: {e}")
asyncio.run(main())
