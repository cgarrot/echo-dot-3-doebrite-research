#!/usr/bin/env python3
import asyncio, struct, random
from bleak import BleakScanner, BleakClient
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"
REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"
CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"
NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
NOTIFS=[]
def mk(name):
    def cb(ch,data):
        NOTIFS.append((name,bytes(data)))
        print(f"   ★ [NOTIF {name}] {data.hex(' ')}  len={len(data)}")
    return cb
async def main():
    found=await BleakScanner.discover(timeout=30,return_adv=True)
    tgt=None
    for a,(d,ad) in found.items():
        if FE00 in [str(u).lower() for u in (ad.service_uuids or [])]:
            print(f"  ★ {a} {d.name!r} rssi={ad.rssi}"); tgt=d if tgt is None else tgt
    if not tgt: print("FE00 absent"); return
    async with BleakClient(tgt,timeout=30) as c:
        print(f"  connecte={c.is_connected}")
        await c.start_notify(STA,mk("STATUS"))
        await c.start_notify(RSP,mk("START_RSP"))
        await c.start_notify(CRS,mk("CMD_RSP"))
        await c.start_notify(NTF,mk("NOTIF"))
        print("  abonnements OK")
        await asyncio.sleep(1)
        rid=random.getrandbits(32)
        await c.write_gatt_char(REQ,struct.pack("<I",rid),response=True)
        print(f"  → START_REQ ecrit rid={rid:#x} ({struct.pack('<I',rid).hex(' ')})")
        for i in range(20):
            await asyncio.sleep(1)
            if any(n=="START_RSP" for n,_ in NOTIFS): break
        print(f"  === total notifications: {len(NOTIFS)} ===")
        for n,d in NOTIFS:
            print(f"     {n}: {d.hex(' ')}")
            if n=="START_RSP" and len(d)>=5:
                st=d[4]; nm={0:"GRANTED",1:"DENIED_ALREADY_PROVISIONING",2:"DENIED_INTERNAL_ERROR"}
                print(f"        reqID={struct.unpack('<I',d[:4])[0]:#x} status={st} → {nm.get(st,'?')}")
        try:
            v=await c.read_gatt_char(STA); print(f"  STATUS final = {v.hex(' ')}")
        except Exception as e: print(f"  STATUS: {e}")
asyncio.run(main())
