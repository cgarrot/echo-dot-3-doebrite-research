#!/usr/bin/env python3
import asyncio, struct, random, sys
from bleak import BleakScanner, BleakClient
FE00="0000fe00-0000-1000-8000-00805f9b34fb"
STA="cf011df7-07ee-40b7-a71d-3f2eb6e0d040"
REQ="cf011df8-07ee-40b7-a71d-3f2eb6e0d040"
RSP="cf011df9-07ee-40b7-a71d-3f2eb6e0d040"
CMD="cf011dfa-07ee-40b7-a71d-3f2eb6e0d040"
CRS="cf011dfb-07ee-40b7-a71d-3f2eb6e0d040"
NTF="cf011dfc-07ee-40b7-a71d-3f2eb6e0d040"
NAME="00002a00-0000-1000-8000-00805f9b34fb"

async def run(addr):
    print(f"=== {addr} ===")
    def on_notif(ch, data): print(f"   [NOTIF {str(ch.uuid).lower()[:8]}] {data.hex(' ')}  {data!r}")
    async with BleakClient(addr, timeout=30) as c:
        print(f"  connecte={c.is_connected}")
        for s in c.services:
            if str(s.uuid).lower()=="00001800-0000-1000-8000-00805f9b34fb":
                try:
                    n=await c.read_gatt_char(NAME); print(f"  ★ NOM DE L APPAREIL = {n.decode(errors='replace')!r}")
                except Exception as e: print(f"  nom: {e}")
        # abonnement AVANT tout
        for ch in (STA,RSP,CRS,NTF):
            try:
                await c.start_notify(ch, on_notif); print(f"  notify ON {ch[:8]}")
            except Exception as e: print(f"  notify {ch[:8]}: {e}")
        await asyncio.sleep(1)
        try:
            v=await c.read_gatt_char(STA); print(f"  STATUS = {v.hex(' ')}")
        except Exception as e: print(f"  STATUS: {e}")
        rid=random.getrandbits(32)
        try:
            await c.write_gatt_char(REQ, struct.pack("<I",rid), response=True)
            print(f"  START_REQ ecrit: {rid:#x}")
        except Exception as e:
            print(f"  START_REQ: {e}")
        await asyncio.sleep(3)
        try:
            v=await c.read_gatt_char(RSP); print(f"  START_RSP = {v.hex(' ')}")
            if len(v)>=5:
                st=v[4]; nm={0:"GRANTED",1:"DENIED_ALREADY_PROVISIONING",2:"DENIED_INTERNAL_ERROR"}
                print(f"     → reqID={struct.unpack('<I',v[:4])[0]:#x} status={st} ({nm.get(st,'?')})")
        except Exception as e: print(f"  START_RSP: {e}")
        await asyncio.sleep(2)

asyncio.run(run(sys.argv[1]))
