import socket, time, sys, datetime
HOST="192.168.1.24"; PORT=5541
def up():
    try:
        s=socket.create_connection((HOST,PORT),timeout=1.5); s.close(); return True
    except: return False
print(f"[{datetime.datetime.now():%H:%M:%S}] surveillance de {HOST}:{PORT} (reboot = coupure >8s)")
outages=0; last=up(); t0=time.time(); down_at=None
print(f"[{datetime.datetime.now():%H:%M:%S}] initial={'UP' if last else 'DOWN'}")
while time.time()-t0 < float(sys.argv[1] if len(sys.argv)>1 else 120):
    cur=up()
    if last and not cur:
        down_at=time.time(); print(f"[{datetime.datetime.now():%H:%M:%S}] ⚠️ COUPURE detectee")
    if not last and cur:
        d=time.time()-down_at
        print(f"[{datetime.datetime.now():%H:%M:%S}] ✅ RETOUR apres {d:.1f}s")
        if d>8: print(f"   ★★ REBOOT PROBABLE (coupure {d:.0f}s > 8s)"); outages+=1
    last=cur; time.sleep(1.5)
print(f"=== bilan : {outages} reboot(s) probable(s) ===")
