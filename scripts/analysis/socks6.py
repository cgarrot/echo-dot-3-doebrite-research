import socket, struct
H=("192.168.1.24",1080)
def conn(atyp, addr, port):
    s=socket.create_connection(H,timeout=6); s.settimeout(5)
    s.sendall(b"\x05\x01\x00"); g=s.recv(2)
    if atyp==1: req=b"\x05\x01\x00\x01"+socket.inet_aton(addr)
    elif atyp==3: req=b"\x05\x01\x00\x03"+bytes([len(addr)])+addr.encode()
    else: req=b"\x05\x01\x00\x04"+socket.inet_pton(socket.AF_INET6,addr)
    s.sendall(req+struct.pack(">H",port))
    try: r=s.recv(16)
    except socket.timeout: r=b"<TO>"
    s.close(); return g,r

tests=[("api.amazon.com",443,1),("api.amazon.com",443,3),
       ("avs-alexa-na.amazon.com",443,1),("amazon.com",80,1),
       ("192.168.1.24",443,1),("10.201.126.241",8080,1),
       ("127.0.0.1",1,1),("8.8.8.8",53,1)]
for a,p,t in tests:
    try:
        g,r=conn(t,a,p)
        code=r[1] if len(r)>1 else -1
        print(f"  {a}:{p} (atyp={t}) → greeting={g.hex(' ')} reply={r.hex(' ')} code={code}"[:110])
    except Exception as e: print(f"  {a}:{p} → ERR {e}")
