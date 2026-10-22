import socket, struct
H=("192.168.1.24",1080)
def full_connect(ip, port):
    s=socket.create_connection(H,timeout=8); s.settimeout(6)
    s.sendall(b"\x05\x01\x00")
    g=s.recv(2); 
    s.sendall(b"\x05\x01\x00\x01"+socket.inet_aton(ip)+struct.pack(">H",port))
    data=b""
    try:
        while True:
            d=s.recv(64)
            if not d: break
            data+=d
            if len(data)>=10: break
    except socket.timeout: data+=b"<TO>"
    s.close()
    return g, data

for ip,p in [("127.0.0.1",7802),("127.0.0.1",22),("1.1.1.1",80),("127.0.0.1",8080)]:
    g,r = full_connect(ip,p)
    print(f"{ip}:{p}  greeting={g.hex(' ')}  reply={r.hex(' ')} len={len(r)}  {r!r}"[:120])
