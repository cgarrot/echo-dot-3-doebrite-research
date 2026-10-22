import socket, struct
HOST, PORT = "192.168.1.24", 1080

def t(ip, port):
    try:
        s = socket.create_connection((HOST, PORT), timeout=6)
        s.sendall(b"\x05\x01\x00")
        r = s.recv(2)
        if len(r)<2 or r[0]!=5: return f"greet={r!r}"
        # ATYP=0x01 IPv4
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", port))
        rep = s.recv(16)
        code = rep[1] if len(rep)>1 else -1
        names={0:"SUCCES",1:"general failure",2:"not allowed",3:"net unreachable",
               4:"host unreachable",5:"conn refused",6:"TTL expired",7:"cmd unsupported",
               8:"addr unsupported"}
        out=f"{ip}:{port} → code={code} ({names.get(code,'code '+str(code))})"
        if code==0:
            # tunnel ouvert : teste une requete HTTP
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                s.settimeout(4)
                d=s.recv(300)
                out += f" · reponse={d[:120]!r}"
            except Exception as e:
                out += f" · pas de reponse ({e})"
        s.close(); return out
    except Exception as e:
        return f"{ip}:{port} → {e}"

print("=== SOCKS5 ATYP=IPv4 ===")
for ip,p in [("127.0.0.1",7802),("127.0.0.1",9091),("127.0.0.1",8080),("127.0.0.1",22),
             ("127.0.0.1",5555),("192.168.1.24",5541),("127.0.0.1",443)]:
    print("  "+t(ip,p))

print("\n=== TEMOIN : port 1080 avec du bruit (pas SOCKS) ===")
try:
    s=socket.create_connection((HOST,1080),timeout=5); s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    s.settimeout(3); print("  bruit →", repr(s.recv(120))[:150]); s.close()
except Exception as e: print("  bruit →",e)
