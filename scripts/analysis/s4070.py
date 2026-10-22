import socket, time
H=("192.168.1.24",4070)
def probe(payload, label, tmo=4):
    try:
        s=socket.create_connection(H,timeout=tmo); s.settimeout(tmo)
        if payload: s.sendall(payload)
        try: d=s.recv(400)
        except socket.timeout: d=b"<TO>"
        s.close(); return d
    except Exception as e: return f"EXC:{type(e).__name__}".encode()
print("=== identification ===")
print("  silence    :", probe(b"", "s")[:120])
print("  GET /      :", probe(b"GET / HTTP/1.0\r\n\r\n","g")[:120])
print("  GET /spotify:", probe(b"GET /spotify HTTP/1.0\r\n\r\n","g")[:120])
print("  POST login :", probe(b"POST /login HTTP/1.0\r\nContent-Length: 0\r\n\r\n","p")[:120])
print("  mDNS-like  :", probe(b"\x00\x00\x00\x00","z")[:120])
print("  binaire    :", probe(b"\x02\x00\x00","b")[:120])
