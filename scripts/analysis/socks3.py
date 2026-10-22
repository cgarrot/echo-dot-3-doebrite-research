import socket, struct
H=("192.168.1.24",1080)
def raw(label, payload, read=40):
    try:
        s=socket.create_connection(H,timeout=6); s.settimeout(5)
        s.sendall(payload)
        try: d=s.recv(read)
        except socket.timeout: d=b"<timeout>"
        print(f"  {label}: {d.hex(' ')}  {d!r}"[:150]); s.close()
    except Exception as e: print(f"  {label}: ERR {e}")

print("=== 1. greeting no-auth ===")
raw("05 01 00", b"\x05\x01\x00")
print("=== 2. greeting user/pass ===")
raw("05 01 02", b"\x05\x01\x02")
print("=== 3. greeting GSSAPI ===")
raw("05 01 01", b"\x05\x01\x01")
print("=== 4. SOCKS4 CONNECT 127.0.0.1:7802 ===")
raw("socks4", b"\x04\x01"+struct.pack(">H",7802)+socket.inet_aton("127.0.0.1")+b"\x00")
print("=== 5. HTTP CONNECT ===")
raw("http", b"CONNECT 127.0.0.1:7802 HTTP/1.0\r\n\r\n")
print("=== 6. SOCKS5 CONNECT domain 'localhost' ===")
raw("dom", b"\x05\x01\x00" + b"\x05\x01\x00\x03\x09localhost" + struct.pack(">H",7802), 60)
print("=== 7. SOCKS5 BIND ===")
raw("bind", b"\x05\x01\x00" + b"\x05\x02\x00\x01"+socket.inet_aton("0.0.0.0")+struct.pack(">H",0), 60)
print("=== 8. SOCKS5 UDP ASSOCIATE ===")
raw("udp", b"\x05\x01\x00" + b"\x05\x03\x00\x01"+socket.inet_aton("0.0.0.0")+struct.pack(">H",0), 60)
print("=== 9. greeting v4 directement ===")
raw("v4greet", b"\x05\x04\x00", 20)
