import socket
H=("192.168.1.24",1080)
print("=== sonde : 1er octet variable, 6 octets envoyes ===")
for b in [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x10,0x47,0x50]:
    try:
        s=socket.create_connection(H,timeout=5); s.settimeout(3)
        s.sendall(bytes([b])+b"\x00\x00\x00\x00\x00")
        try: d=s.recv(40)
        except socket.timeout: d=b"<TO>"
        print(f"  first=0x{b:02x} → {d.hex(' ')}  {d!r}"[:110]); s.close()
    except Exception as e: print(f"  first=0x{b:02x} → {e}")
