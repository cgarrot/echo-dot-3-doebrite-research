import socket, struct, sys, time
HOST, PORT = "192.168.1.24", 1080

def socks5(target_host, target_port, label):
    """Tente une connexion SOCKS5 (no-auth) vers target."""
    try:
        s = socket.create_connection((HOST, PORT), timeout=6)
    except Exception as e:
        return f"CONNECT FAIL: {e}"
    try:
        # greeting: 05 NMETHODS 00(no auth)
        s.sendall(b"\x05\x01\x00")
        r = s.recv(2)
        if len(r) < 2: return f"greeting short: {r!r}"
        if r[0] != 5: return f"not SOCKS5: {r!r}"
        method = r[1]
        if method == 0xFF: return "SOCKS5 present but NO acceptable auth method"
        # CONNECT request
        th = target_host.encode()
        req = b"\x05\x01\x00" + b"\x03" + bytes([len(th)]) + th + struct.pack(">H", target_port)
        s.sendall(req)
        rep = s.recv(10)
        if len(rep) < 4: return f"reply short: {rep!r}"
        code = rep[1]
        names = {0:"succeeded",1:"general failure",2:"not allowed",3:"network unreachable",
                 4:"host unreachable",5:"connection refused",6:"TTL expired",7:"cmd unsupported",
                 8:"addr type unsupported"}
        return f"SOCKS5 OK method={method} → {target_host}:{target_port} = {code} {names.get(code, '?')}"
    finally:
        s.close()

print(f"=== Test SOCKS5 sur {HOST}:{PORT} ===")
for th, tp in [("127.0.0.1", 7802), ("127.0.0.1", 9091), ("127.0.0.1", 8080),
               ("127.0.0.1", 22), ("127.0.0.1", 5555), ("192.168.1.24", 5541)]:
    print(f"  {socks5(th, tp, 'x')}")
