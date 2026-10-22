#!/usr/bin/env python3
"""Spotify Connect v2 — handshake complet + crafting du blob (recherche)."""
import base64, hashlib, hmac, json, os, struct, sys, urllib.parse, urllib.request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEV_HOST = "192.168.1.24"
DEV_PORT = 4070

# --- DH (RFC 2409 group 5, comme librespot) ---
DH_P = int.from_bytes(bytes([
0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
0xf4,0x4c,0x42,0xe9,0xa6,0x3a,0x36,0x20,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff]), "big")
DH_G = 2

def dh_keypair():
    priv = int.from_bytes(os.urandom(95), "little")
    pub = pow(DH_G, priv, DH_P)
    return priv, pub

def dh_shared(priv, remote_pub_bytes):
    remote = int.from_bytes(remote_pub_bytes, "big")
    return pow(remote, priv, DH_P).to_bytes((pow(remote, priv, DH_P).bit_length()+7)//8, "big")

def get_info():
    url=f"http://{DEV_HOST}:{DEV_PORT}/spotifyConnect?action=getInfo"
    return json.loads(urllib.request.urlopen(url, timeout=8).read())

def aes128ctr(key, iv, data):
    c=Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data)+c.finalize()

def aes192ecb_dec(key, data):
    c=Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return c.update(data)+c.finalize()

def aes192ecb_enc(key, data):
    c=Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return c.update(data)+c.finalize()

def varint(n):
    out=bytearray()
    while True:
        b=n&0x7f; n>>=7
        if n: out.append(b|0x80)
        else: out.append(b); break
    return bytes(out)

def inner_key(device_id, username):
    secret = hashlib.sha1(device_id.encode()).digest()
    key = hashlib.pbkdf2_hmac("sha1", username.encode(), secret, 0x100, 20)
    key = hashlib.sha1(key).digest()
    return key + struct.pack(">I", 20)

def build_inner(device_id, username, auth_type=1, auth_data=b"TOKEN", big_len=None):
    """construit le blob interne (a chiffrer en AES192-ECB)"""
    body = bytearray()
    body += b"\x02"                       # read_u8
    body += varint(4) + b"USER"           # read_bytes
    body += b"\x01"                       # read_u8
    body += varint(auth_type)             # read_int
    body += b"\x01"                       # read_u8
    L = big_len if big_len is not None else len(auth_data)
    body += varint(L) + auth_data         # read_bytes
    while len(body) % 16: body += b"\x00"
    key = inner_key(device_id, username)
    return aes192ecb_enc(key, bytes(body))

def add_user(username, inner_blob, device_id):
    # corps = base64(inner_blob)  (le "encrypted_blob" de librespot est base64-decoded)
    body_b64 = base64.b64encode(inner_blob)
    return body_b64

def outer_wrap(shared, payload, device_id):
    base = hashlib.sha1(shared).digest()[:16]
    ck = hmac.new(base, b"checksum", hashlib.sha1).digest()
    ek = hmac.new(base, b"encryption", hashlib.sha1).digest()
    iv = os.urandom(16)
    enc = aes128ctr(ek[:16], iv, payload)
    mac = hmac.new(ck, enc, hashlib.sha1).digest()
    return base64.b64encode(iv+enc+mac)

def query(params, post=False):
    q=urllib.parse.urlencode(params)
    if post:
        url=f"http://{DEV_HOST}:{DEV_PORT}/spotifyConnect"
        req=urllib.request.Request(url, data=q.encode(),
            headers={"Content-Type":"application/x-www-form-urlencoded"})
    else:
        url=f"http://{DEV_HOST}:{DEV_PORT}/spotifyConnect?{q}"
        req=urllib.request.Request(url)
    try:
        r=urllib.request.urlopen(req, timeout=10)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, type(e).__name__.encode()

if __name__=="__main__":
    info=get_info()
    print("=== getInfo ===")
    for k in ("version","deviceID","deviceType","libraryVersion","modelDisplayName","productID"):
        print(f"  {k}: {info.get(k)}")
    pub = base64.b64decode(info["publicKey"])
    print(f"  publicKey: {len(pub)} octets")
    priv, mypub = dh_keypair()
    mypub_b = mypub.to_bytes((mypub.bit_length()+7)//8,"big")
    shared = dh_shared(priv, pub)
    print(f"  ma cle publique: {len(mypub_b)} o · secret partage: {len(shared)} o")
    device_id = info["deviceID"]
    username="a"*len(sys.argv[1]) if len(sys.argv)>1 else "researchuser"
    size = int(sys.argv[2]) if len(sys.argv)>2 else 0
    inner = build_inner(device_id, username, big_len=(size or None))
    blob = outer_wrap(shared, inner, device_id)
    params=[("action","addUser"),("userName",username),
            ("blob",blob.decode()),("clientKey",base64.b64encode(mypub_b).decode()),
            ("deviceName","probe")]
    st,body = query(params, post=True)
    print(f"\n=== addUser (POST) ===")
    print(f"  inner={len(inner)} o · blob={len(blob)} o · username={username!r}")
    print(f"  -> {st} {body[:200]!r}")
