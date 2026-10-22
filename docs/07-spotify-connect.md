# 07 — Spotify Connect

## Discovery

The device advertises over mDNS:

```
_spotify-connect._tcp.local  →  SpotifyConnect._spotify-connect._tcp.local
                              →  linux.local.:4070
                              TXT: CPath=/spotifyConnect
```

The API is reachable without authentication:

```
GET http://<device>:4070/spotifyConnect?action=getInfo    → 200 OK
```

```json
{ "status": 101, "statusString": "OK", "version": "2.9.0",
  "deviceID": "<uuid>", "publicKey": "<96 bytes b64>", "deviceType": "SPEAKER",
  "libraryVersion": "3.209.367-g12ca7f99", "brandDisplayName": "Amazon",
  "modelDisplayName": "Echo_Dot_with_clock", "groupStatus": "NONE",
  "tokenType": "accesstoken", "scope": "streaming",
  "availability": "", "remoteName": "",
  "aliases": [ { "name": "<owner's Spotify display name> - Echo Dot", "id": "1" } ],
  "clientID": "<spotify client id>", "productID": 53 }
```

**`aliases[].name` is the device owner's Spotify display name.** That is finding #5
(information disclosure, unauthenticated, LAN-scoped).

Note `remoteName` and `availability` stay empty even when the Echo is happily playing
Spotify through Alexa: the cloud music integration and the local Spotify Connect
daemon are **two different things**.

## The stack

```
libSpotifyAdapter.so          1 714 016 B
libSpotifyAdapterInternal.so    165 452 B   ← request handlers
libPAL.so                       853 576 B   ← Spotify ESDK platform layer
libGadgetsDelegate.so            22 088 B
libReggaeDevice.so              108 108 B
```

Symbols:

```
SpotifyAdapterInternal::addUser(SpotifyESDKRequest&)                 @ 0x18d55
SpotifyAdapterInternal::putAndWaitAddUserMessageOnQueue(…)           @ 0x18565
amazon::spotify::SpotifyConnectManager::addUser(SpError&, char*, char*, char*, char*, char*, int)
SpConnectionLoginZeroConf                                           @ 0x11abd8
  └─ sp_dbde3c28b4a31824761d46115eed0209                             @ 0x124020  (obfuscated)
```

## The `addUser` parameter set — cracked

Strings in `.rodata` revealed the parameter names:

```
userName · blob · loginId · tokenType
userNameLen · blobLen · tokenTypeLen
```

Sending only `userName`+`blob` yields `400 ERROR-BAD-REQUEST`. Sending the
**full set as a form-encoded POST** changes the answer to **`500`** — i.e.
parameter validation is passed and the request reaches the crypto/login layer.

## The blob format (from librespot, the open reference server)

```
1. DH        : MODP 1536-bit (RFC 2409 group 5), g=2, 95-byte private key
2. shared    = clientKey^priv mod P
3. base_key  = SHA1(shared)[0..16]
4. ck_key    = HMAC-SHA1(base_key, "checksum")
5. ek_key    = HMAC-SHA1(base_key, "encryption")
6. blob      = base64( IV[16] || AES-128-CTR(ek_key[0..16], IV, plaintext)
                       || HMAC-SHA1(ck_key, ciphertext) )
7. inner plaintext = AES-192-ECB(
       key = SHA1( PBKDF2-SHA1( SHA1(deviceID), userName, 0x100 ) ) || u32be(20) )
   layout: u8 || varint(len)+bytes || u8 || varint(authType) || u8 || varint(len)+bytes
```

**Why this is interesting:** the inner key derives from the **deviceID (public,
taken from `getInfo`)** and the **userName (client-chosen)**. So the client can
craft the *decrypted* inner blob arbitrarily and feed it to a C++ parser
(`read_bytes` = read a varint length, then allocate and read that many bytes).

## Where it stopped

A complete Python implementation was written (`scripts/analysis/spotify_connect.py`):
DH keypair, shared secret, both HMACs, AES-CTR, inner AES-192-ECB, blob assembly.

**Every attempt returns `500` with an empty body** — including a *random* blob and a
*corrupted-HMAC* blob. Identical failure for valid and invalid crypto means the
error happens **before** the checksum verification, i.e. in the ESDK's
`SpConnectionLoginZeroConf` → `sp_dbde…` path, which is heavily
symbol-obfuscated (`sp_<32 hex>`).

Consistent explanation, measured via `getInfo`: `remoteName` and `availability`
are empty even while the device plays Spotify. **The local Spotify Connect daemon
never registers with Spotify's servers**, so `addUser` cannot complete regardless
of the input.

**Scope note:** even a full compromise here would run in `puffin`, not as root,
and would not change the OS (see `06-bootloader-and-ota.md`).
