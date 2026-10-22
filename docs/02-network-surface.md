# 02 — Network surface

Two operating states were measured exhaustively: **normal** (joined to a LAN) and
**setup** (factory reset, advertising its own AP).

## Full TCP scans

**Normal mode** — `nmap -p-` equivalent, threaded `connect()`:

```
192.168.1.24  →  [1080, 4070, 5541, 8888, 55442, 55443, 55445]
```

| Port | Service | Verdict |
|---|---|---|
| 1080 | `/system/bin/socks` — SOCKS5, **UID root** | whitelist empty → every CONNECT refused (`0x09`) |
| 4070 | Spotify Connect zeroconf | `getInfo` unauthenticated → **info leak** |
| 5541 | Matter | commissioned & fuzzed |
| 8888 | unknown, RST on any data | closed |
| 55442 | HTTP, 34 routes probed | all 404 |
| 55443 / 55445 | WHALEXA, mTLS | `handshake failure` (private CA) |

**Setup mode** — host connected to the AP (`10.201.126.242/28`):

```
10.201.126.241  →  [8080]     ← only one port
```

`8080` is `oobed`. `1080` (SOCKS) is bound to `p2p0`, which does not exist in this
state; Matter is not started; nothing else listens.

> **Lesson:** a port scan is only valid if you verified *which device* answered.
> A stale ARP cache on the test host once showed the same MAC for three different
> IPs, which briefly made us doubt — and nearly invalidated a real finding. The
> tie-breaker was mDNS resolution of the Matter operational instance, which mapped
> the service instance to `192.168.1.24`.

## `getLinkCode` — the SSRF

`getLinkCode` (unauthenticated) makes the device open a **TLS connection** to:

```
persist.oobe.reg.endpoint : persist.oobe.compapp.port
```

* the **host is DNS-derived and not pinned** — a DNS answer pointing
  `api.amazon.com` at `127.0.0.1` is honoured (observed 4×);
* the **port is client-controlled** through `setLocaleAndEndpoints`.

Proof of reachability: with host → `127.0.0.1` and port → `8080`, a `GET /` sent
through the resulting tunnel returned the device's **own** OOBE error page:

```
HTTP/1.1 405 Method Not Allowed · Allow: POST, OPTIONS
Error 405: Method Not Allowed - Unsupported HTTP Request Method
```

The tunnel speaks TLS with `CN=api.amazon.com` (DigiCert/GeoTrust G1), TLS 1.1,
`ECDHE-RSA-AES128-SHA`, and refuses TLS 1.2. Certificate validation therefore
blocks a full MITM — the SSRF is a **loopback/port oracle**, not a data-exfil proxy.

Loopback services that answer through the tunnel: `8080`. Those that do not:
the AHE (`7802`) and `davs` (`9091`) — protected by
`iptables -m owner ! --uid-owner <uid> -j DROP`.

## `firewall.sh` — Amazon's own port map

The firmware's `firewall.sh` is effectively a service inventory:

```
4070        Spotify Connect login
4071        Whatify
16384-32767 SIP (Drop In / calls)
40317       TPH / phd
55442-55446 WHALEXA (private CA, mTLS, alert 48 unknown_ca on foreign certs)
5540/5541   MATTER
5555        ADB (never listening)
1030        "Octave remote player"
1900/50000/50001  UPnP/SSDP
5353        mDNS
6667        Tuya
50020-50040 SSDP
5000        CMB
5550        Matter casting / UDC
```

## Service inventory from the firmware

Only **three APKs** exist in `/system/priv-app`:

```
com.amazon.credentialmanager.neo
com.amazon.diode.neo
com.amazon.factory_reset.neo
```

There is **no OOBE APK on this product**: provisioning is implemented by the native
binary `/system/bin/oobed` (521 948 bytes), linked against `libcivetweb`,
`libdoppleroobe` and **`libthrift 0.9.0`**. That distinction is what produced the
main finding.
