# 08 — Findings summary

Vendor-ready version: [`../disclosure/DISCLOSURE_AMAZON.md`](../disclosure/DISCLOSURE_AMAZON.md).
Full measurement log: [`../evidence/SYNTHESE.md`](../evidence/SYNTHESE.md).

| # | Finding | Severity | Pre-auth | Evidence |
|---|---|---|---|---|
| 1 | Pre-auth DoS in `oobed` — Apache Thrift 0.9.0, CVE-2019-0205 | **High** | ✅ | reproduced |
| 2 | SSRF in `getLinkCode` (host + port attacker-controlled) | **Medium** | ✅ | reproduced |
| 3 | `/system/bin/socks` — root SOCKS5 with `iptables`/`system()` primitives, ARP-MAC authorization | **Medium** (latent) | local | static + probe |
| 4 | `firewall.sh` — unquoted `$P2P_IP` in root-run iptables rules | **Low** (latent) | — | static |
| 5 | Spotify Connect `getInfo` leaks owner identity | **Low** | ✅ | reproduced |

---

## #1 — DoS, `oobed`, CVE-2019-0205

**Where:** `/system/bin/oobed`, TCP 8080 on the setup AP (`10.201.126.241`).
**Why:** `libthrift.so` is **0.9.0**; `TJSONProtocol` recurses on nested `rec`
structures without a depth limit (CVE-2019-0205, fixed in 0.13.0).

**PoC:** 280 KB of syntactically valid nested Thrift-JSON.

```python
depth = 20000
body = b'[1,"ping",1,1,' + b'{"0":{"rec":' * depth + b'{}' + b'}}' * depth + b']'
```

**Measured:**

| depth | size | result |
|---|---|---|
| 50 → 5 000 | 717 B → 70 KB | 200 OK |
| **20 000** | **280 KB** | connection dropped; server never answers again |

The AP stays up (the board is alive); only `oobed` dies. The service is `oneshot`,
so **init does not restart it** — provisioning stays down until a power cycle.

**Not claimed:** instruction-pointer control. The recursion exhausts the stack and
faults on the guard page. It is a denial of service.

**Fix:** upgrade `libthrift` (≥ 0.13.0) or add a nesting-depth limit in
`TJSONProtocol`/the OOBE processor; add `-fstack-protector-strong` for defence in
depth (canaries are present in most components but not uniformly).

---

## #2 — SSRF, `getLinkCode`

**Where:** OOBE method `getLinkCode`, unauthenticated, port 8080.
**What:** opens an outbound TLS connection to `persist.oobe.reg.endpoint` :
`persist.oobe.compapp.port`.

* host is **DNS-derived, not pinned** — `api.amazon.com → 127.0.0.1` is honoured;
* port comes from the client via `setLocaleAndEndpoints`.

**Proof:** with host `127.0.0.1` and port `8080`, a `GET /` through the tunnel
returns the device's **own** OOBE servlet response:

```
HTTP/1.1 405 Method Not Allowed · Allow: POST, OPTIONS
Error 405: Method Not Allowed - Unsupported HTTP Request Method
```

**Impact:** loopback/port oracle on the device, plus attacker-directed outbound
connections. Full MITM is blocked by certificate validation
(`CN=api.amazon.com`, TLS 1.1 only).

**Fix:** pin the endpoint, validate the port against an allowlist, never connect to
`127.0.0.0/8`.

---

## #3 — `/system/bin/socks`

```
service socks5stream /system/bin/socks -i p2p0 -p 1080
    user root · group root system · disabled · oneshot
```

* accepts SOCKS5 (`05 00` on a no-auth greeting);
* identifies the client by **MAC address from the ARP cache** — spoofable;
* validates a whitelist keyed by `deviceID` (derived from that MAC);
* imports **`system()`** and builds **`/system/bin/iptables`** command lines
  (`setting Up iptables rule to enable port %u`).

**Measured:** on the LAN, every `CONNECT` is refused with a non-standard `0x09`
(whitelist empty), for loopback, LAN and internet destinations alike; invalid
commands give `0x07`, invalid address types `0x08`. In setup mode the port is not
listening at all.

**No execution obtained.** Flagged because a root service that (a) builds
`iptables` command lines and (b) calls `system()`, authorised by a spoofable MAC,
is one interpolation away from root command execution.

**Fix:** `execve` with a fixed argv instead of `system()`; validate the port
numerically; do not authorise on ARP-derived identities; start the service only
during provisioning.

---

## #4 — `firewall.sh`

Root-run init service building iptables rules with unquoted expansions
(`-s $P2P_IP`). `$P2P_IP` is populated from a property written by the OOBE HTTP
layer from `request.getRemoteAddr()`.

**Not currently exploitable** — `getRemoteAddr()` cannot produce shell
metacharacters — but the pattern is one property-write away from root command
injection.

**Fix:** quote every expansion, or validate with a strict IPv4 regex before use.

---

## #5 — Spotify Connect information disclosure

```
GET http://<device>:4070/spotifyConnect?action=getInfo → 200 OK, no auth
```

Returns `deviceID`, session `publicKey`, `clientID`, `productID`, and
**`aliases[].name` = the owner's Spotify display name**.

**Impact:** any LAN host learns the owner's Spotify identity and obtains the inputs
needed for the `addUser` handshake.

**Fix:** drop `aliases` from the unauthenticated response, or return an opaque
label; consider requiring a pairing step before exposing `deviceID`/`publicKey`.

---

## Withdrawn

An earlier draft reported a sixth finding: *"no stack protector in five native
components"*. **That claim was wrong and is withdrawn.** Re-verification with
`objdump -d | grep stack_chk_fail@plt` shows canaries are present throughout:

```
libSpotifyAdapter 823 · libthrift 302 · libdoppleroobe 130
libSpotifyAdapterInternal 73 · libcivetweb 53
```

The original check grepped `readelf -s` for `stack_chk_fail`, which misses the
versioned symbol (`__stack_chk_fail@LIBC`). The failure mode is documented in
`09-methodology.md` as lesson #3.
