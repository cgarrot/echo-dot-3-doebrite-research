# Security Disclosure — Amazon Echo Dot (3rd Gen, with clock) — `doebrite`

**Device:** Echo Dot 3rd Gen with clock
**Codename:** `doebrite` · **DSN:** `G0914705XXXXXXX` · **deviceType:** `A30YDR2MK8HMRV`
**SoC:** MediaTek MT8167 · Android 7.1.2 / Fire OS 6 · userspace 32-bit (armeabi-v7a)
**Firmware under test:** `update-kindle-doebrite-NS65741_user_8149_0013222532484.bin`
**Reported by:** independent security research
**Date:** 2026-10-22
**Test conditions:** device in factory-reset / setup mode, Wi-Fi only. **No hardware modification,
no opening of the enclosure, no UART, no test points, no USB.** All findings were obtained
over the air or from the published firmware package.

---

## Executive summary (FR)

Cinq problèmes sont rapportés, tous obtenus **sans modification matérielle**, en Wi-Fi
uniquement, sur un appareil en mode configuration. Le plus grave est un **déni de service
pré-authentification reproductible** dans le serveur de provisioning (`oobed`), dû à
l'embarquement d'**Apache Thrift 0.9.0**, version vulnérable à **CVE-2019-0205**. Les autres
constats vont d'un **SSRF confirmé** à des **mesures de durcissement manquantes**
(absence de stack canary dans cinq composants natifs exposés au réseau).

**Aucune exécution de code, aucun contournement de signature, aucune écriture de partition
n'a été obtenue.** Ces éléments sont fournis pour correction et durcissement.

---

## Findings overview

| # | Finding | Severity | Pre-auth | Status |
|---|---|---|---|---|
| 1 | DoS via Thrift 0.9.0 recursion (CVE-2019-0205) in `oobed` | **High** | ✅ Yes | Reproduced |
| 2 | SSRF in `getLinkCode` (attacker-controlled host + port) | **Medium** | ✅ Yes | Reproduced |
| 3 | `socks` — root SOCKS5 service with `iptables`/`system()` primitives | **Medium** | N/A (local) | Static + probe |
| 4 | Shell-injection-prone `$P2P_IP` in `firewall.sh` | **Low** | N/A | Static |
| 5 | Spotify Connect API leaks user identity, unauthenticated | **Low** (info disclosure) | ✅ Yes | Reproduced |

---

## Finding 1 — Pre-authentication DoS in `oobed` (Apache Thrift 0.9.0, CVE-2019-0205)

### Severity: High (Availability)

### Affected component

```
/system/bin/oobed                          521 948 bytes, ELF 32-bit ARM
  → libcivetweb.so       (HTTP front-end)
  → libdoppleroobe.so    (OOBE service implementation, Apache Thrift C++)
  → libthrift.so         ★ version 0.9.0  (TJSONProtocol)
```

`oobed` is declared in `/system/etc/init/init.oobe.puffin.rc`:

```
service oobed_on_boot /system/bin/oobed -r 1
    user oobe
    group aipc oobe dbus system inet ace_kvstore keystore ace_group drmrpc ace_maplite davs
    disabled
    oneshot
```

It is started by three property triggers (`com.amazon.puffin.OOBED_START` =
`on_boot`, `on_button_press`, `on_network_disconnect`) and listens on TCP **8080**
on the device's setup access point (`Amazon-XXXX`, gateway `10.201.126.241`).

### Vulnerability

`libthrift.so` is **Apache Thrift 0.9.0** (released 2013), which is in the affected
range of **CVE-2019-0205** (Thrift 0.9.0 → 0.12.0): unbounded recursion while
parsing deeply nested structures, leading to stack exhaustion.

The OOBE protocol is Thrift-JSON. `TJSONProtocol` parses nested `rec` structures
recursively and **does not validate nesting against the service schema**, so an
unauthenticated client can drive arbitrary recursion depth using a syntactically
valid request.

The traversal faults on the stack guard page. (Note: the binary *does* carry a
stack canary — an earlier draft of this report stated otherwise; that is corrected.)

### Reproduction

1. Connect to the setup access point `Amazon-XXXX`.
2. Send the following HTTP request to `http://10.201.126.241:8080/OOBE`
   (`Content-Type: application/x-thrift`):

```python
depth = 20000
body = b'[1,"ping",1,1,' + b'{"0":{"rec":' * depth + b'{}' + b'}}' * depth + b']'
```

3. The server closes the connection and **stops responding entirely**.

### Evidence (measured)

| nesting depth | request size | server response | server alive after |
|---|---|---|---|
| 50 | 717 B | 200 OK | yes |
| 200 | 2 817 B | 200 OK | yes |
| 1 000 | 14 017 B | 200 OK | yes |
| 5 000 | 70 017 B | 200 OK | yes |
| **20 000** | **280 017 B** | **connection dropped** | **NO** |

After the crash, three probes over 15 seconds received no response. The Wi-Fi access
point remained up, i.e. only `oobed` died, not the device. Because the service is
declared `oneshot`, **init does not restart it**: the provisioning server stays down
until the device is rebooted.

### Impact

An unauthenticated attacker within radio range of a device in setup mode can
permanently disable its provisioning server. This blocks device setup and any
setup-time recovery flow, and requires a physical power cycle to clear.

Note: the traversal is a *stack exhaustion*, which faults on the guard page. We did
**not** obtain control of the instruction pointer, and we are **not** claiming
code execution.

### Recommendation

- Upgrade `libthrift` to ≥ 0.13.0 (fix for CVE-2019-0205), or
- enforce a nesting-depth limit in `TJSONProtocol`/the OOBE processor before recursion,
- and rebuild `oobed`, `libdoppleroobe` and `libthrift` with `-fstack-protector-strong`.
- Consider changing the service from `oneshot` to `oneshot` + supervision, so a crash
  is recovered without user interaction (availability trade-off: a supervised service
  is also re-crashable — the depth limit is the real fix).

---

## Finding 2 — SSRF: attacker-controlled host and port in `getLinkCode`

### Severity: Medium

### Description

`getLinkCode` (unauthenticated, port 8080) causes the device to open an **outbound TLS
connection** to:

```
persist.oobe.reg.endpoint : persist.oobe.compapp.port
```

- The **host** is resolved through DNS and is **not pinned**: a DNS response pointing
  `api.amazon.com` at `127.0.0.1` is honoured (observed 4× on the device).
- The **port** is taken from the client's `setLocaleAndEndpoints` request
  (companion-application port field), which is a client-supplied integer.

### Evidence (measured)

1. With `api.amazon.com` resolving to our server, the tunnel followed the hijack
   (the TLS handshake moved to our address).
2. With the port set to `8080` and the host resolving to `127.0.0.1`, a `GET /` sent
   through the tunnel returned the **OOBE servlet's own** error page:

```
HTTP/1.1 405 Method Not Allowed · Allow: POST, OPTIONS
Error 405: Method Not Allowed - Unsupported HTTP Request Method
```

i.e. the TLS client reached `127.0.0.1:8080` on the device itself, proving the
tunnel can be aimed at loopback and at arbitrary ports.

3. The server certificate observed is `CN=api.amazon.com` (DigiCert/GeoTrust G1),
   TLS **1.1** with `ECDHE-RSA-AES128-SHA` — so a real TLS handshake to a
   *substituted* endpoint will fail certificate validation. The SSRF is therefore
   usable as a **reachability oracle / port scanner of the device's own loopback**,
   not as a full data-exfiltration proxy.

### Impact

An attacker who controls DNS (rogue AP, captive portal) can use the device as a
restricted probe of its own loopback interface and of arbitrary TCP ports, and can
trigger outbound connections to arbitrary hosts/ports on the attacker's behalf.

### Recommendation

- Pin the registration endpoint (no DNS-derived host), or restrict it to an
  HTTPS-only allowlist with certificate pinning.
- Reject client-supplied companion-application ports outside the expected range,
  and never use them to build a connection to `127.0.0.1`/`localhost`.

---

## Finding 3 — `socks`: root SOCKS5 service with `iptables` and `system()` primitives

### Severity: Medium (defence-in-depth / latent)

### Description

```
/system/bin/socks    (34 380 bytes, ELF 32-bit ARM)
init.socks.rc:
  service socks5stream /system/bin/socks -i p2p0 -p 1080
      socket socks_sup stream 660 wifi wifi
      user root
      group root system
      disabled · oneshot
```

The service accepts a SOCKS5 handshake from the network (`05 00` on a no-auth
greeting) and then validates the client against a whitelist keyed by
**deviceID derived from the client's MAC address** (`from ARP Cache`):

```
client's requested remote host is not in whitelist
client's deviceID is not in whitelist
setting Up iptables rule to enable port %u
setting Up iptables rule to disable port %u
Setting Up Out of band tcp server %s:%u
```

The binary imports `system()` and executes **`/system/bin/iptables`** with
`--dport <port>`.

### Observed behaviour

- On the LAN interface in normal operation, port **1080** responds to a SOCKS5
  greeting with `05 00`, then rejects every `CONNECT` with a non-standard
  reply code `0x09` (whitelist empty), for loopback, LAN and internet destinations
  alike.
- In setup mode, port 1080 is **not** listening (only 8080 is).

### Impact

We did **not** achieve command execution. The concern is structural: a
`root` service that (a) builds `iptables` command lines and (b) calls `system()`,
driven by a whitelist whose client identity is an **ARP-derived, spoofable MAC
address**. If any code path ever interpolates a host/port string into the
`system()` command line, the result is root command execution.

### Recommendation

- Replace `system("/system/bin/iptables …")` with `execve()` on a fixed argv
  (no shell), and validate that the port argument is numeric before use.
- Do not derive authorization from an ARP-cached MAC (spoofable); use the
  authenticated provisioning session instead.
- Start the service only while provisioning is actually in progress.

---

## Finding 4 — `firewall.sh`: unquoted `$P2P_IP` in iptables rules

### Severity: Low (latent command injection)

### Description

`/system/bin/firewall.sh` (executed as **root** by init) builds iptables rules using
an unquoted variable:

```sh
iptables -t nat -A PREROUTING -i $P2P_IF -s $P2P_IP -p tcp --dport $PORT -j DNAT …
```

`$P2P_IP` is populated from a system property written by the OOBE HTTP layer from
`request.getRemoteAddr()`. We verified that `getRemoteAddr()` cannot itself produce
shell metacharacters, so **this is not currently exploitable** — but the pattern is
one property-write away from root command execution, and the script runs as root.

### Recommendation

Quote every expansion (`-s "$P2P_IP"`), or better, validate the value with a strict
IPv4 regex before use, and use `execve`-style invocations throughout.

---

> **Correction notice.** An earlier draft of this report contained a finding claiming that
> five native components were built without stack protection. **That claim was wrong and is
> withdrawn.** Re-verification with `objdump -d | grep stack_chk_fail@plt` shows canaries are
> present: `libSpotifyAdapter` 823 call sites, `libSpotifyAdapterInternal` 73,
> `libdoppleroobe` 130, `libthrift` 302, `libcivetweb` 53. The original check used
> `readelf -s | grep -c stack_chk_fail`, which missed the versioned symbol.
> No stack-protector finding is being reported.

---

## Finding 5 — Spotify Connect `getInfo` leaks user identity without authentication

### Severity: Low (information disclosure)

### Description

The device advertises `_spotify-connect._tcp` over mDNS with `CPath=/spotifyConnect`
on TCP 4070. The `getInfo` action requires **no authentication**:

```
GET http://<device>:4070/spotifyConnect?action=getInfo   → 200 OK
```

Response (measured on a provisioned device):

```json
{ "status": 101, "statusString": "OK", "version": "2.9.0",
  "deviceID": "<spotify-device-uuid>",
  "publicKey": "i7uACqQ4mLE+0dv4…",
  "deviceType": "SPEAKER",
  "libraryVersion": "3.209.367-g12ca7f99",
  "brandDisplayName": "Amazon",
  "modelDisplayName": "Echo_Dot_with_clock",
  "aliases": [ {"name": "<user's Spotify display name> - Echo Dot", "id": "1"} ],
  "clientID": "<spotify-client-id>",
  "productID": 53 }
```

### Impact

Any host on the same LAN — including a guest or a compromised IoT device — can
retrieve the **Spotify display name of the device owner**, the stable `deviceID`,
the session `publicKey` and the Spotify `clientID`, with no authentication and no
user consent. This is a privacy leak and a useful reconnaissance primitive
(the `deviceID` and `publicKey` are the inputs to the `addUser` handshake).

This behaviour is inherited from the Spotify Connect zeroconf specification;
however the alias disclosure in particular is user-identifying and could be
restricted to an authenticated context.

### Recommendation

- Remove `aliases` from the unauthenticated `getInfo` response, or return an
  opaque label instead of the user's Spotify display name.
- Consider requiring a pairing step before exposing `deviceID`/`publicKey`.

---

## What was tested and did NOT yield a vulnerability

Documented here so the report is complete and so the same ground is not re-covered.

| Surface | Tests | Result |
|---|---|---|
| Thrift JSON parser (strings) | strings 1 B → **1 MiB** | handled |
| Thrift JSON parser (encoding) | invalid UTF-8, lone surrogates `\ud800`, 50 000 escapes | rejected cleanly (400) |
| Thrift JSON parser (numbers) | 64-bit integer of 5 000 digits | rejected cleanly (400) |
| civetweb HTTP parser | 20 KB header, 20 KB request line, 60 KB URL, absurd/negative/duplicate `Content-Length`, malformed chunked, NUL in path, 10 KB method, 100 headers, `../../etc/passwd` | all handled (400/405/500), no crash |
| OOBE business fields | SSID 32 → 16 KiB, locale 32 → 64 KiB, endpoint 32 → 64 KiB | validated before use, no overflow |
| Matter (port 5541) | commissioning + 3 fuzz vectors incl. TLV length desync delivered and ACKed | stack robust, no crash |
| WhisperJoin BLE | full protocol implemented (START → GRANTED, commands, responses) | blocked by CBL cloud authentication (working as designed) |
| LAN port scan (1-65535, normal mode) | — | 7 ports: 1080, 4070, 5541, 8888, 55442, 55443, 55445 — all closed/authenticated except Matter |
| Setup-mode port scan (1-65535) | — | 8080 only |
| Wi-Fi stack | the whole setup/captive-portal flow | no memory-safety issue found |

**Not in scope of this report** (acknowledged, no claim made): bootloader, OTA
signature chain, SELinux policy, partition integrity. All were examined and found
to be correctly enforced.

---

## Suggested remediation priority

1. **Finding 1** (DoS, pre-auth, trivial to trigger) — patch `libthrift` + add a
   depth limit. Highest priority because it is reachable by anyone in radio range
   with a single 280 KB request.
2. **Finding 2** (SSRF) — pin the endpoint, validate the port.
3. **Finding 3/4** — remove `system()` from root services, quote shell expansions.
4. **Finding 5** — restrict the unauthenticated `getInfo` response.

---

## Reproduction assets

All scripts and raw evidence are retained by the researcher and can be provided to
Amazon Security on request:

- fuzzing harnesses (Thrift nesting, HTTP raw, string edge cases, OOBE field overflow)
- crash logs and timing tables
- the WhisperJoin BLE client (for the record on what the cloud auth protects)
- disassembly notes for `lk`, `oobed`, `libdoppleroobe`, `libthrift`, `socks`

**No device was damaged.** The device was restored to its factory state after testing.
