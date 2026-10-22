# 10 — Conclusion

## The question

> *Can a personal Linux firmware be installed on an Amazon Echo Dot 3rd Gen
> (`doebrite`) using only its network interfaces — Wi-Fi, Bluetooth, two buttons
> and power — with no hardware modification?*

## The answer

**No.** Not "not yet found" — **no**: the root of trust is cryptographic and cannot
be broken from userspace, however privileged.

| Path | Blocked by |
|---|---|
| Replace the OS | `lk` verifies `boot`/`recovery` with **RSA-PSS** (Amazon private key) |
| Modify `/system` | `dm-verity` (`squashfs ro verify,slotselect`) |
| Modify `/misc` (BCB) | `lk` still verifies the target image |
| Downgrade | anti-rollback + per-model signed OTA manifest |
| `swdl` / `dkernel` boot modes | **no such image exists** on this product |
| Fastboot / ADB / ATCI | no USB port / no keys / binaries absent |
| Root via a network bug | **no memory-corruption bug found** in 11 parsers, and root would still not defeat the chain above |

**The only object that unlocks a firmware replacement is Amazon's RSA private key.**

## What the campaign did produce

1. **A CVE-class, pre-authentication denial of service** in the provisioning server
   (`oobed`, port 8080) inherited from **Apache Thrift 0.9.0** — CVE-2019-0205.
   One 280 KB request kills it until a power cycle.
2. **A confirmed SSRF** in `getLinkCode`: attacker-controlled host (via DNS) and
   port (via `setLocaleAndEndpoints`), proven to reach the device's own loopback.
3. **A structural risk**: `/system/bin/socks`, a **root** SOCKS5 service that builds
   `iptables` command lines, calls `system()`, and authorises clients by a spoofable
   ARP-derived MAC.
4. **A latent root command injection** pattern in `firewall.sh` (unquoted `$P2P_IP`).
5. **An unauthenticated information leak** in Spotify Connect (`getInfo` discloses
   the owner's Spotify display name and session keys).
6. **The WhisperJoin BLE protocol, fully reversed and implemented** — publicly
   undocumented for this device — plus the identification of **CBL cloud
   authentication** as the control that protects it.
7. **A complete map of the device's attack surface** in both operating states,
   with every closed door measured rather than assumed.

## What remains genuinely unknown

* Whether a memory-corruption bug exists in the **Spotify ESDK** (`sp_<hash>`
  obfuscated symbols). The `addUser` parameter format was cracked and the wire
  protocol reimplemented, but the daemon never registers with Spotify's servers
  (`remoteName` and `availability` stay empty), so the login path cannot complete.
* Whether a bug exists in the **Wi-Fi/BT firmware** — that would be code execution
  on the connectivity chip, not the application processor.
* Whether older firmware revisions (pre-6.5.6.4) contain a now-patched userspace bug.
  Anti-rollback prevents testing this.

## Closing note

Three months of "surely there's a way" produced one CVE-class availability bug, one
SSRF, two hardening issues, one information leak, a fully reversed BLE provisioning
protocol, and — most importantly — **a rigorous, reproducible proof that the device
is not modifiable over the air.**

That negative result is the deliverable. It saves the next researcher the months it
took to establish.
