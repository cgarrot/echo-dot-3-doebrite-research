# 09 — Methodology and lessons

This document exists because the *process* produced as much value as the findings,
including one public correction.

## Rule 1 — A positive witness proves the harness, not the vulnerability

A DNS server that answers does not prove the parser was reached. A device that
pings does not prove it processed your payload. For every negative result, capture
a **witness** that the path was actually exercised (an echo, a log line, a state
change) and a **control** that the witness fails when the path is not taken.

*Applied:* the Matter fuzz initially "succeeded" while never delivering a single
malformed TLV — the CASE handshake was being rejected, so the attribute read never
happened. Only after moving the patch from `WriteElementWithData` (also used by the
handshake) to `PutString` did the fuzz actually reach the parser.

## Rule 2 — Two agents on every factual claim

Three successive versions of the "is `ro.boot.selinux=disable` effective?" question
were produced, each plausible, each wrong. The truth was settled only by
disassembly: `lk` writes `androidboot.selinux=enforce` unconditionally, and `init`
maps `androidboot.*` → `ro.boot.*` **write-once, before** the property is read.

**Corollary:** when two sources disagree, the tie-breaker is a measurement, never
the more confident-sounding source.

## Rule 3 — Never conclude absence from a truncated view

**This rule was learned the hard way, in this very project.**

We concluded that five libraries had **no stack canary**, based on:

```bash
readelf -s libX.so | grep -c stack_chk_fail     # → 0
```

The symbol is versioned (`__stack_chk_fail@LIBC`) and `readelf`'s field was
truncated, so the grep silently matched nothing. The truth:

```bash
objdump -d libX.so | grep -c 'stack_chk_fail@plt'
# libSpotifyAdapter 823 · libthrift 302 · libdoppleroobe 130
# libSpotifyAdapterInternal 73 · libcivetweb 53
```

**A false finding was published and then withdrawn.** The correct technique for
"does X call Y?" is to **count call sites in the disassembly**, never to search a
formatted symbol table.

## Rule 4 — A shared identifier is not an identity

Two products (Echo Dot 3 `doebrite`, Echo Studio `octave`) share the OTA package
name suffix `0013222532484`. An early analysis of the `octave` OOBE APK produced
the conclusion *"`oobed` does not exist on doebrite"* — which was false. The real
`oobed` is 521 948 bytes of native code and is the target of the main finding.

**Identify by `deviceType` and by content, never by a file name.**

## Rule 5 — Measure before/after, never from a single state

The SSRF was found because we compared port state **before and after** calling
`getLinkCode`: port 443 was closed, the call was made, port 443 was open. A single
snapshot would have shown "443 open" or "443 closed" and taught nothing.

**Take a baseline, act, re-measure, and keep the baseline.**

## Rule 6 — Kill your own leads by measurement, not by argument

Every one of these was eliminated by evidence, not by reasoning:

| Lead | Killed by |
|---|---|
| dnsmasq `dhcp-script` (root RCE candidate) | compiled out (`-DNO_SCRIPT`, "recompile with HAVE_SCRIPT") |
| dnsmasq CVE-2017-14491 | `extract_name()` is bounded in 2.51 |
| avahi 0.6.31 (root, `--no-drop-root`) | `rlimit-data=4M` → cannot even start |
| dhcpcd CVE-2016-1503 | fixed in this binary; verified by disassembly at both use sites |
| ADB over TCP 5555 | `ro.adb.secure=1`, no `/adb_keys`, never listening (scanned 1-10000) |
| ATCI over USB | `atci_service`/`atcid` binaries **absent** from `/vendor/bin` |
| Wi-Fi VHT OOB (63 injected beacons, 900 length sweeps) | driver has tailroom; device never faulted |

## Rule 7 — Verify the witness device

A stale ARP cache on the test host briefly showed three different IPs with the same
MAC, which nearly invalidated a real finding. The resolution was mDNS: the Matter
operational instance resolved to the expected address, proving the scans had been
performed against the right device.

**When a scan result contradicts an expectation, first prove *what* answered.**

## Rule 8 — Scope a finding before writing it up

A DoS is not an RCE. A latent pattern is not an exploit. Stack exhaustion is not
stack corruption. Every finding in this repository states what was **measured**,
what is **static**, and what is **not claimed**.

---

## Timeline constraints worth recording

* The OOBE server is **single-threaded**: `getOTADetails` blocks it ~90 s; a
  `setLocaleAndEndpoints` + `getLinkCode` pair blocks it ~60 s. Any fuzzing loop
  must account for this or it will measure its own timeouts.
* BLE addresses **rotate**: scan and connect must happen in one pass.
* A BLE connection **consumes setup mode**: the device stops advertising and the
  setup AP disappears. One shot per factory reset.
* The device clock is **wrong** (1970): any TLS-dependent feature fails until NTP.

## What "done" means

A surface is closed when **all** of the following hold:

1. it was reached (witness),
2. it was exercised with adversarial input at multiple sizes/encodings,
3. the result was reproduced at least twice,
4. the negative was bounded (e.g. "1 MiB", not "large"),
5. the tool and its invocation are in this repository.
