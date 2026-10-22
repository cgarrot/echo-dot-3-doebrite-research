# 06 — Bootloader, OTA and the integrity chain

**This is the document that explains why the OS cannot be replaced.** It is short
because the answer is short.

## The chain

```
BootROM (in the SoC)
  └─ preloader
       └─ lk  (/system/bin/… actually a MTD partition, 237 568 bytes)
            ├─ verifies boot.img   → RSA-PSS (SHA-256, LibTomCrypt)
            ├─ verifies recovery.img
            └─ jumps to kernel
                 └─ mounts /system  → squashfs ro, dm-verity (`verify,slotselect`)
```

## `lk` — read in full

The bootloader was disassembled completely (100 248 lines of Thumb-2). Findings:

* **Unlock path** = SHA-256 + **RSA-PSS** verification with the Amazon public key.
  There is exactly one private key that satisfies it.
* **`ro.oem_unlock_supported=1`** exists but unlocks nothing: the unlock procedure
  requires USB, which the product does not expose.
* **Boot mode switch** at `0x41e1d7c0`, six values resolved:

| value | target | string |
|---|---|---|
| 4, 6 | factory | `factory.img` |
| 10 | — | other path |
| 7 | — | other path |
| **97** | swdl | **`Wifi SWDL Boot Image`** |
| **98** | dkernel | `Diagnostic Boot Image` |

* **`lk` can write to `idme`** (`idme_update_var_ex`, used for bootcount).
* **There is a button-driven boot menu** in the bootloader:

```
Yes (Volume UP)   : Confirm and Boot.
No  (Volume Down) : Abort.
[VOLUME_UP to select.  VOLUME_DOWN is OK.]
[Recovery    Mode] [Fastboot    Mode] [Normal      Boot]
[VOL_UP]Key Detect, current select:%d
Key Uber: Pressed / Released        ← "Uber" = the action button
pmic_detect_homekey
```

## Why every boot mode is a dead end

| Mode | Why it cannot help |
|---|---|
| **swdl** ("Wifi SWDL Boot Image") | `lk` looks up an image named `swdl`. Search for `swdl`/`dkernel` in `boot.img` (device tree), `brhgptpl_0..3` (partition tables) and `system.img`: **0 occurrences**. The mode exists in the code because `lk` is shared across products; the image does not exist on this one. Forcing `bootmode=97` would only fail to boot. |
| **dkernel** | same — no `dkernel` image |
| **factory.img** | the code itself says *"factory image doesn't exist in SD card"*; the Dot 3 has no SD slot |
| **Fastboot** | requires USB — **the product has no USB port** |
| **Recovery** | signed image, and no input channel (no USB, no network, no screen) |

## OTA — four independent layers, all measured

1. **TLS with a strict manifest** — no HTTP fallback. Measured: with a broken clock
   the update fails rather than downgrading.
2. **Per-model signing key** — Fire (`6D:7C:2D`), biscuit (`2D:84:43`),
   octave (`21:CC:97`) are distinct; doebrite has its own.
3. **Bounded verifier** — `minzip` uses `__builtin_add_overflow` on an *untrusted*
   field with the AOSP comment *"which could be exploitable"*, and returns
   `VERIFY_FAILURE`.
4. **Anti-rollback** — enforced by the bootloader.

`update_engine` (root) can write A/B partitions but is `disabled`, the payload is
signed, and its rollback trigger (`com.amazon.system.rollback`) is writable by
`init` only — no `.rc` or `.sh` ever sets it.

## SELinux

`enforcing`, imposed by `lk` itself:

* `/system/build.prop:109` and the ramdisk `default.prop` both carry
  `ro.boot.selinux=disable` — **both inert**;
* `lk` (at `0x41e1d470`) always writes `androidboot.selinux=enforce|permissive`,
  defaulting to **enforce**;
* `init` maps `androidboot.*` → `ro.boot.*` (write-once) *before* the property is read.

`seinfo --permissive` shows a single permissive type: `su`.

Property writers (from `sesearch` on the doebrite policy) — none reachable from the
network: `p2p_server_prop` ← csm_oobe_setup/init · `persist_service_atci_prop` ← init ·
`system_radio_prop` ← fosflags/init/radio/rild/system_app/system_server/usb_audio ·
`lab126_oobe_prop` ← amazon_headless_controller_oobe_app · `ahe_run_prop` ←
PuffinApp/dacd/init · `com.amazon.system.rollback` ← init only.

## The conclusion, stated plainly

**A userspace bug — even a root one — does not change the OS**, because:

* writing `/system` breaks dm-verity → no boot;
* writing `/boot` breaks RSA-PSS → `lk` refuses;
* writing `/misc` does not help, `lk` still verifies the target image;
* downgrading is blocked by anti-rollback.

The only object that unlocks a firmware replacement is **Amazon's RSA private key**.
