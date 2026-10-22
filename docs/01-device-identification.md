# 01 — Device identification

## Why this matters first

Two Amazon products share the same OTA package name suffix:

```
update-kindle-octave-NS65741_user_8149_0013222532484.bin     449 MB   Echo Studio
update-kindle-doebrite-NS65741_user_8149_0013222532484.bin   117 MB   Echo Dot 3 w/ clock
```

Analysing the wrong one wastes days and produces false conclusions. We know because
it happened: an early analysis of the `octave` OOBE APK concluded that `oobed`
"does not exist on doebrite". That conclusion was **wrong**, and was only overturned
by disassembling the actual system image (see `09-methodology.md`).

**Always identify by `deviceType`, never by firmware file name or SWVersion.**

## Identity of the tested unit

| Field | Value |
|---|---|
| DSN | `G091470502330EBE` |
| deviceType | `A30YDR2MK8HMRV` |
| productId | `0013222532484` |
| Wi-Fi MAC | `DC:91:BF:BB:72:4A` |
| BLE name (setup) | `Echo Dot-EBE` |
| Setup AP | `Amazon-EBE`, BSSID `D6:91:BF:BB:72:4A`, gateway `10.201.126.241/28` |
| Matter operational | `35E0AC61C6C83219-079B277EE4E46151` |

`getDeviceDetails` on the setup AP returns, unauthenticated:

```json
[1,"getDeviceDetails",2,1,{"0":{"rec":{
  "1":{"str":"0013222532484"},          // productId
  "2":{"str":"DC91BFBB724A"},           // MAC
  "5":{"rec":{"1":{"str":"-----BEGIN CERTIFICATE-----…"}}},  // ephemeral setup cert
  "6":{"str":"G091470502330EBE"},       // DSN
  "7":{"tf":1},
  "8":{"lst":["str",17,"ja-JP","es-US","hi-IN","fr-FR", …]},
  "11":{"str":"A30YDR2MK8HMRV"},        // deviceType
  "12":{"i32":2}}}}]
```

Note there is **no firmware version field**. The setup certificate is regenerated
per setup session (`CN=setup`, `O=Lab126`, valid from 1970 — the clock is broken).

## Hardware

```
SoC        MediaTek MT8167
Userspace  100 % 32-bit (armeabi-v7a), Android 7.1.2 / Fire OS 6 (SDK 25)
NAND       SLC 4 Gbit = 512 MiB (MT29F4G08ABAFAH4)
Kernel     0x40008000   ← not 0x40080000 as commonly cited
DTBs       13 variants: Crumpet(4) · Doebrite(5) · Pascal(1) · Croissant(3)
           no Octave, no Megalo
USB        none on the product (power jack + 3.5 mm line-out)
           the MT8167 BSP does contain f_acm/f_adb/configfs gadget code — unwired
```

## Partition layout (from the fstab inside the ramdisk)

```
/dev/block/system   /          squashfs ro verify,slotselect
/dev/block/cache    /cache     ubifs
/dev/block/userdata /data      ubifs
/dev/block/persist  /persist   ubifs
MTD: nvram proinfo uboot uboot2 misc boot recovery logo expdb seccfg tee1 tee2 idme_nand
```

**No `swdl`, `dkernel`, or `factory` partition exists.** This kills the
"Wi-Fi SWDL Boot Image" hypothesis later (see `06-bootloader-and-ota.md`).

## The system image *is* the ramdisk

`system.img` is a squashfs (`hsqs`) that contains `/system`, `/sbin/adbd`, `/etc`,
and `vendor → /system/vendor`. There is no separate ramdisk: the kernel's initramfs
**is** the squashfs root. This is unusual and matters for anyone attempting to
repack the OS.
