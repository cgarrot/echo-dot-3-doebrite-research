# 05 — Bluetooth / WhisperJoin

## Why this surface matters

The Dot 3 has a Bluetooth radio and, in setup mode, advertises **WhisperJoin** —
Amazon's provisioning protocol. Unlike the OOBE (HTTP), this is a completely
different code path and had never been documented publicly for this device.

## The whole protocol was implemented from scratch

No phone, no Alexa app. A Python client over `bleak`, driven from a Linux laptop.

### GATT layout (from `BleConstants.java` in the OOBE APK)

```
Service  WhisperJoin :  0000FE00-0000-1000-8000-00805F9B34FB
Status               :  cf011df7-07ee-40b7-a71d-3f2eb6e0d040   read, notify
StartProvisioningReq :  cf011df8-07ee-40b7-a71d-3f2eb6e0d040   write
StartProvisioningRsp :  cf011df9-07ee-40b7-a71d-3f2eb6e0d040   read, notify
ProvisioningCommand  :  cf011dfa-07ee-40b7-a71d-3f2eb6e0d040   write
CommandResponse      :  cf011dfb-07ee-40b7-a71d-3f2eb6e0d040   read, write, notify
Notification         :  cf011dfc-07ee-40b7-a71d-3f2eb6e0d040   read, notify
```

Device advertises as `Echo Dot-EBE` with a **random BLE address that rotates** —
so scan-and-connect must happen in a single pass, keeping the `BLEDevice` object.

### Wire formats (all protobuf)

```
StartProvisioningRequest   = { requestId : sint32 }        ← ZIGZAG, not int32 LE
StartProvisioningResponse  = { requestId : sint32, status : sint32 }
                                status 0 = GRANTED, 1 = busy, 2 = internal error

WhisperJoinBlePacket       = { 1: packetKey int32, 2: chunkIndex int32,
                               3: additionalChunks bool, 4: payload bytes }
ProvisioningCommand        = { 1: uuid bytes(16, LITTLE-ENDIAN LSB-first),
                               2: data bytes }
```

**Two mistakes cost the most time here:**

1. sending `requestId` as a raw little-endian int32 → the device silently ignored it
   (it uses `readSInt32`, i.e. zigzag varint);
2. waiting for a *notification* on `CommandResponse` instead of **reading** the
   characteristic, then sending a `createNextResponsePacket` when
   `additionalChunks` is set.

Once both were fixed:

```
★★★ 6F:18:73:C4:77:BA 'Echo Dot-EBE'
connecte=True
→ requestId=1599004818 payload=08 a4 82 f7 f4 0b
★[START_RSP] 08 a4 82 f7 f4 0b 10 00
   → reqID=1599004818 status=0 (GRANTED)
```

### Commands available

```
RETRIEVE_SUPPORTED_COMMANDS  22947d92-c4bb-47dc-9c00-23679575b5a5
RETRIEVE_SUPPORTED_EVENTS    22947d93-…
RETRIEVE_EVENT_OBJECT        22947d94-…
STOP_PROVISIONING            22947d95-…
PROVISIONING_COMPLETE        6cd1d7e1-c37b-46d7-b268-635186f9aca1
INITIATE_VISIBLE_NETWORK_SCAN c95ec710-f36f-4cd9-9879-1fa22f7eb110
GET_VISIBLE_NETWORKS         c95ec711-…
SAVE_CONFIGURED_NETWORK      c95ec713-…
CONNECT_TO_CONFIGURED_NETWORK c95ec714-…
DELETE_CONFIGURED_NETWORK    c95ec715-…
DELETE_ALL_CONFIGURED_NETWORKS c95ec716-…
REFRESH_WIFI_CONNECTION      c95ec717-…
REGISTER_WITH_CODE_BASED_LINKING c95ec718-…
UNAUTHENTICATED_ECDHE        cc6ad206-b8a2-4710-bf23-e9d7ae3e2d0b
AUTHENTICATED_ECDHE          2caff8db-7767-448c-b12b-eac29589e12b
SET_CONFIGURATION            ac796df3-dd27-4459-a753-44efb4a9f195
GET_CONFIGURATION            dd7ad30e-4a09-4252-98c5-bc159f6bd2f2
GET_DEVICE_DETAILS           bfae2d87-3937-42ec-8016-7ea13542c397
```

## The wall: CBL cloud authentication

Every useful command returns (sint32, after zigzag decoding):

```
0 = SUCCESS · 1 = internal error · 2 = UNKNOWN COMMAND
3 = serialization error · 4 = packet verification error
5 = UNAUTHORIZED PROVISIONER        ← what we get, always
```

`UNAUTHENTICATED_ECDHE` with a valid P-256 SubjectPublicKeyInfo is also refused.

**The decisive discovery is the command name `REGISTER_WITH_CODE_BASED_LINKING`
and its status map:**

```
-11 TOKEN_INVALID   -12 TOKEN_EXPIRED
-13 SERVER_NOT_REACHABLE        -14 SERVER_ERROR
```

**⇒ authentication is a CBL token issued by Amazon's cloud, not a printed code.**

This settles a question that mattered: the barcode PIN (`[a-zA-Z0-9]{8,12}`,
extracted from `RegexBarcodeParser`) is used by *other* Amazon device families.
On an Echo, a physical barcode would not have helped.

## Protocol crypto (for completeness)

```
JPAKE (EC, prime256v1) password = barcodePin   ← for barcode-based devices
Authenticated ECDHE  + ProvisionableDeviceAuthenticationData = cert chain + ECDSA sig
```

The device authenticates **itself** to the client with a certificate chain and a
signature; the client is authenticated by the CBL token at the cloud level.

## Artefacts

- `scripts/ble/` — the full client: scan, START, commands, chunked response reader
- Working transcript: `START_RSP = 08 … 10 00` (GRANTED), followed by 17 commands
  all returning status 5 or 2.
