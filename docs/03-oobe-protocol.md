# 03 — OOBE protocol (port 8080, setup mode)

## Transport

```
POST http://10.201.126.241:8080/OOBE
Content-Type: application/x-thrift
Body is a JSON **array**, not an object:

    [seq, "methodName", 1, 1, {args}]
```

Response:

```
    [seq, "methodName", 2, 1, {"0":{"rec":{…}}}]
```

**The JSON parser is non-conformant**: it rejects whitespace after commas
(`[1, "ping"]` → HTTP 400) but accepts newlines. Always serialise compact:
`json.dumps(p, separators=(',',':'))`.

Errors come back as HTTP status plus a numeric path, e.g.
`Error 500: Internal Server Error - API exception (6:1:101:9:4)`.

## Methods enumerated (15)

```
ping · getDeviceDetails · getScanList · connectToAP · forgetAP
setLocaleAndEndpoints · evaluateCaptivePortal · getLinkCode · getOTADetails
setupComplete · getDeviceStatus · … (see evidence/SYNTHESE.md §OOBE)
```

`TReturnErr` enum:

```
0 NO_ERROR   1 UNKNOWN   2 INVALID_ARGUMENTS   3 BAD_PASSWORD
4 TIMEOUT    5 SERVER    6 ROUTE_CONFLICT      7 CAPTIVE_PORTAL_ERROR
8 CONNECTED_LOCAL         9 DELAYED_CONNECTION_STARTED
```

## The ephemeral setup certificate

The setup certificate is regenerated every setup session. The full WPA2 recipe is
in `evidence/PROVEN.md`; condensed:

```python
d = json.loads(post([1,"getDeviceDetails",1,1,{}]))
pem = d[4]['0']['rec']['5']['rec']['1']['str']      # field 5 = PEM certificate
enc = subprocess.run(["openssl","smime","-encrypt","-aes256","-binary",
                      "-outform","PEM", certfile], input=b"password")
post([1,"connectToAP",1,1,{"1":{"rec":{
    "1":{"str":"SSID"}, "2":{"i32":3}, "3":{"rec":{"1":{"str":enc}}}}}}])
```

`field 2 = 3` selects WPA2. The password is SMIME-encrypted to the device's
ephemeral certificate; the device decrypts it with the matching private key.

## Server behaviour worth knowing

| Observation | Detail |
|---|---|
| **Single-threaded** | `getOTADetails` blocks the whole server ~90 s (no uplink) |
| **Mono-threaded DoS** | a `setLocaleAndEndpoints` + `getLinkCode` pair can block ~60 s |
| **Broken clock** | the device clock is wrong; any TLS validation fails until NTP |
| **No uplink in setup** | `evaluateCaptivePortal` and `getOTADetails` time out; the *phone* is expected to do network work |

## The stack behind it (this is the important part)

```
/system/bin/oobed                       521 948 B   native, user `oobe`
  → libcivetweb.so                       75 832 B   HTTP front-end (C)
  → libdoppleroobe.so                   186 404 B   OOBE service (Apache Thrift C++)
      → libthrift.so                    370 256 B   ★ version 0.9.0 (2013)
  + libace_wifimgr / ace_maplite / ace_ffs / ace_netmgr / libcurl / libcrypto
```

Symbols confirm the protocol implementation:

```
OOBE::DopplerOOBEProcessor::dispatchCall / process_ping / process_forgetAP
OOBE::DopplerOOBEClient::connectToAP / getLinkCode / getScanList
OOBE::OTADetails::read / DeviceDetails::read / APConnectInfo::read
apache::thrift::protocol::TProtocol
```

**`libthrift 0.9.0` is inside the CVE-2019-0205 affected range.** That is finding #1.
See `08-findings.md`.
