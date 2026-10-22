# 04 — Matter

## Commissioning succeeded

The device was commissioned into a Matter fabric using a self-built controller
(`chip-all-clusters-app` from the public `connectedhomeip` SDK):

```
[ZCL] OpCreds: Received an AddTrustedRootCertificate command
[ZCL] OpCreds: AddTrustedRootCertificate successful.
[ZCL] OpCreds: Received an AddNOC command
[ZCL] OpCreds: successfully created fabric index 0x1 via AddNOC
[FS]  GeneralCommissioning: Received CommissioningComplete
```

The Alexa app then displayed the fake device's endpoints as
**"first light", "first remote", "second light"**, and the Echo began polling them:

```
IM:ReadRequest → IM:ReportData (in a loop) + StandaloneAck
Cluster=0x0028 (Basic Information) AttributeId=0x0003 (ProductName) …
```

## Three fuzz vectors

| # | Vector | Result |
|---|---|---|
| 1 | `--product-name` of 4 000 then **60 000 bytes** | Echo reads it (≈50 fragmented ReportData), **survives** |
| 2 | Patch `TLVWriter::WriteElementWithData` to declare `dataLen-100` while writing `dataLen` | our app rolls back (`No memory`), nothing is sent |
| 3 | Patch `TLVWriter::PutString` to declare `len-1` while writing `len` | **session established, ReportData delivered, Echo ACKs, no crash** |

**Vector 3 is the informative one.** The first attempt (vector 2) silently failed
because `WriteElementWithData` is also used by the **CASE handshake**: our Sigma2 was
malformed and the Echo rejected it with

```
CHIP Error 0x54: Invalid CASE parameter
```

so the fuzz could never reach attribute reads. Restricting the patch to
`PutString` (UTF8 strings only, never used by CASE) let the session establish and
delivered a deliberately desynchronised TLV to the Echo's parser.

**Conclusion: the Echo's Matter TLV parser is bounded and robust.**

## The blue-ring episode

The Echo rebooted (~10 min offline) after the first burst of desynchronised TLVs,
then came back **with the Matter fabric intact** (`_matter._tcp` re-announced as
`35E0AC61C6C83219-079B277EE4E46151`). So it was a **service restart, not a wiping
update** — but the crash was never reproduced in the third campaign, so we do not
claim it as a finding.

## Noise

`getOTADetails` blocked the single-threaded OOBE server for ~90 s, unrelated to
Matter. Documented because it is a trivially reachable availability issue.
