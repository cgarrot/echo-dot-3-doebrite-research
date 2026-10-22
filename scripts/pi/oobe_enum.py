#!/usr/bin/env python3
"""
oobe_enum.py — énumération des méthodes RPC du service OOBE (Thrift-JSON) de l'Echo.

Oracle : une méthode inconnue renvoie messageType=3 + "Invalid method name: 'X'".
Tout autre réponse (REPLY type 2, ou EXCEPTION avec un autre message) = méthode
qui EXISTE.

Enveloppe : [1, "<method>", 1, <seqid>, <args>]
Réponse   : [1, "<method>", 2|3, <seqid>, {<fieldId>: {"str"|"i32"|"tf"|"rec"|"lst": ...}}]

Usage:
    ./oobe_enum.py                      # liste complète (généreuse)
    ./oobe_enum.py --extra names.txt    # + noms depuis un fichier
    ./oobe_enum.py --target 10.201.126.241 --port 8080
"""
import argparse
import itertools
import json
import socket
import sys
import time

HOST, PORT = "10.201.126.241", 8080
PATH = ["/OOBE"]

# on ne teste JAMAIS de nom destructif / d'update
BLOCK = ("reset", "reboot", "factory", "wipe", "erase", "delete", "unregister",
         "deregister", "disable", "forget", "update", "ota", "upgrade",
         "shutdown", "clear", "remove", "terminate")

VERBS = ["get", "set", "start", "stop", "scan", "is", "has", "list", "read",
         "query", "request", "send", "submit", "configure", "connect",
         "register", "provision", "complete", "finish", "validate", "verify",
         "test", "check", "select", "choose", "fetch", "retrieve", "apply",
         "commit", "confirm", "save", "store", "load", "report", "notify",
         "wait", "poll", "begin", "open", "close", "add", "put", "post",
         "upload", "download", "sync", "join", "associate", "authorize",
         "authenticate", "exchange", "sign", "pair", "discover", "find",
         "resolve", "lookup", "probe", "ping", "hello", "echo"]

NOUNS = ["Wifi", "WiFi", "Wlan", "WifiNetwork", "WifiNetworks", "WifiScan",
         "WifiScanResults", "WifiScanResult", "ScanResults", "Network",
         "Networks", "NetworkConfig", "NetworkConfiguration",
         "NetworkCredentials", "WifiCredentials", "WifiCreds", "Credentials",
         "Ssid", "SsidList", "WifiConfig", "WifiState", "WifiStatus",
         "WifiInfo", "WifiDetails", "AccessPoints", "AccessPoint", "Connection",
         "ConnectionState", "ConnectionStatus", "NetworkState", "NetworkStatus",
         "NetworkInfo", "NetworkDetails", "Link", "LinkStatus", "Internet",
         "InternetStatus", "DeviceDetails", "DeviceInfo", "DeviceState",
         "DeviceStatus", "DeviceConfig", "SetupState", "SetupStatus",
         "SetupStage", "Setup", "ProvisioningState", "Provisioning",
         "ProvisioningStatus", "Registration", "RegistrationState", "Locale",
         "Locales", "Language", "Country", "CountryCode", "Region",
         "TimeZone", "Timezone", "Endpoints", "Endpoint", "Certificate",
         "Certificates", "Cert", "SoftwareVersion", "FirmwareVersion",
         "Version", "Capabilities", "FeatureFlags", "Features", "Volume",
         "Power", "Led", "LedState", "LedColor", "Identity", "AuthToken",
         "Token", "Tokens", "Session", "Handshake", "Account", "AccountDetails",
         "Customer", "Bootstrap", "Config", "Configuration", "Settings",
         "Time", "Clock", "Mac", "MacAddress", "SerialNumber", "Dsn",
         "DeviceType", "DeviceSecret", "Secret", "Pairing", "Bluetooth",
         "Ble", "Devices", "Neighbors", "Signals", "SignalStrength", "Rssi",
         "Channel", "Channels", "Beacon", "Country", "LocaleAndEndpoints",
         "DeviceCapabilities", "SetupDetails", "SetupInfo", "Oobe", "OOBE",
         "Provision", "ProvisionState", "WifiProvisioning", "NetworkError",
         "Diagnostics", "DebugInfo", "Logs", "Metrics", "Telemetry",
         "ActivationState", "ClaimState", "Ownership", "Owner", "Home",
         "Household", "Password", "Passphrase", "Psk", "Security",
         "SecurityType", "Auth", "Authentication", "Authorization"]

# noms connus / suspects (style Amazon, observés ou devinés)
EXTRA = """ping getDeviceDetails setLocaleAndEndpoints setupComplete completeSetup
finishSetup finalizeSetup startSetup beginSetup setupStatus getSetupStatus
getSetupState getState getStatus getWifiScanResults getWifiScanResult wifiScan
startWifiScan stopWifiScan scanWifi getWifiNetworks getAvailableNetworks
getScannedNetworks getNetworks getAccessPoints setWifiCredentials
setWifiCreds setNetworkCredentials setCredentials setWifiConfig
provisionWifi provisionNetwork provisionDevice registerDevice
getProvisioningState getRegistrationState setLocale setCountry setTimeZone
setEndpoints setCountryCode setLanguage getLocale getCountry getTimeZone
getEndpoints getCertificate getCertificates getSoftwareVersion
getFirmwareVersion getDeviceInformation getDeviceCapabilities getAuthToken
exchangeToken getToken signIn authorize authenticate handshake hello
getNetworkTime syncTime getTime performNetworkTest runNetworkTest
testNetwork getNetworkDiagnostics blink identify setLed setLedColor
getPowerState setPowerState getVolume setVolume getDiagnostics reportEvent
notifyEvent sendEvent getBootstrapInfo getAccountDetails getDeviceSecret
getDeviceInfo getWifiStatus getConnectionState getNetworkStatus
setWifiCredentialsAndConnect connectToWifi connectWifi joinNetwork
getAvailableWifiNetworks getWifiList listWifiNetworks submitSetup saveSetup
applySetup confirmSetup validateSetup getSetupResults getSetupResult
setDeviceConfig setDeviceName setRoom setRoomName setTimeZoneAndLocale
getDeviceDetailsV2 getSetupDetails getWifiScanStatus getScanState
startScan stopScan getScanResults getScanState scanState getScanStatus""".split()


def names(args):
    out = set(EXTRA)
    for v, n in itertools.product(VERBS, NOUNS):
        out.add(v + n)
        out.add(n[0].lower() + n[1:] + v[0].upper() + v[1:])  # style setupComplete
    if args.extra:
        with open(args.extra) as f:
            out.update(w.strip() for w in f if w.strip())
    return sorted(w for w in out if not any(b in w.lower() for b in BLOCK))


def call(method, seq, host, port, timeout=5):
    body = json.dumps([1, method, 1, seq, {}], separators=(",", ":"))
    path = PATH[0]
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           "Content-Type: application/x-thrift\r\nAccept: application/x-thrift\r\n"
           f"User-Agent: Java/THttpClient\r\nConnection: Keep-Alive\r\n"
           f"Content-Length: {len(body)}\r\n\r\n{body}").encode()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(req)
        buf = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            if b"\r\n\r\n" in buf:
                head, rest = buf.split(b"\r\n\r\n", 1)
                cl = 0
                for ln in head.split(b"\r\n"):
                    if ln.lower().startswith(b"content-length:"):
                        cl = int(ln.split(b":")[1])
                if len(rest) >= cl:
                    break
        s.close()
        return buf.split(b"\r\n\r\n", 1)[1].decode("utf-8", "replace")
    except Exception as e:
        return f"__ERR__ {type(e).__name__}: {e}"


def classify(resp):
    if resp.startswith("__ERR__"):
        return "net", resp
    if "Invalid method name" in resp:
        return "unknown", ""
    # 4070 (go-server) : un 404 n'est PAS une méthode valide
    if resp.lstrip().startswith("Error 404") or "Not Found\nNot Found" in resp:
        return "unknown", ""
    if '"str"' in resp or '"i32"' in resp or '"tf"' in resp or '"rec"' in resp:
        return "EXISTS", resp[:400]
    return "EXISTS?", resp[:400]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--path", default="/OOBE",
                    help="chemin de l'endpoint Thrift (défaut /OOBE ; ex. --path / "
                         "pour attaquer 4070 dans le même style)")
    ap.add_argument("--extra")
    ap.add_argument("--sleep", type=float, default=0.0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default="oobe_methods.txt")
    args = ap.parse_args()
    PATH[0] = args.path

    cand = names(args)
    print(f"[enum] {len(cand)} candidats -> {args.target}:{args.port} "
          f"({args.workers} workers)\n", flush=True)

    import threading
    from concurrent.futures import ThreadPoolExecutor
    lock = threading.Lock()
    out = open(args.out, "w")
    out.write(f"# {args.target}:{args.port}\n")
    out.flush()
    found, done = [], [0]
    t0 = time.time()

    def work(m):
        kind, detail = classify(call(m, 0, args.target, args.port))
        with lock:
            done[0] += 1
            if kind.startswith("EXISTS"):
                found.append((m, detail))
                out.write(f"{m}\t{detail}\n")
                out.flush()
                print(f"  \u2705 {m:38s} {detail[:160]}", flush=True)
            elif kind == "net":
                print(f"  \u26a0\ufe0f  {m}: {detail}", flush=True)
            if done[0] % 500 == 0:
                print(f"  ... {done[0]}/{len(cand)} ({time.time()-t0:.0f}s, "
                      f"{len(found)} trouvées)", flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(work, cand))
    out.close()
    print(f"\n[enum] {len(found)} méthodes valides en {time.time()-t0:.0f}s "
          f"-> {args.out}")
    for m, d in found:
        print(f"   {m}: {d[:200]}")


if __name__ == "__main__":
    main()
