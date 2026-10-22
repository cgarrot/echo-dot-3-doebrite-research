# OOBE_SPEC — service de setup local de l'Echo Dot 3 (`A30YDR2MK8HMRV`)

> **Suite de ce document : `BOOTSTRAP_SPEC.md`** — ce qu'il se passe *après* le
> provisioning (réseau, DNS, TLS SAN, volumes, OTA). Ici : uniquement le
> protocole local `/OOBE` de la phase de setup.

État : 2026-10-20. Sources : transcript proxy `oobe_traffic.log` (app Alexa ↔
Echo), énumération active depuis le Mac, sondes réseau. Device **depuis
provisionné** → `/OOBE` n'existe plus (voir §6).

---

## 1. Transport

| élément | valeur |
|---|---|
| endpoint | `POST /OOBE` sur `http://<echo>:8080` |
| proto | **Thrift TJSON** (JSON compact, une requête par connexion) |
| en-têtes app | `Content-Type: application/x-thrift`, `Accept: application/x-thrift`, `User-Agent: Java/THttpClient` |
| réponse | `Content-Type: text/plain`, `Connection: close`, `Allow: POST, OPTIONS` |
| particularité | l'app vise **`192.168.11.1:8080`** (IP canonique d'un AP de setup Amazon), pas l'IP réelle du device (`10.201.126.241`, aléatoire par session) |

### Enveloppe

```
requête  [1, "<method>", 1, <seqid>, { <fieldId>: <valeur> … } ]
réponse  [1, "<method>", 2, <seqid>, { "0": <résultat> } ]        # REPLY
exception[1, "<method>", 3, <seqid>, { "1": {"str": "<msg>"}, "2": {"i32": <type>} } ]
```

`messageType` : `1` = CALL, `2` = REPLY, `3` = EXCEPTION.
Types de valeurs : `{"str": …}`, `{"i32": …}`, `{"tf": …}` (bool),
`{"rec": { … }}` (struct), `{"lst": ["str", <n>, v1 … vn]}` (liste typée).

**Oracle d'énumération** : méthode inconnue →
`{"1":{"str":"Invalid method name: 'X'"},"2":{"i32":1}}` (type 1 = UNKNOWN_METHOD).
Tout autre message = méthode existante. C'est ce qui a permis de balayer 16 740 noms.

Deux familles d'erreurs à ne pas confondre :

| forme | sens |
|---|---|
| `200` + msgtype `3` + `Invalid method name` | méthode inexistante |
| `500` + `Error 500: Internal Server Error - API exception (15:1:100:0:1)` | méthode **existante**, rejet métier (ici : marché non supporté) |

---

## 2. Inventaire des méthodes (état actuel)

| méthode | args | réponse | note |
|---|---|---|---|
| `ping` | `{}` | `{"0":{"tf":1}}` | keepalive |
| `getDeviceDetails` | `{}` | `{"0":{"rec":{…}}}` | voir §3 |
| `setLocaleAndEndpoints` | `{"1":{"rec":{…}}}` | `{"0":{"i32":0}}` | voir §4 |
| `setupComplete` | `{}` | `{"0":{"i32":0}}` | ⚠️ terminal, voir §6 |

**Aucune autre méthode** dans : 16 740 candidats (59 verbes × 121 noms + style
`<nom><Verbe>`, ex. `setupComplete`), puis 1 458 candidats complémentaires
(`names_pass3.txt` : noms nus, gérondifs, `push/transfer/handoff/store/claim/bind`,
`wifiProvisioning`/`networkSetup`/`setSsidAndPsk`…).
**Aucune méthode Wi-Fi / credentials / réseau trouvée à ce stade.**

---


## 2bis. ⚠️ CORRECTION MAJEURE (APK) — les 11 méthodes qui manquaient

L'APK Alexa contient le service Thrift généré `com.amazon.device.setup.thrift.DopplerOOBE`
(**vérifié dans le binaire brut** : 313 occurrences de `DopplerOOBE`, 4 dex sur 19).
Liste complète des **15 méthodes** :

| méthode | rôle | statut |
|---|---|---|
| `ping` | keepalive | ✅ testée live |
| `getDeviceDetails` | infos device + cert | ✅ testée live |
| `setLocaleAndEndpoints` | marché + endpoints | ✅ testée live |
| `setupComplete` | fin de setup | ✅ testée live |
| **`getScanList`** | **scan Wi-Fi** | ❌ jamais devinée |
| **`connectToAP`** | **envoi SSID/PSK** | ❌ jamais devinée |
| **`connectToAPEx`** | idem + `APConnectExtendedInfo` | ❌ |
| `disconnectFromAP` · `forgetAP` | gestion AP connus | ❌ |
| `getKnownList` | réseaux enregistrés | ❌ |
| `getAlexaConnectionState` | état lien Alexa | ❌ |
| `getLinkCode` | code de liaison (CBL) | ❌ |
| `getOTADetails` | infos OTA | ❌ |
| `getRegistrationState` | état d'enregistrement | ❌ |
| `evaluateCaptivePortal` | portail captif | ❌ |

**Conséquence : ma conclusion « pas de méthode Wi-Fi → BLE » était FAUSSE.** Le
provisioning des credentials passe bien par ce service Thrift (`connectToAP`),
il n'a simplement jamais été trouvé : mon sweep de 16 740 noms utilisait des
verbes `get*/set*` — or la méthode s'appelle `connectToAP` et la liste des
réseaux `getScanList`. Aucune des 11 n'était dans le dictionnaire.

Structs d'arguments présents dans l'APK : `APConnectInfo`, `APConnectExtendedInfo`,
`APDetail`, `AlexaConnectionState`. Noms de champs confirmés dans le dex :
`ssid` (123), `password` (286), `psk` (24), `bssid` (19), `apList` (84),
`linkCode` (14), `securityType` (9), `signalStrength` (5).

**Astuce de forge** : le désérialiseur Thrift ignore les champs inconnus → on
peut envoyer *tous* les candidats aux ids 1..10 (`ssid`, `password`, `psk`,
`bssid`, `securityType`…) dans un seul appel ; le device ne lit que ce qu'il
attend. Ça évite de deviner le mapping exact des ids.

**IP de setup câblée dans l'app** : `10.201.126.241:8080` (littéral présent 4×
dans les dex, avec un log `initializeHttpClient - HttpClient initialized with
IP: 10.201.126.241 port: 8080`), **en plus** de `192.168.11.1:8080`. Donc
l'adressage du soft-AP n'est pas aléatoire : il est connu de l'app.

## 3. `getDeviceDetails` — carte des champs

```json
{"0":{"rec":{
  "1": {"str":"0009698494596"},                      // serial (13 chiffres)
  "2": {"str":"DC91BFBB724A"},                       // MAC (BSSID+2, bit local)
  "3": {"rec":{"1":{"str":""},"2":{"i32":0},"3":{"tf":0},
               "4":{"i32":0},"5":{"tf":0},"6":{"i32":0},"7":{"tf":0}}},  // état réseau
  "4": {"str":""},                                   // SSID courant (vide en setup)
  "5": {"rec":{"1":{"str":"-----BEGIN CERTIFICATE-----…"}}},  // cert client
  "6": {"str":"G091470502330EBE"},                   // DSN
  "7": {"tf":1},                                     // flag setup non terminé ?
  "8": {"lst":["str",16,"ja-JP","es-US","fr-FR","es-MX","en-CA","es-ES",
               "en-GB","en-AU","fr-CA","en-IN","it-IT","pt-BR","en-US",
               "de-DE","hi-IN","ar-SA"]},            // 16 locales
  "11":{"str":"A30YDR2MK8HMRV"},                     // deviceType
  "12":{"i32":2}                                     // révision hw / génération
}}}
```

Certificat du champ 5 : `CN=setup, O=Lab126, L=Cupertino, ST=CA, C=US`,
RSA-2048, auto-signé, `notBefore` 1970-01-01, **`notAfter` 1959-11-25 (UTCTime
`591125` ⇒ 1959) donc expiré** au sens RFC 5280 — détail vérifié à l'`openssl`,
voir `OOBE_TRANSCRIPT.md`. C'est le cert client
présenté à Amazon pendant le provisioning (clé privée non exposée).

---

## 4. `setLocaleAndEndpoints` — structure d'args

```
[1,"setLocaleAndEndpoints",1,<seq>,{"1":{"rec":{
    "1": {"str":"<locale>"},      // ex. "fr-FR"
    "2": {"str":"<marché>"},      // ex. "EU" / "CA"
    "4": {"str":"prod.<M>Amazon"},        // service
    "5": {"i32":443},
    "6": {"str":"prod.PANDA_<M>Amazon"},  // endpoint PANDA (MQTT/provisioning)
    "7": {"i32":443},
    "8": {"str":"prod.<M>Amazon"},
    "9": {"str":"prod.<M>Amazon"},
    "10":{"str":"prod.<M>Amazon"}
}}}]
```

Comportement observé : **`en-CA` / `prod.CAAmazon` → 500 `(15:1:100:0:1)`**,
alors que `en-US/US` et `fr-FR/EU` → `{"0":{"i32":0}}`.
Interprétation : le device est **régionalisé en fabrication** (NAR probable) et
refuse un marché hors de sa zone. Avec des args vides, l'erreur devient
`(15:1:100:42:1)` → les sous-codes distinguent « marché refusé » de
« arguments manquants », ce qui confirme que le handler est atteint dans les 2 cas.

---

## 5. Ce qui n'existe pas (résultats négatifs, utiles)

- **Un seul port ouvert** sur l'Echo : `8080`. Testés fermés : 22, 53, 80, 443,
  1883, 1900, 3000, 5000, 8008, 8009, 8081, 8443, 8883, 9000, 10000.
- Pas de mDNS/SSDP sur le mini-réseau ; pas d'autre service Thrift connu.
- Aucune méthode de scan Wi-Fi ni d'envoi de credentials dans le service `/OOBE`
  (cf. §2) → **hypothèse principale : le provisioning Wi-Fi (SSID/PSK) ne passe
  pas par HTTP, mais par BLE** (Wi-Fi Simple Setup / FFS). À confirmer.

---

## 6. Cycle de vie du device (important pour les manips)

1. **Anti-idle ~10-15 min** sans handshake valide → l'AP continue d'émettre mais
   le **plan de données est coupé** (plus de DHCP, plus d'ICMP, 8080 muet).
   Réassocier ne suffit pas.
2. **`setupComplete`** (appelé 17:08) laisse le device dans un état dégradé :
   TCP/8080 accepte encore le SYN mais **aucune réponse HTTP ni ICMP**.
   Signature mesurée : `nc -z` → open, `ping` → 100 % loss, HTTP → timeout.
3. **Réarmement** : maintien du bouton Action ~20-25 s jusqu'à l'anneau orange,
   puis nouvelle session (sous-réseau `10.201.126.240/28` retiré au hasard,
   Echo = `.241`, MAC `DC:91:BF:BB:72:4A`, BSSID `d6:91:bf:bb:72:4a`).

---

## 7. Outillage (Mac `~/echo_re/`, copie sur piveil `~/` ou `~/fakeap/`)

| fichier | rôle |
|---|---|
| `oobe_enum.py` | énumération de méthodes via l'oracle (`--extra`, `--workers`) |
| `OOBE_TRANSCRIPT.md` | transcript verbatim des 7 appels réels de l'app + cert décodé |
| `names_pass3.txt` | 1 458 candidats complémentaires |
| `rewrite_proxy.py` | proxy L7 qui **réécrit** `setLocaleAndEndpoints` (en-CA→en-US/EU) pour que l'app avance et révèle les méthodes suivantes |
| `fakeap/` | AP `TEST` + dnsmasq + tap TLS/HTTP + faux NTP (session 2) |
| `fakeap/hijack_192.168.11.1.sh` | DNAT de **tout** `192.168.11.1` → Echo (corrige « Device Not Discovered ») |
| `fakeap/fakeap_concurrent.sh` | tentative AP+STA — **échoue** : `EBUSY (-16)` |

---

## 8. Contraintes réseau du Pi (piveil)

- brcmfmac/BCM43430 : **pas de monitor mode** (`-95`), **pas de second vif**
  (`-16`) malgré la combo annoncée → **AP et client MITM sont exclusifs**.
  Pas de dongle USB → pas de 2ᵉ radio. Il faut séquencer les sessions.
- Pi 3B, `iw phy` : `managed + AP` mais `#channels <= 1`.
- DNS du Pi cassé (tailscale MagicDNS `100.100.100.100` muet) → `apt`/`curl` KO ;
  contourné en poussant les `.deb` depuis le Mac.

---

## 9. Pièges opérationnels vécus (à ne pas refaire)

- **`nmcli radio wifi` sur `disabled`** ⇒ NetworkManager ne peut pas associer
  wlan0, état `unavailable`, et le `rearm.sh` échoue silencieusement.
  Toujours `nmcli radio wifi on` après avoir rendu wlan0 à NM.
- **AP et client MITM sont exclusifs** : `iw dev wlan0 interface add wlan1
  type __ap` → `EBUSY (-16)` ; pas de dongle USB sur piveil ⇒ une session =
  un rôle.
- **`pkill -f <motif>`** tue aussi la session SSH qui contient le motif dans sa
  ligne de commande (vécu : a tué `tap.py` en pleine capture, tout le 80/443
  blackholé). Utiliser un PID.
- **« Device Not Discovered »** : l'app vise `192.168.11.1` (IP canonique d'un
  AP de setup Amazon) et non l'IP réelle du device. Une règle `REDIRECT` sur
  `--dport 8080` ne suffit pas pour ses sondes de découverte → DNAT de **tout**
  (tcp+udp, tous ports) via `fakeap/hijack_192.168.11.1.sh`.
- Le **téléphone** rejoint volontiers l'AP de test (il a Internet via NAT,
  contrairement à l'AP de setup) et casse alors le canal app↔Echo.

## 10. Prochaines actions (par ordre de valeur)

1. Faire avancer l'app avec `rewrite_proxy.py` → capturer les méthodes suivantes
   (ou constater qu'il n'y en a pas → BLE).
2. Si rien ne sort : **scan BLE** pendant le setup (le Mac est à portée, `bleak`),
   chercher un service GATT d'écriture SSID/PSK.
3. Rejouer `names_pass3.txt` (1 458 noms) en 3 workers max après réarmement.
4. Session « passerelle » : AP `TEST`, l'Echo le rejoint, on capture DHCP/DNS/SNI/NTP
   avec `fakeap_up.sh` (le tap ne termine pas TLS → pas de problème de pinning).
5. Hardware (plus tard) : MT8163 → **BROM download mode** via `mtkclient`
   (pas de vérif de signature en BROM) = dump eMMC complet.

## ★ COUVERTURE COMPLÈTE DE L'API OOBE (mesurée, nuit du 21/10)
Les 15 méthodes sont désormais TOUTES exécutées sur device réel :

| méthode | résultat mesuré |
|---|---|
| ping | `{"0":{"tf":1}}` |
| getDeviceDetails | identité + cert éphémère (champ 5) |
| getScanList | liste APDetail de l'environnement |
| getKnownList | réseaux en mémoire (RSSI signé, 0 = jamais vu) |
| setLocaleAndEndpoints | `{"0":{"i32":0}}` si marché accepté |
| connectToAP | `{"0":{"i32":0}}` = NO_ERROR (7-8 s), 30 s = assoc KO |
| connectToAPEx | idem + APConnectExtendedInfo |
| forgetAP(ssid) | `{"0":{"i32":0}}` — accepte même un SSID inconnu |
| disconnectFromAP | `{"0":{"i32":0}}` |
| getOTADetails | **répond en ~55 s** → `{"1":{"lst":["rec",0]}}` (liste vide) |
| getAlexaConnectionState | **i32:3 = UNKNOWN** (enum 1=DISCONNECTED, 2=CONNECTED, 3=UNKNOWN) |
| setupComplete | `{"0":{"i32":0}}` — ⛔ DESTRUCTEUR (voir PROVEN.md) |
| getLinkCode | 500 (10:1:108:0:5) — exige le cloud |
| getRegistrationState | 500 (12:1:107:22:1) — exige le cloud |
| evaluateCaptivePortal | 500 (14:1:111:9:4) — exige le réseau |

### Deux méthodes utilisaient la PATIENCE, pas un argument
`getOTADetails` et `getAlexaConnectionState` gèlent en apparence mais **répondent
après leur timeout réseau interne (~55 s)**. La leçon : sur ce firmware, un
timeout court ne veut pas dire "méthode cassée" — il faut réessayer avec 90 s
avant de conclure. Ça a coûté plusieurs fausses conclusions cette nuit.
