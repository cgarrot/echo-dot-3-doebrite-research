> # ⚠️ AVERTISSEMENT — IDENTITÉ PRODUIT NON RÉSOLUE (2026-10-21, fin de campagne)
>
> **Une relecture externe a établi que le firmware analysé n'est pas celui de l'appareil.**
>
> ```
> NOTRE APPAREIL (mesuré via getDeviceDetails) : deviceType = A30YDR2MK8HMRV
> archive OCTAVE (celle qu'on a analysée)      : ro.product.config.type = A3RBAYBE7VM004
> paquet DOEBRITE (Dot 3 avec horloge)         : ro.product.config.type = A30YDR2MK8HMRV
>
> ⇒ L'appareil est un DOEBRITE. L'archive analysée est OCTAVE = l'Echo Studio.
> ```
>
> **Deux paquets distincts portent le même numéro `0013222532484`.** Ce numéro est
> **commun aux deux produits** — il ne discrimine rien. Le champ qui discrimine
> (`deviceType`) était dans ce document depuis le premier jour et n'a jamais été
> confronté à l'archive. **Erreur de méthode : un identifiant partagé utilisé comme
> s'il était unique, alors que l'identifiant unique était sous nos yeux.**
>
> ## Ce qui TOMBE (conclusions matérielles issues d'octave)
> - `LK_SECURITY_MODEL.md` et F17 → binaire `lk` d'**octave** (241 664 o), pas le nôtre (237 568 o)
> - La topologie LED « 2× LP5036, 24 modules » → venait de l'**image octave**, pas d'une mesure
> - « system = 1,57 GiB ext4 » → c'est la Studio ; le Dot a **~130 Mio en squashfs**
> - La « correction stockage » eMMC 4 Go → **fausse** ; c'est une **NAND SLC 4 Gbit = 512 Mio**
> - ~~Les adresses de chargement `0x40080000`~~ → **CORRIGÉ : `0x40008000`** (vérifié sur l archive doebrite)
> - La règle firewall du port **1030** → citée depuis **octave**, à retrouver dans doebrite
>
> ## Ce qui SURVIT
> - **Toutes les mesures faites SUR l'appareil** : OOBE 8080 (211 cas), provisioning,
>   scan réseau, scan 1030 avec témoin, EAPOL, injection 802.11, dnsmasq/DHCP en conditions réelles
> - Les **résultats offensifs mesurés** : DoS NTP, DoS QUIET IE
> - L'**architecture** commune (mt8167, `com.amazon.echo.csm.oobe`, `adbd` en SU, `ro.adb.secure=1`)
>
> ## La piste neuve, sur le BON binaire
> **`SWDL`** — dans le `lk` de **doebrite**, le sélecteur de démarrage compare à **97 (0x61)**,
> cherche une partition **`swdl`**, et charge une image via les **mêmes routines de vérification**
> que le boot normal. Diagnostics : « Wifi SWDL Boot Image ». **Un mode de téléchargement par
> Wi-Fi, avec contrôle d'image.** C'est la piste la plus concrète du dossier, et elle n'est
> pas encore analysée.
>
> **Ne pas diffuser de conclusion matérielle avant ré-analyse sur l'archive doebrite.**

---

# SYNTHESE — état consolidé de l'opération Echo Dot 3 (octave)

> Fichier agrégateur. Chaque agent tient son propre `FINDINGS_<AGENT>.md`.
> Ce document donne la vue d'ensemble et renvoie aux fichiers de détail.
> Dernière mise à jour : fin de session du 2026-10-21.

---

## 0. LE TOURNANT DE LA SESSION

On a cru pendant 20 heures que le firmware était **inobtenable** (device à jour,
manifeste OTA en TLS strict sans fallback, aucune `.bin` publique).
**C'était faux.** L'utilisateur a trouvé deux OTA `octave` publiques, dont
**exactement la version de son appareil** :

```
update-kindle-octave-NS65741_user_8149_0013222532484.bin   449 Mo
   ota.prop : product=octave · version_number=0013222532484
              version_name=Fire OS 6574.1 (NS65741/8149)
   ⇒ IDENTIQUE au SWVersion renvoyé par getDeviceDetails sur le device

update-kindle-octave-NS6575_user_8338_0013323244164.bin    453 Mo (version suivante)
```

Format **OTA A/B** (`payload.bin`, update_engine) — pas `system.new.dat`.
Déballé par `payload_dump.py` (ag2) et `payload_dumper` :

```
system.img      1,7 Go  (ext4, monté sur t3600:~/oct_mnt)
boot.img        9,9 Mo
lk.img          236 Ko   (bootloader)
preloader.img   148 Ko   (preloader MediaTek)
tee1/tee2.img   2,2 Mo   (TrustZone)
```

**Conséquence : on a le device complet hors ligne.** Tout ce qui suit en découle.

---

## 1. IDENTITÉ DU DEVICE (mesurée sur le matériel)

| Champ | Valeur |
|---|---|
| Modèle | Echo Dot 3 avec horloge |
| Codename | **octave** |
| DSN | G091470502330EBE |
| deviceType | A30YDR2MK8HMRV |
| MAC Wi-Fi | DC:91:BF:BB:72:4A |
| SoC | **MT8167** |
| Android | **7.1.2** (SDK 25) — Fire OS 6 |
| Userspace | **100 % 32 bits** (`armeabi-v7a`, pas de `/system/lib64`) |
| SWVersion | 0013222532484 |

---

## 2. LA CARTE COMPLÈTE DES PORTS (source : `/system/bin/firewall.sh`)

Amazon documente lui-même ses règles. **C'est la découverte structurelle majeure.**

| Port | Service | Note |
|---|---|---|
| **4070** | Spotify Connect login server | ouvert en mode enregistré (HTTP, 404 partout) |
| 4071 | Whatify Spotify Connect | |
| **16384-32767** | **SIP Calling** (VoIP) | |
| 40317 | TPH / phd | télémétrie |
| **55442-55446** | **WHALEXA** (Whole Home Audio, `whad`) | **mTLS à CA privée** — mesuré : `alert 48 unknown_ca` |
| **5540 / 5541** | **MATTER** (UDP + TCP) | `# Matter use` |
| **5555** | **ADB over WiFi** | voir §4 |
| **1030** | **« Octave remote player »** | **FERMÉ — mesuré sur la bonne interface** : scan de 10.201.126.241 avec témoin 8080 (OUVERT) ⇒ 1030 **fermé**. Aucun service ne le bind malgré la règle firewall |
| 1900 / 50000 | UPnP / SSDP | |
| 5353 | mDNS (avahi, Spotify Connect) | |
| 6667 | Tuya (ampoules) | |
| 50020-50040 | SSDP LifX / TPLink / Yeelight | |
| 5000 | CMB | |

**Ports du mode setup** : 8080 (OOBE thrift) · 53 (dnsmasq) · 67 (DHCP).
**Ports du mode enregistré (mesurés par scan 1-10000)** : 1080, 4070, 8888, 5541 —
**l'ensemble change selon l'état du device**.

---

## 3. LES DAEMONS, LEURS VERSIONS, LEURS PRIVILÈGES

**~30 services tournent en `root`.** Les plus intéressants :

| Daemon | Version | Année | Écoute | Verdict |
|---|---|---|---|---|
| **dnsmasq** | **2.51** | **avril 2010** | UDP/53 (setup) | TCP bloqué par firewall · amont inexistant en setup ⇒ CVE-2017-14491 **non atteignable** (voir §5) |
| **avahi-daemon** | **0.6.31** | **2011** | UDP 5353 | CVE connues = **DoS seulement** |
| dhcpcd | 6.8.2 | 2015 | 67 | **CVE-2016-1503 corrigée dans ce binaire** (bornes présentes aux deux points d'usage, désassemblé — §12) |
| hostapd / wpa_supplicant | — | — | — | robustes (7 modes EAPOL rejetés) |
| otbr-agent | 1.1.1 | 2024 | — | Thread Border Router |
| SmartHomeChipd | — | — | 5540/5541 | Matter **contrôleur** |
| **csm.oobe** | — | — | **8080** | **APK** `com.amazon.echo.csm.oobe` (5 541 classes Java + `libcivetweb.so` 75 832 o en JNI). **L'architecture OOBE a été refondue depuis le Dot 2** : `oobed` (239 220 o) + `liboobed.so` + `libconnection_utils.so` existent sur **biscuit** et sont **absents sur octave** |
| wifid | — | — | — | root, expose `createCustomPacketFilter` via LIPC |
| otaalexa | — | — | — | **déclaré dans init.rc mais ABSENT de /system** (anomalie) |

---

## 4. ADB OVER WIFI — LA PISTE LA PLUS DIRECTE

```
init.mt8167.usb.rc :
    on boot
        ...
        # Enable adb over network
        setprop service.adb.tcp.port 5555        ← INCONDITIONNEL, à chaque boot

init.usb.rc :
    service adbd /sbin/adbd --root_seclabel=u:r:su:s0    ← contexte SELinux SU = ROOT
        class core
        socket adbd stream 660 system system
        disabled                                          ← MAIS désactivé

firewall.sh :
    iptables -A INPUT  -i $interface -p tcp --dport 5555 -j ACCEPT   ← PORT OUVERT
```

**État mesuré : 5555 est FERMÉ** (le service `adbd` est `disabled` et n'est démarré
que par des triggers USB — or le port micro-USB du Dot 3 est **alimentation seule**,
les lignes data ne sont pas connectées au SoC).

**⇒ Un déclencheur ne suffirait PAS** : `ro.adb.secure=1` exige une clé RSA déjà approuvée
dans `/data/misc/adb/adb_keys`, et sur un appareil sans écran aucune approbation n'est
possible. Il faudrait donc **root pour autoriser ADB, et ADB pour avoir root** — cercle
vicieux. **PISTE FERMÉE** (voir §10 chaîne n°1).

---

## 5. POURQUOI dnsmasq 2.51 NE MARCHE PAS (mesuré, pas supposé)

CVE-2017-14491 (heap overflow 1-2 octets, `add_resource_record` → `answer_request`)
exige **deux conditions** :
1. un serveur DNS **amont** contrôlé par l'attaquant,
2. que dnsmasq **cache** la réponse piégée puis la re-serve.

**Mesures sur le device en setup :**
```
UDP/53  → répond (rcode 5 = REFUSED pour tout nom hors config)
TCP/53  → TIMEOUT (bloqué par le firewall) ⇒ CVE-2015-3294 inatteignable
name=api.amazon.com (dans address=) → rcode 0, an=1   ✅ chemin local atteint
16 payloads forgés (QDCOUNT élevé, noms 255 o, EDNS 65535, multi-questions)
   → AUCUN crash, dnsmasq répond toujours
```
**Le device n'a aucun amont en setup** : ses 128 entrées `address=` sont locales,
tout le reste est REFUSED. **Rien à empoisonner, rien à cacher.**

---

## 6. LES PORTES FERMÉES (avec leur preuve)

| Surface | Verdict | Preuve |
|---|---|---|
| OOBE thrift 8080 | fermée | 211 cas, parseur durci |
| OOBE chemins (`/debug/pprof`, `/status`, `/v2/*`…) | fermée | 25 chemins × GET/POST : **`/OOBE` est la seule route**, GET rejeté globalement (405) |
| CMS / X.509 / TJSON | fermée | 168 + 43 cas |
| Manifeste OTA | fermée | TLS strict **sans fallback** (mesuré : horloge cassée → échec, pas de downgrade HTTP) |
| Signature OTA | fermée | **une clé par modèle** : Fire `6D:7C:2D` · biscuit `2D:84:43` · **octave `21:CC:97`** |
| Parseur minzip | fermée par conception | `__builtin_add_overflow` sur champ *untrusted* + 5 contrôles de bornes |
| Anti-rollback | fermé | assert de version dans updater-script |
| BLE FFS | fermée | cloud-gated, JPAKE off |
| Driver Wi-Fi (VHT_CAP len=0) | atteint, inexploitable | 900 longueurs × 3 passes, tailroom absorbe |
| RSN / CVE-2020 MediaTek | fermée | salve brute en injection : 8 pings OK |
| EAPOL / wpa_supplicant | fermée | 7 modes malformés rejetés |
| dhcpcd 6.8.2 | fermée | bornes d'options présentes (désassemblage §12) + 11 familles de fuzzing sans crash |
| SOCKS5 1080 | **pas un pivot** | `0509` sur **toute** cible, y compris loopback |
| Bluetooth Classic | fermée | inquiry 45 s depuis le Mac : aucun appareil |
| Ports 5541/8888 (inconnus) | identifiés | **5541 = Matter**, 8888 = custom opaque |
| WhisperJoin `/v2/*` | fermée | testé sur 5541/8888/4070/80 → reset ou 404 |

---

## 7. LES RÉSULTATS OFFENSIFS RÉELS

| # | Trouvaille | Portée |
|---|---|---|
| **1** | **DoS radio par QUIET IE (802.11h)** | un AP malveillant fait taire la radio de tout Echo à portée, 67 s+, latch 255 cycles |
| **2** | **DoS persistant par empoisonnement NTP** | on contrôle l'horloge (preuve : le device affiche la date qu'on sert) → TLS cassé → appareil inutilisable ; **réversible** (par NTP correct ou reset) |
| **3** | **L'anti-rollback d'abord cru absent** | l'updater-script fait un assert de version |
| **4** | **Bugs driver Wi-Fi** | 2 lectures OOB (VHT_CAP 4 o, QUIET 6 o) — théoriques, non réalisables |
| ~~5~~ | ~~dhcpcd~~ | **RETIRÉ : auto-réfutant.** Les underwrite/overread des options 119/121 sont **corrigés en 6.8.2**, et notre binaire **est** 6.8.2 ⇒ ce n'est pas un résultat offensif sur cet appareil. Conservé seulement comme note historique d'audit |
| **6** | **OOBE : parseur JSON non conforme** | rejette les espaces après virgule (`[1, "ping"...]` → 400) mais accepte les newlines — bug de robustesse, pas d'élévation |

---

## 8. CE QUI RESTE OUVERT (par ordre de réalisme)

| # | Piste | Pourquoi c'est vivant | Effort |
|---|---|---|---|
| ~~1~~ | ~~Déclencher `adbd`~~ | **FERMÉE** : `ro.adb.secure=1` + `ro.debuggable=0` + pas d'écran pour approuver la clé RSA. Un shell adb exigerait une clé pré-provisionnée dans `/data/misc/adb/adb_keys` ⇒ root préalable (cercle vicieux) | — |
| ~~2~~ | ~~Analyser `oobed`~~ | **SANS OBJET** : `oobed` n'existe pas sur octave. Le serveur 8080 est l'APK `com.amazon.echo.csm.oobe` — déjà décompilée (5 541 classes) | — |
| **3** | Matter | protocole **public**, port ouvert, SDK open source — mais le device est **contrôleur** (il faut lui présenter un faux appareil) | élevé |
| ~~4~~ | ~~Port 1030~~ | **FERMÉ — mesuré le 2026-10-21 sur l'interface P2P** (témoin 8080 OUVERT, 1030 fermé). Voir §20 | — |
| **5** | `createCustomPacketFilter` de wifid (LIPC) | post-exploitation : règles firewall arbitraires depuis un code execution userland | — |

---

## 9. INVENTAIRE COMPLET DES LIVRABLES (40 fichiers)

### Documents de synthèse (à lire en premier)
```
SYNTHESE.md               ← ce fichier : vue d'ensemble, 15 sections + errata
INDEX_PISTES_AG3.md       ← chaque piste : verdict → preuve → statut (mesuré/dérivé/ouvert)
INVENTAIRE_FINAL.md       ← l'inventaire d'origine
```

### Journaux des 3 agents (le détail brut, section par section)
```
FINDINGS_AG2.md    OTA, firmware, binaires, clés par modèle, SELinux, daemons
FINDINGS_AG3.md    APK, composants exportés, adbd, lk, dhcpcd, secrets (22 sections)
FINDINGS_AG4.md    réseau, EAPOL, injection 802.11, OOBE (33 sections)
```

### Le matériel et le système
```
RECON.md                    l'identification du device (MT8167, octave, DSN)
FIREOS_PACKAGES.md          les paquets FireOS
WS1_FIRMWARE.md             notes firmware
OTA_AUDIT.md                les 4 niveaux de la chaîne OTA
OS_PLAN.md · OS_BUILD_LOG.md   l'OS custom compilé (boot.img 8,8 Mo)
APK_FINDINGS.md             l'APK Alexa (côté téléphone)
```

### Le bootloader et le boot
```
LK_SECURITY_MODEL.md        ★ le bootloader lu instruction par instruction (RSA-PSS, unlock)
BOOTROM_PROCEDURE.md        ⚠️ NON EXÉCUTABLE dans ce cadre (voir §16) — trace documentaire
BOOTSTRAP_SPEC.md · BOOTSTRAP_ECHO.md
```

### Le protocole OOBE / setup
```
OOBE_SPEC.md · THRIFT_IDL.md · OOBE_TRANSCRIPT.md · oobe_arg_templates.md
```

### Les surfaces réseau (une par lane)
```
PROVEN.md                   ★ les recettes validées (connectToAP compris)
VERDICT_RESEAU.md           le verdict réseau, corrigé
LOCAL_SURFACE.md            les ports locaux (1080/4070/6543/8888)
WIFI_INJECTION_LANE.md      la lane injection 802.11
EAPOL_LANE.md               la lane EAPOL (7 modes)
WIFI_DRIVER_AUDIT.md · WLAN_AUDIT.md    l'audit du driver Wi-Fi
NETWORK_PARSERS.md          les parseurs réseau
CMS_FINDINGS.md             CMS / X.509 / TJSON
DNSMASQ_251.md              dnsmasq 2.51
WPA_SUPPLICANT_FINGERPRINT.md
QUIET_IE_DOS.md             ★ la vuln DoS radio (802.11h)
```

### Le Bluetooth et le provisioning
```
BLE_LANE.md · FFS_PROTOCOL.md · FFS_SDK.md
```

### Les alternatives et l'analyse des manques
```
ALTERNATIVE_PATHS.md        ★ la voie sans matériel, évaluée
GAPS_ANALYSIS.md            ★ les gaps identifiés en fin de campagne
IMPERSONATION.md
TUTORIEL.md                 le tutoriel de provisioning
```

**Environnement** :
- device : **mode enregistré** (tests réseau) ou **setup** (AP `Amazon-EBE`, `10.201.126.241:8080`)
- notre AP de test : `TEST` / `testing1234`, Pi `192.168.1.41` (piveil)
- image montée : t3600:`~/oct_mnt` (system.img 1,7 Go)
- images OTA : `~/Downloads/update-kindle-octave-*.bin` (v1 = celle du device)

---

## 10. MISE À JOUR FINALE — les 6 chaînes de root et pourquoi chacune échoue

Toutes mesurées le 2026-10-21, sur le firmware EXACT du device (0013222532484).

| # | Chaîne | Maillon manquant | Preuve |
|---|---|---|---|
| 1 | `adbd` root sur 5555 | `ro.adb.secure=1` — clé RSA à approuver, pas d'écran | `default.prop` |
| 2 | `setprop lab126.*` → `firewall.sh` root | aucun des 12 appelants de `writeSystemProperty` ne reçoit de valeur contrôlée | code décompilé |
| 3 | `dnsmasq.conf` → `dhcp-script` | **doublement fermé** : SELinux (4 domaines écrivains) **et** `dhcp-script` compilé OUT (`-DNO_SCRIPT`) | `sesearch` + strings du binaire |
| 4 | `atci_service` (root) | socket Unix `660 radio:system` | `ls -Z` / file_contexts |
| 5 | OTA / signature | 4 niveaux : TLS sans fallback · clé par modèle · minzip borné · anti-rollback | mesures + code source |
| 6 | `avahi` 0.6.31 (root) | **`rlimit-data=4 Mo`** (ne peut pas démarrer) + **`rlimit-fsize=0`** (aucune écriture possible, donc gain nul même si une CVE passait) + ne répond pas sur 5353 | config `avahi-daemon.conf` + 3 probes |

### Le tableau des ports, mesuré en mode ENREGISTRÉ

```
Scan TCP 1-10000 : [1080, 4070, 5541, 8888]  — rien d'autre
   1080  SOCKS5, refus de POLITIQUE (0509 sur 19 cibles testées)
   4070  servlet inconnu de com.amazon.echo.csm.oobe — 9 chemins POST → tous 404
   5541  MATTER (contrôleur, pas commissionnable)
   8888  relais TCP transparent vers api.amazon.com:443 (par conception)

5555, 40317, 1900       : le firewall les AUTORISE, aucun service ne les bind
1030                     : FERMÉ — mesuré sur l'interface P2P du setup (témoin 8080 OUVERT)
5353 (avahi)             : aucune réponse (mort au boot, rlimit)
```

### Les 2 seules vulnérabilités réelles de la campagne

1. **DoS radio par QUIET IE (802.11h)** — un AP malveillant fait taire la radio de tout Echo à portée, 67 s+, latch 255 cycles.
2. **DoS persistant par empoisonnement NTP** — contrôle total de l'horloge (le device affiche la date qu'on sert), TLS cassé, appareil inutilisable ; réversible par NTP correct ou reset usine.

### Le constat structurel

Amazon a empilé des protections dont **chacune couvre la négligence des autres** :
SELinux actif couvre les propriétés · `-DNO_SCRIPT` couvre la config inscriptible ·
`ro.adb.secure` couvre adbd en SU · TLS strict couvre la capture OTA ·
une clé par modèle couvre la signature · les parseurs bornés couvrent le fuzzing.

**Il y a des négligences. Aucune n'est exploitable seule.**


---

## 11. ÉPUISEMENT DU RÉSEAU — le dernier tour

### dhcpcd 6.8.2 (root) : le meilleur candidat, testé le plus rigoureusement

**Pourquoi c'était la meilleure cible du dossier** : dhcpcd est un CLIENT DHCP, il parse les
réponses du SERVEUR — et **nous sommes son serveur DHCP légitime** (notre AP). CVE-2016-1503
(« mismanages option lengths, execute arbitrary code via a malformed DHCP response »,
aka Android bug 26461634) affecte dhcpcd < 6.10.0. Notre binaire : **6.8.2**.

**Protocole de test** (rigoureux) :
1. dnsmasq arrêté, fuzzer DHCP sur le Pi (port 67)
2. deauth forcé → le device refait DISCOVER
3. réponses malformées envoyées
4. **TÉMOIN** : avec une réponse valide, DISCOVER→OFFER→REQUEST→ACK → bail rendu
   ⇒ les paquets SONT parsés, le canal est validé

**Payloads tirés** :
- 11 familles : option 119 len=255 sur 10 o · len=255 · 121 incohérente · 52 overload ·
  43 de 255 · 61 de 255 · 53 dupliquée ×10 · 119 len=0 · option tronquée · 43 de 1400 o
- **concaténation RFC 3396** : même option répétée N fois (N = 3, 6, 10, 15, 25, 40, 50),
  chaque instance valide, total 1,4 Ko → 17 Ko (fragmentation IP)

**Résultat : AUCUN CRASH.** dhcpcd encaisse tout et continue à DISCOVER.

⇒ Le trigger exact de CVE-2016-1503 n'a pas été recherché par diff de sources (la branche 6.8
n'est pas taguée sur le dépôt amont, et le diff n'a pas été réalisé). La conclusion « corrigée »
vient du **désassemblage du binaire**, pas d'une comparaison de sources (§ ci-dessous).

### L'état final du réseau

| Surface | Verdict | Fermée par |
|---|---|---|
| dhcpcd 6.8.2 | ❌ | 11 familles + concaténation, aucun crash (témoin validé) |
| avahi 0.6.31 | ❌ | `rlimit-data=4 Mo` (ne démarre pas) + `rlimit-fsize=0` (gain nul) |
| dnsmasq 2.51 | ❌ | `-DNO_SCRIPT` + SELinux sur `csm_oobe_data` |
| SOCKS 1080 | ❌ | `05 09` hors RFC = refus de politique |
| 4070 servlet | ❌ | 9 chemins POST → 404 ; servlet non identifié |
| 5541 Matter | 🟡 | contrôleur, jamais parlé (nécessite un faux appareil) |
| 8888 | ❌ | relais TCP vers api.amazon.com:443 (par conception) |
| 5555 / 40317 / 1900 | ❌ | aucun service ne bind (scan 1-10000) |
| **1030** « Octave remote player » | ❌ **FERMÉ — mesuré sur la bonne interface** | scan de `10.201.126.241` en mode setup, **témoin 8080 OUVERT** (donc l'interface est la bonne) ⇒ **1030 fermé**. Le firewall l'autorise, aucun service ne le bind. Voir §20 |
| 5353 mDNS | ❌ | aucune réponse |
| bootloader lk | ❌ | RSA-PSS + SHA-256 ; et aucun canal d'écriture (USB alim seule) |
| SELinux | ⚠️ | **actif, mode non tranché statiquement** — `lk` écrit toujours `androidboot.selinux=enforce|permissive`, et l'affectation `disable` de `default.prop` est rejetée (ro.* write-once). Vérifier sur l'appareil : `getprop ro.boot.selinux` |
| OTA | ❌ | 4 niveaux indépendants |

**Il ne reste aucune surface réseau non mesurée.**


---

## 12. CLÔTURE DÉFINITIVE DE dhcpcd — et une leçon de méthode

### CVE-2016-1503 est CORRIGÉE dans le binaire (désassemblage, pas supposition)

```
parseur dhcpcd 6.8.2, à 0xf438 :
   f4ac:  ldrb.w ip, [ip, #1]     ; len = p[1]
   f4b0:  add.w  r6, r5, ip       ; r6 = p + 2 + len
   f4b4:  cmp    r6, lr           ; comparé à la fin du buffer
   f4b6:  bls.n  0xf4bc           ; OK → accepté
   f4b8:  movs   r0, #0           ; sinon → OPTION REFUSÉE
```
Et le chemin d'écho (0xda00) borne aussi `dst + len + 3` contre `dst_end` **avant** le `__aeabi_memcpy`,
avec en plus un **filtre bitmap** : seules les options présentes dans la *parameter request list*
du device sont recopiées.

**⇒ C'est exactement le correctif de la classe « option length ». Il est là.**
Corroboration NVD : « invalid read and crash via vectors related to the option length ».

### ⚠️ LEÇON DE MÉTHODE (à retenir pour tout futur audit)

> **Un témoin positif prouve que le HARNAIS fonctionne,
> il ne prouve PAS que le paquet malformé atteint le code vulnérable.**

Dans notre test DHCP, le témoin `DISCOVER→OFFER→REQUEST→ACK` validait le canal,
pas l'atteinte du parseur. Les options 43/119/121 n'étaient pas dans la *parameter request list*
du device → **non recopiées par le chemin d'écho** (filtre bitmap) ; les autres lecteurs
(`dhcp_getoption`) les lisent mais les **bornent**. Formulation exacte : non demandées donc
non recopiées par ce chemin, et bornées partout ailleurs.

### Deux pièges de désassemblage ARM32 rencontrés (réutilisables)

1. **Binaire mixte ARM/Thumb** : `.text` commence en ARM (`e92d4800 push {fp,lr}`)
   et contient des zones Thumb dès 0xd700. Désassembler en ARM seul rate la moitié du code.
2. **Constantes en `movw`/`movt`** : le magic cookie DHCP apparaît comme
   `movw #0x8263 / movt #0x6353` = 0x63538263, soit `63 82 53 63` en little-endian.
   Chercher la constante « naturelle » 0x63825363 ne donne rien.

### Verdict

**dhcpcd : FERMÉ** — la CVE est patchée, le code le montre, et notre fuzzing
(11 familles + concaténation RFC 3396 jusqu'à 17 Ko) n'a rien cassé pour cette raison.

**Il ne reste plus aucune surface réseau non mesurée. Le dossier est clos.**

---

## 13. ERRATA — corrections apportées après relecture croisée

Ces corrections ont été faites après relecture de cette synthèse par ag3, qui a trouvé
six erreurs. Elles sont listées ici pour que le lecteur sache ce qui a changé et pourquoi.

| # | Erreur | Correction | Source |
|---|---|---|---|
| 1 | « SELinux ENFORCING » / « `Permissive Types: 1` = su » présentés comme preuve d'état runtime | **`seinfo --permissive` liste ce que la POLICY déclare permissif, pas le mode d'exécution** — à ne pas citer comme preuve d'état. **La preuve est dans `lk`, à 0x41e1d470** : il écrit TOUJOURS `androidboot.selinux=` dans la cmdline, et la **branche par défaut est `enforce`** ; `permissive` n'est atteint que si `fos_flags` est posé. Et la ligne `ro.boot.selinux=disable` existe **dans DEUX fichiers** : **`/default.prop` du ramdisk de boot (ligne 151)** et **`/system/build.prop:109`** — les deux sont en aval de l'affectation de `lk` et donc **inertes** — mais elle est **INERTE** : init mappe `androidboot.*`→`ro.boot.*` (write-once) avant de lire build.prop, donc la valeur de `lk` gagne. **⇒ SELinux est ENFORCING.** | F22 + lk 0x41e1d470 |
| 2 | `oobed` listé comme daemon du port 8080 | **`oobed` n'existe pas sur octave** — l'architecture OOBE a été **refondue entre générations** : `oobed` (239 220 o) + `liboobed.so` + `libconnection_utils.so` sur **biscuit** (Dot 2), **absents sur octave** ; `libcivetweb.so` passe de 153 416 à 75 832 o. Sur octave le 8080 est servi par l'**APK** `com.amazon.echo.csm.oobe`. La piste « analyser oobed » disparaît **pour octave** ; le binaire biscuit reste valide **comme documentation du protocole Doppler** (`THRIFT_IDL.md`, `OOBE_SPEC.md`), pas comme description du Dot 3 | F7/F14 + §12 ag2 |
| 3 | dhcpcd décrit comme « patché » (§7) puis « vulnérable » (§11) | **Aligné sur §12 : CVE-2016-1503 est corrigée dans ce binaire**, mesuré par désassemblage (bornes présentes aux deux points d'usage) | F21 |
| 4 | `adbd` en tête des pistes ouvertes alors que §10 le ferme | **Rétrogradé en fermé** : `ro.adb.secure=1` + `ro.debuggable=0` + aucun écran pour approuver la clé RSA | F5/F14 |
| 5 | « options 43/119/121 jamais atteintes, par construction » | **Trop fort.** Le filtre bitmap s'applique au **chemin de recopie** ; `dhcp_getoption` lit toute option mais la **borne**. Formulation corrigée | F21 |
| 6 | dnsmasq 2.51 daté 2009 · diff « infaisable » | **avril 2010** · et « non réalisé » (la branche 6.8 n'est pas taguée), pas « infaisable » | F21 |

### Ce qui a été vérifié et tient

- La leçon de méthode : *un témoin positif prouve que le harnais est bon, pas que le paquet malformé atteint le code vulnérable.*
- Les deux pièges de désassemblage ARM32 : `.text` mixte ARM/Thumb, et constantes en `movw`/`movt` (le cookie DHCP apparaît comme `0x63538263`, soit `63 82 53 63` en little-endian).
- Le tableau des 6 chaînes de root : le fond tient — seules les preuves ont été requalifiées.
- La phrase de clôture : *Amazon a empilé des protections dont chacune couvre la négligence des autres.*


---

## 14. DEUX NOTES DE MÉTHODE, nées de nos propres erreurs

### Note 1 — le témoin positif
> Un témoin positif (DISCOVER→OFFER→REQUEST→ACK) prouve que le **harnais** est bon.
> Il ne prouve **pas** que le paquet malformé atteint le code vulnérable.

Application : un résultat de fuzzing nul s'interprète **en lisant le code**, pas en
ajoutant des paquets. C'est ce qui a permis de conclure sur dhcpcd (§12).

### Note 2 — il faut deux agents sur toute affirmation factuelle
> Sur la localisation de `ro.boot.selinux`, nous avons eu **trois affirmations fausses
> successives** — « désactivé » (ag4), « pas dans default.prop donc enforcing » (moi),
> « dans default.prop » (ag3) — et **chaque fois c'est une mesure qui a tranché.**
> La vérité : `ro.boot.selinux=disable` est à **`/system/build.prop:109`**, et il est
> **inerte** parce que `lk` a déjà posé `androidboot.selinux=enforce` (write-once).

**Conséquence pour la suite** : toute affirmation de ce dossier qui n'est pas classée
« mesuré » doit être lue comme une hypothèse de travail, même quand elle vient d'un agent
sûr de lui — y compris de moi.

### Détail relevé au passage
`default.prop` (ramdisk) ligne 9 : **`ro.oem_unlock_supported=1`** — le flag qui autorise
`oem unlock` côté framework. Cohérent avec le mécanisme d'unlock de `lk`, mais **n'ouvre
rien** : la vérification reste une signature RSA-PSS (§10 chaîne n°1). Et de toute façon
sans canal d'écriture (USB = alimentation seule), un unlock ne servirait à rien.

### Une leçon sur la provenance
L'un d'entre nous avait extrait `default.prop` de la **v2** de l'OTA alors que l'appareil
tourne la **v1**. Cela ne changeait rien ici, mais c'est exactement le type d'écart qui
fausse un dossier sans qu'on s'en aperçoive. **Toujours vérifier de quelle version vient
un extrait avant de le citer.**


---

## 16. CADRE D'EXÉCUTION — ce qui est hors périmètre par décision utilisateur

**Décision explicite de l'utilisateur, tenue pendant toute la campagne :**
> **logiciel uniquement.** Pas d'ouverture de l'appareil, pas de soudure, pas de pastilles
> (TM4/TM5), pas de BROM/`mtkclient`, pas d'UART, pas de dongle côté device.

**Conséquence sur les documents :**

| Document / piste | Statut |
|---|---|
| `BOOTROM_PROCEDURE.md` | **Référence documentaire, NON EXÉCUTABLE dans ce cadre.** Gardé comme trace (le preloader et lk ont été extraits et analysés), mais **retiré des pistes vivantes**. |
| `lk` / `amzn_image_verify` | **Documentaire.** Même un unlock réussi serait inutilisable : le port micro-USB du Dot 3 est **alimentation seule** (mesuré), donc aucun canal d'écriture. |
| Port 5555 / ADB | Fermé par `ro.adb.secure=1` **et** par l'absence de moyen d'approuver une clé (pas d'écran). |
| Tout ce qui suppose un accès physique | **Hors périmètre.** |

**Ce qui a été fait SANS aucun accès physique** : tout le reste — le firmware a été obtenu
depuis des OTA publiques, monté et audité hors ligne ; les tests réseau ont été menés
depuis le Pi et le Mac ; l'appareil n'a jamais été ouvert.


---

## 17. QUESTION OUVERTE AJOUTÉE EN FIN DE CAMPAGNE — les secrets d'un appareil VIVANT

Le négatif « aucun secret en dur » (P5, §13) a une **portée limitée à l'image système**,
c'est-à-dire à ce que contient l'OTA publique. Or **les secrets d'un appareil vivant ne
sont pas dans l'OTA** :

```
/persist    → zone de persistance (identité, calibration, flags)
/factory    → zone usine (clés de production, MAC, certificats)
/data       → (dont /data/misc/adb/adb_keys, /data/securedStorageLocation/SmartHome/)
```

**Ces trois partitions n'ont JAMAIS été inspectées** — elles ne sont pas dans le `.bin`
téléchargé, et on n'y a pas accès sans root (cercle vicieux).

**Ce que ça signifie pour le dossier** : on peut affirmer « pas de clé privée dans les
images publiques ». On **ne peut pas** affirmer « pas de clé privée sur l'appareil ».
C'est une nuance de portée à ne pas perdre.

Corollaire : `/data/securedStorageLocation/SmartHome/PROT_CHIP/*.db` est en **chmod 777**
sur le device vivant — donc lisible par tout processus y ayant accès. C'est une **cible
d'escalade** si un pied est obtenu, pas un accès initial.


---

## 18. REPRODUCTIBILITÉ — ce qui peut être rejoué, et où sont les outils

**Vérifié le 2026-10-21 : les 11 outils d'analyse sont présents dans `~/echo_re/`.**

```
~/echo_re/                       (Mac)
  payload_dump.py    118 l.   déballage des OTA A/B (payload.bin)
  ext4tool.py        142 l.   lecture ext4 sans montage
  axml_scan.py       215 l.   parseur AndroidManifest binaire
  socks_pivot.py     108 l.   test de pivot loopback (a réfuté le SOCKS 1080)
  upnp_ssdp_fuzz.py  182 l.   SSDP / UPnP
  avahi_probe.py      74 l.   mDNS / avahi
  login_4070.py       68 l.   POST login sur le serveur 4070
  udp_scan.py         40 l.   scan UDP (plage SIP 16384-32767)
  vht_inject.py       33 l.   injection 802.11 (bug VHT_CAP)
  vht_sweep.py        38 l.   balayage d'alignement 900 longueurs
  probe_oobe_paths.py        probe des chemins HTTP du 8080

piveil (Pi, /home/pi/fakeap/)   26 scripts .py + 8 .sh
  oobe_fresh.py · oobe_race.py · oobe_enum.py · dns_fuzz_client.py
  dnsmasq_attack.py · evil_dhcp2.py · fake_ota.py · fake_amazon.py
  dns_payload_14491.py · dhcp_fuzz.py · dhcp_concat2.py · dnsmasq_cve.py
  firewall.sh · csm_dnsmasq.sh · hostapd.conf · dnsmasq.conf
```

**Ce qui reste NON reproductible, et pourquoi :**
- **`FINDINGS_AG4.md` §10-11** (TCPTunnelServer, DroppingPrivilege) sont des analyses
  **biscuit** — un bandeau doit le dire en tête de section (demandé à ag4).
- **sha256 des OTA** non recopiés (ag2) — les fichiers sont dans `~/Downloads/`.
- **Diff dhcpcd 6.8.2→6.10.0** non réalisé (branche 6.8 non taguée en amont).
- **Commandes exactes de `payload_dump.py`** absentes du FINDINGS d'ag2.

**Note de méthode n°3** : un dossier n'est reproductible que si l'outil **et** l'invocation
sont dans le document. Plusieurs résultats de cette campagne sont mesurés mais non rejouables
en l'état — c'est écrit ici plutôt que découvert plus tard.

**Note de méthode n°4** : les fichiers cités doivent être **présents au chemin cité**.
Deux chemins erronés ont été trouvés lors de cet audit (`binaries/biscuit_bins/oobed` vs
`~/echo_re/binaries/oobed`). Un `ls` de contrôle avant clôture évite ce type d'écart.


---

## 19. DERNIÈRES MESURES — identité des images, stockage, recovery

### `octave` est une PLATEFORME, pas un produit
Le noyau de l'OTA contient **19 device trees sur 7 familles** (Lidar · Sapphire · Kyanite ·
Pablo · **Octave** (pre-HVT, HVT, HVT 2.0, EVT, PRQ) · Megalo) ; « doebrite » : **0 occurrence**.
`pre-device=octave` et `ro.product.device=octave` dans les deux archives.
**⇒ Une archive couvre une famille entière ; le bootloader choisit le DTB selon la carte.**
La correspondance image↔appareil est établie par trois faits indépendants : le produit déclaré,
`pre-device`, et surtout **l'appareil qui s'est mis à jour lui-même vers ce build**
(`getDeviceDetails` : 0009698494596 → 0013222532484 = `post-build-incremental` du NS65741).

### Stockage : 1,57 GiB de partition système
Superbloc ext4 : **411 264 blocs × 4 096 = 1,57 GiB** (936 Mo utilisés).
⇒ La valeur « 4 Gbit = 512 Mio » relevée dans un démontage est une **erreur de lecture** :
c'est une eMMC de 4 Go.

### Modes de démarrage : recovery et fastboot existent, tous deux fermés
```
ramdisk : /sbin/recovery (847 836 o) · /sbin/adbd (683 932 o)
          init.recovery.mt8167.rc · service recovery · seclabel u:r:recovery:s0

default.prop du RAMDISK :
   ligne   8 : ro.adb.secure=1      ← le recovery a SON adbd, mais il est SECURE
   ligne  14 : ro.debuggable=0
   ligne 151 : ro.boot.selinux=disable   ← la ligne existe bien ici aussi

lk : "fastboot keys triggered, enter fastboot" · getvar expose otu_code,
     unlock_status, secure, antirback_*  ·  tcp/udp/socket : 0 occurrence
     ⇒ fastboot est USB-only
```
**⇒ Recovery : adbd présent mais `ro.adb.secure=1` et aucun `service.adb.tcp.port`
dans les `.rc` du ramdisk ⇒ pas de shell réseau par ce chemin.**
**⇒ Fastboot : le déclencheur par touches existe et exposerait `otu_code`, mais le
transport est l'USB — or le micro-USB du Dot 3 est alimentation seule (mesuré).**
**⇒ Les deux chemins sont fermés par la contrainte utilisateur (logiciel uniquement).**


---

## 20. LE DERNIER GAP — FERMÉ LE 2026-10-21

**La question** : le port 1030 (« Octave remote player ») était autorisé par le firewall
sur l'interface **P2P du mode setup**, mais n'avait jamais été scanné là — les mesures
« fermé » avaient été faites sur le LAN (mesure juste, **interface fausse**).

**La mesure, faite sur la bonne interface** (`10.201.126.241`, AP de setup du device) :

```
  port   état       
  ----------------------
  8080   OUVERT     ← TÉMOIN d'interface : on est bien sur le bon réseau
  1030   fermé      ← LA CIBLE
  4070   fermé   ·   4071  fermé   ·   5540  fermé   ·   5541  fermé
  5555   fermé   ·     80  fermé   ·     53  fermé   ·     67  fermé
  1900   fermé   ·  40317  fermé   ·   1080  fermé   ·   8888  fermé
  5000   fermé

  UDP 53   : répond (28 o)  ← le dnsmasq du device
  UDP 1900 : pas de réponse
```

**⇒ PORT 1030 FERMÉ.** Le firewall l'autorise, mais **aucun service ne le bind**.
Le témoin 8080 (OUVERT) garantit que la mesure n'est pas un faux négatif d'interface.

**C'était le dernier point du dossier où une mesure manquait. Il n'en manque plus.**

**Statut final : 13 surfaces réseau mesurées, 0 gap.**

---

## 21. ANALYSE DU **BON** FIRMWARE (doebrite) — la chaîne de boot décodée

Archive analysée : `update-kindle-doebrite-NS65741_user_8149_0013222532484.bin`
(117 Mo, `product=doebrite`, même version que celle de l'appareil).

### Les partitions du paquet
```
boot.img   9,5 Mo      lk.img   232 K      system.img  131 Mo (squashfs)
tee1/tee2  2,3 Mo      brhgptpl_0..3  180 K ×4  (GPT du bootloader : lk_a/lk_b)
```
**Pas de `preloader.img` dans cette OTA** (contrairement à octave).

### L'architecture de stockage — TOTALEMENT différente d'octave
```
/dev/block/system             /          squashfs  ro verify,slotselect
/dev/storage/by-name/cache    /cache     ubifs
/dev/storage/by-name/userdata /data      ubifs
/dev/storage/by-name/persist  /persist   ubifs  ro
+ microSD (sdcard1) et USB OTG montables (voldmanaged)
```
**⇒ NAND + ubifs + squashfs. Pas d'eMMC, pas d'ext4.** La NAND 4 Gbit (512 Mio)
est cohérente avec un system de 131 Mo.

### ★ LA CHAÎNE DE BOOT, décodée par désassemblage de `lk.img`

Le sélecteur (`0x1d7c0`) lit le mode et dispatche sur **6 valeurs** :

| mode | partition cherchée | chaîne associée | déclencheur |
|---|---|---|---|
| **97** | **`swdl`** | « Wifi SWDL Boot Image Header » / « Wifi SWDL Boot Image » | **bit 5 du registre `0x10007024`** |
| **98** | **`dkernel`** | « **Diagnostic Boot Image** » | `idme_boot_mode` = 98 ⇒ `fastboot oem idme` (**USB**) |
| 4 / 6 | `factory.img` | « factory image doesn't exist in SD card » | touches / idme |
| 7 / 10 | (boot normal / autres) | — | idme |

**Le chemin SWDL, en clair** :
```asm
1d862: ldr r0 → "swdl"      ; nom de partition
       bl  0x1198c          ; vérifie qu'elle existe
       bge 0x1d878
1d878: bl  0x12314           ; récupère l'image
       ldr r0 → "swdl"
       bl  0x11dec           ; CHARGE la partition
       bge 0x1d976           ; succès → démarre
```
**Et la condition d'entrée** :
```asm
113b6: bl  0x133f6           ; = 0x12eec(5)
113ba: cbz r0, 0x113cc       ; si 0 → chemin des touches
113be: movs r2, #97          ; sinon → MODE 97 = SWDL
113c4: str  r2, [r5]

0x12eec: ldr r3 → 0x10007024 ; REGISTRE MATÉRIEL
         ldr r1, [r3]
         lsr.w r0, r1, #5     ; décale de 5
         and.w r0, r0, #1     ; teste LE BIT 5
         bx lr
```

**⇒ La formulation finale, après trois corrections successives :**

1. **Ce n'est pas un strap matériel** (ma première version, trop forte). C'est un
   **bit MMIO (`0x10007024`, bit 5) que `lk` lui-même pose**, via un wrapper dédié.
   L'ABI du wrapper, lue correctement (correction d'ag3, ma première lecture était fausse) :
   ```asm
   131fc: mov  r1, r0      ; r1 = la VALEUR (poser/effacer)
   131fe: movs r0, #5      ; r0 = 5, l'INDEX du bit, codé en dur
   13200: b.w  0x12d00     ; setter(bit=5, value=r1)
   12d06: lsls r3, r0      ; masque = 1 << 5
   12d0a: cbz  r1, ...     ; valeur 0 → EFFACER ; sinon → POSER
   ```
   **Les deux sites** : `0x111c6` (valeur 0 ⇒ **efface** le bit après avoir posé le mode 97 =
   consommation) et `0x1ea0e` (valeur 1 ⇒ **pose** le bit = armement), le second étant
   enregistré comme **handler dans une table de pointeurs de fonction** (littéral
   `0x41e1ea05` à l'offset `0x38cb4`).
2. **Mais aucun code atteignable depuis Android ne le pose** : le **noyau ne référence
   jamais `0x10007024`** — 0 occurrence sur 11,7 Mo décompressés. Le seul écrivain est
   donc `lk`, c'est-à-dire du code qui s'exécute **avant** le noyau.
3. ★ **Et surtout : LA PARTITION CIBLE N'EXISTE PAS.** Le `fstab` du ramdisk énumère
   **13 partitions MTD** — `nvram · proinfo · uboot · uboot2 · misc · boot · recovery ·
   logo · expdb · seccfg · tee1 · tee2 · idme_nand` — plus `cache`/`userdata`/`persist`
   (ubifs) et `system` (squashfs). **Aucune `swdl`, aucune `dkernel`, aucune `factory`.**
   Et `system.img` ne contient **aucune occurrence** de `swdl` ni `dkernel`.

**⇒ FORMULATION FINALE (validée par les deux analyses) :**

> **SWDL est gardé par un bit MMIO que seul du code s'exécutant avant le noyau peut
> poser ; aucun écrivain n'existe côté Android, et la partition cible est absente de
> la table réelle.**

`lk` échouerait au `mt_part_get_partition("swdl")` sur une partition absente et se
replierait sur le boot normal.

**⚠️ MAIS CETTE SECONDE DÉMONSTRATION EST INVALIDE (voir §22)** : une table de montage
n'est pas un inventaire de partitions ; une image brute de démarrage peut exister sans
y figurer. **Et la première l'est aussi** : l'absence de la constante  ne
prouve pas l'absence d'accès (un pilote accède relativement à une base issue du DT).

**⇒ FORMULATION RETENUE** : « chemins de démarrage identifiés ; présence des images et
activation depuis les interfaces disponibles **NON ÉTABLIES** ». Ce n'est pas « mesuré fermé ».

**Attention : cette phrase (« le mode n'a rien à charger ») reposait sur l'inventaire
fstab, qui n'est PAS un inventaire de partitions. Elle est retirée.**

### Ce qui manque pour conclure sur chaque mode
| mode | ce qui est établi | ce qui N'EST PAS établi |
|---|---|---|
| **97 (swdl)** | le chemin existe dans `lk`, un écrivain du bit 5 existe dans `lk` | **qui appelle cet écrivain** ; si la partition `swdl` existe sur la NAND ; si un accès Wi-Fi permet de l'armer |
| **98 (dkernel)** | le mode vient de `idme_boot_mode` | si un autre écrivain d'idme existe ; si `dkernel` existe |
| **4/6 (factory)** | cherche `factory.img` sur carte SD | si un autre support est accepté |

**Ce qui EST solide** : aucune référence à `idme`/`bootmode`/`swdl`/`dkernel` dans les
400+ binaires, `.sh` et `.rc` du **système Android** ⇒ **Android ne peut pas écrire le mode
directement**. C'est une absence de référence textuelle, pas une preuve d'impossibilité.

### Ce que ça vaut pour le dossier
**C'est la première fois qu'on décrit la chaîne de boot alternative COMPLÈTE d'un Echo,
avec les partitions, les triggers et les routines de chargement.** Trois environnements
alternatifs existent (`swdl`, `dkernel`, `factory`) — et **les trois exigent soit un strap
matériel, soit l'USB, soit une microSD**. Aucun n'est atteignable par le logiciel seul.

**La conclusion « ce Dot 3 ne se rootera pas sans ouvrir le boîtier » est maintenant
étayée au niveau du bootloader, sur le bon firmware.**

---

## 22. STATUT DES PISTES APRÈS RELECTURE EXTERNE — trois fermetures invalides

Une relecture externe (BRIEF_EXTERNE_v3 + REPONSE_EXTERNE_v3) a examiné ce dossier.
Elle ne conteste pas les mesures, mais **trois de nos raisonnements de fermeture**.
Ils sont acceptés. Les pistes concernées sont **rouvertes**.

### ❌ Fermeture invalide n°1 — « 0 occurrence de `0x10007024` donc le noyau n'y touche pas »

**Pourquoi c'est faux** : `0x10007024 = 0x10007000 + 0x24`. Un pilote Linux récupère une
**base de registres** par le mécanisme de ressources (souvent issue du Device Tree) puis
accède **relativement** à cette base. Le binaire n'a **aucune obligation** de contenir
l'adresse physique finale sous forme de constante 32 bits.

**⇒ La recherche négative n'établit que l'absence de cette représentation dans le fichier.**
Elle n'exclut ni une base issue du DT, ni une adresse construite par instructions,
ni un accès indirect par une fonction de gestion des registres.

**Statut : la question « qui peut écrire le bit 5 » reste OUVERTE.**

### ❌ Fermeture invalide n°2 — « `swdl`/`dkernel` absents du fstab donc partitions absentes »

**Pourquoi c'est faux** : une **table de montage** décrit les systèmes de fichiers à monter.
Une partition contenant une **image brute de démarrage** peut exister sans y figurer — elle
n'est jamais montée. Linux distingue partitions MTD, dispositifs UBI et volumes ; leur
existence ne dépend pas de leur montage.

**⇒ L'absence de `swdl`/`dkernel` dans le fstab ne démontre pas leur absence sur la NAND.**
Leur absence de l'OTA ne le démontre pas non plus (une mise à jour peut laisser intactes
des régions préexistantes), ni leur absence des chaînes de `system` (aucune référence
textuelle trouvée ≠ inexistence).

**Statut : « une image de service présente mais non montée » est PLAUSIBLE.
« Le mode ne trouve rien à charger » n'est PAS démontré.**

### ❌ Fermeture invalide n°3 — « `ro.adb.secure=1` + pas d'écran ⇒ ADB impossible »

**Pourquoi c'est faux** : le code AOSP d'authentification lit des clés **déjà approuvées**
dans `/adb_keys` et `/data/misc/adb/adb_keys`. **Une clé pré-provisionnée serait reconnue
sans aucune interaction à l'écran.**

**⇒ L'absence d'écran n'établit pas l'impossibilité d'ADB.** Elle ne fournit simplement
aucun moyen d'**ajouter** notre clé. Ce sont deux questions distinctes :
1. le démon démarre-t-il et écoute-t-il sur un transport TCP ?
2. un client non autorisé peut-il s'authentifier ?

**Statut : « pas d'accès ADB utilisable dans l'environnement examiné » tient.
« ADB est impossible » ne tient pas.**

### Ce que la relecture ajoute : une 7ᵉ famille

**La pile Wi-Fi sous les services IP** — traitement 802.11, firmware du contrôleur radio,
pilote hôte. Nos travaux ont couvert le **driver hôte** (audit RX, injection, EAPOL) mais :
- nous n'avons pas caractérisé le **firmware du contrôleur radio** (processeur séparé)
- le modèle du SoC principal (`MT8167`) ne suffit pas à décrire le contrôleur Wi-Fi
- précédent de la famille : les travaux Project Zero sur Broadcom ont montré qu'une chaîne
  pouvait passer par le composant radio **puis** le noyau hôte

**Statut : famille non couverte, à ajouter à la cartographie.**

### Et ce que la relecture recommande de faire d'abord

**La piste 1.5 — les services activés APRÈS configuration.** Raison : notre dossier
rapporte du code qui **modifie redirections et règles NAT** après certaines opérations,
alors que **les scans ont été réalisés avant ces opérations**.

> Le résultat « port fermé » est correct. La conclusion « règle orpheline dans tous les
> états » ne suit pas.

**⇒ Expérience définie** (à exécuter, voir §23) : mesurer l'exposition TCP **avant** et
**après** une transition de connexion Wi-Fi réussie, avec le 8080 comme témoin
d'interface, et vérifier la répétabilité.

**Ce que cette expérience peut conclure** :
- ✅ **réussite** : un service supplémentaire devient joignable, répétablement → la
  cartographie initiale était **incomplète** (résultat qui corrige le dossier)
- ❌ **échec valide** : association réussie, témoin 8080 stable, scans complets, aucune
  exposition nouvelle → **cette transition** n'expose rien (et ne ferme pas les autres)
- ⚠️ **non concluant** : refus, échec d'association, AP perdu, témoin muet → **la piste
  n'est pas fermée**

### Conséquence sur la conclusion générale

**La phrase « aucune voie purement logicielle » est trop forte au regard des pièces.**
La formulation défendable est :

> **Aucune voie purement logicielle n'a été DÉMONTRÉE à ce jour. Trois fermetures
> reposaient sur des raisonnements invalides et sont rouvertes ; la piste la plus
> prometteuse (services activés après configuration) n'a pas encore été testée.**

---

## 23. EXPÉRIENCE 1.5 — TENTÉE, NON CONCLUANTE, PISTE OUVERTE

### Protocole exécuté (deux passes)

**Passe 1 — sans portail captif** :
```
ÉTAT A   témoin 8080 OUVERT · ping OOBE OK · scan 1046 ports → [8080]
TRANSITION  connectToAP(TEST, WPA2) → {"0":{"i32":0}} = NO_ERROR
ÉTAT B   témoin stable 135 s (9/10 sondes) · scan → [8080]
         nouveaux ports : AUCUN · ports disparus : AUCUN
VERDICT  ❌ échec valide — CETTE transition n'expose rien
```

**Passe 2 — avec portail captif forcé** (DNS hijack de `acsechocaptiveportal.com`,
`connectivitycheck.android.com`, `checkip.amazonaws.com` → notre Pi, qui répond
une page HTML au lieu du `204` attendu) :
```
ÉTAT A   témoin 8080 OUVERT · scan → [8080]
TRANSITION  connectToAP → {"0":{"i32":7}} = **CAPTIVE_PORTAL_ERROR**
            ★ 19:00:29  GET /generate_204  Host=acsechocaptiveportal.com  (×2)
            → LE DEVICE A APPELÉ NOTRE PORTAIL CAPTIF
ÉTAT B   témoin tombé à t+15 s · AP disparu · device parti de TEST
VERDICT  ⚠️ NON CONCLUANT
```

### Ce qui est acquis

1. **`TReturnErr` — valeurs observées** : `0 = NO_ERROR`, **`7 = CAPTIVE_PORTAL_ERROR`**
   (enum complet : 0 NO_ERROR · 1 UNKNOWN · 2 INVALID_ARGUMENTS · 3 BAD_PASSWORD ·
   4 TIMEOUT · 5 SERVER · 6 ROUTE_CONFLICT · **7 CAPTIVE_PORTAL** · 8 CONNECTED_LOCAL ·
   9 DELAYED_CONNECTION_STARTED)
2. **Le device détecte effectivement un portail captif** : il a émis
   `GET /generate_204` vers `acsechocaptiveportal.com`, qui pointait sur notre Pi.
   **Le mécanisme `enableNatIfNotEnabled` a donc un déclencheur réel et atteignable.**
3. **Mais l'appareil quitte ensuite le réseau** : l'AP de configuration disparaît,
   et la mesure d'exposition TCP n'est plus possible.

### Pourquoi c'est non concluant, et ce que ça laisse ouvert

Le protocole prévoyait ce cas : « *si le témoin tombe, l'absence de réponse ne permet
pas de déclarer la piste fermée* ». C'est exactement ce qui s'est produit.

**⇒ La piste 1.5 reste OUVERTE.** Ce qui manque n'est pas la volonté de tester, mais :
- un moyen de **maintenir l'AP de configuration actif** pendant que le device est
  connecté au réseau (pour scanner les deux interfaces en même temps) ;
- ou de mesurer **depuis le réseau TEST** l'effet du tunnel (mais le tunnel est bindé
  sur l'interface P2P, pas sur `wlan0`).

### Ce que la relecture externe avait raison de dire

> « Le résultat "port fermé" est correct. La conclusion "règle orpheline dans tous les
> états" ne suit pas. »

**Confirmé** : la passe 2 montre que l'état change réellement (erreur 7 + appel au portail).
On ne peut donc plus affirmer que la règle 1030 ou le tunnel sont inertes **dans tous les
états** — seulement qu'ils étaient inactifs **dans les états mesurés jusqu'ici**.

---

## 24. ★ HYPOTHÈSE 1.5 CONFIRMÉE — `getLinkCode` OUVRE LE PORT 443

**C'est la première fois de la campagne qu'une surface NOUVELLE apparaît après une transition.**

### La mesure

```
ÉTAT A (avant transition)
   P2P  10.201.126.241 : [8080]
   TEST 192.168.50.25  : []          (device absent)

TRANSITION  connectToAP(TEST, WPA2) → {"0":{"i32":7}} = CAPTIVE_PORTAL_ERROR
            (notre portail captif est détecté : GET /generate_204 Host=acsechocaptiveportal.com)

ÉTAT B (scans continus des DEUX côtés, 10 s × 15)
   P2P  : [8080]  pendant toute la fenêtre
   TEST : [4070]  pendant toute la fenêtre   ← le device est en setup ET sur le réseau client
   evaluateCaptivePortal → {"0":{"i32":0}} = NO_ERROR

★ APPEL getLinkCode
   réponse : {"1":{"rec":{"1":{"str":"CCXLWY"}}},"2":{"i32":0},"3":{"i32":2}}
                     ↑ UN LINK CODE
   AVANT : P2P = [8080]
   APRÈS : P2P = [8080, **443**]
```

### Ce que ça démontre

1. **`getLinkCode` est une méthode ACTIVE** — elle retourne un code (`CCXLWY`) et
   **modifie l'état du device**.
2. **Elle ouvre le port 443 sur l'interface P2P.** C'est le tunnel compagnon décrit
   dans `firewall.sh` : `DNAT 443 → $TCPTUNNEL_LOCAL_LISTENING_PORT` (31415).
   Le commentaire du script le dit : *« The companion app make authorize link code call
   on port number 443 »*.
3. **Le port 443 accepte le TCP mais réinitialise sur toute donnée** : le tunnel accepte
   la connexion puis échoue à ouvrir sa jambe distante (probablement parce que
   `persist.oobe.reg.endpoint` ou `persist.oobe.compapp.port` ne sont pas positionnés).

### Ce que ça corrige dans le dossier

| Affirmation retirée | Remplacée par |
|---|---|
| « le tunnel est inerte dans tous les états » | **Le tunnel est ACTIVABLE par `getLinkCode`, et il ouvre 443** |
| « règle 1030 orpheline dans tous les états » | **La règle 443 est fonctionnelle ; 1030 reste non mesurée dans cet état** |
| « aucune méthode de configuration n'a d'effet » | **`getLinkCode` a un effet observable et mesurable** |

### Ce qui reste à explorer sur cette surface

- **Parler au tunnel** : il réinitialise sur HTTP/thrift/JSON/TLS. Sa jambe distante
  échoue. Si elle aboutissait, on obtiendrait un **relais TCP à travers le device**.
- **La cible du tunnel** est `persist.oobe.reg.endpoint` + `persist.oobe.compapp.port`.
  On ne peut pas les écrire — **mais c'est LA question** : si un chemin existait pour
  les positionner, le tunnel pointerait où on veut.
- **Le link code `CCXLWY`** : c'est le code de jumelage du device. Il est retourné
  **sans authentification**. C'est une donnée d'enregistrement.
- **La combinaison portal + getLinkCode** : on n'a pas encore testé si le port 443
  reste ouvert après la fin du portail, ni si d'autres ports apparaissent dans
  d'autres combinaisons d'états.

**Statut : piste OUVERTE et ACTIVE. C'est la première faille de cartographie
positive de toute la campagne.**

### ★★ CONFIRMATION FINALE : le tunnel est un RELAIS VERS `api.amazon.com:443`

Après `getLinkCode`, le port 443 du P2P devient un **serveur HTTPS** qui répond :
```
GET /   →  HTTP/1.1 403 Forbidden
           x-amz-rid: 01PYFF5807DWRT0PPZQZ
           Strict-Transport-Security: max-age=47474747; includeSubDomains; preload
           Vary: User-Agent,Accept-Encoding
```
**Certificat présenté** (TLS 1.1 exigé, pas 1.2) :
```
subject = CN=api.amazon.com
issuer  = C=US, O=DigiCert Inc, CN=GeoTrust TLS RSA CA G1
valid   = Sep 16 2026 → Apr 1 2027
SAN     = api.amazon.com · wsync.us-east-1.amazon.com · account.apis.amazon.com
sha256  = d62e7c585a8fb66300e88eac9182129c5ee24a53
```

**⇒ C'est exactement ce que fait `TCPTunnelSession` :
`getNewSocket(registrationEndpointHostname, registrationEndpointPort)` puis un pipe
bidirectionnel. Le tunnel est un **relais TCP transparent vers `api.amazon.com:443`**.

### Ce que ça vaut — et ce que ça ne vaut pas

| ✅ Acquis | ❌ Ce que ce n'est pas |
|---|---|
| `getLinkCode` **active** le tunnel (mesuré 2×) | Ce n'est **pas** un accès à un service interne du device |
| Le tunnel **fonctionne** (TLS + réponse Amazon) | Ce n'est **pas** un proxy vers une cible arbitraire |
| Il expose **443** sur le P2P, pendant une fenêtre | Ce n'est **pas** root |
| Il retourne un **link code** sans authentification (`CCXLWY`, `BDTKNL`) | On atteint Amazon, qu'on atteint déjà directement |

**La cible du tunnel est `persist.oobe.reg.endpoint` (hôte) + `persist.oobe.compapp.port`
(port). Le port est positionnable via `setLocaleAndEndpoints` → `updateRegistrationEndpointPortProperty()`,
mais **l'hôte ne l'est pas** : `getRegistrationEndPointHostName()` fait un **lookup dans un JSON**,
jamais une valeur arbitraire. Un relais vers `api.amazon.com:<port arbitraire>` n'ouvre rien de plus.

### Valeur réelle de cette découverte

**Elle corrige le dossier, et c'est tout ce qu'on lui demandait :**
- ❌ « le tunnel est inerte dans tous les états » → **FAUX, mesuré**
- ❌ « la règle iptables 443 est orpheline » → **FAUX, elle fonctionne**
- ❌ « aucune méthode de setup n'a d'effet observable » → **FAUX, `getLinkCode` en a un**

**Et elle donne un outil : un relais TCP à travers le device, activable à volonté, vers
`api.amazon.com:443`. Ce n'est pas une voie vers root, mais c'est la première surface
que la campagne démontre activable.**

### Observation annexe : `getOTADetails` bloque le serveur OOBE

Appelée dans cet état, `getOTADetails` **timeout**, et **toutes les méthodes suivantes
timeoutent aussi** pendant ~90 s avant que le serveur ne réponde à nouveau.
C'est cohérent avec un serveur **mono-thread** : l'appel cloud-gated bloque le thread.
**⇒ DoS de l'API OOBE par un simple appel `getOTADetails`.**

---

## 25. 🚨 SSRF CONFIRMÉ — LE TUNNEL COMPAGNON EST UN RELAIS VERS UNE CIBLE QUE NOUS CONTRÔLONS

**C'est le premier résultat offensif positif de toute la campagne.**

### La chaîne, prouvée étape par étape

| # | Étape | Preuve |
|---|---|---|
| 1 | `getLinkCode` ouvre le port **443** sur l'interface P2P | mesuré 2×, avec codes différents (`CCXLWY`, `BDTKNL`) |
| 2 | Le tunnel est un **relais TCP** vers `(persist.oobe.reg.endpoint, persist.oobe.compapp.port)` | `TCPTunnelSession.getNewSocket(host, port)` + le certificat `CN=api.amazon.com` obtenu avant le hijack |
| 3 | **L'hôte est résolu par le DNS — que NOUS contrôlons** | `api.amazon.com → 127.0.0.1` hijacké, **4 requêtes du device** vers notre dnsmasq, servies avec `127.0.0.1` |
| 4 | **Le port est positionnable** par `setLocaleAndEndpoints(companionAppPort=N)` | la méthode retourne `{"0":{"i32":0}}` = **NO_ERROR** |
| 5 | **La preuve finale** : après hijack + port=8080, une requête `GET /` sur 443 renvoie | `HTTP/1.1 405 Method Not Allowed` · `Allow: POST, OPTIONS` · `Error 405: Method Not Allowed - Unsupported HTTP Request Method` |

**⇒ C'est exactement l'erreur du servlet OOBE. Le device s'est connecté à SON PROPRE
`127.0.0.1:8080` et nous a relayés.**

### La primitive obtenue

```
Le device ouvre une connexion TCP vers  (IP que nous choisissons via api.amazon.com,
                                         PORT que nous choisissons via
                                         persist.oobe.compapp.port)
et fait passer nos octets.

⇒ SSRF avec contrôle TOTAL de la destination (IP par DNS, port par propriété).
```

### Ce que ça vaut, et ce que ça ne vaut pas — honnêtement

| ✅ Acquis | ❌ Ce que ce n'est pas |
|---|---|
| Le device se connecte **où on veut** | On ne contrôle pas **depuis quelle interface** il sort (il choisit) |
| Le device relaie **nos octets** | Ce n'est pas root |
| On peut viser **n'importe quel port** | La cible doit être joignable **depuis le device** |
| On peut donc viser **son loopback** | L'API OOBE en loopback a les **mêmes contrôles** (Origin, méthode) |

### Pourquoi c'est important quand même

1. **On atteint des services que le device ne devrait exposer qu'à lui-même.**
   Sur Android, certains composants se fient à l'adresse source ou à une socket Unix ;
   **tout service qui écoute sur `127.0.0.1` devient joignable par ce relais.**
   Candidats sur ce firmware : l'**Alexa Hybrid Engine** (`alexa.hybrid.service.port`,
   protégé par un contrôle d'UID sur le loopback), `SmartHomeChipd`, les services ADB
   internes.
2. **La cible IP est contrôlée par une donnée que l'attaquant réseau fournit déjà** :
   le DNS. Aucune authentification.
3. **Le port vient d'une méthode de configuration non authentifiée** (`setLocaleAndEndpoints`).

### Ce qui reste à faire sur cette primitive

- **Identifier un service loopback-only du device** (AHE, SmartHomeChipd, autres) et
  vérifier si son contrôle d'accès tient quand la connexion vient du loopback.
- **Tester les ports internes** : `alexa.hybrid.service.port`, `alexa.hybrid.secure.port`,
  les sockets `aicfmessenger`, les ports de `shchipd`.
- **Vérifier si le tunnel peut viser une IP hors du réseau local** (le device a Internet :
  il pourrait servir de rebond vers l'extérieur).

**Statut : PRIMITIVE CONFIRMÉE. Exploitation non réalisée. C'est la piste la plus
concrète ouverte par cette campagne — et elle vient de la méthode du reviewer :
mesurer avant/après, et ne pas conclure depuis un état unique.**

---

## 26. LA CIBLE LA PLUS INTÉRESSANTE DU FIRMWARE — ET POURQUOI ELLE EST FERMÉE

### ★ L'Alexa Hybrid Engine écoute sur `0.0.0.0:7802` avec `SocketPermissions: "ALL"`

`/system/etc/ahe.config.json` (doebrite, lu dans l'image) :
```json
"AlexaHybrid.SDK.ExecutionController.Address": "0.0.0.0"
"AlexaHybrid.SDK.ExecutionController.Port": "7802"
"AlexaHybrid.SDK.ExecutionController.SocketPermissions": "ALL"     ← ★★★
"AlexaHybrid.SDK.ExecutionController.StartLSF": "false"            ← pas de framework de sécurité
"ArtifactManager.DavsPollServer.TcpPort": "9091"
"AlexaHybrid.SDK.LocalRequestOrchestrator.SocketPermissions": "ALL"
"AlexaHybrid.SDK.PlatformServices.SocketPermissions": "ALL"
```

**Un moteur d'exécution locale (pryon/LiteSpeed) qui écoute sur toutes les interfaces,
avec des permissions de socket « ALL » et **sans** LSF. C'est la cible la plus
intéressante de tout le firmware.**

**Mesure** : `7802` et `9091` **ne sont PAS en écoute**, ni sur le P2P ni sur TEST.

### Pourquoi : la chaîne de démarrage est fermée par SELinux

```
com.amazon.ahe.run=true  →  start ahe          (0.0.0.0:7802)
   écrivable par : PuffinApp, dacd, init          ← sesearch sur sepolicy doebrite

dacd démarre par com.amazon.puffin.PUFFIN_START=1
   puffin_start_prop écrivable par : init, ledcontroller

kvs_init_completed=1 → accoinputmanager, minerva_service, provisionee_svc, blemesh_service
   écrivable par : init, kvs_util

audio_mixer.init=true → commsd
   écrivable par : init, mixer
```

**⇒ Chaque propriété qui démarre un service est inscriptible uniquement par `init`
ou par un daemon natif local. Aucune n'est atteignable depuis le réseau.**

### Les autres découvertes de cette exploration

- **DOEBRITE a une architecture « ACE » complète** : 361 binaires dont
  `ace`, `ace_blemesh_service`, `ace_chip_service`, `AceCredentialManagerService`,
  `aceinmanager`, `acedropboxd`, `ace_eventmgr`, `provisionee_svc`, `minerva_service`.
- **Le layout est différent d'octave** : le squashfs **est** le ramdisk
  (`/system`, `/sbin/adbd`, `/etc`, `/vendor → /system/vendor`).
- **Autres services à propriété** : `cmbd`, `credmgrsvc`, `gadgetsd`, `dacd`,
  `oobe_setup`, `rollback` — tous sur le même modèle fermé.

### Conclusion de cette sous-piste

**La cible existe, elle est mal configurée (`ALL`, `0.0.0.0`, pas de LSF), mais
son démarrage dépend d'une propriété que seuls `init` et des daemons locaux
peuvent écrire. **Le maillon manquant est le même que partout dans ce dossier :
une écriture de propriété depuis le réseau.**

**C'est cohérent avec la conclusion générale — et ça la renforce : les négligences
existent (7802 ouvert à tous, permissions ALL), mais chaque chemin pour les atteindre
est fermé par SELinux ou par la chaîne de démarrage.**

### La vraie portée du SSRF — et sa limite en laboratoire

**En laboratoire, le gain est nul** : le device est sur `TEST`, notre réseau, et le client
du tunnel (le Mac) atteint déjà tout ce que le device atteint. Le SSRF ne donne **rien de plus
ici**.

**Dans le scénario réel, il est sérieux** :
```
1. Un Echo est en mode setup, l'attaquant contrôle l'AP (Amazon-EBE)
2. L'attaquant fait rejoindre à l'Echo le Wi-Fi de la VICTIME (connectToAP)
3. L'attaquant hijacke le DNS de l'Echo (il est le DHCP de l'AP de setup)
   → api.amazon.com = l'IP qu'il veut, dans le LAN de la victime
4. Il pose le port via setLocaleAndEndpoints
5. Il appelle getLinkCode → le tunnel s'ouvre
6. Il se connecte à 443 sur le P2P → LE DEVICE SE CONNECTE OÙ IL VEUT
   DANS LE LAN DE LA VICTIME, ET LUI RELAIE LES OCTETS

⇒ L'Echo devient un PROXY SSRF vers le réseau interne de la victime,
  depuis un appareil qui n'a l'air de rien.
```

**Limite mesurée** : les deux seuls services **loopback-only** du device
(`AHE_PORT`, `AICF_MESSENGER_PORT`) sont protégés par `-m owner ! --uid-owner` ⇒
le tunnel (UID de l'APK OOBE) serait `DROP`. **Le SSRF ne contourne donc pas ces deux-là.**

### Ce que ça vaut pour le dossier

**C'est le premier résultat offensif complet et reproductible de la campagne :**
- **Primitive** : SSRF avec contrôle total de la destination (IP par DNS, port par propriété)
- **Déclencheur** : `getLinkCode`, non authentifié
- **Portée réelle** : atteindre le LAN de la victime depuis un Echo en setup
- **Ce que ce n'est pas** : un accès au loopback protégé, ni root

**Et ça valide définitivement la méthode de la relecture externe : mesurer avant/après
sur une transition, et ne pas conclure depuis un état unique. Trois affirmations du
dossier sont tombées grâce à ça.**

---

## 27. POURQUOI UN OS CUSTOM RESTE HORS D'ATTEINTE — les trois écrivains de partition

Pour installer un OS custom, il faut **écrire une partition de boot**. Trois composants
peuvent le faire sur ce firmware. Les trois sont fermés.

| Écrivain | Privilège | Déclencheur | Pourquoi c'est fermé |
|---|---|---|---|
| **`update_engine`** | **root** (`user root`, group `root system ...`) | `disabled` — lancé par l'APK OTA | Payload **signé** (clé par modèle, RSA-2048) + manifeste **TLS strict sans fallback**. Le payload vient du manifeste, qu'on ne peut pas forger. |
| **`update_verifier rollback`** | oneshot | `com.amazon.system.rollback=1` | Cette propriété tombe dans **`default_prop`**, écrivable par **`init` seulement** (`sesearch` sur le sepolicy doebrite). Et **aucun `.rc` ni `.sh` ne la pose** — c'est un hook pour un outil externe (fastboot `oem`, outil d'usine). |
| **`lk` (bootloader)** | pré-noyau | commande `flash:` / fastboot | **RSA-PSS + SHA-256**, et le transport est **USB** (le micro-USB du Dot est alimentation seule). |

### Ce que `update_verifier rollback` ferait s'il était déclenchable

Chaîne de caractères lue dans le binaire :
```
"Rollback requested"
"Setting current slot as unbootable and rebooting into the other slot"
fireos/base/features/BspDiagService/processes/update_verifier/rollback.cpp
```
**⇒ Un vrai basculement de slot A/B** — donc, si l'autre slot contenait une version
antérieure, un **downgrade** (et la réouverture de toutes les CVE de la campagne).

**Mais le déclencheur est fermé**, et rien ne garantit que le slot B contienne une
version différente.

### Et l'Alexa Hybrid Engine, la cible la plus intéressante

`0.0.0.0:7802` · `SocketPermissions: "ALL"` · `StartLSF: "false"` — **mais** démarré par
`com.amazon.ahe.run=true`, écrivable **uniquement** par `PuffinApp`, `dacd` et `init`
(`sesearch` sur `ahe_run_prop`). Et `dacd` démarre par `puffin_start_prop` ← `init`,
`ledcontroller`. **Aucun maillon n'est joignable depuis le réseau.**

### Conclusion de cette dernière exploration

**L'installation d'un OS custom exige un écrivain de partition, et les trois existants
sont protégés par : signature (update_engine), SELinux + absence de déclencheur (rollback),
ou cryptographie + transport absent (lk).**

**Ce n'est pas « on n'a pas trouvé » : c'est « les trois chemins sont identifiés et
chacun est fermé par un mécanisme différent ».**

---

## 28. LA DERNIÈRE SURFACE NON PARLÉE : MATTER (5541 TCP · 5550 UDP/Casting/UDC)

### Ce que le firewall doebrite révèle

```sh
# TPH traffic (déjà connu)
# Casting and User Directed Commissioning support for Matter
$IPTABLES -A INPUT -i $interface -p udp --dport 5550 -j ACCEPT     ← ★ NOUVEAU
# Matter use
$IPTABLES -A INPUT -i $interface -p udp --dport 5540 -j ACCEPT
$IPTABLES -A INPUT -i $interface -p udp --dport 5541 -j ACCEPT
```

**Mesures** : `5541` **ouvert en mode enregistré** (scan TCP 1-10000, confirmé plusieurs fois).
`5540` et `5550` en UDP : aucune réponse aux sondes brutes (normal, UCP/MRP exige un
message bien formé).

### Pourquoi c'est la dernière vraie piste

1. **C'est un protocole PUBLIC** (Matter, ex-Project CHIP) — SDK open source
   (`connectedhomeip`), client Python officiel, spécification complète.
2. **L'appareil est un CONTRÔLEUR** (`CHIPCapabilityConfig.json` : `commissioneeTypes`
   liste les types qu'il sait commissionner) et il fait aussi du **Casting** (5550).
3. **UDC (User Directed Commissioning)** est le mécanisme par lequel un **appareil
   s'annonce** auprès d'un contrôleur. Donc **on peut se présenter à lui**.
4. **Rien de tout ça n'a été parlé** : nos 2600 cas de fuzzing ont couvert HTTP, thrift,
   DNS, DHCP, EAPOL, 802.11 — **jamais Matter**.

### L'attaque, en clair

```
1. Implémenter un FAUX APPAREIL Matter (SDK public), avec un setup code qu'on choisit
2. L'annoncer en UDC sur 5550 (ou par un QR code si l'app doit le faire)
3. L'Echo le commissionne → il nous envoie ses credentials réseau
   (SSID, mot de passe Wi-Fi, dataset Thread)
4. Pendant le commissioning, lui répondre avec des messages Matter MALFORMÉS
   → fuzzer son contrôleur CHIP (implémentation Magike/Amazon 2024-2026)
```

**Ce que ça peut donner** : le fuzzing d'une pile Matter récente (peu de recul, peu
d'audits publics), et la récupération des credentials réseau du device.

**Ce que ça ne donne pas directement** : root. Il faudrait une vulnérabilité dans
le contrôleur Matter, ou un défaut d'autorisation dans le commissioning.

### Pourquoi on ne l'a pas fait

**Coût** : implémenter un appareil Matter complet (clusters, attestation, certificats
DAC/PAI, PASE) demande plusieurs heures et le SDK `connectedhomeip`. C'est le seul
chantier qui reste, et il est entièrement dans nos moyens logiciels.

---

## 29. ★ RELECTURE EXTERNE v4 — formulation adoptée, et la limite n°1 testée

### La formulation retenue (adoptée telle quelle)

> **À ce stade, aucune chaîne purement logicielle permettant de faire tourner un firmware
> Linux personnel sur cet Echo Dot Doebrite n'a été établie avec les seuls boutons,
> l'alimentation et le Wi-Fi.**
>
> Une primitive de relais TCP a toutefois été démontrée pendant la configuration. Elle
> permet de piloter une connexion sortante de l'appareil et a notamment permis d'atteindre
> son service de configuration sur `127.0.0.1:8080`. Cette primitive n'a pas fourni, dans
> les essais réalisés, les capacités d'exécution ou de chargement nécessaires à l'objectif.
> Les contrôles par UID des services testés n'ont pas été franchis, et les autres cibles
> examinées n'ont pas fourni de prolongement utilisable.
>
> Ces résultats établissent les limites des chemins testés, mais **ne démontrent pas
> l'impossibilité de toute voie logicielle**. La couverture reste incomplète pour certaines
> transitions d'état et certains composants, notamment le micrologiciel radio.
>
> **La conclusion est donc une absence de solution démontrée dans le périmètre examiné.
> L'existence d'une autre voie compatible avec nos contraintes reste indéterminée.**

### Les deux formulations excessives retirées

| Ce que la v4 disait | Reformulation |
|---|---|
| « la **seule** combinaison qui pourrait mordre » | « la combinaison **encore identifiée à examiner** » — l'absence d'autres combinaisons connues n'établit pas l'unicité |
| « si un port apparaît, nous saurons **sous quelle identité** il est joignable » | Une ouverture de port ne révèle pas l'identité du composant. Il faut distinguer : identité du socket du relais · destinataire final · privilèges du destinataire |
| « n'importe quel hôte, n'importe quel port » | La destination est **configurable**, mais son accès reste soumis au routage, au filtrage et à la disponibilité. La preuve la plus solide reste `127.0.0.1:8080`. |

### ★ LIMITE N°1 TESTÉE : le scan loopback à travers le relais

La relecture pointait : *« un service lié uniquement à la boucle locale peut rester
invisible lorsqu'on scanne l'adresse du point d'accès »*. **C'est exactement ce que le
SSRF permet de tester, et on l'a fait.**

**Méthode** : pour chaque port P → `setLocaleAndEndpoints(companionAppPort=P)` →
`getLinkCode` → se connecter à 443 (le relais vise alors `127.0.0.1:P`) → envoyer un octet.

**Résultats** :
```
127.0.0.1:8080  → ★ RÉPOND (le 405 du servlet OOBE)      seul service trouvé
127.0.0.1:7802  → pas de service   (Alexa Hybrid Engine non démarré)
127.0.0.1:9091  → pas de service   (DAVS poll server non démarré)
autres ports    → NON TESTABLES : le serveur OOBE se bloque ~60 s après chaque
                  paire set_port+getLinkCode (comportement mono-thread, déjà observé
                  avec getOTADetails)
```

**⇒ Le scan loopback ne révèle aucun service nouveau.** Le seul atteint est celui
qu'on connaissait déjà (l'API de configuration).

**⇒ Mais la limite est méthodologique, pas conceptuelle** : le serveur OOBE ne soutient
pas le rythme nécessaire pour scanner plus de ~1 port par minute. Un scan complet
du loopback demanderait des heures, avec une instabilité permanente.

### Les deux autres limites de la relecture, telles quelles

**Limite n°2 — les contrôles par UID** : viser `127.0.0.1` ne change pas l'identité du
socket sortant (`iptables -m owner` s'appuie sur l'UID du socket). Un relais applicatif
ne neutralise donc pas ce contrôle. **Les deux échecs contre `AHE_PORT` et
`AICF_MESSENGER_PORT` sont des négatifs utiles, mais ils ne démontrent pas qu'aucun
autre composant accessible ne pourrait agir sous ses propres privilèges.**
→ **Inconnue conservée, sans piste identifiée.**

**Limite n°3 — couverture incomplète** : transitions d'état non testées, couche radio
non cartographiée, couverture exacte des signatures non établie, présence des images
de maintenance non établie. **Ces lacunes empêchent une conclusion universelle. Elles
ne constituent pas des indices positifs.**

---

## 30. MATTER : joignable, mais derrière un handshake

### Mesures sur le device ENREGISTRÉ (sur la Livebox, 192.168.1.24)

```
ports ouverts : 1080 · 4070 · 5541 · 8888 · 55442
```

**5541 (Matter TCP)** — tous les messages envoyés sont **RST**, y compris les opcodes
Matter valides :
```
MRP Standalone Ack (0x10)   → RST
PASE PBKDFParamRequest (0x20) → RST
StatusReport (0x40)         → RST
hdr + TLV vide              → RST
session=1, opcode=0x10      → RST
8 octets de ZÉROS           → silencieux (accepté)
```

**⇒ Le port valide la **session** avant de traiter le message. Matter exige :
PASE (SPAKE2+, commissioning) puis CASE (session opérationnelle chiffrée).
**Sans session valide, tout message est rejeté.**

**Pour fuzzer Matter sérieusement, il faut donc :**
1. implémenter un **faux appareil Matter** avec le SDK `connectedhomeip` ;
2. le faire **commissionner** par l'Echo (UDC sur 5550, ou QR code via l'app) ;
3. une fois la session CASE établie, **envoyer des messages malformés**.

**C'est plusieurs heures de travail, et c'est le seul chantier restant.**

### 55442 — un serveur HTTP non identifié (WHALEXA)

```
connexion passive → HTTP/1.1 500 Server Error · "Client closed connection"
GET /             → HTTP/1.1 404 Not Found · "Error 404: Not Found\nNot Found"
```

**Même format d'erreur que le port 4070** (`Error %d: %s\n%s`) ⇒ **même framework**.
**34 routes testées sur les deux ports → toutes 404.** Les routes restent inconnues.

### État final de cette exploration

| Surface | État |
|---|---|
| **5541 Matter** | **joignable, session requise** — le seul chantier qui reste |
| 55442 / 4070 | HTTP, routes inconnues |
| 1080 | SOCKS5, refus de politique |
| 8888 | relais TCP |

**Aucune de ces surfaces n'a été franchie. Mais pour Matter, on sait maintenant
exactement ce qui manque : une session PASE/CASE.**

---

## 31. MATTER — CAMPAGNE DE FUZZING : harnais construit, pile robuste

### Ce qui a été démontré (et c'est un résultat majeur)

**Le commissioning Matter complet a RÉUSSI sur cet Echo** :
```
[ZCL] OpCreds: Received an AddTrustedRootCertificate command
[ZCL] OpCreds: AddTrustedRootCertificate successful.
[ZCL] OpCreds: Received an AddNOC command
[ZCL] OpCreds: successfully created fabric index 0x1 via AddNOC
[FS]  GeneralCommissioning: Received CommissioningComplete
```
L'app Alexa a ensuite affiché les endpoints de notre faux appareil :
**« first light », « first remote », « second light »**.

**⇒ Un appareil Matter contrôlé par nous est entré dans le fabric de l'Echo,
et l'Echo l'interroge en boucle (ReadRequest → ReportData).**

### Le harnais de fuzzing

**Construit sur le t3600** (x86_64, sur la Livebox) :
```
SDK connectedhomeip cloné + sous-modules (20 Go)
bootstrap réparé (DNS cassé par tailscale : 100.100.100.100 → 1.1.1.1)
dépendances installées (libssl-dev, libevent-dev, libdbus, avahi, cairo…)
build : gn gen --args="chip_build_tests=false is_debug=false chip_build_all_clusters_app=true"
        ninja examples/all-clusters-app/linux:chip-all-clusters-app  →  100 Mo
```

**Fuzzing tentés :**
| Fuzz | Résultat |
|---|---|
| `--product-name` de 4 000 octets | ❌ l'Echo lit et survit |
| `--product-name` de 60 000 octets | ❌ l'Echo lit (fragmenté en ~50 ReportData) et survit |
| **Patch `TLVWriter::WriteElementWithData`** : déclarer `dataLen-100` en écrivant `dataLen` (désync) | ⚠️ notre app rollback (`No memory`) — le TLV malformé n'est jamais envoyé |
| **Patch à `dataLen-1`** | ⚠️ après relances, l'Echo ne peut plus rétablir la session CASE (`Invalid CASE parameter`) |

### Ce que ça démontre

1. **La pile Matter de l'Echo est ROBUSTE** : elle encaisse une chaîne de 60 Ko fragmentée
   en ~50 messages sans broncher.
2. **Le harnais est fonctionnel** : on contrôle chaque octet que l'Echo reçoit.
3. **La limite est opérationnelle** : la table de fabric dans le KVS devient incohérente
   après plusieurs relances, et le CASE échoue. **Fuzzer sérieusement demanderait de
   re-commissionner à chaque essai** (avec l'app de l'utilisateur à chaque fois).

### Conclusion honnête sur Matter

**Le commissioning Matter est la première surface que nous ayons franchie de bout en bout
sur cet appareil** — de la découverte mDNS au `CommissioningComplete`. **Mais elle ne mène
pas à une exécution de code** : la pile est récente (2024-2026), bien testée, et résiste
à ce que nous avons tenté.

---

## 32. CARTE RÉSEAU FINALE : 7 ports TCP, tous fermés sauf Matter

**Balayage exhaustif 1-65535 de l'Echo (192.168.1.24, confirmé par mDNS `A7FA253E6C23.local → 192.168.1.24`) :**

| Port | Service identifié | État |
|---|---|---|
| **1080** | **`/system/bin/socks`** (SOCKS5 à whitelist, **user root**) | ❌ refuse tout (code 9 = « not in whitelist ») |
| **4070** | Spotify Connect (login) | ❌ identifiants requis |
| **5541** | Matter | ⚠️ commissionné, fuzzé, robuste |
| **8888** | RST immédiat | ❌ fermé |
| **55442** | HTTP interne | ❌ 404 sur 34 routes |
| **55443 / 55445** | WHALEXA mTLS | ❌ `handshake failure` (CA privée) |

### Découverte : `/system/bin/socks` — un proxy SOCKS5 **root** à whitelist

```
service socks5stream /system/bin/socks -i p2p0 -p 1080
    socket socks_sup stream 660 wifi wifi
    disabled · oneshot · user root · group root system
```

**Architecture décodée (strings + .rc) :**
- Le serveur écoute sur **p2p0:1080**, identifie le client **par son MAC via la table ARP**
  (`Failed to get macaddr for client %s from ARP Cache`)
- Il valide `deviceID` dans une `IDbyMac table` puis `host` dans la whitelist
  (`client's requested remote host is not in whitelist`)
- Si autorisé : il **écrit une règle iptables** (`setting Up iptables rule to enable port %u`,
  `/system/bin/iptables --dport`) et proxifie
- La whitelist est alimentée par le socket UNIX `/dev/socket/socks_sup` (660 wifi:wifi)
- Le binaire appelle **`system()`** (exécution shell) et utilise `strcpy`/`sscanf`/`strtok_r`

**⇒ En mode normal la whitelist est VIDE → tout est refusé (code 9 mesuré).
Aucun fichier `.rc`/`.sh` ne démarre le service (`disabled`), il est lancé par `ctl.start`.
La primitive (iptables + `system()`) existe mais n'est pas atteignable sans une entrée
de whitelist, qui exige un accès local au socket UNIX.**

### Faux positif corrigé (méthode)

**Un cache ARP corrompu sur le Mac affichait `.24`, `.14`, `.41` avec le MÊME MAC de
Raspberry Pi. La cause réelle : le piveil fait du **proxy ARP** — le ping l'a révélé
(`92 bytes from piveil.home (192.168.1.41): Redirect Host(New addr: 192.168.1.24)`).
La résolution mDNS de `A7FA253E6C23.local` a confirmé que `.24` EST l'Echo.
**Leçon ajoutée : ne jamais conclure depuis une table ARP — croiser avec mDNS.**

---

## 33. MATTER — 3ᵉ et dernière campagne de fuzz : négatif propre

**Trois vecteurs testés, du plus grossier au plus fin :**

| # | Vecteur | Résultat |
|---|---|---|
| 1 | `--product-name` de **4 000** puis **60 000** octets | L'Echo lit, fragmente en ~50 ReportData, **survit** |
| 2 | Patch `TLVWriter::WriteElementWithData` : déclarer `dataLen-100` en écrivant `dataLen` | Notre app rollback (`No memory`), rien n'est envoyé |
| 3 | Patch `TLVWriter::PutString` : en-tête déclare `len-1`, données écrivent `len` | **Session CASE OK, `ReportData` envoyé, l'Echo ACQUITTE, aucun crash** |

**Leçon technique majeure :** le patch #2 était dans `WriteElementWithData`, utilisé
**par le handshake CASE lui-même** → notre Sigma2 était malformé et l'Echo le rejetait
(`CHIP Error 0x54: Invalid CASE parameter`). **Le fuzz ne pouvait jamais atteindre
la lecture d'attributs.** En limitant le patch à `PutString` (chaînes UTF8 uniquement,
jamais utilisées par CASE), la session s'établit et le rapport malformé est délivré.

**Résultat final mesuré :** TLV désynchronisé délivré et acquitté → **le parseur TLV
du contrôleur Matter de l'Echo est borné et robuste.** Aucun reboot pendant le test
(surveillance `5541` toutes les 1,5 s, seuil de coupure 8 s).

### L'épisode de l'anneau bleu

**L'Echo a rebooté (~10 min hors ligne) après notre première salve de TLV désynchronisés.
Il est revenu avec son fabric Matter INTACT** (`_matter._tcp` réannoncé :
`35E0AC61C6C83219-079B277EE4E46151`). **Ce n'était donc pas une mise à jour effaçante,
mais un redémarrage de service.** La cause exacte (notre fuzz ou un OTA Amazon)
n'a pas été tranchée : l'absence de reproduction lors de la 3ᵉ campagne plaide
pour un concours de circonstances plutôt que pour un crash reproductible.

---

## 34. BLUETOOTH — la seule surface jamais explorée, et sa limite structurelle

**Pile BT du firmware doebrite :**
```
/system/bin/btmanagerd            (17,9 Ko)  — daemon
/system/bin/btclient              (106 Ko)   — client Amazon/MTK
/system/bin/btclient_ble          (43 Ko)    — client BLE
/system/bin/btmac.sh              (521 o)    — MAC BT depuis /proc/idme/bt_mac_addr
/system/lib/hw/bluetooth.default.so (1,4 Mo) — HAL Android
/system/lib/libbluetooth_mtk.so   (22 Ko)    — bibliothèque MTK
```

**Le point décisif, mesuré dans les .rc :**
```
init.ace.rc:30     service btmanagerd /system/bin/btmanagerd
                       class main · user root · group aipc bluetooth net_bt_admin …
                       disabled              ← JAMAIS démarré automatiquement
init.mt8516.rc:220     start btmanagerd        ← autre SoC (MT8516), PAS le nôtre
```
**⇒ Sur le MT8167 (doebrite), `btmanagerd` n'est jamais lancé. Le BT n'est actif
qu'en mode setup (BLE pour l'app), jamais en fonctionnement normal.**

**Balayage BT réel depuis le XMG (Intel AX201, HCI 5.2, `hcitool`/`bluetoothctl`/`btmon`) :**
inquiry classique 25 s et LE scan 20 s → **aucun appareil**, y compris pendant
et après le reboot de l'Echo. **Cohérent avec un BT éteint en mode normal.**

**⇒ La surface Bluetooth n'est atteignable qu'en mode setup — c'est-à-dire dans un
état que seul l'utilisateur (ou une réinitialisation usine) peut déclencher.**

---

## 35. ★ WHISPERJOIN — le protocole de provisioning Amazon, extrait de l'APK

### Ce que c'est

**L'APK `com.amazon.echo.csm.oobe` embarque **453 classes Java** du protocole de
provisioning d'Amazon, réparties en trois couches :**

```
com.amazon.whispercloak    → la crypto   (ECJ-PAKE, ECDH, AES-GCM, SecureChannel)
com.amazon.whisperbridge   → le transport (serveur GATT BLE)
com.amazon.whisperjoin     → le protocole (commandes, événements, barcode)
```

### Les UUID GATT, en clair dans `BleConstants.java`

```
Service WhisperJoin :  0000FE00-0000-1000-8000-00805F9B34FB
Status              :  cf011df7-07ee-40b7-a71d-3f2eb6e0d040
StartProvisioningReq:  cf011df8-07ee-40b7-a71d-3f2eb6e0d040
StartProvisioningRsp:  cf011df9-07ee-40b7-a71d-3f2eb6e0d040
ProvisioningCommand :  cf011dfa-07ee-40b7-a71d-3f2eb6e0d040
CommandResponse     :  cf011dfb-07ee-40b7-a71d-3f2eb6e0d040
Notification        :  cf011dfc-07ee-40b7-a71d-3f2eb6e0d040
```

### Le handshake

```
StartProvisioningRequest  = un simple requestID aléatoire (int)
StartProvisioningResponse = { requestID, status }  avec
    0 = GRANTED · 1 = DENIED_ACTIVELY_PROVISIONING_ALREADY · 2 = DENIED_INTERNAL_ERROR
```
**Puis l'échange de clé : `AUTHENTICATED_ECDHE_COMMAND` (et une variante non authentifiée).**

### ★ Le secret : `barcodePin`

```java
JPAKESessionKeyNegotiatorImpl(String participantId, String barcodePin) {
    ECJPAKEPrimeOrderGroup group = new ECJPAKEPrimeOrderGroup("prime256v1");
    mParticipant = new ECJPAKEParticipant(participantId, barcodePin.toCharArray(), group);
}
```

**Le mot de passe du ECJ-PAKE est le **PIN du code-barres de l'appareil**. Format exact,
extrait de `RegexBarcodeParser.java` :**

```
ABV = "(IB[0-9]{2})"                  version du code-barres
PID = "([a-zA-Z0-9]{4})"              product ID
PUK = "([-A-Za-z0-9+/=]+={0,3})"      clé PUBLIQUE du device (base64)
PIN = "([a-zA-Z0-9]{8,12})"           ★ mot de passe ECJ-PAKE
```

**L'authentification du DEVICE se fait par certificat + signature
(`ProvisionableDeviceAuthenticationData` = chaîne de certificats + signature),
vérifiée contre le PUK du code-barres.**

### Les commandes disponibles

```
GET_DEVICE_DETAILS · GET_VISIBLE_NETWORKS (scan Wi-Fi) · GET_CONFIGURATION
CONNECT_TO_CONFIGURED_NETWORK · DELETE_CONFIGURED_NETWORK
DELETE_ALL_CONFIGURED_NETWORKS · GET_PROVISIONING_FAILURE_CAUSE
AUTHENTICATED_ECDHE_COMMAND
```

**`GET_CONFIGURATION` et `GET_VISIBLE_NETWORKS` sont exactement les primitives
qui intéressent un attaquant (credentials Wi-Fi, cartographie du voisinage).**

### Ce qui reste à déterminer (ouvert)

1. **Le Echo Dot 3 (2018) utilise-t-il WhisperJoin en BLE ?** Le Dot 3 fait son setup
   par AP Wi-Fi + OOBE sur 8080 (surface déjà explorée à fond). Le BLE WhisperJoin
   est documenté dans l'APK car celle-ci gère plusieurs générations.
2. **Le PIN est-il dérivable du DSN (`G091470502330EBE`), ou est-ce un secret
   indépendant imprimé sur la boîte ?** Non tranché — c'est LA question qui décide
   si le protocole est rejouable sans possession physique de l'emballage.
3. **Le mode `UnauthenticatedEcdheKeyExchange` est-il accepté par un Dot 3 ?**
   S'il l'est, la barrière du PIN disparaît pour la session (le device resterait
   authentifié par certificat, mais le canal serait ouvert).

**Pour trancher : mettre l'Echo en mode setup et scanner le BLE pour le service
`0000FE00-...`. Cela exige une réinitialisation de l'appareil.**

---

## 36. ★ WHISPERJOIN BLE — surface ENTIÈREMENT FRANCHIE, puis fermée par l'authentification

### Ce qui a été réalisé (première fois de la campagne)

**Le protocole de provisioning BLE d'Amazon a été parlé de bout en bout avec un client
écrit from scratch, sans l'app Alexa, sans téléphone, depuis un laptop Linux :**

```
1. Scan BLE          → "Echo Dot-EBE" (service 0000FE00-...)
2. Connexion GATT    → 6 caractéristiques cf011df7..cf011dfc
3. START_PROVISIONING → requestId protobuf (0x08 + zigzag varint)
   ★ RÉPONSE : 08 <key> 10 00  → status 0 = GRANTED
4. PROVISIONING_COMMAND → WhisperJoinBlePacket{packetKey, chunkIndex, additionalChunks, payload}
   payload = ProvisioningCommand{uuid, data}  (protobuf)
5. Lecture de COMMAND_RESPONSE + protocole de chunks
   ★ RÉPONSES REÇUES ET DÉCODÉES
```

**Détails techniques qui ont débloqué la chose (tous extraits de l'APK) :**
- **`StartProvisioningRequest` = protobuf `sint32 requestId` (champ 1, ZIGZAG)** —
  un int32 little-endian brut est silencieusement ignoré (`requestId_ = readSInt32()`)
- **`WhisperJoinBlePacket`** : champ 1 packetKey (int32), 2 chunkIndex, 3 additionalChunks, 4 payload
- **`ProvisioningCommand`** : champ 1 uuid (16 o **little-endian, LSB d'abord**), 2 data
- **La réponse se LIT** (caractéristique `read`), elle n'arrive pas seulement en notification :
  `readCharacteristic(PROVISIONING_COMMAND_RESPONSE)` puis, si `additionalChunks`,
  renvoyer un `createNextResponsePacket` (même clé, payload 1 octet)

### Le mur : provisioner non autorisé

**Table des statuts (décodage zigzag) :**
```
0 = SUCCESS · 1 = internal error · 2 = UNKNOWN COMMAND · 3 = serialization error
4 = packet verification error · 5 = UNAUTHORIZED PROVISIONER
```

**Résultat mesuré sur 17 commandes :**

| Commande | Statut |
|---|---|
| `GET_DEVICE_DETAILS`, `GET_VISIBLE_NETWORKS`, `INITIATE_VISIBLE_NETWORK_SCAN`, `SAVE_CONFIGURED_NETWORK`, `SET_CONFIGURATION`, `PROVISIONING_COMPLETE` | **5 = unauthorized provisioner** |
| `GET_CONFIGURATION`, `STOP_PROVISIONING`, `RETRIEVE_SUPPORTED_COMMANDS` | **2 = unknown command** |

**`UNAUTHENTICATED_ECDHE` (clé P-256 DER, format confirmé champ 1) → également refusé.**
**`AUTHENTICATED_ECDHE` exigerait une signature que nous n'avons pas.**

### ★ Le vrai mécanisme d'authentification : CBL, pas le code-barres

**La commande `REGISTER_WITH_CODE_BASED_LINKING` (`c95ec718-f36f-4cd9-9879-1fa22f7eb110`)
et ses statuts (`-11 TOKEN_INVALID`, `-12 TOKEN_EXPIRED`, `-13 SERVER_NOT_REACHABLE`,
`-14 SERVER_ERROR`) révèlent le modèle :**

**L'Echo s'authentifie par un **token CBL** (Code-Based Linking) délivré par le **cloud Amazon**,
et non par le PIN du code-barres (celui-ci sert à d'autres familles d'appareils, type prises/Fire TV).**

**Conséquence nette : le PIN de l'emballage n'aurait pas débloqué la surface.
Il faudrait un compte Amazon et le flux de liaison cloud — ce qui donne la *propriété*
de l'appareil (le configurer), pas un accès privilégié au système.**

### Ce que cette surface permet néanmoins

**Un provisioning complet de l'Echo en BLE pur, sans l'app Alexa** — Wi-Fi + liaison compte.
**C'est une capacité réelle, mais qui n'écrit aucune partition et n'élève aucun privilège.**

### Verdict

**WhisperJoin est la surface la plus profonde que nous ayons franchie — et elle s'arrête
sur une authentification cloud correctement implémentée. Ce n'est pas un défaut à exploiter,
c'est un contrôle d'accès qui fonctionne.**

---

## 37. MODE SETUP — cartographie réseau mesurée depuis l'AP de l'appareil

### La mesure qui manquait

**Pour la première fois, une machine a été connectée **sur l'AP de setup de l'Echo**
(`Amazon-EBE`, BSSID `D6:91:BF:BB:72:4A`) et tout son réseau a été balayé.**

```
XMG (Intel AX201) : 10.201.126.242/28
Echo (AP + DHCP)  : 10.201.126.241   (ICMP bloqué)
```

**Balayage TCP 1-65535 → UN SEUL port ouvert : 8080**

```
8080 = l'APK com.amazon.echo.csm.oobe (Jetty embarqué)
GET  /      → 405 Method Not Allowed (Allow: POST, OPTIONS)
POST /OOBE  → 400 Bad Request (corps vide)
```

**⇒ En mode setup, `1080` (le SOCKS root) n'écoute PAS : il est lié à `p2p0`, une
interface Wi-Fi Direct qui n'existe pas dans cet état. `5541` (Matter) et `8888`
ne sont pas ouverts non plus.**

**⇒ La surface du mode setup se réduit donc à `8080`, déjà explorée à fond
(15 méthodes Thrift-JSON, SSRF `getLinkCode`, certificat éphémère, portail captif).**

### Format d'appel OOBE (pour mémoire, il diffère de ce qu'on croit)

**Le corps est un **tableau** JSON, pas un objet, avec `Content-Type: application/x-thrift` :**
```python
POST /OOBE   [1, "getDeviceDetails", 1, 1, {}]
```
**Réponse : `[1, "getDeviceDetails", 2, 1, {"0":{"rec":{...}}}]`**

### `getDeviceDetails` — ce que l'appareil révèle en setup

```
1  : productId       0013222532484
2  : MAC             DC91BFBB724A
5  : certificat      -----BEGIN CERTIFICATE----- (CN=setup, éphémère)
6  : DSN             G091470502330BE
7  : (bool)          true
8  : locales         17 langues (ja-JP, es-US, hi-IN, fr-FR, …)
11 : deviceType      A30YDR2MK8HMRV
12 : (i32)           2
```

**Aucune version de firmware n'est exposée. Aucun champ nouveau par rapport à
ce qui était déjà documenté.**

### Conclusion de la section

**Le mode setup ne contient aucune surface inédite : c'est l'AP + le 8080, tous deux
déjà mesurés. Le SOCKS root et Matter ne sont actifs qu'en fonctionnement normal,
et y sont fermés.**

---

## 38. BOUTONS & BOOTLOADER — le dernier chemin physique, et sa fermeture

### Ce que `lk` contient réellement

**Désassemblage Thumb complet (100 248 lignes) du bootloader. Trois interfaces
utilisateur existent, pilotées par les boutons :**

```
Yes (Volume UP)   : Confirm and Boot.
No  (Volume Down) : Abort.
[VOLUME_UP to select.  VOLUME_DOWN is OK.]
[Recovery    Mode]
[Fastboot    Mode]
[Normal      Boot]
[VOL_UP]Key Detect, current select:%d
Key Uber: Pressed / Released        ← "Uber" = le bouton d'action
pmic_detect_homekey
```

**⇒ Il y a bien un **menu de boot** dans le bootloader, navigable aux boutons volume,
avec trois choix : Recovery / Fastboot / Normal. Sans écran, il ne peut guider
que par des bips.**

### Le switch de mode de boot (0x41e1d7c0), résolu

**La variable de mode vient de `idme bootmode` (chaînes `bootmode`, `Error IDME:
reading bootmode failed`, `Error IDME: bootmode negative`). Les 6 branches :**

| valeur | cible | chaîne résolue |
|---|---|---|
| **4, 6** | factory | `factory.img` |
| 10 | — | (autre chemin) |
| 7 | — | (autre chemin) |
| **97** | swdl | **`Wifi SWDL Boot Image`** |
| **98** | dkernel | **`Diagnostic Boot Image`** |

**`lk` sait aussi ÉCRIRE dans idme (`idme_update_var_ex`, `idme_write`), ce qui sert
au bootcount.**

### ★ La fermeture, par la mesure

**Recherche de `swdl` / `dkernel` dans tout ce qui pourrait les héberger :**

```
boot.img (device tree)          → 0 occurrence
brhgptpl_0..3.img (partitions)  → 0 occurrence
system.img                      → 0 occurrence
```

**⇒ Le mode `swdl` (« Wifi SWDL Boot Image ») **n'a pas d'image cible sur ce produit**.
Le code de `lk` la cherche par nom (`bl` avec la chaîne `swdl`) ; elle n'existe pas.
**Forcer `bootmode=97` ne mènerait qu'à un échec de démarrage, pas à un mode de
téléchargement Wi-Fi.**

### Pourquoi les autres branches ne sauvent pas la mise

| Mode | Pourquoi il ne mène pas à l'OS |
|---|---|
| **Fastboot** | nécessite un **port USB — le Dot 3 n'en a aucun** |
| **Recovery** | image **signée** ; et sans USB ni réseau, aucune entrée |
| **factory.img** | inexistante sur ce produit (message du code : *« factory image doesn't exist in SD card »*) |
| **dkernel** | aucune image `dkernel` définie |

### Conclusion de la section

**Le dernier chemin purement physique — les boutons — a été exploré jusqu'au bout
du désassemblage. Il existe bien un menu de boot, mais toutes ses branches exigent
soit un port USB que l'appareil n'a pas, soit une image signée ou absente.**

**Il ne reste plus aucune surface non mesurée : Wi-Fi, BLE, boutons, alimentation.
Toutes ont été franchies ou fermées par une mesure.**

---

## 39. ★★ PREMIER CRASH REPRODUCTIBLE — CVE-2019-0205 dans `oobed` (Thrift 0.9.0)

### Correction d'une erreur de la campagne

**Nos notes affirmaient que `oobed` n'existait pas sur doebrite. C'ÉTAIT FAUX.**
**`/system/bin/oobed` fait **521 948 octets** et c'est lui qui sert le port 8080.**

```
init.oobe.puffin.rc :
  service oobed_on_boot  /system/bin/oobed -r 1
      user oobe
      group aipc oobe dbus system inet ace_kvstore keystore ace_group drmrpc ace_maplite davs
      disabled · oneshot
  on property:com.amazon.puffin.OOBED_START=on_boot|on_button_press|on_network_disconnect
```

**L'app OOBE en Java que nous avions analysée (`com.amazon.echo.csm.oobe`) n'est
pas dans cette image : il n'y a que 3 APK (`credentialmanager`, `diode`,
`factory_reset`). Toute l'analyse de protocole reste valide (c'est le même
Thrift-JSON), mais **la cible est un binaire natif C++, pas du Java.**

### La chaîne réelle, par les imports dynamiques

```
oobed  →  libcivetweb.so   (serveur HTTP natif C)
       →  libdoppleroobe.so (logique OOBE, Apache Thrift C++)
       →  libthrift.so      (TJSONProtocol)   ← version 0.9.0 (2013)
       +  libace_wifimgr / ace_maplite / ace_ffs / ace_netmgr / libcurl / libcrypto
```

**Vocabulaire confirmé par les symboles :**
```
OOBE::DopplerOOBEProcessor::dispatchCall / process_ping / process_forgetAP
OOBE::DopplerOOBEClient::connectToAP / getLinkCode / getScanList
OOBE::OTADetails::read / DeviceDetails::read / APConnectInfo::read
apache::thrift::protocol::TProtocol        ← le parseur
```

### ★ Protections mémoire : absentes

```
libcivetweb.so    : 0 __stack_chk_fail
libdoppleroobe.so : 0 __stack_chk_fail
libthrift.so      : 0 __stack_chk_fail      ← AUCUN stack canary
oobed             : 0 __stack_chk_fail      (PIE, RELRO+BIND_NOW)
```

**Quatre composants natifs qui parsent nos octets, aucun protégé par une canari.**

### Le crash, mesuré

**Structure Thrift-JSON **valide** avec des records imbriqués (le parseur TJSONProtocol
descend récursivement sans valider le schéma) :**

```python
body = b'[1,"ping",1,1,' + b'{"0":{"rec":' * depth + b'{}' + b'}}' * depth + b']'
```

| profondeur | taille | résultat |
|---|---|---|
| 50 | 717 o | 200 OK |
| 200 | 2 817 o | 200 OK |
| 1 000 | 14 017 o | 200 OK |
| 5 000 | 70 017 o | 200 OK |
| **20 000** | **280 017 o** | **RemoteDisconnected — serveur MORT** |

**Après le crash : 3 tentatives sur 15 s → aucune réponse.
L'AP Wi-Fi reste actif : la carte est vivante, **seul `oobed` est tombé**.
Comme le service est `oneshot`, **init ne le relance pas** : l'OOBE reste mort
jusqu'au prochain redémarrage de l'appareil.**

### Qualification

**C'est exactement **CVE-2019-0205** (Apache Thrift 0.9.0 → 0.12.0 : épuisement de
pile par structures JSON profondément imbriquées). Amazon embarque **0.9.0**,
la version vulnérable, dans un service **joignable sans authentification** sur
le port 8080 du réseau de setup.**

**Portée : déni de service persistant sur le serveur de provisioning.**
**Ce n'est pas une exécution de code : l'épuisement de pile heurte la page de garde
(SIGSEGV), il n'écrase pas d'adresse de retour de façon contrôlable via cette seule
primitive. Mais c'est le **premier impact réel et reproductible** de toute la campagne,
et il ouvre le fuzzing ciblé du même parseur (chaînes, échappements Unicode, nombres)
que nous n'avons pas encore exercé.

---

## 40. CAMPAGNE DE FUZZING NATIF — résultats complets

### Le harnais

**Machine connectée sur l'AP de setup (`Amazon-EBE`, 10.201.126.242/28), ciblant
`10.201.126.241:8080` (`oobed`).**

### 1. Parseur Thrift (TJSONProtocol 0.9.0) — testé sur `ping`

| entrée | taille | résultat |
|---|---|---|
| chaîne simple | 1 024 → **1 048 576 o** | ✅ 200 OK |
| UTF-8 invalide (`\xff\xfe`) | 1 024 → 262 144 o | 400 (rejeté proprement) |
| surrogates isolés (`\ud800` × 2000) | 12 031 o | 400 (rejeté) |
| échappements profonds (`\\` × 50 000) | 100 031 o | ✅ 200 OK |
| entier 64 bits de 5 000 chiffres | 5 030 o | 400 (rejeté) |
| **records imbriqués** | **20 000 niveaux** | **☠️ CRASH (CVE-2019-0205)** |

**⇒ Le parseur encaisse 1 Mo de chaîne et rejette proprement tout ce qui est malformé.
Sa seule faiblesse est la récursion (déni de service).**

### 2. Parseur HTTP (civetweb) — requêtes brutes

| test | résultat |
|---|---|
| header de 20 Ko | 500, vivant |
| ligne de requête de 20 Ko | 500, vivant |
| URL de 60 Ko | 500, vivant |
| `Content-Length: 999999999999` | 400, vivant |
| `Content-Length: -1` | timeout, vivant |
| deux `Content-Length` | 400, vivant |
| `Transfer-Encoding: chunked` malformé | 400, vivant |
| octet NUL dans le chemin | 500, vivant |
| méthode de 10 Ko | 500, vivant |
| traversée `../../../../etc/passwd` | **405** (route absente), vivant |
| 100 en-têtes | 400, vivant |

**⇒ civetweb est robuste sur tous ces cas.**

### 3. Champs métier de l'OOBE

| champ | tailles testées | résultat |
|---|---|---|
| SSID (`connectToAP`) | 32 → 16 384 o | 500 `API exception`, vivant |
| locale (`setLocaleAndEndpoints`) | 32 → 65 536 o | 500, vivant |
| endpoint URL | 32 → 65 536 o | 500, vivant |

**⇒ Les valeurs sont validées avant d'atteindre le code Wi-Fi : pas de débordement.**

**Note mesurée : `connectToAP` échoue avec `API exception (6:1:101:9:4)` quand l'AP
demandé n'existe pas ; `getScanList` retourne 8 réseaux ; `ping` retourne `true` ;
`evaluateCaptivePortal` bloque (pas d'uplink).**

### Conclusion

**Sur les trois parseurs natifs joignables sans authentification, un seul cède :
la récursion Thrift (déni de service). Ni le parseur HTTP, ni les champs métier
n'ont donné de corruption mémoire. La pile de traitement d'`oobed` est globalement
bien écrite — à l'exception d'`libthrift 0.9.0`, obsolète et vulnérable.**

---

## 41. SPOTIFY CONNECT — API exposée sans authentification, protocole décodé

### La surface

**Le device annonce `_spotify-connect._tcp` en mDNS :
`SpotifyConnect.local:4070`, **`CPath=/spotifyConnect`**.**

```
GET /spotifyConnect?action=getInfo   → 200 OK, AUCUNE authentification
```

**Réponse complète (mesurée) :**
```json
{ "status": 101, "statusString": "OK", "version": "2.9.0",
  "deviceID": "93cc9e5a-45e3-456e-b2c0-92f5f91a18bc",
  "publicKey": "i7uACqQ4mLE+0dv4…",           // 96 octets
  "deviceType": "SPEAKER",
  "libraryVersion": "3.209.367-g12ca7f99",
  "brandDisplayName": "Amazon",
  "modelDisplayName": "Echo_Dot_with_clock",
  "aliases": [ {"name": "GARROT - Echo Dot", "id": "1"} ],
  "clientID": "27d4dfe427b34d57995b463e5d63198d",
  "productID": 53 }
```

**⇒ Fuite d'information : n'importe quel hôte du LAN obtient le `deviceID`, la clé
publique de session, le `clientID` Spotify et **l'alias Spotify de l'utilisateur**,
sans aucune authentification.** (Sévérité : faible — information disclosure.)

### La pile technique

```
libSpotifyAdapter.so           1 714 016 o   canari=0   strcpy+strcat+memcpy
libSpotifyAdapterInternal.so     165 452 o   canary=0   contient le handler addUser
libPAL.so                        853 576 o   canary=0   (ESDK Platform Abstraction)
libGadgetsDelegate.so             22 088 o   canary=0
libReggaeDevice.so               108 108 o   canary=0
```

**Symboles identifiés :**
```
SpotifyAdapterInternal::addUser(SpotifyESDKRequest&)              @ 0x18d55
SpotifyAdapterInternal::putAndWaitAddUserMessageOnQueue(…)        @ 0x18565
amazon::spotify::SpotifyConnectManager::addUser(SpError&, char*, char*, char*, char*, char*, int)
```

**Paramètres attendus repérés dans les chaînes : `userName`, `blob`, `userNameLen`,
`blobLen`, `addUserInvalidParams`, `addUserWithLogin`.**

### Le protocole, entièrement décodé (depuis librespot)

**Le blob de `addUser` est construit ainsi :**

```
1. DH  : MODP 1536 bits (RFC 2409 group 5), générateur 2, clé privée 95 octets
2. shared      = clientKey^priv mod P
3. base_key    = SHA1(shared)[0..16]
4. checksumKey = HMAC-SHA1(base_key, "checksum")
5. encryptKey  = HMAC-SHA1(base_key, "encryption")
6. blob        = base64( IV[16] + AES-128-CTR(encryptKey[0..16], IV, plaintext)
                          + HMAC-SHA1(checksumKey, ciphertext) )
7. plaintext interne = AES-192-ECB( clé = PBKDF2-SHA1(SHA1(deviceID), userName, 0x100)
                                    → puis SHA1 → + u32 BE(20) )
   contenu : u8 + varint-len + bytes + u8 + varint(authType) + u8 + varint-len + bytes
```

**Implémentation fonctionnelle écrite et testée (DH, HMAC, AES, crafting du blob
interne) — mais l'ESDK **d'Amazon** rejette toutes les variantes en
`400 {"status":102,"spotifyError":1,"ERROR-BAD-REQUEST"}`, c'est-à-dire **avant
toute cryptographie** : les noms/format de paramètres attendus diffèrent de la
spécification librespot, et n'ont pas pu être déterminés par désassemblage dans le
temps imparti.**

### Pourquoi c'était intéressant

**Le plaintext interne est **entièrement contrôlé** par le client (clé dérivée de
`deviceID` connu + `userName` choisi), et il est parsé par du **C++ sans canary**
(`read_bytes` : `read_int(longueur)` puis allocation/lecture de cette longueur).
Une longueur incohérente y serait un candidat sérieux. **Ce chemin reste ouvert**
mais bloqué par la validation des paramètres de l'ESDK propriétaire.

---

## 42. CORRECTION — erreur sur les stack canaries

**Les sections 39, 40 et 41 affirmaient qu'`oobed`, `libthrift`, `libdoppleroobe`,
`libcivetweb` et `libSpotifyAdapter` étaient construits SANS stack canary.
**C'est FAUX.**

**Mesure correcte (`objdump -d | grep -c stack_chk_fail@plt`) :**

| composant | sites d'appel à `__stack_chk_fail` |
|---|---|
| `libSpotifyAdapter.so` | **823** |
| `libthrift.so` | **302** |
| `libdoppleroobe.so` | **130** |
| `libSpotifyAdapterInternal.so` | **73** |
| `libcivetweb.so` | **53** |

**La méthode fautive : `readelf -s | grep -c stack_chk_fail`. Le symbole est versionné
(`__stack_chk_fail@LIBC`) et la troncature du champ dans la sortie `readelf` faisait
échouer le filtre. L'extraction `awk '$7=="UND"{print $8}'` tronquait elle aussi le nom.**

**Conséquence : tous ces composants SONT protégés par une canari de pile. Les
débordements de pile y sont donc détectés avant le retour de fonction.
Le CVE-2019-0205 reste valide — c'est un épuisement de pile qui heurte la page de
garde, indépendamment de la canari.**

**Leçon de méthode ajoutée : une absence ne se conclut jamais depuis une sortie
tronquée — il faut compter les sites d'appel dans le désassemblage, pas chercher
un nom dans une table de symboles formatée.**
