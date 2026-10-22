# WLAN_AUDIT — audit mémoire du driver mt76x8 (Echo Dot 3)

Audit du 2026-10-21, source `vendor/amazon/wlan/mediatek/driver/mt76x8/`
(93 `.c`, 7,8 Mo, livré dans les sources GPL d'Amazon).
Contexte : **nous contrôlons l'AP**, donc toute trame forgée atteint ce code, en
espace noyau.

**Verdict en une phrase : le driver est déjà durci sur les chemins de parsing de
trames. Aucun dépassement d'écriture trouvé. Un défaut de lecture hors bornes
réel mais sans effet observable.**

---

---

## ⚠️ ENCADRÉ CRITIQUE — la source 2024 n'est PAS la preuve que l'appareil est patché

**Ce rapport audite `Echo_Dot_3rd_Gen_Clock_AVS_src-6.5.6.4-20240803`, publié en
2024. Notre appareil tourne un firmware d'usine de 2019, jamais mis à jour.**

Les CVE 2020 des drivers MediaTek (compteur de PMKID, compteur de cipher suites
non bornés dans le parsing du RSN IE) ont été **corrigées vers 2020**. Le code
de 2024 que j'ai lu contient ces correctifs (`rsn.c:266` clamp PMKID,
`rsn.c:337` clamp pairwise). **Le binaire de 2019, lui, précède ces correctifs.**

Conséquence : « le driver est durci » est vrai **de la source 2024** et
**n'autorise aucune conclusion sur l'appareil**. Les motifs de 2020 sont
probablement **encore ouverts** sur notre Echo.

Ce que ça change : la lecture de source ne peut plus trancher. Il faut **tester
l'appareil** en lui émettant les trames que le code de 2024 rejette et que celui
de 2019 acceptait. C'est l'objet de `fuzz_wifi_rsn.py`.

**Corollaire de méthode** : toute conclusion « c'est patché » tirée d'un drop GPL
récent est invalide pour un appareil dont on n'a pas daté le firmware. À vérifier
au dump (`strings` sur le binaire `wlan_mt76x8` : présence des chaînes
« Support maximum PMKID Cnt » et des bornes associées = version patchée).

---

## 1. Méthode

1. Cartographie des points d'entrée RX : `mgmt/rsn.c`, `mgmt/wnm.c`, `mgmt/scan.c`,
   `mgmt/assoc.c`, `mgmt/auth.c`, `mgmt/hs20.c`, `mgmt/p2p_ie.c`, `nic/nic_rx.c`.
2. Recherche systématique des copies dont la **longueur n'est pas une constante**
   (`kalMemCopy`/`kalMemMove`/`memcpy` dont le dernier argument n'est ni un
   littéral ni un `sizeof`) — 68 occurrences, triées par « la longueur vient-elle
   d'une trame ? ».
3. Lecture manuelle des candidats retenus, en vérifiant pour chacun :
   la borne d'écriture (taille de destination), la borne de lecture (longueur
   restante de la trame), et si la valeur copiée est **relue** ensuite.

---

## 2. Ce qui est DÉJÀ PATCHÉ (et ça explique le résultat)

`mgmt/rsn.c:122 rsnParseRsnIE()` est un modèle de robustesse. Chaque champ est
validé contre la longueur restante **avant** d'être lu :

```
:166  if (u4RemainRsnIeLen < 4) { … return FALSE; }        /* group cipher */
:180  if (u4RemainRsnIeLen < 2) { … return FALSE; }        /* pairwise count */
:193  if (u4RemainRsnIeLen < (INT_32) i) { … return FALSE; } /* pairwise list */
:209  if (u4RemainRsnIeLen < 2) { … return FALSE; }        /* akm count */
:222  if (u4RemainRsnIeLen < (INT_32) i) { … return FALSE; } /* akm list */
:238  if (u4RemainRsnIeLen < 2) { … return FALSE; }        /* capabilities */
:257  if (u4RemainRsnIeLen < 2) { … return FALSE; }        /* pmkid count */
```

Et surtout, les compteurs sont **clampés** avant les copies :

```
:266  if (u2DesiredPmkidCnt > MAX_NUM_SUPPORTED_PMKID) {
:284  kalMemCopy(prRsnInfo->aucPmkidList, cp, u2SupportedPmkidCnt * RSN_PMKID_LEN);
:337  if (u2PairSuiteCount > MAX_NUM_SUPPORTED_CIPHER_SUITES)
```
(numéros de ligne vérifiés par script sur le fichier livré)

Ce sont exactement les motifs des CVE 2020 de drivers MediaTek (PMKID count,
cipher suite count). **Ils sont corrigés dans ce drop de 2024.** Chercher un
dépassement sur les IE RSN/WPA est donc une impasse : le code est post-patch.

---

## 3. Le seul défaut réel trouvé — `mgmt/wnm.c` (BTM Request)

### 3.1 Le code

```c
/* mgmt/wnm.c:340 */
VOID wnmRecvBTMRequest(IN P_ADAPTER_T prAdapter, IN P_SW_RFB_T prSwRfb)
…
:354  if (prSwRfb->u2PacketLen < OFFSET_OF(ACTION_BTM_REQ_FRAME_T, aucOptInfo)) {
:355      DBGLOG(WNM, WARN, "BTM: Request frame length is less than a standard BTM frame\n");
:356      return;
:357  }
…
:385  if (ucRequestMode & BTM_REQ_MODE_ESS_DISC_IMM) {
:390      kalMemCopy(prBtmParam->aucSessionURL, &pucOptInfo[1], pucOptInfo[0]);
:391      prBtmParam->ucSessionURLLen = pucOptInfo[0];
```

### 3.2 Type de défaut : **lecture hors bornes** (pas d'écriture)

| | |
|---|---|
| Défaut | `pucOptInfo[0]` est lu **à l'offset exact** où s'arrête la validation (`<` et non `<=`) → lecture 1 octet hors trame |
| Puis | `kalMemCopy(dst, &pucOptInfo[1], pucOptInfo[0])` : la longueur vient de la trame et **n'est pas comparée à la longueur restante** → lecture jusqu'à **255 octets hors trame** |
| Destination | `UINT_8 aucSessionURL[255]` (`include/mgmt/wnm.h:125`) |
| Écriture | `pucOptInfo[0]` est un `UINT_8` ⇒ **max 255 dans 255 octets** ⇒ **pas de dépassement d'écriture** |
| Effet observable | **aucun** : `aucSessionURL` et `ucSessionURLLen` ne sont **jamais relus** après cette copie (vérifié : seules occurrences = la copie et la définition) |

**Sévérité réelle : faible.** C'est un OOB read qui copie de la mémoire noyau
adjacente dans un champ… que personne ne consomme. Ce n'est **pas** une primitive
d'exploitation, et je ne vais pas le présenter comme telle.

### 3.3 Trame à forger (pour reproduction)

Action frame, catégorie WNM (10), action BTM Request (7), adressée au device :

```
octet   0            : 0xD0            (management, action)
octets  1-2          : durée
octets  3-8          : BSSID de l'AP (celui qu'on contrôle)
octets  9-14         : MAC du device
octets 15-20         : BSSID de l'AP
octets 21-22         : seq
octet  23            : 0x0A            (catégorie WNM)
octet  24            : 0x07            (action = BTM Request)
octet  25            : Dialog Token
octet  26            : Request Mode    ← bit 4 (0x10) = BSS_TRANSITION_DISASSOC_IMMINENT
octets 27-28         : Disassociation Timer
octet  29            : Validity Interval
octets 30..n         : Optional subelements
   30                : longueur déclarée L (0x00..0xFF, on met 0xFF)
   31..31+L          : « Session URL » (contenu arbitraire, ou rien du tout)
```

Pour déclencher le chemin : `ucRequestMode & 0x10` (bit 4,
`BTM_REQ_MODE_ESS_DISC_IMM`). Envoyer la trame **tronquée** après l'octet 30
(longueur = 0xFF mais aucune donnée derrière) maximise la lecture hors bornes.

---

## 4. Autres candidats examinés

| Emplacement | Longueur variable | Verdict |
|---|---|---|
| `mgmt/scan.c:1392,1431` | `u2RawLength`, `u2IELength` du BSS_DESC | longueurs produites **en interne** (scan), pas directement de la trame forgée |
| `mgmt/hs20.c:168` | `u2HS20AssocInfoIELen` | longueur d'un IE stocké, pas la trame brute |
| `nic/nic_rx.c:2016` | `ucSsidLen` d'un **événement firmware** | provient du firmware, pas directement de notre trame |
| `mgmt/p2p_ie.c:124`, `p2p_func.c` (27) | longueurs de buffers de requête | chemins TX/construction, pas RX |
| `mgmt/assoc.c`, `mgmt/auth.c` | `u2FrameLength`, longueurs d'IE en TX | émission, pas parsing |

Aucun de ces chemins n'a été audité exhaustivement — ce sont des **pistes
écartées ou non conclues**, pas des « sûrs ».

---

## 5. Ce que je n'ai PAS fait, et pourquoi ça compte

- **Pas d'audit exhaustif** des 93 fichiers. J'ai couvert les parseurs de trames
  les plus exposés (IE RSN/WPA, BTM, scan), pas `que_mgt.c` (227 Ko), `gl_wext_priv.c`
  (560 Ko), `wlan_oid.c` (447 Ko) ni la couche `chips/`.
- **Pas de vérification des parseurs DHCP/ARP/NTP** demandés au point (4) : ils ne
  sont pas dans ce driver WLAN (c'est de la pile IP du noyau et du userspace
  Android). Une recherche dans `platform.tar` ne les y trouve pas non plus. Si on
  veut cette piste, elle est dans le noyau Linux 4.4 lui-même et dans Android —
  pas ici. Autant le dire plutôt que de laisser croire que c'est couvert.
- **Pas de diff** avec une version antérieure (on n'a qu'un drop, 2024). Le fait
  que les motifs CVE soient corrigés est cohérent avec un code post-patch, mais je
  ne peux pas le prouver par comparaison.

---

## 6. Conclusion honnête

La piste « frame forgée → dépassement noyau » est **peu probable sur ce driver** :
les chemins de parsing d'IE sont explicitement bornés et clampés, ce qui est la
signature d'un code déjà corrigé. Le seul défaut trouvé est une lecture hors
bornes de gravité faible, sans effet observable.

Si on veut chercher du côté radio, les endroits non couverts et les plus prometteurs
resteraient : `nic/que_mgt.c` (files de TX/RX, 227 Ko) et `chips/` (couche chip),
qui n'ont pas la même discipline de bornage — mais je n'en sais rien, je ne les ai
pas lus, et je ne vais pas l'affirmer.
