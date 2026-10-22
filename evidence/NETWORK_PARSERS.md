# NETWORK_PARSERS — Surfaces DHCP / DNS / NTP / RA / ARP (agent-8a68e0, 2026-10-21)

## ⚠⚠ MISE À JOUR CRITIQUE (12h30) : le client réel est dhcpcd **6.8.2**
Fingerprint obtenu (evil_dhcp2, 11:07) : `opt60 = dhcpcd-6.8.2:Linux-4.4.22+:armv7l:MT8167`
(305 octets de DISCOVER, param-list 55 = [1,33,3,6,15,28,51,58,59,119] — le client
DEMANDE domain_search et static_routes). Amazon a upgradé l'upstream, PAS le 5.5.6
d'AOSP. Re-audit complet contre v6.8.2 (tarball upstream) : les fixes 6.x ont tué
les armes principales, mais deux SURLECTURES vivent toujours (détails §1bis).
L'échange complet DISCOVER→OFFER(552)→REQUEST→ACK(552) a FONCTIONNÉ à 11:07 avec
csr_gate4_oob → harnais validé sur le vrai client.

Mission : les 5 surfaces réseau où NOUS sommes le serveur et où le parseur
tourne côté device. Device = Echo Dot 3 "octave", MT8167, FireOS 6 (Android 7.1
Nougat), firmware usine 2019. noyau 4.4.22 (GPL : t3600
`~/echo_build/work/kernel/mediatek/mt8167/4.4`).

## ⚠ Correction majeure de terrain : la campagne DHCP v1 était NULLE
`evil_dhcp.py` (v1) construisait des réponses BOOTP **12 octets trop courtes**
(yiaddr/siaddr/giaddr omis) → cookie à l'offset 224 au lieu de 236 → le client
rejetait chaque réponse **avant de parser la moindre option**. Les DISCOVER
répétés sans REQUEST en étaient la signature. **La surface DHCP était donc
entièrement vierge.** evil_dhcp2.py corrige (en-tête exact, OFFER/ACK, fingerprint).

## 1. DHCP — la priorité. Cible = dhcpcd 5.5.6 AOSP, exécuté en ROOT
### Identification du parseur (source vérifiée)
Android ≤ 8 : le client DHCP = **dhcpcd** (`/system/bin/dhcpcd`), forké par
netd (root). Le client natif netd `DhcpClient.cpp` n'existe pas avant P ;
`external/dhcpcd` AOSP (tag `android-wear-7.1.1_r1` = code Nougat) contient
`dhcp.c` 5.5.6-era. Réception : `dhcpcd.c:handle_dhcp_packet` →
`dhcp = xzalloc(sizeof(struct dhcp_message))` = **bloc heap de 552 o exact**
(240 en-tête+cookie, `options[312]`), `memcpy(dhcp, pp, bytes≤552)`.
Confirmation empirique attendue : fingerprint (option 60 "dhcpcd-5.5.6" /
option 55) capturé par evil_dhcp2 au premier DISCOVER.

### Audit du code réel (fetched, lignes exactes) — 4 classes d'attaque
| # | Bug | Site | Type | Armes |
|---|-----|------|------|-------|
| A | **Underrwrite heap 1 o** : 1er label de domaine VIDE → `*(out-1)=' '` écrit AVANT un `xmalloc(count)` frais (count calculé au 1er passage SANS le label vide → toujours court) | `dhcp.c:decode_rfc3397` (via `print_option`/`get_option_string` dans `configure_env` au BIND, ACK) | **écriture hors bornes côté heap, process root** ; vestige de la famille CVE-2012-6698 (decode_search OOB write, 3.x) — jamais corrigée sur cette branche | options 119/81/120 : `ds_underr`, `fqdn_underr`, `sip_underr`, `ds_underr_long`, `concat_underr` |
| B | **Lecture gate 4 o à p==e** : route classless tronquée sans passerelle → `memcpy(&rt->gate.s_addr, p, 4)` sans check `p+4≤e` | `dhcp.c:decode_rfc3442_rt` (+ le variant chaîne `decode_rfc3442`) | surlecture jusqu'à 4 o **hors du bloc heap** si l'option termine le paquet 552 | `csr_gate4_oob`, `csr_gate0_oob`, `ms249_gate_oob` |
| C | **`valid_length` ne rejette que -1** : `dl % sz` (≠0) passe ! puis `get_option_routes` lit 4 o (gate) depuis une option routers/static-routes de longueur non multiple de 4 | `dhcp.c:valid_length` + `get_option_routes` | surlecture 1-4 o hors bloc en fin de paquet | `opt3_len1_end`, `opt3_len5_end`, `opt33_len5_end` |
| D | **CVE-2019-11579 (PUBLIÉE)** : `overl = 0x80 \| p[1]` lit p[1] sans vérifier la longueur de l'option 52 ; corrigé upstream 7.2.1 (2019) → **présent dans 5.5.6** | `dhcp.c:get_option` case DHO_OPTIONSOVERLOADED | lecture 1 o hors bloc si [52,0] en fin de paquet | `opt52_end` (+ `opt52_len0` mi-paquet = lecture in-bounds inoffensive) |

Éléments SÛRS vérifiés (ne pas re-tester) : TLV bornés par clamp `e-(p+1)`
(fix CVE-2014-7912) · concat RFC3396 borné (somme ≤ 504 < 552 du buffer
opt_buffer) · option 52 unique (fix CVE-2014-6060) · guard hops/pointeurs de
compression (retour 0 propre) · label 0x40/0x80 rejeté · surcharge
bootfile/sname bornée par champs.

### CVE publiées dhcpcd/Android (contexte)
- **CVE-2014-7912** (get_option, Android <5.1, RCE) — FIXÉ dans notre arbre (clamp présent)
- **CVE-2016-1503** (heap overflow, Android 4.x-6.x <2016-04-01, bug 26461634) — les fixes 2016 sont présumés inclus dans 7.1 ; notre audit des chemins restants ne montre pas le débordement de 1503
- **CVE-2014-6060** (overload re-traité) — FIXÉ (marqueur 0x80)
- **CVE-2019-11579** (1-byte read overflow option 52) — **PRÉSENT** (fix 7.2.1 > 5.5.6)
- **CVE-2012-6698/6699/6700** (decode_search 3.x : OOB write/read) — famille dont notre bug A est le vestige
- CVE-2016-1504 (invalid read, lengths) — surface couverte par nos cas garde

### §1bis — VERDICT REVU sur dhcpcd **6.8.2** (la vraie version du device)
| Arme (5.5.6) | Statut 6.8.2 | Détail du fix rencontré |
|---|---|---|
| A. underrwrite decode_rfc3397 | ❌ MORT | garde `out != start` avant `*(out-1)` ; labels bornés `q+l>e` |
| B. gate-OOB decode_rfc3442_rt | ❌ MORT | `if (p + 4 + ocets > e)` rejet propre |
| C. valid_length dl%sz (opts 3/33) | ❌ MORT | `dl - (dl % ADDRSZ)` tronque ; option 33 exige len%8==0 |
| longueurs menteuses (len_lie) | ❌ MORT | `if (p + ol > e) → EINVAL` (rejet au lieu du clamp) |
| **CVE-2019-11579 opt52** | ✅ **VIVANTE** | `overl = 0x80 \| p[1]` inchangé (fix upstream 7.2.1) → cas `opt52_end` |
| **lecture à 552 via `while (p < e)`** | ✅ **VIVANTE (trouvaille)** | paquet de 552 o terminé par un CODE d'option sans longueur → `ol = *p` / `l = *p++` lit à l'offset 552 = hors du `calloc(552)` → cas `last_byte_code` |
| contournement BOOTP (pas d'option 53) | ✅ TOUJOURS LÀ | dhcp.c:1140-1142/2459 : type=0 → l'offre est prise sans REQUEST/ACK → `bootp_opt52` tire la CVE au PREMIER paquet |
| auth option 90 (nouveau 6.x) | ❏ mémoire-sûr | mais INJECTION D'ÉTAT : reconf-key (proto RECONFKEY, type 1) acceptée dans l'ACK → clé 16 o contrôlée par nous, puis FORCERENEW authentifié possible (fonctionnel) |

Deux surlectures de 1 octet + un contournement d'état — pas de quoi rooter seul,
mais ce sont des crash-candidats parfaits et des briques de rapport.

### Outil + protocole
`/home/pi/fakeap/evil_dhcp2.py` (aussi `~/echo_re/`) : 24 cas, `--case`, `--seq`,
fingerprint. **Protocole** : 1) `ctrl_ok` (doit configurer + fingerprint) →
2) `ds_underr` → 3) `csr_gate4_oob` → 4) `opt52_end` → 5) reste. Oracle crash =
re-DISCOVER sans REQUEST ; discriminer rejet propre vs crash en rejouant
`ctrl_ok` (si ça configure → parser vivant). Les armes tirent à l'ACK
(`configure_env` au bind). Prérequis : dnsmasq en mode dns-only (déjà le cas),
relancer evil_dhcp2 avec sudo (port 67).

## 2. DNS — bionic Nougat (dans netd = root) : durci, campagne de confirmation
Code cible : bionic 7.1.2 `libc/dns/net/getaddrinfo.c` (`getanswer`) + `res_send.c`
+ `res_cache.c`. Audit : `getanswer` = variant **durci** post-fixes (BOUNDS_CHECK/
BOUNDED_INCR partout, `qdcount!=1` rejeté, rdlength A/AAAA vérifié, CNAME
copié via strlcpy borné) — l'équivalent bionic des fixes glibc CVE-2015-7547
y est. Le cache (`res_cache.c` N) stocke la réponse brute sans re-parse
dangereux. Reste à tester empiriquement : boucles de pointeurs, décomptes
menti, fallback TCP (`send_vc`), EDNS0. Outil : `/home/pi/fakeap/dns_fuzz.py`
(17 cas UDP + tcp_len_lie). Aucune CVE Nougat connue spécifique au parseur
beyond les fixes 2016 — la valeur est la confirmation empirique. Oracle :
device muet en DNS / re-quêtes en rafale / crash netd (=> perte réseau
totale, réassociation Wi-Fi).

## 3. NTP — identifier d'abord le client (fingerprint pending)
Indices : requêtes 48 o vers ntp-g7g.amazon.com, **transmit timestamp à ZÉRO**
(3 requêtes vues), réponses VN=4 acceptées (bootstrap a continué). Un tx=0
n'est PAS le comportement SntpClient.java (framework, qui stamp son tx) →
probable **client natif Amazon maison ou minimal C** → surface mémoire
plausible. Outil : `/home/pi/fakeap/ntp_fuzz.py` — loggue LI/VN/mode de chaque
requête (interprétation auto : VN=3 → Java sûr ; VN=4 → natif) + 15 cas de
mutation (stratum kiss-of-death, LI=alarm, rootdelay/disp 0xFFFFFFFF,
originate/tx zéro, temps aberrants, réponse <48 o, champs d'extension RFC7822
à longueurs menteuses). Aucune CVE publique connue sur le client NTP Android
(SntpClient.java a eu des fixes de spoofing mais pas mémoire). Commencer par
le fingerprint (remplace ntp_fake, même comportement par défaut ctrl_ok).

## 4. RA IPv6 — noyau 4.4.22 : parseur borné, valeur fonctionnelle
Audit `net/ipv6/ndisc.c` (arbre GPL du device) : `ndisc_parse_options` rejette
`l==0` et `opt_len<l` (boucle bornée) ; PIO exige nd_opt_len==4 ; MTU lu
in-bounds ; array indexé par type u8 sur 256 entrées. CONFIG_IPV6=y,
ROUTER_PREF=y, NDISC_NODETYPE=y. **Pas de bug mémoire identifié** — les
options RDNSS/DNSSL sont juste stockées (`nd_useropts`) pas parsées en noyau
4.4. Valeur résiduelle : (a) route par défaut v6 via nous si accept_ra actif
(`lifetime_max` = MITM v6 gratuit), (b) MTU fonctionnel, (c) PIO multiples =
config d'adresses. Outil : `/home/pi/fakeap/ra_fuzz.py` (stdlib pur, AF_PACKET,
14 cas + flood). Référence CVE moderne : CVE-2026-14258 (RA zero-length option
→ boucle CPU) touche dhcpcd lui-même, pas le noyau ; dhcpcd 5.5.6 Android
n'écoute pas les RS/RA (ipv6rs désactivé par Android).

## 5. ARP — aucun espoir de corruption, outil MITM seulement
noyau 4.4 arp.c : parseur trivial, aucune CVE 4.4-era. ARP spoof = interception
(déjà acquis via l'AP). Garde-pieds : flood gratuitous ARP = épuisement de la
table neighbor (DoS fonctionnel) — sans intérêt pour root. **Priorité nulle.**

## §2bis — CHRONY : présent (core service natif root) mais PARSEUR BORNÉ
découvert par ag3 dans le bundle GPL (fireos/external/chrony, 133 fichiers,
patchs Amazon 2018-2020, « Chronyd as core service »). Audit fait sur la source
extraite : check_packet_format (version/length%4) ✓, **check_packet_auth**
(marche à travers ext-fields + MAC — le trou signalé par le commentaire est
en réalité borné : ext_length ≤ remainder, progression ≥ 8, KEY_CheckAuth
propre) ✓ → **pas de corruption mémoire identifiée**. Reste fonctionnel :
time-shift si on DNAT udp/123 vers nous (iptables -t nat -A PREROUTING -i wlan0
-p udp --dport 123 -j DNAT --to 192.168.50.1:123) — impact TLS/validation d'âge
des certificats, pas root. NB : le querier tx=0 de ntp-g7g n'est PAS chrony
(chrony randomise les bits bas de son tx) → il existe un 2ᵉ client natif
minimal inconnu = cible fuzz valable. ntp_fuzz.py (15 cas) déployé sur piveil
en mode fingerprint — une requête du device suffit à l'identifier.

## §6bis — mDNS : jamais attaqué, outillé, audit statique amorcé
ag2 : oracle d'impact = le SRV `_amzn-alexa._tcp` disparaît (dns-sd -B / avahi).
mdns_fuzz.py (13 cas, piveil) : boucles ptr (self + cycle à 2), label brut
0x7F (>63), nom >255 décompressé, rdlength menti, ancount menti, qdcount 100,
TXT inner-desync (2 niveaux de longueur), SRV cible-boucle. Source AOSP
nougat (mDNSResponder) récupérée (mDNS.c 540 Ko…) — log git Android N→O
vérifié : pas de correctif sécurité dans la fenêtre (le « Fix random
underflow » = fix CPU). Audit profond du cache-add/cache-flush restant à faire.

## §7 — ★ DNSMASQ 2.51 (2010) TOURNE SUR LE DEVICE — le meilleur lead réseau restant
Découvert dans le bundle GPL (fireos/external/dnsmasq, VERSION "2.51",
build DNS+DHCP+IPv6, -DNO_TFTP -DNO_SCRIPT, patch Amazon DHCP_HIDE_HOSTNAME).
C'est lui qui sert le DHCP (et probablement le DNS) du **réseau de setup
Amazon-XXXX en mode orange** (10.201.126.241) — NOUS sommes le client.

### Ce qui est VIVANT sur 2.51 (après vérification)
| CVE | verdict sur 2.51 | pourquoi |
|---|---|---|
| CVE-2017-14492/14493 (RA/DHCPv6 RCE) | ❌ N/A | DHCPv6/RA n'existent pas avant 2.60/2.7x |
| CVE-2017-14491 (heap 2 o DNS) | ❌ mort en setup | exige un domaine contrôlé en AMONT (pas d'Internet en setup) |
| CVE-2017-14494 | partiellement | logging DHCP — crash/leak candidat faible |
| ★ **CVE-2015-3294** (fix 2.73) | ✅ **VIVANT, atteignable** | « crash sur requêtes DNS malformées, mémoire du process LISIBLE » — côté REQUÊTE (nous), pas d'upstream requis |
| fuzz rfc2131.c 2010 (options 12/60/77/81/82/55) | ✅ à faire | code d'époque, chemins dhcpcd-serveur jamais audités en violence |

### Protocole fenêtre orange (à jouer par ag1)
1. Pi rejoint Amazon-XXXX (bypass.sh existant) — getKnownList/scan OK.
2. **Sonde UDP** : `dig @10.201.126.241 +time=2 +tries=1 pwn.test` et
   `nc -u -z -w1 10.201.126.241 53 67` — UDP jamais scanné sur le device.
3. Si DNS répond → requêtes malformées CVE-2015-3294-style (EDNS0 multi,
   noms pervers, qdcount/ancount menti) — oracle = plus de réponse /
   DHCP de setup mort (2ᵉ client ne reçoit plus de lease).
4. DHCP-client fuzz : evil_dhcp2 inversé (à écrire, ~1 h) — DISCOVER avec
   options hostiles (81 bit 0x04, 77 counted-strings mensongers, 82).

## Récap outil & fichiers
| outil | où | port/rôle | cas |
|---|---|---|---|
| evil_dhcp2.py | ~/echo_re/ + piveil ~/fakeap/ | UDP 67 (sudo) | 24 |
| dns_fuzz.py | idem | UDP+TCP 53 (stopper dnsmasq d'abord) | 18 |
| ntp_fuzz.py | idem | UDP 123 (remplace ntp_fake) | 15 |
| ra_fuzz.py | idem | AF_PACKET wlan0 | 14 |
Logs piveil : /tmp/fakeap/{evil_dhcp2,dns_fuzz,ntp_fuzz,ra_fuzz}.log,
dhcp_fingerprint.log + .bin.

## Ce qui resterait si DHCP échoue
1. DNS empirique (outils prêts) 2. NTP fingerprint→si natif, fuzz mémoire
3. RA fonctionnel (MITM v6) 4. dhcpv6 n'existe pas dans ce client 5. le
GROS morceau restant = réponses aux renewals unicast (T1) : mêmes armes en
unicast après configuration initiale (le harnais gère déjà : réponse unicast
si ciaddr présent — à valider).

## §8 — Outils livrés (2ᵉ vague, 12h30-13h00) et état de coordination
| outil | où | cible | cas |
|---|---|---|---|
| mdns_fuzz.py | ~/echo_re/ + piveil | responder mDNS 5353 (jamais attaqué) | 13 (boucles ptr, label 0x7F, nom>255, TXT desync, …) |
| ntp_fuzz.py | idem, LIVE sur :123 | client NTP tx=0 (identité inconnue) + chrony | 15 + fingerprint LI/VN/mode |
| dnsmasq_attack.py | idem | ★dnsmasq 2.51 DU DEVICE en fenêtre orange (10.201.126.241) | 20 (9 DNS + 11 DHCP-client) + sonde UDP 53/67 |

Coordination : ag1 pilote les fenêtres (session de tir 11:39+ en cours,
ordre ctrl_ok → bootp_opt52 → opt52_end → last_byte_code) ; ag2 : liste
d'opérations Coral pour 4070 (son angle le plus propre) ; ag3 : nous a
fourni le bundle GPL (chrony extrait-audité BORNÉ, dnsmasq 2.51 = LA
découverte). Oracle crash DHCP (méthode ag2) : un dhcpcd relancé refait un
DISCOVER → 2ᵉ DISCOVER dans le log = crash confirmé, pas rejet propre.

## §9 — Bilan technique honnête de la journée (2 vagues)
Parseurs réseau du device passés au crible : dhcpcd 6.8.2 (solide, 2 lectures
1 o + bypass BOOTP + injection reconf-key), bionic N (durci), chrony (borné),
ndisc 4.4.22 (borné), mdnsresponder (pas de fix sécurité N→O), dnsmasq 2.51
(old-code borné côté DHCP-serveur sur les chemins audités ; DNS-request side =
CVE-2015-3294 classe, à sonder en orange). Le device est défendable — les
vraies cartes restantes : (1) dnsmasq 2.51 vs requêtes malformées (orange),
(2) le client NTP natif tx=0 inconnu (fingerprint armé), (3) mDNS empirique,
(4) opérations Coral sur 4070 (ag2), (5) la voie matérielle amonet (inchangée).

## §10 — NTP FERMÉ (fingerprint obtenu 11:39:18, live)
Premier octet requête = 0x1B (LI=0, VN=3, mode=3) + tx=0 → client **Java de
la famille SntpClient** (variante FireOS sans stamp du transmit). Java =
mémoire-sûr → le fuzz NTP mémoire est MORT. Reste fonctionnel : time-shift
via DNAT :123 (impact validation certificats/TTL — angle mineur). Le serveur
ntp_fuzz.py reste en place (il sert l'heure ctrl_ok et logge — utile pour
les fenêtres futures), plus besoin de le viser comme surface d'élévation.

## §11 — Priorités finales après fermeture NTP
1. ★dnsmasq 2.51 (orange, sonde + CVE-2015-3294) — tool prêt
2. Tir DHCP en cours : bootp_opt52 → opt52_end → last_byte_code (ag1)
3. mDNS empirique (13 cas, oracle SRV)
4. Coral/4070 (ag2)
5. amonet (matériel, plan B inchangé)

## §12 — Clôtures du 13h (mesures)
- **DHCPv6 FERMÉ** : probe RA M=1 sur TEST (11:56) → aucun SOLICIT (dhcpcd du
  device = v4 only) → CVE-2019-11577 (présente dans le code 6.8.2) inatteignable.
  Tool : dhcpv6_probe_fuzz.py (piveil, réutilisable si hypothèse v6 change).
- **bootp_opt52 / opt52_end tirés à 11:49 sans effet** (mesure ag1) — les
  lectures 1 o ne franchissent pas de page : classe close.
- Correction SoC propagée : **MT8167** (fingerprint opt60), pas MT8163.
- dnsmasq 2.51 UDP : 450 cas sans crash (ag1) ; reste TCP/53 (dns_tcp_attack.py,
  CVE-2015-3294 = tcp_request) → fenêtre orange.
- busybox 1.22.1 config SERVEUR complète découverte (ag3, bundle GPL) →
  scan ports orange à faire (voir ALTERNATIVE_PATHS.md B.2).

## Voir aussi : ALTERNATIVE_PATHS.md (inventaire fait/non-fait + voies A/B/C
## vers le changement d'OS — fastboot pads USB = recommandation n°2)

## §13 — FERMETURES FINALES (fenêtre orange 13h25, mesures ag4)
- **BUSYBOX = FERMÉ PAR LA MESURE** : en mode setup, scan TCP de 36 ports
  communs → seul **8080** ouvert ; UDP 69 (tftp RRQ **et WRQ**), 123 (ntp),
  514, 5353, 5355, 161, 1900 → TOUS muets. La config busybox-serveur
  (inetd/telnetd/tftpd/httpd du bundle) est compilée mais **rien n'écoute** :
  outils shell uniquement, comme le suspectait ag3. Sujet clos définitivement.
- **TCP/53 FERMÉ en setup (ag1)** → CVE-2015-3294 (tcp_request) inatteignable
  → salve dnsmasq close : UDP DNS robuste (~470 cas), DHCP serveur robuste,
  TCP fermé.
- rdisc/ntpd/dnsd/iputils : muets par la même mesure.
- Balayage complet 1-12000 : À REFAIRE dans une vraie fenêtre (mon run a
  scanné après le retour du Pi sur TEST — invalidé ; les 36 ports échantillonnés
  propres rendent le rendement improbable).

## VERDICT FINAL SURFACE RÉSEAU (tout l'inventaire est maintenant mesuré) :
setup-mode = TCP 8080 seul (épuisé : 211 cas) + UDP 53/67 (épuisés) ;
état enregistré = 4070 (2458+1408+~10k thrift-noms, 0 route — thrift-enum
partiel à finir), 6543 (404), 1080 (gated), 8888 (RST), mDNS (selon état).
Il ne reste de testable : thrift-4070 complet + mDNS en état enregistré
(host_matrix d'ag2 : 648 cas vhost/TJSON/h2c, prêt), le reste = matériel
(dongles injection/BT) ou ouverture (voie fastboot — cf. ALTERNATIVE_PATHS §F).
