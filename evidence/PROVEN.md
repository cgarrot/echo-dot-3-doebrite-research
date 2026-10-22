# PROVEN — provisioning d'un Echo Dot 3 **sans app, sans BLE, sans compte Amazon**

Chaîne **validée de bout en bout** le 2026-10-20 : l'Echo (`A30YDR2MK8HMRV`,
DSN `G091470502330EBE`, MAC `dc:91:bf:bb:72:4a`) a rejoint le hotspot ouvert
`clem` de l'utilisateur, piloté uniquement par notre protocole HTTP local.
Confirmation triple : réponse `{"0":{"i32":0}}` (NO_ERROR) sur `connectToAP`,
`getKnownList` montre `clem` à **RSSI −29**, et le device apparaît dans la liste
des clients du téléphone.

Seul geste humain : **le réarmement physique** (mic-off + vol-down ~20 s → orange).

---

## 1. La séquence exacte

```
[humain]  réarmement : bouton → anneau orange, AP "Amazon-EBE" émis
[Pi]      wlan0 rejoint Amazon-EBE (keepalive ARP/rejoint)
[Pi]      POST http://<echo>:8080/OOBE   (Thrift TJSON, une connexion par appel)
```

| # | appel | payload | réponse attendue |
|---|---|---|---|
| 0 | `ping` | `{}` | `{"0":{"tf":1}}` — témoin de vie |
| 1 | `getDeviceDetails` | `{}` | 12 champs (serial, MAC, cert, DSN, locales, deviceType) |
| 2 | `setLocaleAndEndpoints` | `{"1":{"rec":{"1":{"str":"fr-FR"},"2":{"str":"EU"},"4":{"str":"prod.EUAmazon"},"5":{"i32":443},"6":{"str":"prod.PANDA_EUAmazon"},"7":{"i32":443},"8":…,"9":…,"10":…}}}` | `{"0":{"i32":0}}` |
| 3 | `getScanList` | `{}` | liste des Wi-Fi vus par l'Echo |
| 4 | **`connectToAP`** | `{"1":{"str":"<SSID>"},"3":{"i32":1}}` (réseau **ouvert**) | **`{"0":{"i32":0}}` = NO_ERROR** |
| 5 | `getKnownList` | `{}` | le SSID apparaît, champ 2 = RSSI (négatif si vu, `0` si jamais vu) |
| 6 | `setupComplete` | `{}` | `{"0":{"i32":0}}` — ⚠️ terminal, ferme le service |

`smethod` en **1-based** : `1` = NONE (ouvert), `2` = WPA_PSK, `3` = WPA2_PSK.
Pour un réseau ouvert, **aucun champ mot de passe** n'est envoyé → aucune
crypto à négocier, donc aucun interblocage possible.

## 2. Ce qui ne marche pas encore

- **WPA2 avec mot de passe** : le champ password attend un **blob CMS** (enveloppe
  cryptographique). Le CMS produit par l'app 2026 fait **crasher le déchiffrement
  du firmware 2019** (« Client closed connection » après ~35 s de crypto).
  ⇒ en l'état, seuls les réseaux **ouverts** sont provisionnables par cette voie.
  La matrice de formes (`oobe_matrix.py`, 20 variantes) reste disponible pour
  chercher la structure attendue par le firmware 2019.
- `getScanList` **peut bloquer** : observé un timeout sur un service pourtant sain
  (20:16), et un succès plus tard dans une autre fenêtre. ⇒ à considérer comme
  « utilisable mais risqué », à appeler **en dernier** ou avec un retry unique.
- Le champ 4 de `getKnownList` vaut `i32 1` **à la fois** pour un réseau WPA2
  (Livebox) et pour un réseau ouvert (TEST) → **ce n'est probablement pas
  `smethod`** (ou c'est la valeur *stockée*, pas celle du réseau). Question
  ouverte, non bloquante.

## 3. Discipline d'appel (leçons payées cash)

- Le service est **mono-thread avec un mutex** : un seul appel bloquant gèle
  TOUT le service. Symptôme : TCP accepte, mais **aucune réponse HTTP**, même à
  `ping`, pendant plusieurs minutes. Récupération = réarmement physique.
- ⛔ **Ne jamais appeler avec `{}`** : `getAlexaConnectionState`,
  `getOTADetails`, `getLinkCode`, `evaluateCaptivePortal`. Ils bloquent.
- `getRegistrationState` avec `{}` est sûr : il répond
  `500 API exception (12:1:107:22:1)` (erreur métier ≠ méthode absente).
- Une connexion TCP par appel (le serveur impose `Connection: close`), `seqid`
  incrémental, **pas de parallélisme** (le firmware hoquette au-delà de ~4 flux ;
  317 timeouts constatés à 8 workers).
- Distinguer les deux familles d'erreurs :
  `Invalid method name` (msgtype 3, i32=1) = méthode inexistante ;
  `500 API exception (a:b:c:d:e)` = méthode **présente**, refus métier.

## 4. Reproductible

```bash
# outils (ce dépôt)
oobe_forge.py     # probe / scan / known / state / connect (--confirm) / dry-run
oobe_matrix.py    # 24 formes : --run --open-ssid ORACLE-OPEN
oobe_enum.py      # énumération par oracle "Invalid method name" (16 740 noms)
# infrastructure (piveil)
~/fakeap/         # hostapd TEST / dnsmasq / tap.py (SNI) / ntp_fake / NAT
```
Le tour complet tient en **~70 s** dans une fenêtre orange (10-15 min utiles
avant l'anti-idle).

## 5. Pourquoi c'est important

1. **Aucune dépendance** à l'app Alexa, au BLE, ni à un compte Amazon.
2. Le device rejoint **n'importe quel SSID ouvert que nous choisissons** → on
   peut le placer sur **notre** passerelle à volonté, de façon reproductible et
   indéfinie, et capturer tout son trafic (cf. `BOOTSTRAP_SPEC.md`).
3. On sait maintenant **quelles méthodes existent** (15) et **lesquelles sont
   sûres** à appeler : la surface est cartographiée, pas devinée.

## 6. Documents liés

| fichier | contenu |
|---|---|
| `RECON.md` | journal de bord consolidé (réseau, infra, division du travail) |
| `OOBE_SPEC.md` | protocole `/OOBE` : transport, 15 méthodes, schémas, pièges |
| `OOBE_TRANSCRIPT.md` | les 7 appels réels de l'app, verbatim |
| `BOOTSTRAP_SPEC.md` | ce que le device fait sur le réseau après provisioning |
| `LOCAL_SURFACE.md` | ports 1080/4070/6543/8888 du device provisionné |
| `oobe_forge.py` · `oobe_matrix.py` · `oobe_enum.py` | outils |
| `~/fakeap/` | AP de test + capture L7 |

# 🔥 WPA2 PROVISIONING RÉUSSI — la méthode complète (nuit du 20-21/10 ~22h50)
## La découverte qui a tout débloqué : LE CERTIFICAT SETUP EST ÉPHÉMÈRE
- getDeviceDetails champ 5 = certificat RSA-2048 CN=setup,O=Lab126
- Ce cert est REGENERÉ à chaque session orange (hash différent à chaque fois)
- Conséquence : chiffrer le PSK avec un cert d'une session précédente → échec RSA silencieux (30s de retry) → erreur 9:4
- Solution : récupérer le cert FRAIS, chiffrer avec, POST → 7,4s → NO_ERROR

## La recette WPA2 complète (reproductible) :
```
1. Orange (Micro-OFF + Vol-DOWN 20 s)
2. AP WPA2 TEST/testing1234 actif sur le Pi (hostapd, canal 11)
3. Client (Mac en0 ou Pi wlan0) rejoint Amazon-EBE
4. POST getDeviceDetails → extraire champ 5 (cert PEM)
5. openssl smime -encrypt -aes256 -binary -outform PEM -in <psk_file> <cert>
6. POST connectToAP {"1":{"rec":{"1":{"str":"TEST"},"2":{"i32":3},"3":{"rec":{"1":{"str":"<PEM>"}}}}}}
7. → NO_ERROR (0) en ~7 s → l'Echo rejoint le réseau WPA2
```

Architecture à 2 radios : le Mac tire sur Amazon-EBE (en0), le Pi reçoit sur TEST (wlan0 AP).

## ⛔ AVERTISSEMENT (nuit du 20/21) — setupComplete est DESTRUCTEUR
Mesuré : `setupComplete` fait sortir le device du mode setup (l'AP Amazon-EBE disparaît
immédiatement) MAIS sans chemin de registration viable (pas de getLinkCode, pas
d'enregistrement DSS, aucun réseau Amazon joignable), il tombe dans un entre-deux :
ni joignable sur aucun réseau connu (TEST, Livebox, clem), ni en mode setup.
Il ne réémet RIEN. La seule sortie est le ré-armement physique (mic-off + vol-down ~20 s).

RÈGLE : tant qu'on n'a pas un chemin de registration complet, NE JAMAIS appeler
setupComplete. Ce n'est pas un "geste de propreté", c'est une perte de session.

## Sémantique des couleurs (source : chaînes de l'app Amazon)
  ORANGE (fixe/pulsé)  -> mode setup, prêt à configurer  ← état cible
  ÉTEINT / bref bleu   -> se croit configuré mais sans réseau : retry en boucle
  ROUGE                -> bouton micro coupé (privacy matérielle), pas un état réseau
  VIOLET               -> documenté seulement pour Echo Loop / lunettes, pas le Dot
