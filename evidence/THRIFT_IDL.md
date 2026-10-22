# THRIFT_IDL — le service `DopplerOOBE`, schéma **exact** (extrait par jadx)

Source : `base.apk` → `classes5.dex` → `com.amazon.device.setup.thrift.*`
(décompilé avec `jadx -e /tmp/classes5.dex`, 19 fichiers `.java`).
**Ce document remplace la matrice de devinettes** : les ids de champs et les
enums ne sont plus à trouver, ils sont lus dans le code.

## 1. Enums

### `SecurityMethod` (champ `smethod`, i32)
```
NONE      = 1
WPA_PSK   = 2
WPA2_PSK  = 3
WEP       = 4
WPA_EAP   = 5
WPA2_EAP  = 6
```

### Autres
`RegistrationState`, `ConnectionState`, `AlexaConnectionState`, `UpdateState`,
`LinkCodeSource` — présents dans le même paquet (`classes5.dex`).

## 2. Structures

### `APConnectInfo` — argument de `connectToAP`
| id | nom | type |
|---|---|---|
| 1 | **essid** | string |
| 2 | **smethod** | enum `SecurityMethod` (i32) |
| 3 | **password** | `PKCS7Type` (struct) |
| 4 | eapmethod | string |
| 5 | identity | string |
| 6 | client_cert | string |
| 7 | priv_key | string |
| 8 | preauthCode | `PKCS7Type` |
| 9 | isTetheredNetwork | bool |

Constructeur complet : `APConnectInfo(essid, smethod, password, eapmethod,
identity, client_cert, priv_key, preauthCode, isTetheredNetwork)`.

### `PKCS7Type` — le mot de passe chiffré
| id | nom | type |
|---|---|---|
| 1 | **text** | string (PEM PKCS#7/CMS) |

### `APConnectExtendedInfo` — argument de `connectToAPEx`
| id | nom | type |
|---|---|---|
| 1 | ipaddress | string |
| 2 | subnet | string |
| 3 | gateway | string |
| 4 | dns | list\<string\> |

### `APDetail` — entrées de `getKnownList` / `getScanList`
| id | nom | type | note |
|---|---|---|---|
| 1 | **essid** | string | |
| 2 | **signal** | i32 | **RSSI signé** (`-43` vu, `0` = jamais vu) |
| 3 | secured | bool | |
| 4 | **smethod** | enum `SecurityMethod` (i32) | **c'est bien `smethod`** |
| 5 | supported | bool | |
| 6 | state | i32 | |
| 7 | isTetheredNetwork | bool | |

> ⚠️ Correction définitive : j'avais supposé que le champ 4 n'était *pas*
> `smethod` (il valait `1` pour TEST **et** pour la Livebox). Le code dit
> `SMETHOD(4, "smethod")`. Donc c'est bien `smethod`, et la valeur `1` (NONE)
> enregistrée pour la Livebox signifie que **l'entrée a été mémorisée avec
> smethod = NONE**, pas que le champ est autre chose.

### `DeviceDetails` — réponse de `getDeviceDetails`
| id | nom | type |
|---|---|---|
| 1 | **SWVersion** | string |
| 2 | MAC | string |
| 3 | currentAP | `APDetail` |
| 4 | IPAddress | string |
| 5 | **deviceCertificate** | string (PEM) — ⚠️ **ÉPHÉMÈRE** : régénéré à chaque session de setup |
| 6 | deviceSerialNumber | string (le DSN) |
| 7 | tetheringSupported | bool |
| 8 | supportedLocales | list\<string\> |
| 9 | supportedCountryCodes | list\<string\> |
| 10 | supportedWakeWords | list\<string\> |
| 11 | deviceType | string |
| 12 | **codeSource** | i32 |

> Observation inquiétante : `SWVersion` (champ 1) valait `0009698494596` lors de
> la première session et `0013222532484` lors de la seconde. Ce champ n'est donc
> pas un identifiant stable — il a **changé**, ce qui suggère qu'une mise à jour
> (ou un changement de configuration) a bien eu lieu quand le device a eu accès à
> Internet. À confronter à la version d'usine attendue.

## 3. Signatures des méthodes (client Thrift)

```java
ReturnError          connectToAP(APConnectInfo info)         // 1 seul argument (struct)
ReturnError          connectToAPEx(APConnectInfo, APConnectExtendedInfo)
List<APDetail>       getScanList()
List<APDetail>       getKnownList()
ReturnError          disconnectFromAP()   forgetAP()
DeviceDetails        getDeviceDetails()
RegistrationState    getRegistrationState()
AlexaConnectionState getAlexaConnectionState()
String               getLinkCode()
OTADetails           getOTADetails()
ReturnError          evaluateCaptivePortal()
ReturnError          setLocaleAndEndpoints(LocaleAndEndpointInfo)
ReturnError          setupComplete()
boolean              ping()
```
⇒ `connectToAP` prend **une seule structure** : la forme correcte est donc
`{"1":{"rec":{…}}}` (le `rec` est obligatoire), pas la forme « plate ».

## 4. Payloads exacts

### Réseau OUVERT (validé en conditions réelles)
```json
[1,"connectToAP",1,7,{"1":{"rec":{
    "1": {"str": "clem"},
    "2": {"i32": 1}
}}}]
```
→ `{"0":{"i32":0}}` (NO_ERROR). Aucun champ `password`.

### Réseau WPA2 — LE CHIFFREMENT EXACT DE L'APP (décompilé)

Source : `com/amazon/alexa/device/setup/echo/softap/encrypt/Encryptor.java`
(classes16.dex) — vérifié, ce n'est plus une hypothèse :

```java
public static PKCS7Type encrypt(String plaintext, String certPem) {
    X509Certificate cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certPem.getBytes("UTF-8")));
    CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
    gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));   // key transport RSA
    byte[] der = gen.generate(new CMSProcessableByteArray(plaintext.getBytes("UTF-8")),
                              new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).build()).getEncoded();
    return new PKCS7Type("-----BEGIN PKCS7-----\n"
            + Base64.encodeToString(der, Base64.DEFAULT) + "-----END PKCS7-----\n");
}
```
Et l'appelant (`ThriftClientImpl.connectToAP`) :
```java
aPConnectInfo.setPassword(Encryptor.encrypt(aPConnectInfo.password.text,
                                            deviceDetails.deviceCertificate.pem_text));
```
⇒ **cipher = AES-256-CBC**, **key transport = RSA (PKCS#1 v1.5)**, **destinataire =
le certificat du device** (`DeviceDetails` champ 5), **sortie = PEM `BEGIN PKCS7`**
avec un base64 replié à **76 colonnes** (Android `Base64.DEFAULT`).
Variante « tethered » : `setPreauthCode(Encryptor.encrypt(linkCode, même cert))`.

**Correction** : mon hypothèse « il faut du 3DES pour le firmware 2019 » était
fausse — l'app elle-même utilise AES-256. Si le firmware 2019 plante sur le blob
2026, la cause est donc **structurelle** (BouncyCastle récent ajoute des
structures CMS optionnelles, p. ex. l'attribut RFC 6211 `cmsAlgorithmProtect`),
pas algorithmique. `openssl cms/smime` produit un CMS **minimal** → c'est
précisément la variable à tester : même crypto, moins d'en-têtes.

### Réseau WPA2 — payload
```json
[1,"connectToAP",1,8,{"1":{"rec":{
    "1": {"str": "TEST"},
    "2": {"i32": 3},
    "3": {"rec": {"1": {"str": "<PEM PKCS#7 chiffré au cert du device>"}}}
}}}]
```
Le PEM se fabrique avec `psk_to_pkcs7.sh` à partir du certificat récupéré dans
`getDeviceDetails` **champ 5** (`CN=setup, O=Lab126`, RSA-2048). 7 variantes sont
produites, dans cet ordre de test :
```
1. smime_aes256         = l'équivalent exact de l'app (AES-256, entête PKCS7)
2. smime_aes256_stream  = idem sans canonicalisation S/MIME
3. smime_aes256_w76     = idem, base64 replié à 76 colonnes (comme Android)
4. cms_aes256 / cms_aes256_binary        (entête « BEGIN CMS »)
5. smime_aes128 · smime_des3             (replis si AES-256 indisponible en 2019)
```
Le contenu à mettre dans `text` est le PEM **tel quel** (retours à la ligne
échappés en `\n` dans le JSON).

## 5. Lecture d'un `getKnownList` réel (confirme le schéma)

```json
[1,"getKnownList",2,1,{"0":{"lst":["rec",2,
 {"1":{"str":"TEST"},             "2":{"i32":0},   "3":{"tf":0},"4":{"i32":1},"5":{"tf":0},"6":{"i32":1},"7":{"tf":0}},
 {"1":{"str":"<home-ssid>"}, "2":{"i32":-43}, "3":{"tf":0},"4":{"i32":1},"5":{"tf":0},"6":{"i32":1},"7":{"tf":0}}]}}]
```
→ `1=essid`, `2=signal`, `3=secured`, `4=smethod`, `5=supported`, `6=state`, `7=tethered`.
Les deux entrées portent `smethod=1 (NONE)` et `secured=false` : elles ont été
**mémorisées sans méthode de sécurité**, ce qui est cohérent avec des
`connectToAP` réussis sur réseau ouvert et des tentatives WPA2 qui ont échoué au
déchiffrement avant l'enregistrement.

## 6. Reproduction de l'extraction

```bash
python3 - <<'PY'   # extrait le dex qui contient le paquet thrift
import zipfile; z=zipfile.ZipFile('~/echo_re/apk/x/base.apk')
for n in z.namelist():
    if n.endswith('.dex') and b'com/amazon/device/setup/thrift/DopplerOOBE;' in z.read(n):
        open('/tmp/'+n,'wb').write(z.read(n)); print('/tmp/'+n)
PY
jadx -d /tmp/jd5 -j 6 --no-res -e /tmp/classes5.dex
# → /tmp/jd5/app/src/main/java/com/amazon/device/setup/thrift/*.java
```
Le SDK dont ce code est issu est **`whisperjoin`** (`com.amazon.whisperjoin.*`,
décompilé dans `classes18.dex` : `softap/actions/SoftApDeviceActionsImpl`,
`softap/wifi/requests/RequestBuilder`…). Amazon publie une partie de ce SDK :
chercher `whisperjoin` côté GitHub donnerait très probablement le **source non
obfusqué** (donc les payloads officiels) — piste à creuser en WS1.
