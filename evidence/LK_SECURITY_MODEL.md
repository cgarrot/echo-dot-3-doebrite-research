# `lk` (bootloader) — modèle de sécurité reconstruit

Source : `~/echo_re/fw/lk.img` (241 664 o), extrait de l'OTA
`update-kindle-octave-NS6575_user_8338_0013323244164.bin` (Fire OS 6.5.7.5).

**Statut de chaque affirmation** : `[M]` = mesuré dans le binaire, `[I]` = inféré du
code désassemblé, `[?]` = inconnu.

---

## 1. Format et conventions de désassemblage `[M]`

```
offset 0x000  en-tête MTK : magic 0x58881688, size=237164, nom "LK\0\0"
offset 0x200  payload ARM32, table de vecteurs (07 00 00 ea = b)
base de chargement  0x41e00000        ← établie par vote de 405 littéraux
```

**Piège n°1 — le bit Thumb.** Les pointeurs de fonction sont impairs (`0x41e0e7a9`).
Il faut désassembler à `ptr & ~1`, sinon on obtient du charabia.

**Piège n°2 — les chaînes ne sont PAS référencées par adresse absolue.**
Le compilateur a produit du code PIC :

```asm
41e0e7b4:  ldr  r0, [pc, #188]   @ charge le mot à 0x41e0e874 = 0x0001xxxx (un DELTA)
41e0e7bc:  add  r0, pc           @ r0 = delta + (0x41e0e7bc + 4)
```
Le littéral contient un **décalage relatif à l'instruction**, pas une adresse.
Conséquence : chercher `41e2ed5e` dans le binaire ne donne **rien**, alors que la
chaîne est bien utilisée. C'est ce qui m'a fait conclure à tort « chaîne inutilisée »
pendant l'analyse.

**Recette qui marche** (`/tmp/resolve2.py` sur t3600) : désassembler tout le payload
avec `arm-none-eabi-objdump -D -b binary -m armv7 -M force-thumb
--adjust-vma=0x41e00000`, puis, pour chaque `ldr rX, [pc, #N]` suivi d'un
`add rX, pc`, lire le delta et résoudre `delta + (adresse_du_add + 4)`.
→ 664 références code→chaîne résolues sur 97 136 instructions.

**Table de symboles reconstruite** : les messages de log de `lk` contiennent le nom
de leur propre fonction (`dprintf(..., "amzn_verify_unlock: ...")`). En associant
chaque chaîne « nom de fonction » au dernier prologue (`push`/`stmdb sp!`) qui la
précède, on obtient une table de 28 symboles — sans jamais avoir eu de `.symtab`.

---

## 2. Table de symboles `[M]`

| adresse | nom |
|---|---|
| `0x41e00274` | `bootcount` |
| `0x41e0030c` | `bootmode` |
| `0x41e00b4c` | `unlock_code` (parcours de partition ?) |
| **`0x41e00ff0`** | **`amzn_image_verify`** |
| `0x41e0120e` / `0x41e01476` | `sha256` |
| `0x41e0196e` | `unlock_code` (wrapper) |
| **`0x41e019d2`** | **`amzn_verify_code_internal`** |
| **`0x41e01ae2`** | **`amzn_verify_unlock`** |
| **`0x41e01c60`** | **`amzn_set_onetime_unlock_cert`** |
| **`0x41e01cb0`** | **`amzn_set_onetime_unlock_code`** |
| **`0x41e01d20`** / `0x41e01d84` | **`amzn_verify_onetime_unlock_code`** |
| **`0x41e01f00`** | **`amzn_onetime_unlock_b64_encode`** |
| `0x41e111c8` | `bootmode` (variante) |
| `0x41e14a22` / `0x41e14cc0` | `preloader` |
| **`0x41e1adbe`** | **`amzn_get_one_tu_code`** |
| `0x41e1b0dc` / `0x41e1b5ce` | `bootstrap2` / `bootstrap` |
| `0x41e1c168` | `bootargs` |
| `0x41e1dac4` | `unlock_code` (handler de commande) |
| `0x41e1e3b6` | `reboot` |
| `0x41e1f108` | `unlock_code` (variante) |
| `0x41e1f238` / `0x41e1fa54` | `boot0` |
| `0x41e1f4a8` | `cmd_flash_mmc_sparse_img` |
| `0x41e1f910` | `singlebootloader` |

---

## 3. Le graphe de la vérification `[M]` (appels résolus)

```
amzn_image_verify (0x41e00ff0)
   ├─ sub_41e01208, sub_41e012a4, sub_41e010b0   (locaux)
   ├─ sub_41e1ad20     ← copie 20 octets de "OCTAVE" puis transforme
   └─ sub_41e1ad20/1ad20 cluster = fabrication d'identifiant

amzn_verify_unlock (0x41e01ae2)
   ├─ sub_41e1ad68     ← construit "0x%08x%08x" depuis id 12 et id 13
   └─ amzn_verify_code_internal (0x41e019d2)

amzn_verify_code_internal (0x41e019d2)
   ├─ alloc(36)                     → contexte
   ├─ memcpy(0xd0 octets)           → état de hachage (taille LibTomCrypt)
   ├─ 0x41e0c9f4                    → init SHA-256   [I]
   ├─ 0x41e09048                    → décodage base64 [I]
   ├─ 0x41e07f64                    → vérification RSA/PSS [I]
   └─ retourne 0, -1, -2 selon l'échec

amzn_verify_onetime_unlock_code (0x41e01d20)
   ├─ amzn_verify_unlock
   ├─ amzn_onetime_unlock_b64_encode (0x41e01f00, 217 instructions, table de
   │   caractères base64 + appels LibTomMath 0x41e025xx–0x41e04axx)
   └─ mêmes primitives crypto

amzn_get_one_tu_code (0x41e1adbe)
   ├─ lit "serial" (idme)
   ├─ copie "OCTAVE"  ← nom de code de la carte
   ├─ formatte "0x%08x%08x" puis "%08x%08x%08x" depuis getter(12), getter(13)
   ├─ amzn_onetime_unlock_b64_encode
   └─ appelle sub_41e1b090
```

Le getter générique utilisé pour les identifiants est un **thunk** :
`0x41e10bfc → b.w 0x41e23528`, et `0x41e23528` est une **lecture indexée** :

```asm
41e23528:  cmp  r0, #99          @ index borné à 99
41e2352c:  ldr  r3, [pc,#48] ; add r3, pc ; ldr r3,[r3]   @ table globale
41e23532:  ldr.w r3, [r3, r0, lsl #2]                      @ r3 = table[idx]
41e23536:  ldr  r0, [r3, #0]                               @ valeur = *(uint32_t*)r3
```
→ tableau de **100 entrées**, chacune pointant sur une valeur 32 bits. La chaîne
d'erreur associée est `"V1.1.4.TB"`.
`[?]` **Non déterminé** : la nature exacte de cette table (versions ? valeurs OTP ?
champs eFuse ?). C'est la seule pièce manquante pour dire si les identifiants qui
composent le code de déverrouillage sont **immuables** (OTP) ou **modifiables**
(idme/partition). Si modifiables, le code de déverrouillage devient reproductible
hors ligne ; s'ils sont en OTP, il est unique par appareil.

---

## 4. Le code de déverrouillage à usage unique (`one TU code`) `[M]`+`[I]`

Schéma reconstruit :

1. **Fabrication locale** — `amzn_get_one_tu_code` combine `serial` + `OCTAVE` +
   deux valeurs 32 bits (ids 12 et 13) en une chaîne hexadécimale, puis la
   **base64-encode** (`amzn_onetime_unlock_b64_encode`).
   C'est la *challenge* propre à l'appareil.
2. **Signature externe** — Amazon renvoie un certificat/code signé (RSA-PSS +
   SHA-256), stocké par `amzn_set_onetime_unlock_cert` /
   `amzn_set_onetime_unlock_code`.
3. **Vérification** — `amzn_verify_onetime_unlock_code` décode le base64,
   recalcule le SHA-256 et vérifie la signature via `amzn_verify_code_internal`.
4. **Effet** — une fois le drapeau posé, le chemin de boot imprime
   *« Device is unlocked kernel verification skipped! »* et **saute la
   vérification du noyau**.

`[I]` Conséquence : **il n'existe pas de chemin logiciel d'unlock sans une signature
Amazon**. Le code de déverrouillage n'est pas un secret à deviner, c'est une
signature à obtenir. Toute la sécurité repose sur la clé privée Amazon, pas sur
l'obscurité de l'algorithme (que nous venons de lire entièrement).

---

## 5. La machine à états du boot `[M]`

Messages présents dans le binaire et leur usage :

| état | chaîne | propriété noyau posée |
|---|---|---|
| green | `boot state: green` | `androidboot.verifiedbootstate=green` |
| yellow | `boot state: yellow` + `yellow state` | `androidboot.verifiedbootstate=yellow` |
| orange | `boot state: orange` | `androidboot.verifiedbootstate=orange` |
| red | `boot state: red` + `Red State` | `androidboot.verifiedbootstate=red` |

Messages d'interaction / d'échec :
```
Your device has loaded a different operating system        (orange)
Your device has failed verification and may not work properly (red)
Cannot get custom public key, abort in 5 seconds
Yes (Volume UP)   : Confirm and Boot.
No  (Volume Down) : Abort.
Your device will boot in
OTP counter will not update
lk stage img ver not sync / prelaoder stage img ver not sync
Failed to verify image
```
Propriétés exportées au noyau :
```
androidboot.secure_cpu=%s        androidboot.unlocked_kernel=%s
androidboot.rpmb_state=%d        androidboot.pl_version / tee_version / lk_version
androidboot.pl_build_desc=%s     androidboot.lk_build_desc=%s
androidboot.prod=%d              androidboot.verifiedbootstate=<état>
```
`[M]` Présents aussi : `6F7225E` et `20230407_021107` (empreinte de build),
`%07x-%lld_%06lld`, `%s-%s` (formats de nommage d'images).

**Le message `Cannot get custom public key, abort in 5 seconds`** `[I]` : c'est le
chemin **orange** — l'appareil veut vérifier le noyau avec une clé publique
« custom » (celle de l'utilisateur, posée lors d'un unlock). Si elle est absente,
il attend 5 s puis avorte le boot custom. Ce n'est donc pas un défaut : c'est le
comportement attendu d'un appareil déverrouillé sans clé enregistrée.

---

## 6. Ce que cela ferme et ce que cela ouvre

**Ferme** `[M]`+`[I]` :
- Pas de backdoor dans l'unlock : l'algorithme est entièrement lu, il ne contient
  aucun secret, seulement une **vérification de signature**. Rien à casser côté
  cryptographie (RSA-PSS via LibTomCrypt, SHA-256).
- Le chemin « deviner le code » n'existe pas : ce n'est pas un PIN.

**Ouvre / pistes restantes** :
1. `[?]` Identifier la table de 100 entrées à `0x41e23528` : si les ids 12/13 sont
   en RAM/idme plutôt qu'en OTP, le code de déverrouillage devient calculable.
2. `[?]` Localiser le **stockage** du certificat one-time (`amzn_set_onetime_unlock_cert`
   écrit où ? idme, `seccfg`, partition dédiée ?) et vérifier s'il est protégé en
   écriture.
3. `[?]` `amzn_image_verify` : déterminer **d'où** vient la clé publique custom et
   si son absence est *fail-open* ou *fail-closed* (le message « abort in 5
   seconds » suggère fail-closed, mais l'anti-rollback `lk stage img ver not sync`
   mérite d'être suivi).
4. `[M]` Le BROM reste le seul chemin qui ne demande aucune signature — voir
   `BOOTROM_PROCEDURE.md`.

---

## 7. Outillage réutilisable

| fichier (sur t3600) | rôle |
|---|---|
| `/tmp/lk.dis` | désassemblage complet (97 306 lignes), VMA correcte |
| `/tmp/strrefs.json` | 664 couples `{code, chaîne}` résolus |
| `/tmp/sym.json` | table de symboles reconstruite |
| `/tmp/resolve2.py` | résolveur `ldr delta + add pc` |
| `/tmp/sym.py` | reconstruction de symboles depuis les messages de log |

`arm-none-eabi-objdump` (paquet `binutils-arm-none-eabi`) est installé sur t3600.
