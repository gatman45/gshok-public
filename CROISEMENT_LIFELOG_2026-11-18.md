# Croisement point par point des rapports LifeLog et de suivi — 2026-11-18

- **Objet** : confronter entre eux les 8 rapports LifeLog du dossier `analysis/firmware_reverse/05_protocols/ble/`, le rapport DEX/DRSP côté application, les rapports machine de `08_validation/` et l'état du code `v8`, puis classer chaque énoncé en **validé**, **contredit**, **non attribué** ou **à arbitrer par test**.
- **Ce que ce document n'est pas** : ni une nouvelle mesure de la montre, ni une réécriture des constats. Les constats gardent leur texte ; ce document dit lesquels tiennent quand on les met côte à côte, et lesquels se contredisent.
- **Règle d'attribution appliquée sans exception** : aucune capture du 2026-11-18 ne vaut comme mesure de la DW-H5600 (émulateur en bootloader → `0 scan CASIO`, voir `CROISEMENT_CLASSES_2026-11-18.md` §1). Les fichiers `mesure_reelle_1.json` / `mesure_reelle_2.json` sont donc traités comme **non attribués**, pas comme des mesures.

---

## 1. Les sources, et ce que chacune peut prouver

| Code | Source | Nature | Ce qu'elle prouve | Ce qu'elle ne prouve pas |
|---|---|---|---|---|
| **A** | `analysis/btsnoop/*_att.csv` (5 sessions, 2026-08-21 → 2026-10-26), `analysis/chrono_2d_20261109_*.csv` (Frida, 2026-11-09) | vraie DW-H5600, sniff HCI ou Frida | les octets émis par la montre, leurs horodatages, leurs handles | la sémantique des octets ; l'état interne de la montre |
| **B** | APK `split_arm64_v8a.apk` (SHA-256 `43868ed6…a3507`), DEX + `libapp.so` (blutter) | code officiel CASIO | comment **l'application** interprète les octets | ce que la montre fait ; les branchements non atteints |
| **C** | client tiers `gshock_api` (`casio-chk/py`, lecture seule) | client indépendant | une seconde lecture des mêmes octets | rien sur la montre |
| **D** | `v8/src`, `v8/tests/native` (15 harnais) émulateur | ce que **l'émulateur** émet, octet pour octet | la fidélité, sauf si la référence est A ou B |
| **E** | `v8/docs/probe_*.jsonl`, `mesure_reelle_*.json`, `gatt_reel_2026-11-18.json` | 2026-11-18, source ambiguë | que quelque chose a répondu | **rien sur la montre** (non attribué) |

Règle de lecture conservée de `RAPPORT_PREUVES_2026-11-18.md` : une réponse **acceptée par le client** n'est pas une preuve de fidélité — l'application ne teste que `data[0]`/`data[1]` dans plusieurs chemins (constat 52 §6, `PROTO_AXES_SOURCES.md` §7.3).

---

## 2. Tableau maître

Verdicts : **VALIDÉ** (mesuré, reproductible), **VALIDÉ-RESTREINT** (vrai dans les limites explicites du constat), **CONTREDIT** (la mesure dit l'inverse), **NON ATTRIBUÉ** (source E), **À ARBITRER** (le test n'existe pas encore).

### 2.1 En-tête et framing du flux `0x05`

| ID | Énoncé | Src | Verdict | Preuve / arbitrage |
|---|---|---|---|---|
| L01 | Première notification = `0x05` + **22 octets**, `crc16_kermit(v[1:-2])==LE(v[-2:])` **et** `crc16_kermit(v[1:])==0` | A | **VALIDÉ** | 4/4 sessions ; rejoué le 18/11 : les 3 en-têtes imprimés sont identiques à ceux du constat 48 §4 |
| L02 | Il n'y a **pas** de préfixe de longueur dans le flux | A | **VALIDÉ** | T1 : max 8/390, et les 8 portent tous sur des tranches pleines (valeur constante `0xEF`) ; rejoué |
| L03 | Après l'en-tête, **aucune** suite de messages CRC | A | **VALIDÉ-RESTREINT** | T2 29/390, T3 échantillonné 1 départ sur 7, chaînage 1/487 ; le constat borne lui-même le faux négatif |
| L04 | Découpage imposé par la MTU : tailles dominantes 244 / 23 / 13 / 102 | A | **VALIDÉ** | T4 ; rejoué (`-4` : 244×132, 23×125) |
| L05 | Aucun codec standard (zlib, gzip, deflate, xz) ne décode le payload | A | **VALIDÉ-RESTREINT** | 0/20 essais ; la revue §10.1 du constat 50 a **déjà** restreint le verdict à ces 4 conteneurs — l'énoncé large « aucun compactage » reste UNKNOWN, et c'est correct |
| L06 | Structure `<type:8><longueur:32 LE><corps>` sur 0,2 % à 19 % du flux | A+B | **VALIDÉ** (partiel) | 3/3 sessions portant le motif ; couverture publiée §7 du constat 53 — c'est la formulation honnête |
| L07 | Sur `-4`, le corps est un tableau **1 bit/octet** | A | **À ARBITRER** | HYPOTHÈSE assumée (bit 0 = 0,18) ; le test qui trancherait est un rejeu du parseur Dart complet, pas une statistique |
| L08 | Aucun entrelacement périodique 2→32 ne produit de colonne fixe | A | **VALIDÉ-RESTREINT** | 0 colonne ≥ 90 % ; le constat 50 §10.2 borne correctement (entrelacement irrégulier non exclu) |

### 2.2 Records `0x00` et `0x65`

| ID | Énoncé | Src | Verdict | Preuve / arbitrage |
|---|---|---|---|---|
| L09 | **12 paires ancrées**, pas 4 : 3 / 2 / 5 / 2 (+1 session sans flux) | A | **VALIDÉ** | Rejoué le 18/11 par `lifelog_matrix_par_type.py` : `3 ex.`, `2 ex.`, `5 ex.`, `2 ex.` |
| L10 | La rupture à l'offset 124 est une **perte de synchro**, pas une fin de flux | A | **VALIDÉ** | reprise par une nouvelle paire à 46 963 / 50 510 / 4 770 ; même queue `00 00 f0 08…` dans les 4 |
| L11 | Cadence dominante **60 s**, trous (120/240 s) **comptés** par le `u16` final | A | **VALIDÉ-RESTREINT** | 12 exemplaires, saut `1265→1268` en face d'un trou de 240 s ; deux émissions dans la même minute sur `_5` |
| L12 | `0x00` = 15 o : `[année−2000][mois][jour][heure][minute]` en **binaire**, puis `int32`/`int32`/`u16` | A+B | **VALIDÉ** | constat 52 §5 (désassemblage) + 3 dates cohérentes ; l'hypothèse BCD est **REFUTÉE** (le `0xd2` était le poids faible de l'`int32`) |
| L13 | Nature des deux `int32` (offsets 5..8, 9..12) | A | **À ARBITRER** | UNKNOWN ; test : session longue avec plusieurs valeurs, ou lecture du dispatch Dart |
| L14 | `0x65` = 99 o, préfixe de 20 o identique aux 12, **97 %** constant intra-session (`-3`, `-4`) | A | **VALIDÉ** | rejoué : `12 exemplaire(s)`, `constance 97%`, variables `[94, 95, 96]` |
| L15 | `0x65` **ne porte pas de date** ; il est daté par le `0x00` qui précède | A | **VALIDÉ** | rejoué : « aucune (aucun motif calendaire dans les 99 o) » |
| L16 | Aucun champ partagé ≥ 8 o entre `0x00` et `0x65` | A | **VALIDÉ** | rejoué : « champs partagés (>= 8 octets) : aucun » |
| L17 | Type `0x56` : annonce 1 115, 869 reconstruits, trou de **246 o** à la position 4 | D→A | **À ARBITRER** | Voir §4.5 : la source existe (`analysis/tmp/v8_frame56_origine_20261115.txt`, 3 765 o, 15/11 18:13) et elle **tranche le déficit**, pas son origine (H2 transport / H3 émetteur) |
| L18 | « records `0x52`/`0x50`/`0x72` également capturés » | A | **CONTREDIT** | constat 53 §6 : ce sont les queues `[94..98]` du corps `0x65` relues comme en-têtes ; 685 faux en-têtes `0xFF` sur `-2` |
| L19 | « seulement deux types existent » | A | **CONTREDIT** (formulation) | correct : « seulement deux types sont **ancrables** avec la règle actuelle » ; couverture 0,77 % à 19 % |

### 2.3 Ce que l'émulateur émet (côté D)

| ID | Énoncé | Src | Verdict | Preuve / arbitrage |
|---|---|---|---|---|
| L20 | Cycle 1 = 38 blocs, types `00 65 50 51 52 56 72`, type décodé = identifiant annoncé | D | **VALIDÉ** | `test_lifelog_conformite` : **29/29**, `EXIT=0` (aujourd'hui) |
| L21 | Aucun `0xFE` dans un champ obligatoire (en-tête 5 o + date 5 o) | D | **VALIDÉ** | même harnais, A1g ; et le test exige que le contrôle **naïf** trouve des `0xFE` (23 blocs), sinon il ne prouverait rien |
| L22 | Date du record `0x00` = horloge de l'émulateur à ±120 s | D | **VALIDÉ** | A1f, via `clock_time.cpp` |
| L23 | `00 01 04` est la trame d'occupation par défaut, émise sur `0x0024` | A+D | **VALIDÉ** | census 18/11 : `00 01 04` **132×**, **toutes H->C**, sur `0x0013` ; `00 01 07` 19× ; `00 00 00` H->C 18× |
| L24 | `00 32` : 2 formes, réponse = requête avec octet 2 remplacé (`13`/`03`), trame `0x01` à **795 ms**, silence sur `04 32` | A+D | **VALIDÉ** | 14/14 échanges ; `test_lifelog_p32` **13/13** ; rejeu hôte `prep32` : `p32=1 convoy01=1`, `2` lignes dans `/capture.jsonl` |
| L25 | `2F 0C 04 00 00 00` (6 o) = réponse mesurée au déclencheur `2F` | A | **VALIDÉ** (octets) | 1 occurrence datée, écho applicatif +12 ms ; **l'étiquette de provenance reste « amont »** dans `lifelog_prep.cpp` — à corriger, pas les octets |
| L26 | `0x3D` : variantes 17/18/19 o, différence d'**un octet** entre `…03 00…` et `…03 01…` | A | **VALIDÉ**, **table à corriger** | Voir §4.3 : 3 erreurs de comptage et **1 variante mesurée absente** de la table du constat 55 |
| L27 | `03 01` n'est **jamais** émis par l'émulateur | A+D | **VALIDÉ** (comme défaut) | 14 occurrences réelles, toutes sur `0x0013`, 295–2 052 ms après `04 2E…` ; aucun `emit` correspondant dans `src/` |
| L28 | `47 01` n'est **jamais poussé**, « seulement servi si l'app demande `0x47` » | D | **CONTREDIT** | `src/watch_emu.cpp:149` `g_buttonAuto = true` : poussé, par **deux** déclencheurs. Mesure du 18/11 : 8 occurrences, 5 après l'écho `39 04` à **245–379 ms**, 3 après une réponse `0x28` à **146–781 ms**. Écart qui existait : l'émulateur émettait immédiatement, ~100× plus tôt ; **corrigé** le jour même à 293 ms (déclencheur A) et 637 ms (B, médiane de 146/637/781), tenu par P1a/P1b/P2a–P2e (§4.4, §4.8, §4.9). Le constat 55 §6 est faux, et son diagnostic (« le blocage correspond au `47 01` manquant ») **tombe** |
| L29 | `3D 20 …` (17 o) n'est pas poussé, il est servi à la 1re demande | D | **VALIDÉ** | `lifelog_prep.cpp:232` : `g_count3d==0 ? kHex3dFirst : kHex3dSecond` |
| L30 | `5A 01` sur `0x0018` H->C — présenté comme un **battement de 30 s** que l'émulateur ne pousserait jamais | A+D | **RÉFUTÉ** (prémisse) — puis **VALIDÉ** quant au fond | Le relevé du 18/11 tranche : **16 écritures `5A` du central sur `0x0016` ⇔ 16 réponses `5a 01` sur `0x0018`**, chacune 58 à 1 566 ms après l'écriture, sur 4 captures. Ce n'est pas un battement, c'est une **réponse** ; les « 30 s » sont la période de poll de l'application (30,10 / 30,15 / 29,59 s), pas celle de la montre. L'émulateur servait déjà `5a 01` sur la commande `0x5A` : **rien à coder**, et C5 confirme qu'il n'en pousse aucun sans demande — ce qui est conforme (§4.8) |
| L31 | La période de 60 s entre deux records vient de la **journalisation** et de l'horloge, pas d'un minuteur d'émission | A+D | **VALIDÉ** | C1–C4 : 1 paire `0x00`+`0x65` par cycle (mesure : 5 paires pour 5 cycles en `-4`), cycle de **51 354 ms** contre 53 500 ms mesurés (-4 %), et deux cycles à 61 s d'écart portent deux dates à 60 s d'écart. **Le §10.1 du constat 53 prescrivait un minuteur « toutes les 60 s » : c'est sa formulation qui était fausse, pas le code** |
| L31b | Le compteur `u16` final du record `0x00` s'incrémente d'un cycle à l'autre | A+D | **CONTREDIT puis CORRIGÉ** | C3 constatait le même compteur d'un cycle à l'autre, alors que la montre passe de 1265 à 1268 en face d'un trou de 240 s. Le champ est **corps[18..19]** (les deux derniers des 15 octets du record), pas corps[13..14] comme l'écrivait la première version du harnais. Incrémenté d'une unité par record émis à partir de la valeur mesurée (`0x04ef`) ; `reset()` n'y touche pas. Portée : continuité **dans une exécution** ; au redémarrage la base est réapprise, donc la continuité **entre démarrages** n'est pas assurée (§4.8). Tenu par C3, A1f-3 et A1i-3 |

### 2.4 Application et corpus

| ID | Énoncé | Src | Verdict | Preuve / arbitrage |
|---|---|---|---|---|
| L32 | Le chemin « QW3515 » **est** le chemin DW-H5600 (pas d'exclusion de modèle) | B | **VALIDÉ** | constat DEX §3.2–3.4 : 1 définition, 1 consommateur, 7 sites d'appel, `DW_H5600` dans `isStartQW3515LogReceiveOnConnected()` |
| L33 | `00 01 04` fait **abandonner** l'app (`startState=1`, `startReason=4`) | B | **VALIDÉ** | logcat 13:23:31.822 + `MSG_INTERRUPT_NORMAL`, pas de nouvelle tentative (`mRestartLoadLifelogCount=1`) |
| L34 | **Aucun** transfert LifeLog réussi vers une DW-H5600 dans le corpus | B | **VALIDÉ** (absence) | `WatchData=LifeLog` 2 fois : 1 démarrage, 1 complétion `Success=false` |
| L35 | `00 01 04` = « busy », le client **re-poll** | C | **CONTREDIT partiel de L33** | `PROTO_AXES_SOURCES.md` §7.3 : le client amont traite tout `≠ 00 00 00` comme occupé et re-polle ; l'app officielle, elle, **abandonne**. Mêmes octets, deux conséquences ⇒ le **contexte** (réponse à un START vs réponse à un poll) est la variable manquante |
| L36 | Les mesures LifeLog du 18/11 prouvent quoi que ce soit sur la montre | E | **NON ATTRIBUÉ** | `mesure_reelle_1.json` 18:02–18:05 (`finished:false`), `mesure_reelle_2.json` 18:07–18:10 (`finished:false`), source `ble:E0:72:A1:F9:ED:D5` = adresse **identique** montre/émulateur |

---

## 3. Ce qui est validé sans réserve (et pourquoi)

1. **Le framing `0x05`** (L01–L04) : deux propriétés CRC indépendantes sur 4 sessions, chacune à 1/65 536, plus la constance de `ff f0` et de la longueur 22. Aucune des 4 sessions ne vient de l'émulateur.
2. **Les deux records ancrables** (L09, L10, L14, L15, L16) : le résultat a été reproduit aujourd'hui par l'outil cité, sans modification, sur le même corpus, avec les mêmes chiffres (12 paires, constance 97 %, aucune date dans `0x65`, aucun champ partagé).
3. **L'encodage de l'horodatage** (L12) : le désassemblage Dart et les octets concordent sur 3 dates ; l'hypothèse BCD a été réfutée par un désalignement identifié (le `0xd2` était le poids faible de l'`int32` suivant). C'est le seul point du dossier où **deux sources indépendantes** (A et B) se confirment.
4. **Les octets servis par l'émulateur** (L20–L22, L24) : 477 assertions natives vertes sur 15 harnais, dont 29 pour la conformité, 13 pour `00 32`, 10 pour la cadence et 63 pour le routage GATT et le FS de session, et chaque constante provient d'une trame datée.
5. **Les deux cycles sur carte** (L20, L24) : le firmware flashé sur l'émulateur a rejoué un cycle entier en 68,6 s — 13 annonces, 372 blocs, 0 erreur — puis, après le préambule central, le 2e passage (3 blocs). Les **372 blocs du cycle 1** et les **3 du cycle 2** sont **identiques octet pour octet** à la capture `-4`, lus hors console par le canal flash (§4.9). C'est la seule preuve du dossier qui vienne de la carte et non d'un harnais hôte.
6. **Le chemin applicatif** (L32–L34) : identifié dans le DEX, confirmé par le logcat de la même session, et l'absence de succès est un comptage exhaustif, pas une impression.
7. **Les défauts restants** : `03 01` jamais émis (L27) — un seul à ce jour. Le compteur `u16` recopié (L31b) est **corrigé** et tenu par C3/A1f-3/A1i-3 (§4.8) ; le « battement `5A 01` » (L30) n'était pas un défaut mais une **erreur de lecture** de ma part : la montre répond, elle ne bat pas (§4.8).

## 4. Ce que j'ai arbitré aujourd'hui par la mesure

Les six arbitrages ci-dessous ont été exécutés le 2026-11-18 après rédaction des rapports ; ils portent sur des affirmations qui se contredisaient **entre rapports** ou **entre un rapport et le code**.

### 4.1 Suite native complète — 15 harnais, 477 assertions, 0 échec

`bash zz_build/run_native.sh` sous WSL, code de sortie 0 sur les 15 binaires :

| Harnais | OK | Harnais | OK |
|---|---:|---|---:|
| `test_containers` | 110 | `test_lifelog_p32` | 13 |
| `test_convoy_status_census` | 16 | `test_lifelog_setup_classes` | 37 |
| `test_core` | 50 | `test_v8_dfu` | 56 |
| `test_generated_lengths` | 11 | `test_v8_evidence` | 14 |
| `test_lifelog_conformite` | 29 | `test_watch_emu_gatt` | **45** |
| `test_lifelog_cadence` | **10** | `test_watch_emu_replay` | 6 |
| `test_lifelog_decode` | 40 | | |
| `test_lifelog_flow_header` | 7 | | |
| `test_lifelog_header` | 15 | | |

**Conséquence** : L20, L21, L22, L24 sont tenus par du code exécuté, pas seulement par un tableau. Le compte de `test_lifelog_conformite` est passé de 24 (constat 54) à 29 : le constat 54 est donc **périmé sur son chiffre**, pas sur ses verdicts. `test_watch_emu_gatt` est passé de 38 à 40 avec P1a/P1b, puis à 45 avec P2a–P2e (§4.8) : **452 assertions avant P1a/P1b, 454 après, 459 après P2**. Les trois totaux qui circulent dans ce dossier sont donc datés, aucun ne se contredit — le « 452 » est l'état du matin, le « 454 » celui de la première correction, le « 459 » celui du soir.

### 4.2 Reproductibilité des trois outils d'analyse

Exécutés sur `analysis/btsnoop/*_att.csv`, sorties dans `/tmp` (les JSON officiels n'ont pas été écrasés), `pipefail` actif, `EXIT=0` :

- `lifelog_header.py` → `PREFIXE_REFUTE + ENTETE_CRC_CONFIRME` sur chaque session, en-têtes identiques au constat 48 §4 ;
- `lifelog_payload_probe.py` → meilleure transformation `complement_ff` à 0,23–9,52 %, RLE sans convention concluante, corps `H=1,60` avec bit 1–7 à 0,90 sur `-4` : identique au constat 50 §10.2 ;
- `lifelog_matrix_par_type.py` → 12 exemplaires, 3/2/5/2 paires, `constance 97%` sur `-3` et `-4`, « aucune » date dans `0x65`, « aucun » champ partagé.

**Conséquence** : les verdicts des constats 48, 50 et 53 ne dépendent pas d'un run unique. En revanche, ils dépendent tous du **même corpus de 4 sessions** — ce n'est pas 4 preuves indépendantes, c'est une preuve et trois copies.

### 4.3 Constat 55 §5–§6 : trois erreurs de comptage et une variante manquante

Census exhaustif des valeurs `3D2*`/`3D3*` sur `0x0013` :

| Valeur mesurée | Longueur **réelle** | Occurrences | Constat 55 |
|---|---:|---:|---|
| `3D300002010003002F280028002800FA0000` | **18 o** | 8 (3 captures) | annoncé 19 o ❌ |
| `3D300002010003012F280028002800FA0000` | **18 o** | 1 (`-4`) | annoncé 19 o ❌ |
| `3D200002010003012F280028002800FA00` | **17 o** | 1 (`-4`) + 3 chrono 2D | annoncé 18 o ❌ |
| `3D300002010003012F280028002800FA0001` | 19 o | 3 chrono 2D | 19 o ✅ |
| **`3D320002010003072F280028002800FA0000`** | **18 o** | **1 (`-4`)** | **absent de la table** ❌ |

Trois conséquences, toutes factuelles :

1. les longueurs du constat 55 §5 sont **décalées d'un octet** (17→18, 18→19, deux fois), et « indice 8 » est en réalité l'**indice 7** (l'octet qui précède `2F`) ;
2. il existe une **cinquième** forme, `3D 32 … 03 07 …`, jamais décrite : `0x32` en second octet et `07` au lieu de `00`/`01` ;
3. **les verdicts du constat 55 tiennent** : `kHex3dFirst` et `kHex3dSecond` (`lifelog_prep.cpp:64-65`) sont **octet pour octet** deux des formes mesurées. C'est la table qui est fausse, pas le code — et la conclusion « l'écart `0x3D`/`0x30` est réfuté » reste juste.

### 4.4 `47 01` : le constat 55 est contredit par le code

- Mesure (A) : `47 01` apparaît **8 fois**, dans **3 captures**, **toutes sur `0x0018` H->C** — jamais sur `0x0013`.
- Code (D) : `g_buttonAuto = true` par défaut, et **deux** déclencheurs sont implémentés (`class28-flag01` différé de 637 ms et `echo-3904` de 293 ms depuis le 18/11 — §4.8). Le second ne dépend plus de `afterHandshake()` : cette garde excluait 2 des 3 mesures (§4.9).
- Commentaire du code : « 6 occurrences dans 4 captures », « 4/6 à 1 à 3 ms ». **Faux sur le compte** (8 dans 3) et **sur l'ancrage du délai**.

**Le voisinage exact de chaque occurrence a été relevé le 18/11** :

| Déclencheur mesuré | Cas | Délai depuis le déclencheur |
|---|---:|---|
| écho `39 04` sur `0x002D` | **5 / 8** | 245 / 249 / 264 / 341 / 379 ms |
| réponse `0x28` finissant par `01` | **3 / 8** | 146 / 637 / 781 ms |

Dans les 8 cas l'application répond `3D 30` sur `0x0016` en 40 à 136 ms : `47 01` **provoque** bien une écriture, ce n'est pas un message isolé.

**D'où venait le « 1 à 3 ms »** : la notification part **1 à 2 ms après un PDU vide sur `0x0000`** (5 cas sur 5). Ce PDU vide est l'événement de connexion qui la transporte, pas son déclencheur. Le délai réel depuis l'écho `39 04` est de **232 à 379 ms** (médiane 293), soit ~100× plus que ce que faisait l'émulateur. Le commentaire de `watch_emu.cpp` a été corrigé en gardant la trace de l'erreur, **et le comportement suit désormais la mesure** : `scheduleButton("echo-3904", 293)` sur `kChrAllFeat`, plus une file à deux emplacements pour ne perdre aucun déclencheur (§4.8, P1a/P1b).

**Conséquence directe** : le constat 55 §6 affirme que `47 01` n'est « jamais poussé » et que le blocage observé sur l'émulateur « correspond exactement » à ce manque. Les deux affirmations sont **à retirer**. Le blocage, s'il se reproduit, a une autre cause et ne peut plus être attribué à `47 01`. Ce qui restait ouvert était plus étroit : la **garde** `afterHandshake()` sur le déclencheur B. Elle est tranchée depuis (§4.9) : elle **excluait** bien 2 des 3 cas mesurés et a été retirée. Le **délai** est réglé pour les deux déclencheurs (293 ms et 637 ms, §4.8).

### 4.5 U20 (`0x56` 1115/869) : la provenance existe

Le constat 53 §6.3 concluait « une mesure antérieure, non reproductible sur ce corpus » et renvoyait à `lifelog_decode.h:30`. Le fichier source est nommé par ce commentaire et **existe** : `analysis/tmp/v8_frame56_origine_20261115.txt` (3 765 o, 2026-11-15 18:13). Il contient la table complète du cycle 1 :

```
id    annonce  recon  ecart  blocs
0x00       20     20      0  [23]
0x65       99     99      0  [102]
0x50      301    301      0  [247, 58]
0x51      301    301      0  [247, 58]
0x52      745    745      0  [247, 247, 23, 236]
0x56     1115    869    246  [247, 247, 23, 247, 23, 94]
0x72     2373   2373      0  [...]
```

Le déficit est donc **situé** (position 4 de la séquence de blocs, 246 o utiles) et **tranché** sur sa nature (ni bug de décodage, ni trame légitimement courte : les 6 autres concordent au byte). Ce qui reste ouvert est l'**origine** : H2 (bloc perdu dans le transport) ou H3 (l'émetteur a sauté le bloc) — indécidables sans capture **côté montre**. U20 n'est donc pas « non reproductible » : elle est **documentée et bornée**, et son arbitrage exige une capture HCI que le corpus n'a pas.

### 4.6 `00 01 04` : le défaut de l'émulateur est bien la mesure

Census sur `0x0013`, par direction :

| Valeur | Direction | Occurrences |
|---|---|---:|
| `00 00 00` | C->H (poll de l'app) | 174 |
| `00 01 04` | **H->C** | **132** |
| `00 01 07` | **H->C** | **19** |
| `00 00 00` | H->C | 18 |

L'émulateur répond `00 01 04` : c'est la **forme dominante mesurée** de la montre, et le code la sert sur `0x0024` (= `0x0013`), avec un drapeau `startStateIsMeasured()`. **L23 est validé** et le choix par défaut est défendable.

Mais **L33 vs L35** reste une contradiction réelle entre deux rapports : les mêmes octets font *abandonner* l'app officielle (constat DEX) et *re-poller* le client tiers (`PROTO_AXES_SOURCES.md` §7.3). Aucun des deux ne se trompe : ils décrivent deux contextes. Le point à arbitrer est **lequel des deux contextes l'émulateur reproduit** quand il émet cette trame 700 ms après toute écriture de classe 00.

### 4.7 Cadence et battement : un harnais neuf, et une de mes conclusions corrigée

`v8/tests/native/test_lifelog_cadence.cpp` (**10 assertions, `EXIT=0`**) instruit les deux questions que le §5 laissait ouvertes. Résultat : la première était **mal posée**, et c'est mon énoncé L31 qui était faux, pas le code.

| Case | Mesure | Verdict |
|---|---|---|
| C1-1 | cycle terminé, **380 blocs** émis pour 380 attendus, 0 tête non conforme | VALIDÉ |
| C1-2 | **une** paire `0x00`+`0x65` par cycle | VALIDÉ — conforme à la mesure (5 paires / 5 cycles en `-4`) |
| C1-3 | durée du cycle **51 354 ms** contre 53 500 ms mesurés (**−4 %**) | VALIDÉ — le `kFrameGap` de 1 621 ms du 17/11 est le bon ordre de grandeur |
| C1-4 | aucun trou de 60 s entre deux blocs d'un même cycle | VALIDÉ — le transfert est continu, ~60 ms/bloc |
| C2 | deux cycles à 61 s d'écart → deux dates à **60 s** d'écart | VALIDÉ — la période vient de l'horloge |
| C3 | compteur `u16` **identique** d'un cycle à l'autre | **ÉCART constaté** — la montre incrémente (1265 → 1268). **Corrigé** le jour même : C3 exige désormais `+1` (§4.8) |
| C4 | aucune émission spontanée sur 180 s après la fin | VALIDÉ — c'est l'app qui réécrit le préambule |
| C5 | **aucun** `5A 01`, ni pendant le cycle ni sur 90 s | **CONFORME** — et non plus « écart » : la montre ne bat pas, elle répond (§4.8) |

**Ce que cela corrige dans ce rapport** : j'avais écrit que l'émulateur devait réémettre une paire toutes les 60 s et que son absence était une faille. C'est faux, et la donnée qui le dit est dans le dossier depuis le 18/11 : `mesures_cadence_2026-11-18.txt` montre que le cycle 1 de `-4` dure 53,5 s et que `-4` contient **5 paires pour 5 cycles**. Une paire par cycle est donc le comportement mesuré. La phrase du constat 53 §10.1 (« un banc qui n'émet qu'une paire ne peut pas reproduire un consommateur qui attend des réémissions ») confondait la **période de journalisation** (60 s de contenu, portée par la date de chaque record) avec une **période d'émission**. Le §10.1 est retiré au §6.

**Ce que le harnais découvre à la place** : le seul champ que l'émulateur ne met pas à jour, c'est le **compteur de séquence** (C3). Il est recopié de la capture, donc identique à chaque cycle ; sur la montre il avance (1265 → 1268 en face d'un trou de 240 s). L'écart est étroit et nommable : un consommateur qui déduplique sur ce `u16` verrait le même enregistrement à chaque poll, alors que la date, elle, est bien recalée (C2). **Il est refermé dans la foulée** (§4.8) : le compteur avance maintenant d'une unité par record émis, et C3 exige `+1` au lieu de constater l'égalité.

### 4.8 Les trois corrections, et la mesure qui en réfute une

Les trois demandes du 18/11 ont été traitées dans l'ordre où la mesure les autorisait. **Une seule des trois était fondée** ; deux l'étaient, mais pas pour la raison invoquée — et la troisième pas du tout.

**(1) Délai du `47 01` : 293 ms (déclencheur A), 637 ms (déclencheur B).** La bande mesurée du déclencheur A est 232 / 245 / 293 / 341 / 379 ms sur 5 cas (médiane 293, appariement « dernier `39 04` avant la notification »). L'émulateur émettait dans la boucle même de la réception (`emitButton` immédiat). Il planifie maintenant : `scheduleButton()` place `{payload, dueMs}` dans une file de **2 emplacements** (les deux déclencheurs mesurés — `class28-flag01` à +637 ms et `echo-3904` à +293 ms — peuvent donc tomber dans la même seconde sans que l'un écrase l'autre), la boucle vide la file quand `millis()` dépasse l'échéance, et la file est vidée à la déconnexion et au changement de mode d'appairage (sinon un `47 01` partirait sur une session morte). Le déclencheur B a été réarbitré dans la même journée (§4.9) : sa garde `afterHandshake()` contredisait 2 des 3 mesures et a été retirée, et son délai est passé de 200 ms à la médiane mesurée de 637 ms. Cinq assertions le tiennent : **P1a** aucun `47 01` à +150 ms, **P1b** exactement un entre +150 et +550 ms ; **P2a** `afterHandshake()` faux au moment du test, **P2b/P2c** réponse `28 07 1B … 01 01` servie et aucun `47 01` à +200 ms, **P2d/P2e** exactement un `47 01` entre +200 et +900 ms (`test_watch_emu_gatt`, 38 → 45).

**(2) Compteur `u16` du record `0x00` : +1 par record.** La base est la valeur du **premier** record servi (`0x04ef`, mesuré dans `kF06B0`), l'incrément vaut un par record `0x00` émis, et `reset()` ne les remet **pas** à zéro — il remet l'heure et les compteurs de session, pas la séquence. Le CRC est recalculé par `build()` : il n'y a rien à corriger à la main. Le champ est en **corps[18..19]**, pas corps[13..14] : mon premier harnais lisait le second `u32`, d'où un « compteur identique » qui mesurait autre chose que le compteur. Trois assertions le tiennent, toutes **plus précises** qu'avant, aucune plus faible : **C3** `compteurB = compteurA + 1` ; **A1f-3** 23 octets identiques à `kF06B0` **sauf** `d[19..20]` et le CRC, avec `séquence = précédente + 1` ; **A1i-3** flux réassemblé identique entre MTU 250 et MTU 23 **sauf** ces mêmes 4 octets, avec `+1`.

**Portée exacte de ce compteur — trois réserves, vérifiées dans le code :**

1. **Aucune remise à zéro ailleurs.** `g_seqBase`, `g_seqBaseSet` et `g_seqNext` n'ont qu'un seul site de définition (`lifelog_flow.cpp:113-115`) et aucun `reset` dans tout le firmware : `reset()` les laisse explicitement intacts, commentaire à l'appui. Ils ne sont écrits que par `avancerSequence()`.
2. **La base est lue avant l'écriture.** `mesure` est extraite de `body[off..off+1]` **avant** que ces deux octets ne soient réécrits ; au premier record, `val = base + 0 = mesure`, donc le premier record émis est identique à `kF06B0` — c'est A1c, qui le prouve octet pour octet.
3. **Les octets testés sont ceux du fil.** `avancerSequence(g_body)` s'exécute **avant** `build()` (donc le CRC couvre la nouvelle valeur), et `sendBlock()` émet `g_hdr` — la trame construite — découpée selon le MTU ; le « sink » des harnais est le callback `emit()` du firmware lui-même. C3/A1f-3/A1i-3 portent donc sur la charge utile notifiée, pas sur un tampon de travail.

Ce que ce compteur **ne** fait pas, et que le rapport ne doit pas laisser croire : il y a continuité entre les records d'une **même exécution**, mais au redémarrage la base est réapprise du premier record servi (`0x04ef`) et la numérotation repart de 1263. La **continuité numérique entre deux démarrages n'est pas assurée** — rien n'est persisté, et inventer une persistance serait exactement le genre de fabrication que ce dossier s'interdit.

**(3) `5A 01` toutes les 30 s : réfuté, rien n'a été poussé.** Le relevé du 18/11 compte **16 écritures `5A` du central sur `0x0016` et 16 réponses `5a 01` sur `0x0018`**, sur 4 captures, chacune 58 à 1 566 ms après l'écriture. La correspondance est 1:1 : c'est une **réponse**, pas un battement. Les « 30 s » sont la période de poll de l'application. Coder un minuteur aurait donc **fabriqué une trame que la montre n'envoie jamais** — exactement ce que la règle du dossier interdit. L'émulateur servait déjà `5a 01` sur la commande `0x5A` (`lifelog_prep::onSetupCommand`) et notifie sur `kChrAllFeat` : rien à ajouter. C5 est réécrit en conséquence : il n'affirme plus un « écart » mais la conformité (aucune trame non sollicitée, pendant le cycle comme sur les 90 s qui suivent).

Les trois corrections sont prouvées par la suite native (477 assertions, 0 échec) **et** par un rejeu sur carte (§4.9).

### 4.9 Vérification sur carte, et la garde du déclencheur B tranchée

**Flash.** Firmware `v8` écrit sur COM4 (carte `e0:72:a1:f9:ed:d4`), trois fois : après la correction de fenêtre ci-dessous (83,21 s), puis après le retrait de la garde B (75,56 s, 873 600 o). Réponse `Hash of data verified` à chaque fois. L'attribution est certaine : la carte répond sur COM4 avant et après (`help`, `dump session`).

**Rejeu n°1 : plantage, préexistant, sans rapport avec les corrections.** `IntegerDivideByZero` dans `lfs_alloc` (`lfs.c:689`) appelé par `session::flushInternal()` : le FS LittleFS était plein (`rotations=1`, `cause=place_insuffisante`), et la garde `journal::mounted()` ne couvre que le journal, pas le FS de session. Contourné par `clear session`, `clear`, `jdrop`. Il n'était pas causé par les trois corrections, mais il empêchait tout rejeu sur une carte dont le FS a déjà servi : **corrigé depuis** (garde d'espace, `prev` sacrifié puis récupéré au démarrage — T-K, plus bas).

**Rejeu n°2 : `TIMEOUT` — et ce n'était pas un défaut du flux.** Le banc attendait 45 s ; `zz_build/t_duree.exe` calcule les durées à partir des constantes du flux : 5,3 s d'indexation + **50,5 s** pour le cycle 1 (13 trames, 372 blocs) + 7,8 s pour le cycle 2 (3 trames), total imprimé **65,6 s**. Le cycle 1 seul dépasse donc la fenêtre : le `TIMEOUT` était **arithmétique**. Fenêtre portée de 45 s à **90 s** (`flowSelfTest()` : `kFenetreMs = 90000`, commentaire de mesure à l'appui) et sonde `probe_flowtest.py` : `ATTENTE_MAX = 100.0` — puis à **120 s** quand 90 s se sont révélées trop courtes à leur tour (§ plus bas). **Aucune minuterie du flux n'a été raccourcie** : seule l'attente du banc change.

**Rejeu n°3, après correction : cycle complet.** `flowtest : termine, 13 trames, 37 emissions 0023, 380 0024, 0 erreurs` en **68,6 s** — le seul écart avec les 65,6 s calculées est le temps de démarrage et d'indexation réel.

**Rejeu n°4, après retrait de la garde B : binaire et source à nouveau d'accord.** Le changement de garde et de délai a été suivi d'un **troisième flash** (`SUCCESS` 75,56 s, 873 600 o, `Hash of data verified`), puis d'un rejeu : `flowtest : termine, 13 trames, 37 emissions 0023, 380 0024, 0 erreurs` en **68,2 s**. Le binaire sur la carte est donc celui du source corrigé, et le verdict du rejeu se reproduit à l'identique. `dump session` rend des `seq` de **0 à 419** (420 objets) sur ce run : le cycle a bien été écrit en entier.

**Piège de mesure, à connaître** : `probe_flowtest.py` a rendu deux fois `SYNTHESE ABSENTE` sur ces rejeux alors que le verdict existait — la console HWCDC tronque les lignes longues et le sondage abandonne après 1,5 s de silence, ce qui peut manger la ligne de verdict (et une des 37 émissions `0023` : 36 comptées une fois). Le verdict ci-dessus vient d'un lecteur qui attend explicitement la ligne `flowtest :` jusqu'à 115 s. **Un « SYNTHESE ABSENTE » de cette sonde n'est pas une preuve d'échec du flux** — il faut relire avec un lecteur qui n'abandonne pas.

**Comparaison avec la capture `-4` — refaite sur le canal flash, et complète.** La console ne restitue que 596 o par ligne : les blocs de 247 o y sont coupés (`write failed due to waiting USB Host - timeout` côté HWCDC), et la comparaison précédente ne portait donc que sur **120 trames sur 380**. La mesure a été refaite par un **autre canal**, hors console : lecture de la partition `spiffs` par le bootloader ROM (`esptool read_flash 0x140000 0xB0000`) puis montage LittleFS hors carte (`littlefs-python`, `tools/read_lfs_dump.py --get /emu_session.jsonl`). Les 372 blocs du cycle 1 sortent donc **entiers**, sans troncature.

Découpage mesuré de `-4` (509 notifications `0x0013`, dont **408 blocs de données `05…`**) : blocs **0..371** = cycle 1 (**372 blocs**, dont un bloc de 8 o `05 01 01 01 01 01 72 45`), blocs **372..374** = le 2e passage (3 blocs), blocs **375..407** = 33 blocs des passages 3 à 6. Ce découpage est rendu par `tools/compare_blocks_4.py`, qui sépare les cycles sur la marque mesurée `00 2e ff ff ff ff ff` et non sur une position supposée.

| Élément | Carte (canal flash) | `-4` | Verdict |
|---|---|---|---|
| cycle 1, blocs de données | **372** | 372 (indices 0..371) | **372 identiques octet pour octet**, décalage 0, 0 écart |
| cycle 1, tailles | 247:241, 23:120, 210/178/173/168/146×2/102/89/50/18/8:1 | même profil | identique |
| cycle 2, blocs de données | **3** (23 o, 102 o, 11 o) | 3 (indices 372..374) | **3 identiques octet pour octet** |
| passages 3 à 6 | — | 33 (indices 375..407) | non joués (T-E) |
| total | 375 | 408 | écart = les 33 blocs des passages 3 à 6, nommés |
| annonces `00 2e` / réponses `07 2e` / `04 2e` | 13 / 13 / 1 par cycle | 13 / 13 / 1 | identique |
| préambules `00 1d` + `09 1d` | 4 + 4 | 4 + 4 | identique |
| base du compteur `u16` | `0x04ef` | `0x04ef` | identique |

**La réserve du « 120 sur 380 » est levée**, et deux affirmations du dossier sont retirées avec elle : le « 380 = 380 » du tableau précédent (la carte émet **372** blocs au cycle 1, pas 380, et `-4` en contient 408 au total) et la lecture du cycle 2 comme un rejeu complet. La comparaison ne porte plus sur un échantillon : elle porte sur **tous** les blocs émis par l'émulateur, lus hors console.

**Le cycle 2 n'est pas un second cycle complet — et c'est la mesure.** Après le préambule central (`04 00 …`, 10 o), la montre rejoue **3 frames**, pas 372 : `kDataFrames2` (table mesurée, `lifelog_frames.h`) = 3 trames, 3 blocs. Le verdict du banc a été corrigé en conséquence : il comparait le compteur **cumulé** `dataTx()` à 383 et imprimait `383 blocs joues / 383 mesures -> OK` alors que le cycle 2 n'avait **rien** ajouté — un OK tautologique. Il mesure maintenant les **trames** sur le delta depuis la clôture du cycle 1 : `flowtest 2 : cycle 1 13 trames, cycle 2 joue (preambule central injecte), 3 trames jouees / 3 mesures -> OK`. Le compte des **blocs** n'est pas fait par la carte (`dataTx()` est une somme de notifications, pas de blocs : 383 notifications pour 372 blocs) mais par `tools/compare_blocks_4.py`, hors console.

**T-K : plus de `IntegerDivideByZero`, et la place est rendue.** Trois défauts distincts, tous corrigés dans `src/session.cpp` : (1) garde d'espace **avant** écriture, faute **collante** nommée et annoncée dans `dump session` (`--- ecriture interrompue : place_insuffisante (n refus) ---`) ; (2) rotation au démarrage qui **sacrifie** `prev` quand sa conservation ne laisse pas la place d'une session entière (mesure : `prev` de 528 070 o, 159 744 o libres, session coupée à 123 472 o au milieu du cycle 2) ; (3) **récupération au démarrage** : `clear session` n'efface que le fichier courant, un `prev` de 528 Ko d'un démarrage précédent affamait encore la session suivante — il est maintenant effacé s'il ne reste pas `kMaxBytes + kMinFreeBytes`. Après correction, la même séquence carte donne une session **complète** (fin `session_end`, `lost:0`), `prev` absent de la liste des fichiers, et **aucune panique** : `lfs.c:689` n'est plus atteint. Le chemin de faute lui-même est tenu par `test_watch_emu_gatt` **T5a–T5d, T6a/T6b, T7a/T7b** (63 assertions dans ce harnais, 477 au total, 0 échec).

**Deux mesures indépendantes, mêmes nombres.** `dump5` (session de 744 lignes, deux `session_start` par append) et `dump7`, pris après `clear session` et un rejeu complet (session de 176 532 o, `session_end` `lost:0`, 431 événements), donnent exactement le même verdict : **372 blocs de cycle 1 identiques** et **3 blocs de cycle 2 identiques** à `-4`. Sur `dump7`, `prev` est **conservé** (243 369 o) parce que la place restante suffisait — la règle de rotation joue donc dans les deux sens : sacrifié quand la session suivante n'aurait pas tenu (§ ci-dessus), gardé sinon.

**La fenêtre du banc est passée à 120 s, et c'est une mesure.** À 90 s, le rejeu du 18/11 à 21:52 a conclu `TIMEOUT` à `t=90 009 ms`, soit exactement la fenêtre, alors que les deux cycles avaient été joués et que la session s'était close normalement — un TIMEOUT arithmétique, pas un écart de flux. Le rejeu propre suivant s'est clos à **81,4 s** (`termine, 16 trames, 45 emissions 0023, 383 0024, 0 erreurs`, verdict cycle 2 `OK`) : la marge de 120 s est justifiée par la mesure.

**Déclencheur B du `47 01` : la garde `afterHandshake()` est retirée.** Le corpus (4 CSV) contient 8 réponses `0x28` : **3** finissent par `01` et sont suivies d'un `47 01` à **146 ms** (`-2` 22:33:31.763), **637 ms** (capture du 14/11, 22:14:46.308) et **781 ms** (`-4` 22:18:40.906) ; **aucune** des 5 finissant par `00` n'en déclenche — 3/3, 0 faux positif. Or la garde telle qu'elle était écrite exigeait une écriture `00 xx` sur `0x0023` dans la session : les sessions `-2` et 22:14:46 n'en contiennent **aucune** avant le `47 01`. La garde excluait donc **2 mesures sur 3**, dont la plus courte. Elle est supprimée ; il ne reste que la condition mesurée (dernier octet de la réponse `0x28` = `01`), et le délai passe de 200 ms à la **médiane** des trois mesures (**637 ms**), par cohérence avec les 293 ms du déclencheur A. Cinq assertions neuves le tiennent (P2a–P2e, `test_watch_emu_gatt` 40 → 45), dont **P2a** qui vérifie que `afterHandshake()` est bien faux au moment du test — l'ancienne garde échouait P2d/P2e.

**Ce que la carte n'a pas pu mesurer : T-C.** Le délai réel du `47 01` sur la carte exige une session BLE : l'hôte Windows n'a **aucun adaptateur Bluetooth** (`BleakBluetoothNotAvailableError`), WSL ne partage pas la radio, `emitButton`/`scheduleButton` retournent sans émettre si `!g_connected`, et `conn <n>` demande une seconde cible. Le déclencheur est donc prouvé **hors carte** (P1a/P1b/P2a–P2e) et **la mesure du délai sur carte reste ouverte** : elle demande le téléphone ou un dongle BT. C'est la seule réserve qui subsiste sur le `47 01`.

---

## 5. Ce qui reste à arbitrer, avec le test exact

| # | Question ouverte | Test | Résultat attendu si le modèle est bon | Coût |
|---|---|---|---|---|
| ~~T-A~~ | ~~Cadence 60 s (L31)~~ | **FAIT** — `test_lifelog_cadence` C1–C4 (§4.7) | question mal posée : 1 paire/cycle est la mesure ; l'écart résiduel (compteur `u16`, C3) est **refermé** depuis (§4.8) | fait |
| T-B | Contexte de `00 01 04` (L33/L35) | rejeu BLE : `00 2F 00 00 00` seul, puis `00 00 00` seul, comparer la trame et le délai | la trame diffère selon la requête, ou l'app officielle abandonne dans les deux cas | 2 h (Go + émulateur) |
| T-C | `47 01` (L28) | rejeu BLE : écrire l'écho `39 04` sur `0x002D`, observer `0x002D` puis `3D 30` | le **délai** est réglé et tenu hors carte (293 ms déclencheur A, 637 ms déclencheur B — P1a/P1b/P2a–P2e) et la **garde `afterHandshake()` est tranchée** (retirée, §4.9) ; la mesure du délai **sur carte** reste ouverte : elle exige une session BLE que l'hôte n'a pas (pas d'adaptateur) | bloqué : téléphone ou dongle BT |
| ~~T-D~~ | ~~`5A 01` (L30)~~ | **FAIT** — `test_lifelog_cadence` C5 (§4.7) | 0 émission confirmée sur 90 s ; écart ouvert côté code (16 occurrences mesurées sur `0x0018`) | fait |
| ~~T-D2~~ | ~~Pousser `5A 01` toutes les 30 s (L30, résultat de C5)~~ | **ABANDONNÉ sur preuve** — 16 écritures ⇔ 16 réponses (§4.8) | ne rien coder : un minuteur inventerait une trame que la montre n'envoie pas | — |
| ~~T-D3~~ | ~~Incrémenter le compteur `u16` entre deux cycles (L31b, résultat de C3)~~ | **FAIT** — `avancerSequence()` dans `lifelog_flow`, C3/A1f-3/A1i-3 resserrés (§4.8) | `compteurB = compteurA + 1` : vert, 477 assertions | fait |
| ~~T-J~~ | ~~Garde `afterHandshake()` du déclencheur B~~ | **FAIT** — voisinage des 3 `47 01` post-`28` sur les 4 CSV (§4.9) | garde **retirée** : elle excluait 2 des 3 cas mesurés (aucune écriture `00 xx` sur `0x0023` dans ces sessions) ; délai 200 → 637 ms ; P2a–P2e | fait |
| ~~T-K~~ | ~~Rejeu sur carte d'un FS déjà rempli~~ | **FAIT** — garde d'espace avant écriture, faute collante, `prev` sacrifié puis récupéré au démarrage (§4.9) | plus de `IntegerDivideByZero` dans `lfs_alloc` : session complète (`session_end`), cause nommée dans `dump session` ; T5a–T5d, T6a/T6b, T7a/T7b | fait |
| T-E | Passages 3 à 6 de `-4` (demande ouverte ; 33 blocs, indices 375..407) | étendre `kDataFrames2`/une table de passages à partir des paires ancrées à 51 666 et 52 678, puis `test_lifelog_conformite` | les types restent ceux des identifiants annoncés, aucune trame inventée | 2 h |
| T-F | Origine du trou `0x56` (L17) | capture **HCI côté montre** d'un cycle complet | H2 ou H3 tranché par la présence du bloc dans le flux radio | hors de portée sans la montre |
| T-G | Sémantique `0x3D` (L26) | provoquer une variation (heure, fuseau) et relire les 6 formes | un des octets suit la variation | hors de portée sans la montre |
| T-H | App CASIO WATCHES contre l'émulateur (L36, demande ouverte) | connexion réelle depuis le téléphone, journal `capture.jsonl` + logcat | attribution certaine (l'émulateur est la seule cible) | dépend du téléphone |
| T-I | Mesures du 18/11 (L36) | appliquer `CROISEMENT_CLASSES_2026-11-18.md` §9 sur la montre **réveillée** | un scan doit trouver la montre quand l'émulateur est muet | action utilisateur (bouton) |

**Aucun de ces tests ne peut être remplacé par une lecture de code** : T-B et T-C mesurent un enchaînement temporel, T-D2 et T-D3 changent le comportement, T-E mesure une couverture, T-F et T-G exigent la montre.

**T-E est bloqué par une contrainte, pas par la technique** : `tools/gen_lifelog_frames.py` est verrouillé, et il est câblé sur la capture `chrono_2d` (`assert len(cyc1) == 7`, `assert len(cyc2) == 3`, `--csv` par défaut `chrono_2d_20261109_195845.csv`). Étendre `kDataFrames2` aux cycles 3–5 de `-4` exigerait donc de modifier le générateur **et** de lui fournir un CSV de `-4` au même format — deux choses hors du périmètre autorisé. Le header reste généré, il n'est pas touché à la main.

---

## 6. Ce qui est retiré du dossier

| Affirmation retirée | Où elle était | Pourquoi |
|---|---|---|
| « l'émulateur n'émet jamais `47 01`, d'où le blocage » | constat 55 §6 | contredit par `g_buttonAuto = true` (§4.4) |
| « `47 01` : 6 occurrences dans 4 captures » | commentaire `watch_emu.cpp:126` | 8 occurrences dans 3 captures (§4.4) |
| « `47 01` : 4/6 à **1 à 3 ms** après l'écho `39 04` » | commentaire `watch_emu.cpp:128`, et `:1233` | l'ancrage était un **PDU vide** (`0x0000`), pas l'écho : depuis l'écho c'est **232 à 379 ms** sur 5 cas. Commentaire corrigé et comportement aligné sur la mesure depuis le 18/11 (§4.4, §4.8) |
| longueurs 18/19 o des trames `0x3D` | constat 55 §5–§6 | 17/18 o réels (§4.3) |
| « trois variantes mesurées » de `0x3D` | constat 55 §5 | cinq formes existent, dont `3D 32 … 03 07` (§4.3) |
| « le chiffre 1115/869 est non reproductible » | constat 53 §6.3 | la source est nommée et existe (§4.5) |
| tout verdict « montre » tiré de `mesure_reelle_*.json` | dossier du 18/11 | source non attribuable (§2.4, L36) |
| « le modèle d'émission doit être une paire toutes les 60 s, donc il manque un minuteur » | constat 53 §10.1, et mon L31 initial | la mesure donne **une paire par cycle** (5 paires / 5 cycles en `-4`) et la période de 60 s est portée par la date, pas par une horloge d'émission (§4.7, C1–C2) |
| « `5A 01` est un battement de 30 s que l'émulateur ne pousse jamais » | mon L30 initial, et la demande T-D2 | 16 écritures du central ⇔ 16 réponses, sur 4 captures (§4.8) : la période de 30 s est celle du poll de l'app. Le « jamais poussé » est donc **vrai et sans défaut** |
| « le compteur `u16` du record `0x00` est en corps[13..14] » | première version de `test_lifelog_cadence.cpp` | ces deux octets sont dans le second `u32` ; le compteur est en **corps[18..19]** (`0x04ef` dans `kF06B0`) — §4.8 |
| « `47 01` sortait 1 à 3 ms après l'écho `39 04` » | mon §4.4, et le commentaire `watch_emu.cpp:128` | la bande est **232 à 379 ms** (médiane 293) sur 5 cas appariés au dernier `39 04` ; le code émettait immédiatement et suit désormais la mesure (§4.8, P1a/P1b) |
| « on ne déclenche le `47 01` que sur la variante **d'après** handshake » | commentaire du déclencheur B, `watch_emu.cpp` (~l.1206) | le corpus donne **3/3** sur les `28` finissant par `01`, dont **2** dans des sessions où le central n'écrit aucun `00 xx` sur `0x0023`. La garde excluait 2 mesures sur 3 : retirée, délai 200 → 637 ms (§4.9, P2a–P2e) |
| « la fenêtre du banc `flowtest` est de 45 s » | `flowSelfTest()` et `probe_flowtest.py` | le cycle 1 seul dure **50,5 s** (65,6 s avec le cycle 2) : un `TIMEOUT` à 45 s était arithmétique, pas un défaut du flux (§4.9) |

Les constats eux-mêmes ne sont **pas** réécrits : ce tableau est la correction, et il renvoie à la ligne fautive.

---

## 7. Journal des commandes exécutées

```bash
# 1. suite native (WSL), 15 harnais
MSYS_NO_PATHCONV=1 wsl bash -c 'cd /mnt/f/freebuff/gshock/DW-H5600-EMU/v8 && bash zz_build/run_native.sh'
# -> 15 BUILD OK, exit=0, 452 assertions, 0 echec
#    (452 = etat AVANT les deux assertions P1a/P1b ajoutees plus bas, #12)

# 2. reproductibilité des constats 48 / 50 / 53 (sorties dans /tmp, JSON officiels intacts)
cd DW-H5600-EMU && set -o pipefail
python tools/reverse/lifelog_header.py        --json /tmp/xcheck/hdr.json analysis/btsnoop/*_att.csv
python tools/reverse/lifelog_payload_probe.py --json /tmp/xcheck/pay.json analysis/btsnoop/*_att.csv
python tools/reverse/lifelog_matrix_par_type.py --json /tmp/xcheck/mat.json analysis/btsnoop/*_att.csv
# -> EXIT=0 ; verdicts identiques aux constats

# 3. census 0x3D (constat 55)
python - <<'PY'  # valeurs 3D2*/3D3* de chaque *_att.csv : valeur + longueur + occurrences
# -> 18 o x8, 18 o x1 (0301), 17 o x1, 18 o x1 (3D32...0307)

# 4. census 47 01 / 03 01
# -> 4701 : 8, toutes 0x0018 H->C ; 0301 : 14, toutes 0x0013 H->C

# 5. census état de démarrage sur 0x0013
# -> 000000 C->H 174 ; 000104 H->C 132 ; 000107 H->C 19 ; 000000 H->C 18

# 4 bis. voisinage exact des 8 `47 01` (déclencheur et délai)
# -> 5 apres echo 3904 a 245/249/264/341/379 ms ; 3 apres `28 xx` a 146/637/781 ms
# -> dans les 5 premiers cas la notification suit un PDU VIDE 0x0000 de 1 a 2 ms

# 5 bis. census `5a 01` (colonne `valeur`, pas `value`)
# -> 16 occurrences, toutes 0x0018 H->C (11 dans -4, 4 dans -2, 1 dans la brute)

# 6. harnais de cadence (nouveau)
g++ -std=gnu++17 -O0 -Wall -Wextra -I v8/tests/native/shim -I v8/src \
  -o v8/zz_build/test_lifelog_cadence.exe v8/tests/native/test_lifelog_cadence.cpp \
  v8/src/lifelog_flow.cpp v8/src/lifelog_header.cpp v8/src/clock_time.cpp -lpthread
./v8/zz_build/test_lifelog_cadence.exe    # -> 10 OK, 0 ECHEC
# -> C1-3 duree=51354 ms (mesure -4 : 53500) ; C2 ecart=60 s ; C3 compteurs identiques ; C5 0 `5a 01`

# 7. provenance 0x56
ls -l analysis/tmp/v8_frame56_origine_20261115.txt   # 3765 o, 15/11 18:13

# 8. suite complete apres ajout du harnais (encore 452 : P1a/P1b n'existent pas)
bash zz_build/run_native.sh   # -> 15 BUILD OK, exit=0, 452 assertions, 0 echec

# 9. `5A 01` : reponse ou battement ? (colonne `valeur` de l'extraction att)
# -> 16 ecritures C->H 0x0016 `5A` ; 16 reponses H->C 0x0018 `5A 01` ; 4 captures
# -> deltas ecriture->reponse 58 / ... / 1566 ms ; les « 30 s » sont ceux de l'app

# 10. delai `39 04` -> `47 01`, appariement au DERNIER `39 04` avant la notification
# -> 232 / 245 / 293 / 341 / 379 ms (mediane 293) ; 3 cas sans echo partent >= 781 ms
#    apres un `28 07 xx xx xx 01` (declencheur B, garde afterHandshake)

# 11. `kF06B0` decode octet par octet
# -> 00 | 0f 00 00 00 | 1a 0a 1a 16 12 | cf f5 00 00 | 70 02 00 00 | ef 04
#    corps[18..19] = ef 04 inverses -> 0x04ef = 1263 : c'est le compteur, PAS corps[13..14]

# 12. suite apres corrections (47 01 a 293 ms, compteur, C3/C5/A1f-3/A1i-3, P1a/P1b)
bash zz_build/run_native.sh   # -> 15 BUILD OK, exit=0, 454 assertions, 0 echec
# -> cadence 10 OK (C3 exige +1) ; conformite 29 OK ; gatt 40 OK
#    (P1a aucun `47 01` a +150 ms ; P1b exactement un entre +150 et +550 ms)

# 13. durees reelles du flux (constantes du code, pas d'estimation a la main)
./zz_build/t_duree.exe
# -> index 5.3 s, cycle1 50.5 s (13 trames / 372 blocs), cycle2 7.8 s (3 trames), total 65.6 s
#    => la fenetre de 45 s du banc etait inferieure au cycle 1 : TIMEOUT arithmetique

# 14. flash sur COM4 (trois fois : fenetre 90 s, puis retrait de la garde B)
# -> SUCCESS, 83.21 s puis 75.56 s (873600 o), « Hash of data verified »
# -> confirmation d'attribution : `help` repond sur COM4 avant et apres

# 15. rejeu carte (cycle complet) + dumps
# -> flowtest : termine, 13 trames, 37 emissions 0023, 380 0024, 0 erreurs, 68.6 s
# -> dump session : 420 objets JSON (seq 0..419), blocs de 247 o TRONQUES par HWCDC

# 16. comparaison carte <-> -4 sur les trames de 23 o recuperables
# -> 380 blocs / 13 `00 2e` / 13 `07 2e` / 1 `04 2e` / 4x(`00 1d`+`09 1d`) ; base 0x04ef
# -> -4 : 408 blocs ; carte cycle 1 = 372 blocs identiques (decalage 0), cycle 2 = 3 identiques ;
#    ecart nomme = 33 blocs des passages 3 a 6 (T-E)
#    (index 62, corps identique, CRC `01 01` aberrant)

# 17. garde afterHandshake du declencheur B, mesuree sur les 4 CSV
# -> 8 reponses 0x28 : 3 finissent par 01 -> 3 `47 01` (146 / 637 / 781 ms)
#    les 5 finissant par 00 -> aucun `47 01` (3/3, 0 faux positif)
# -> `00 xx` sur 0x0023 avant le `47 01` : present en -4 (781 ms), ABSENT en -2 (146 ms)
#    et dans la capture du 14/11 (637 ms) : la garde excluait 2 mesures sur 3 -> retiree

# 18. suite apres retrait de la garde et delai 637 ms (P2a..P2e)
bash zz_build/run_native.sh   # -> 15 BUILD OK, exit=0, 477 assertions, 0 echec
# -> cadence 10 OK ; conformite 29 OK ; gatt 63 OK (P1/P2 + T5a-T5d, T6a/T6b, T7a/T7b)

# 19. rejeu apres le 3e flash (binaire == source corrige)
# -> flowtest : termine, 13 trames, 37 emissions 0023, 380 0024, 0 erreurs, 68.2 s
# -> dump session : seq 0..419 (cycle ecrit en entier)
# -> NB : probe_flowtest.py peut rendre « SYNTHESE ABSENTE » (lignes tronquees par
#    HWCDC + abandon apres 1.5 s de silence) ; relire avec un lecteur qui attend le verdict

# 20. lire les blocs de 247 o SANS la console : bootloader ROM + LittleFS hors carte
MSYS_NO_PATHCONV=1 python -m esptool --port COM4 --baud 460800 read_flash 0x140000 0xB0000 zz_build/lfs_dump7.bin
zz_build/.venv_lfs/Scripts/python.exe tools/read_lfs_dump.py zz_build/lfs_dump7.bin --list
# -> capture.jsonl, emu_session.jsonl (176532 o), emu_session.prev.jsonl (243369 o), errors.jsonl
zz_build/.venv_lfs/Scripts/python.exe tools/read_lfs_dump.py zz_build/lfs_dump7.bin --get /emu_session.jsonl zz_build/session7.jsonl

# 21. comparaison des DEUX cycles, blocs entiers, decoupes sur la marque `00 2e ff ff ff ff ff`
MSYS_NO_PATHCONV=1 python tools/compare_blocks_4.py zz_build/session7.jsonl
# -> cycle 1 372 blocs, 372 identiques a -4[0:372] (decalage 0, 0 ecart)
# -> cycle 2   3 blocs,   3 identiques a -4[372:375]
# -> ecart nomme : 33 blocs -4[375..407] = passages 3 a 6 (T-E)
# -> VERDICT cycle 1 OK, cycle 2 OK

# 22. FS de session plein : prev sacrifie puis recupere (T-K)
# -> avant : `lfs.c:689 IntegerDivideByZero` dans lfs_alloc apres un cycle complet
# -> apres : garde d'espace, faute collante annoncee dans `dump session`, session
#    complete (`session_end`, lost:0), prev conserve quand la place le permet (243369 o)

# 23. fenetre du banc portee a 120 s (a 90 s : TIMEOUT a t=90009 ms, cycles joues)
MSYS_NO_PATHCONV=1 python zz_build/probe_raw.py COM4 "clear session" zz_build/clear5.txt 8
MSYS_NO_PATHCONV=1 python zz_build/probe_raw.py COM4 "flowtest 2" zz_build/flowtest2g.txt 150
# -> flowtest : termine, 16 trames, 45 emissions 0023, 383 0024, 0 erreurs (81.4 s)
# -> flowtest 2 : cycle 1 13 trames, cycle 2 joue (preambule central injecte), 3 trames jouees / 3 mesures -> OK
```

---

## 8. Conclusion en une phrase

Sur 37 énoncés croisés : **25 sont validés** (dont 6 par du code exécuté : la suite native — 477 assertions sur 15 harnais — le harnais de cadence écrit aujourd'hui, et le rejeu sur carte, 372 blocs + 3 blocs de cycle 2, identiques à `-4`) et **4 le sont sous réserve explicite** ; **4 sont contredits** — trois par la mesure ou par le code dans le constat 55 ou dans un commentaire de `watch_emu.cpp`, un par une divergence réelle entre deux rapports (`00 01 04`) ; **1 est non attribué** (les mesures du 18/11) ; **3 restent à arbitrer**, et ils exigent la montre ou une capture HCI. Le cinquième « contredit » — le compteur `u16` recopié — est **refermé** : le champ est corrigé et trois assertions le tiennent (§4.8).

Les erreurs du dossier sont corrigées ici, pas effacées — y compris **plusieurs des miennes** : la « faille de réémission 60 s » n'existe pas (§4.7), les longueurs de trames `0x3D` du constat 55 étaient décalées d'un octet (§4.3), le « 1 à 3 ms » de `47 01` était mesuré depuis un PDU vide au lieu de l'écho (§4.4), et le « battement `5A 01` de 30 s » était un **poll de l'application** que j'avais pris pour une émission de la montre (§4.8) — la demande qui en découlait est la seule des trois que j'ai refusée. Il faut y ajouter une erreur de harnais : mon premier `counter00()` lisait corps[13..14] au lieu de corps[18..19], et « constatait » donc une égalité qui ne portait pas sur le compteur. Et deux erreurs de plus, trouvées en vérifiant sur carte : la fenêtre de 45 s du banc était plus courte que le cycle qu'elle devait mesurer (§4.9), et la garde `afterHandshake()` du déclencheur B excluait deux des trois émissions qu'elle prétendait filtrer (§4.9) — les deux sont corrigées dans le code, pas dans le texte.

**Ce qui reste ouvert, et qui ne dépend pas de moi** : la mesure du délai du `47 01` **sur carte** (pas d'adaptateur Bluetooth sur l'hôte : seule une session BLE peut la donner) et les **33 blocs** des passages 3 à 6 de `-4` (T-E, dont la table de trames correspondante n'existe pas encore). Deux points de cette liste sont **refermés** depuis : les blocs illisibles par la console (lus par le canal flash, 372 + 3 comparés) et le plantage `lfs_alloc` du FS plein (T-K corrigé et rejoué sur carte).
