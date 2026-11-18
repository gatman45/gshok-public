# # DW-H5600 — LifeLog : observations du protocole et validation d'un émulateur

**Date :** 18 novembre 2026  
**Projet :** CasioLab / DW-H5600-EMU  
**Objet :** partager des observations reproductibles sur le transfert LifeLog du DW-H5600, susceptibles d'être utiles à un client tiers comme GShockAPI.

## 1. Périmètre et méthode

Ce document présente uniquement les travaux relatifs au protocole LifeLog du DW-H5600.

Les observations du protocole proviennent de captures BLE réalisées avec une véritable DW-H5600, recueillies entre août et octobre 2026. Elles ont été confrontées au comportement de l'application CASIO WATCHES et à celui d'un émulateur développé indépendamment.

Une distinction est maintenue entre :
- les octets observés sur la montre ;
- l'interprétation effectuée par l'application ;
- les octets produits par l'émulateur ;
- les hypothèses dont la sémantique n'est pas encore établie.

Les résultats de l'émulateur ne sont pas présentés comme de nouvelles mesures de la montre.

## 2. Framing du flux LifeLog

Le flux de notifications étudié utilise notamment des trames commençant par `0x05`.

Sur quatre sessions BLE de référence :

- la première notification observée commence par `0x05` ;
- l'en-tête fait 22 octets ;
- deux contrôles CRC-16/Kermit concordent :
  - `crc16_kermit(v[1:-2])` correspond aux deux derniers octets en little-endian ;
  - `crc16_kermit(v[1:])` donne zéro ;
- aucun préfixe de longueur distinct n'a été identifié avant cet en-tête.

Les notifications suivantes présentent plusieurs tailles. Le découpage observé est notamment compatible avec les contraintes de transport BLE/ATT et les tailles dominantes comprennent 244 et 23 octets.

**Limite :** le framing est validé, mais la structure sémantique de l'intégralité du payload n'est pas encore décodée.

## 3. Deux types de records identifiés

Deux types de records sont actuellement ancrables de manière reproductible dans le corpus.

### 3.1 Record `0x00`

- Longueur : 15 octets.
- Préfixe temporel :
  - année moins 2000 ;
  - mois ;
  - jour ;
  - heure ;
  - minute.
- Ces cinq valeurs sont encodées en binaire, et non en BCD.
- Elles sont suivies de deux champs de 32 bits et d'un compteur de 16 bits.

L'interprétation des deux champs `int32` reste ouverte.

Le compteur final est cohérent avec une progression d'un enregistrement à l'autre. Sa continuité a été reproduite dans l'émulateur au cours d'une même exécution ; sa continuité entre redémarrages n'est pas garantie.

### 3.2 Record `0x65`

- Longueur : 99 octets.
- Les 20 premiers octets sont identiques dans les 12 exemplaires ancrés.
- Le contenu présente environ 97 % de constance intra-session dans les captures étudiées.
- Aucun horodatage calendaire n'a été identifié dans ce record.
- Aucun champ commun d'au moins 8 octets n'a été identifié entre les records `0x00` et `0x65`.

L'association temporelle actuellement observée repose donc sur le record `0x00` qui précède le `0x65`.

La signification détaillée du contenu de `0x65` reste à établir.

## 4. Cadence et séquences observées

La cadence dominante des records `0x00` est de 60 secondes.

Les captures montrent également des intervalles plus longs, notamment 120 et 240 secondes. Le compteur final du record `0x00` progresse en tenant compte des enregistrements manquants dans la séquence observée.

Les essais sur l'émulateur indiquent qu'il faut reproduire un cycle de journalisation, et non simplement programmer une émission indépendante toutes les 60 secondes.

Le cycle de référence de l'émulateur dure environ 51,4 secondes, contre environ 53,5 secondes mesurées sur la séquence de référence utilisée pour la comparaison.

## 5. Résultat de conformité de l'émulateur

Le firmware de l'émulateur a été exécuté sur le banc matériel, puis ses données ont été relues directement depuis la mémoire flash.

Cette méthode a permis d'éviter les troncatures observées lors des extractions par console série.

La comparaison avec la capture de référence `-4` donne :

| Élément | Émulateur | Référence | Résultat |
|---|---:|---:|---|
| Cycle 1 | 372 blocs | 372 blocs | 372 identiques octet pour octet |
| Cycle 2 | 3 blocs | 3 blocs | 3 identiques octet pour octet |
| Passages 3 à 6 | non émis | 33 blocs | non couverts |

**Résultat : 375 blocs émis par l'émulateur sur 375 sont identiques à leur référence.**

La couverture du corpus complet est toutefois de 375 blocs sur 408, soit **91,9 %**. Les 33 blocs restants correspondent aux passages 3 à 6 de la capture de référence et ne sont pas encore reproduits.

Cette distinction est importante : la conformité des blocs effectivement émis est de 100 %, mais la couverture du corpus n'est pas complète.

## 6. État des validations

Les outils d'analyse ont été rejoués sur le corpus existant le 18 novembre :

- validation de l'en-tête et des CRC ;
- analyse des payloads ;
- regroupement des records par type ;
- vérification des 12 exemplaires ancrés ;
- comparaison complète des blocs émis sur le banc.

La suite native de l'émulateur compte 15 harnais et 477 assertions, sans échec au dernier passage.

Ces tests établissent la reproductibilité du comportement implémenté. Ils ne remplacent pas une capture BLE supplémentaire sur une véritable montre.

## 7. Points restant ouverts

Les sujets suivants ne sont pas présentés comme résolus :

1. Décodage sémantique complet du payload des notifications `0x05`.
2. Interprétation des deux champs `int32` du record `0x00`.
3. Signification détaillée du record `0x65`.
4. Reproduction des 33 blocs correspondant aux passages 3 à 6 de la capture `-4`.
5. Validation de bout en bout d'un transfert LifeLog réussi avec l'application officielle et une véritable DW-H5600.

Un point d'interopérabilité mérite également attention : la réponse `00 01 04` est traitée différemment selon le client étudié. Le client tiers analysé la traite comme un état occupé et peut réinterroger le périphérique, tandis que l'application officielle abandonne le transfert dans le contexte observé. Le contexte exact de cette réponse reste à arbitrer.

## 8. Conclusion

Le framing du flux LifeLog et deux types de records (`0x00` et `0x65`) ont été caractérisés à partir de captures réelles.

Un émulateur indépendant reproduit exactement les 375 blocs qu'il émet, comparés à la capture de référence par lecture directe de la mémoire flash. Il reste 33 blocs du corpus à couvrir et plusieurs champs à interpréter.

L'objectif de ce partage est de mettre à disposition des observations techniques vérifiables pouvant aider à comprendre ou à améliorer l'interopérabilité LifeLog. Il ne prétend pas fournir une spécification complète du protocole.

**Périmètre volontairement exclu :** firmware et bootloader, procédure DFU, mécanismes cryptographiques, investigations de sécurité et autres surfaces internes non nécessaires à l'étude LifeLog.
