# Étiquettes RFID de la QIDI Box

Documentation du format utilisé par la QIDI Box pour identifier les bobines de filament, et de la
manière de fabriquer ses propres étiquettes pour des bobines d'autres marques.

## Le support

La QIDI Box lit des puces **FM11RF08S** : clones MIFARE Classic 1K, ISO/IEC 14443-A, 13,56 MHz,
16 secteurs de 4 blocs de 16 octets. Tout lecteur PC/SC compatible MIFARE Classic convient donc
pour les programmer.

## Où sont les données

Trois octets utiles, en tête du **bloc 4** (secteur 1, bloc 0) :

| Octet | Sens | Plage |
|---|---|---|
| 0 | code matériau | 1..50 |
| 1 | code couleur | 1..24 |
| 2 | code fabricant | 1 par défaut |

Les treize octets suivants sont à zéro. Un bloc 4 entièrement nul correspond à une étiquette vierge.
Une étiquette vierge du commerce se programme donc en écrivant ce seul bloc.

## Clés

Les outils communautaires essaient `D3F7D3F7D3F7` (clé définie par le NFC Forum pour la zone NDEF
des MIFARE Classic) puis `FFFFFFFFFFFF` (clé d'usine). Les étiquettes vendues vierges sont en
général restées en clé d'usine ; les étiquettes d'origine QIDI semblent issues d'une matrice NDEF
reformatée. Si la Box refuse une étiquette écrite, réécrire le trailer du secteur 1 :

```
clé A      : D3F7D3F7D3F7
bits accès : FF078069
GPB        : 69
clé B      : D3F7D3F7D3F7
```

En ligne de commande : `--fix-keys`, dans l'interface : « Écrire + clés D3F7 ».

## Codes matériaux

| Code | Matériau | Code | Matériau |
|---|---|---|---|
| 1 | PLA | 30 | PAHT-CF |
| 2 | PLA Matte | 31 | PAHT-GF |
| 3 | PLA Metal | 32 | Support PAHT |
| 4 | PLA Silk | 33 | Support PET/PA |
| 5 | PLA-CF | 34 | PC/ABS-FR |
| 6 | PLA-Wood | 37 | PET-CF |
| 7 | PLA Basic | 38 | PET-GF |
| 8 | PLA Matte Basic | 39 | PETG Basic |
| 11 | ABS | 40 | PETG Tough |
| 12 | ABS-GF | 41 | PETG Rapido |
| 13 | ABS-Metal | 42 | PETG-CF |
| 14 | ABS-Odorless | 43 | PETG-GF |
| 18 | ASA | 44 | PPS-CF |
| 19 | ASA-AERO | 45 | PETG Translucent |
| 24 | UltraPA | 47 | PVA |
| 25 | PA-CF | 49 | TPU-Aero |
| 26 | UltraPA-CF25 | 50 | TPU |
| 27 | PA12-CF | | |

Les codes 9, 10, 15-17, 20-23, 28, 29, 35, 36, 46 et 48 ne sont pas documentés.

## Codes couleurs

| Code | Couleur | Code | Couleur |
|---|---|---|---|
| 1 | #FAFAFA blanc | 13 | #CADE4B lime |
| 2 | #060606 noir | 14 | #1353AB bleu royal |
| 3 | #D9E3ED gris | 15 | #5EA9FD bleu ciel |
| 4 | #5CF30F vert clair | 16 | #A878FF violet |
| 5 | #63E492 menthe | 17 | #FE717A rose |
| 6 | #2850FF bleu | 18 | #FF362D rouge |
| 7 | #FE98FE rose clair | 19 | #E2DFCD beige |
| 8 | #DFD628 jaune | 20 | #898F9B argent |
| 9 | #228332 vert | 21 | #6E3812 brun |
| 10 | #99DEFF bleu clair | 22 | #CAC59F kaki |
| 11 | #1714B0 bleu foncé | 23 | #F28636 orange |
| 12 | #CEC0FE lavande | 24 | #B87F2B bronze |

### Changer le jeu de clés (et pourquoi certaines applis échouent)

Sur une MIFARE Classic, la clé A n'est jamais lisible : une lecture du trailer renvoie des zéros à
sa place. Ce n'est pas un signe de protection.

Si une application Android affiche « clé protégée par un mot de passe » et `sector 1 AUTH FAILED`
alors que le tag se lit très bien ailleurs, c'est qu'elle n'essaie qu'une seule clé. Les étiquettes
QIDI d'origine sont en `D3F7D3F7D3F7` ; les vierges du commerce en `FFFFFFFFFFFF`. Les deux se
ramènent à l'autre jeu :

```
--cli qidi-write --material … --color … --fix-keys ffff   # revenir aux clés d'usine
--cli qidi-write --material … --color … --fix-keys d3f7   # imiter une étiquette d'origine
```

Dans l'interface, deux boutons : « Écrire + clés D3F7 » et « Écrire + clés FFFF ».

## Où coller l'étiquette

Le lecteur est intégré à la box, au niveau du support de bobine : l'antenne est juste derrière la
face de la bobine tournée vers l'intérieur de la box. L'étiquette doit être collée à plat sur cette
face, près du moyeu. Une MIFARE Classic n'a pas de sens d'orientation, contrairement aux étiquettes
Bambu : seules la face et la distance comptent. Éviter un support métallisé, qui étouffe le champ.

Le plus simple est de prendre une bobine QIDI d'origine comme référence et de reproduire la position
de son étiquette.

## Références

- Wiki QIDI, guide officiel des étiquettes : `wiki.qidi3d.com/en/QIDIBOX/RFID`
- BoxRFID (lecture/écriture sous Electron, source Python incluse) : `github.com/TinkerBarn/BoxRFID`
- Autres implémentations : `QIDI-filament-nfc-flipper` (Flipper Zero), `QboxTagger` (iOS),
  application Android « My Filaments ».

Le champ « fabricant » n'est pas encore exploité par la box : laisser la valeur 1.
