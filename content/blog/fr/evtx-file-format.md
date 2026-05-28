---
title: "Le format de fichier EVTX, décodé"
description: "Une visite pratique du format binaire EVTX : en-tête de fichier, chunks ELFCHNK, templates BinXML, tableaux de substitution, et pourquoi parser cette chose est plus difficile qu'il n'y paraît."
date: "2026-05-27"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

L'ancien format EVT était presque lisible avec un éditeur hexadécimal et de la patience. EVTX ne l'est pas. Microsoft l'a remplacé dans Vista par quelque chose conçu pour le débit en écriture et la consommation par machine, et l'effet de bord est que tout le monde qui veut lire un fichier EVTX finit par réimplémenter les mêmes quelques centaines de pages de notes de reverse-engineering d'Andreas Schuster. Le format n'est documenté dans `[MS-EVEN6]` qu'à la couche protocole. La structure sur disque, vous devez la deviner vous-même ou l'emprunter à `libevtx`.

Ce billet est la version de cela que j'aurais aimé avoir quand j'ai commencé.

## L'en-tête de fichier, en bref

Chaque fichier EVTX s'ouvre par un en-tête de 4096 octets. La magie est `ElfFile\0` à l'offset 0. Après ça, les champs qui vous intéressent réellement pendant le triage :

- `FirstChunkNumber` et `LastChunkNumber` indices de chunk, pas offsets d'octets.
- `NextRecordIdentifier` le prochain RecordID qui serait écrit. Utile pour repérer la troncature.
- `HeaderSize` presque toujours 128, avec le reste des 4096 octets rempli de zéros.
- `MinorVersion` / `MajorVersion` `3.1` est la version que tout Windows moderne écrit.
- `FileFlags` bit 0 mis signifie que le fichier est dirty (pas proprement fermé), bit 1 signifie qu'il a été "plein" et tourne. Les deux comptent pour l'interprétation forensique.
- Un CRC32 sur les 120 premiers octets de l'en-tête. Les outils qui ignorent le CRC parseront joyeusement des en-têtes corrompus ; les outils qui l'imposent rejetteront des fichiers d'où vous pouvez encore récupérer des enregistrements. Sachez ce que fait le vôtre.

Après l'en-tête, vous obtenez une séquence de chunks de 65 536 octets. Toujours 64 Ko, toujours alignés. C'est l'unité que Windows écrit atomiquement, et l'unité que vous carvez.

## ELFCHNK : l'en-tête de chunk

Chaque chunk commence par `ElfChnk\0` à la frontière du chunk. L'en-tête fait 512 octets et porte les champs qui rendent le parsing possible :

- `FirstEventRecordNumber` et `LastEventRecordNumber` la plage de RecordID couverte par ce chunk.
- `FirstEventRecordIdentifier` et `LastEventRecordIdentifier` la même chose, conservée pour le legacy.
- `FirstEventRecordOffset` où commencent les octets du premier enregistrement à l'intérieur de ce chunk.
- `LastEventRecordOffset` où commence le dernier enregistrement. Si ça dépasse la fin du chunk peuplé, le chunk a été partiellement écrit ; le writer a crashé.
- Une `StringTable` et une `TemplateTable`, toutes deux des tables de hachage indexées par des hashes de style FNV, pointant dans la charge utile BinXML du chunk.
- Deux CRCs : un sur l'en-tête, un sur la zone des enregistrements.

Les tables de chaînes et de templates sont la partie qui désarçonne les gens. Templates et chaînes sont stockés *une fois par chunk* et référencés par offset au sein du chunk. Cela signifie que vous ne pouvez pas parser un enregistrement isolément de manière significative. Vous avez besoin de son chunk englobant, avec ses tables résolues, pour rendre le XML de l'enregistrement. Carvez un enregistrement sans son chunk et vous obtenez un tableau de substitution sans template dans lequel substituer.

`NumLogRecords` vit implicitement comme `LastEventRecordNumber - FirstEventRecordNumber + 1`. Quelques documentations anciennes nommaient ce champ ; les parsers modernes le calculent.

## Encodage d'EventRecord

Au-delà de l'en-tête de chunk vous obtenez des enregistrements, dos à dos, jusqu'à ce que le chunk soit plein ou que le reste soit zéroté. Chaque enregistrement commence par la magie `2a 2a 00 00` (ce qui rend le carving par signature depuis le disque brut faisable, plus sur ça dans un billet séparé) suivi de :

- `Size` longueur totale de l'enregistrement y compris la répétition de taille à la fin.
- `EventRecordIdentifier` le RecordID monotone croissant.
- `WriteTime` un FILETIME Windows, ticks de 100 ns depuis 1601-01-01 UTC.
- La charge utile BinXML.
- `Size` à nouveau, répété à la queue pour qu'un lecteur puisse parcourir les enregistrements à l'envers.

La charge utile BinXML est là où commence le vrai travail.

## BinXML et le modèle template/substitution

BinXML est un flux de tokens qui encode XML comme des opcodes binaires. Les opcodes qui comptent :

- `0x00` end-of-stream.
- `0x01` open start tag (avec attributs).
- `0x02` close start tag.
- `0x03` close empty tag.
- `0x04` end element.
- `0x05` value, suivi d'un `ValueType` et des octets de valeur.
- `0x06` attribute.
- `0x0c` template instance.
- `0x0d` normal substitution.
- `0x0e` conditional substitution.
- `0x0f` start of stream (avec un préambule de 3 octets).

Le writer du journal d'événements Windows n'émet presque jamais de XML brut pour un événement. Il émet une *instance de template* (`0x0c`), qui référence une définition de template (stockée une fois par chunk par ID) et fournit un *tableau de substitution* contenant les valeurs des variables pour ce template. Pour rendre un seul enregistrement XML lisible par un humain vous devez :

1. Localiser le template dans la table de templates du chunk par son ID et son offset.
2. Parcourir le BinXML du template, en le traitant comme un squelette avec des placeholders de substitution numérotés.
3. Pour chaque placeholder, chercher l'entrée correspondante dans le tableau de substitution, vérifier son type contre le type déclaré du placeholder, et l'inliner.

Le tableau de substitution a des entrées typées : UInt32, UInt64, Boolean, GUID, FILETIME, SID, HexInt32, HexInt64, BinXML, EvtHandle, EvtXml, plus des chaînes soit en UTF-16LE inline soit par référence d'offset, plus des tableaux de tout ce qui précède. Le type 0x21 est "BinXML" ce qui signifie que la substitution est elle-même un flux BinXML imbriqué, ce qui signifie que les parsers doivent récurser. C'est là que les implémentations naïves s'effondrent.

Deux pièges à signaler :

- Les templates peuvent être référencés depuis *d'autres* enregistrements dans le même chunk par offset. Si vous construisez un parser qui résout les templates seulement quand il voit leur déclaration inline, vous manquerez des enregistrements qui référencent un template plus ancien par ID seulement.
- Le type "conditional substitution" (`0x0e`) signifie : substituer si la valeur n'est pas null, sinon omettre l'élément parent. Sauter cette distinction produit du XML qui a l'air bien mais a des éléments vides où le vrai log n'aurait rien.

## Pourquoi c'est plus difficile que parser EVT

EVT était un fichier plat d'enregistrements de forme fixe. Les chaînes étaient stockées inline. Vous pouviez écrire un parser en un après-midi.

EVTX est un format paginé, optimisé pour l'écriture, auto-déduplicant. La même chaîne ("Microsoft-Windows-Security-Auditing") est stockée une fois par chunk et référencée depuis chaque enregistrement qui l'utilise. Le même squelette XML ("un événement 4624") est stocké une fois par chunk comme template, et chaque enregistrement 4624 dans ce chunk est un tableau de substitution contre lui. L'état entre enregistrements compte. L'état entre chunks non, ce qui est la grâce salvatrice : perdez un chunk et vous perdez ses enregistrements, mais le reste du fichier est récupérable.

Cette déduplication est ce qui rend EVTX assez petit pour rester sur des hôtes occupés et ce qui rend les parsers naïfs faux. Si vous avez déjà vu un EVTX "parsé" où le champ `Provider` de chaque enregistrement dit "Unknown", vous avez vu un parser qui n'a pas résolu la table de chaînes.

## Les outils qui marchent vraiment

- `python-evtx` (Willi Ballenthin) lent, Python pur, mais l'implémentation de référence la plus propre. Lisez son code source avant d'écrire le vôtre.
- `evtx_dump` du crate Rust `evtx` d'Omer Ben-Amram rapide, robuste, le défaut pour le dump en ligne de commande. Sortie JSONL qui se pipe partout.
- `libevtx` et `evtxtools` (Joachim Metz) bibliothèque C, la référence canonique pour le format. Les bindings Python (`pyevtx`) sont plus lents que `python-evtx` sur certaines charges mais gèrent mieux les cas limites.
- `EvtxECmd` d'Eric Zimmerman .NET, haut la main le meilleur pour le travail de terrain IR à cause de son système de maps. Les maps sont des fichiers YAML qui aplatissent les substitutions EventData en colonnes nommées, ce que vous voulez pour le grep et le travail de timeline. Appariez-le avec `Timeline Explorer`.
- Le parser sur ce site basé sur le navigateur, utile quand vous ne voulez pas téléverser des données régulées à un fournisseur et que vous n'avez pas votre kit sur la machine depuis laquelle vous travaillez.

Si vous écrivez un parser à partir de zéro (ne le faites pas, mais si vous le devez), le corpus de test contre lequel valider sont les échantillons EVTX publics du repo [poster SANS DFIR](https://github.com/forensicmatt/EVTX-ETW-Resources) et les logs d'échantillon `hayabusa` de Yamato Security. Ils couvrent les cas de chunk malformé et d'enregistrement partiel sur lesquels votre code se trompera à la première passe.

L'autre chose à dire : le format est partagé avec d'autres artefacts Windows. Le même encodage FILETIME apparaît dans le [registre](https://www.registryparser.com), dans les horodatages `$STANDARD_INFORMATION` de [MFT](https://www.mftparser.com), dans les en-têtes [Prefetch](https://www.prefetchparser.com). Devenez bon à lire FILETIME de tête et beaucoup de forensique Windows devient plus silencieuse.

## Pour aller plus loin

- L'original d'Andreas Schuster ["Introducing the Microsoft Vista Event Log File Format"](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf) (DFRWS 2007). Le papier de reverse-engineering que tout cite depuis.
- La [spécification de format libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc) de Joachim Metz. Le plus proche d'une référence complète.
- Le [code source python-evtx](https://github.com/williballenthin/python-evtx) de Willi Ballenthin. Lisez `Evtx/Nodes.py` pour la hiérarchie de nœuds BinXML.
- Le [crate Rust evtx d'Omer Ben-Amram](https://github.com/omerbenamram/evtx). Le chemin rapide sur lequel la plupart de l'outillage moderne s'appuie.
