---
title: "Format de fichier EVTX expliqué : chunks, templates et internes BinXML"
description: "Comment un fichier .evtx est disposé au niveau octet : en-tête de fichier, chunks de 64 Ko, la table de templates, et le flux d'enregistrements BinXML qui la référence."
date: "2026-05-17"
---

Le [format de journal d'événements Windows `.evtx`](/en/blog/what-is-an-evtx-file) est livré avec Vista pour remplacer le `.evt` orienté ligne. C'est un container binaire, append-only, en chunks écrit par un seul processus (le service EventLog) et roté quand plein. La plupart des analystes n'ont jamais besoin de savoir comment il est disposé au niveau octet. Ceux qui carvent des enregistrements depuis de l'espace non alloué, parsent à la main des chunks endommagés, ou se disputent avec un parser qui refuse de lire un fichier tronqué très bien si.

Ce billet est la version pratique. Assez d'internes pour déboguer un parse cassé, pas tant que vous finissiez par écrire votre propre parser à partir de zéro.

## En-tête de fichier

Tout `.evtx` commence par un en-tête de 4 Ko. La magie est `ElfFile\0\0`. Les champs qui comptent pour un enquêteur sont version, nombre de chunks, indices de chunk le plus ancien et actuel, et un CRC32 sur l'en-tête lui-même. L'en-tête est réécrit en place chaque fois que le fichier tourne ou qu'un chunk est scellé, donc ses flags `Dirty` et `Full` sont des indices utiles. Un fichier avec `Dirty` mis était ouvert quand l'hôte a crashé ou quand l'image disque a été acquise en direct.

Après l'en-tête vient une séquence de chunks de taille fixe.

## Chunks : 64 Ko chacun

Chaque chunk fait exactement 65 536 octets et a son propre en-tête de 512 octets. La magie du chunk est `ElfChnk\0`. L'en-tête porte les IDs d'enregistrement de log du premier et dernier enregistrement dans le chunk, les offsets de fichier, et deux CRC32 : un sur l'en-tête, un sur les données d'enregistrement.

Les chunks sont indépendants. Vous pouvez carver un chunk depuis l'espace non alloué et le parser sans le reste du fichier. C'est ce qui rend EVTX [récupérable depuis des fragments de disque](/en/blog/carve-deleted-evtx-records), et c'est aussi ce qui rend le format plus amical pour l'outillage forensique que quelque chose qui compressait à travers tout le fichier.

À l'intérieur d'un chunk :

- **String table.** Chaînes internées dans ce chunk, référencées par offset.
- **Template table.** Templates XML utilisés par les enregistrements dans ce chunk, aussi indexés par offset.
- **Enregistrements.** Un flux d'enregistrements BinXML, chacun référençant un template plus des valeurs de substitution par enregistrement.

## BinXML et templates

Les enregistrements EVTX ne sont pas stockés comme texte XML. Ils sont stockés en **BinXML**, une représentation binaire tokenisée d'un document XML. Pour économiser de l'espace, le squelette structurel (noms d'éléments, noms d'attributs, forme d'arbre) est factorisé dans un **template** stocké une fois dans la table de templates du chunk. Chaque enregistrement dit ensuite "utilise le template ID 5, avec les valeurs [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

Pour reconstruire le XML pour un enregistrement, un parser :

1. Lit le flux de tokens de l'enregistrement.
2. Cherche le template par ID dans la table de templates du chunk.
3. Substitue les valeurs par enregistrement aux positions de placeholder du template.
4. Émet le XML résultant.

C'est pourquoi les parsers (le [parser navigateur sur ce site](/en/blog/how-to-open-an-evtx-file), le crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) qu'il enveloppe, et python-evtx partagent tous cette exigence) doivent tracker le contexte chunk-local. Les IDs de template ne sont pas globaux à travers le fichier. Deux chunks peuvent avoir des tables de templates entièrement différentes ; le même numéro d'ID de template signifie des choses différentes dans chacun.

C'est aussi la raison la plus commune pour laquelle les analystes voient du "XML poubelle" quand ils essaient de décoder à la main un enregistrement qu'ils ont sorti avec `xxd`. Sans la table de templates, les valeurs de substitution ne sont qu'un sac de valeurs typées sans schéma.

## Chunks scellés versus dirty

Quand le service EventLog finit d'écrire un chunk et passe au suivant, il calcule et écrit le CRC32 du chunk et marque l'en-tête du chunk `Full`. Un fichier propre a chaque chunk dans cet état sauf le dernier.

Un chunk `Dirty` (dernière modification après la dernière mise à jour de l'en-tête de fichier) est la queue vivante. Il est souvent parsable, mais les outils refusent parfois de le lire parce que le flux d'enregistrement peut se terminer au milieu d'un token. Pour la forensique ça compte : un bundle [collecté depuis un hôte vivant](/en/blog/collecting-evtx-from-live-system) aura un chunk de queue dirty sur le canal actif, et le comportement de votre parser sur ce chunk doit être connu. Saute-t-il le chunk, erreur-t-il sur le fichier, ou récupère-t-il ce qu'il peut ?

EvtxECmd, hayabusa, et python-evtx récupèrent tous des chunks dirty avec une tolérance variable. Event Viewer natif est le plus strict et refuse le fichier complètement plus souvent que les autres.

## Implications pratiques

- Un `.evtx` tronqué, courant quand vous [collectez depuis un hôte vivant](/en/blog/collecting-evtx-from-live-system), est souvent largement récupérable. Chaque chunk complet est indépendant.
- Les chunks carvés depuis du non alloué peuvent être enveloppés avec un en-tête de fichier synthétique et parsés. C'est comme ça que libevtx et python-evtx récupèrent depuis `pagefile.sys` (voir [parser pagefile](https://www.pagefilesysparser.com)) et les sweeps de carving de [dump RAM](https://www.ramparser.com).
- Un échec de parse d'un chunk ne signifie pas l'échec du fichier. Les parsers robustes passent au chunk suivant et signalent le mauvais séparément.
- Le CRC32 du chunk est ce qui signale la falsification. Un enregistrement modifié qui ne recalcule pas le CRC est détectable. La plupart des attaquants ne s'embêtent pas parce qu'effacer le log (déclencher [1102](/en/blog/event-id-1102-cleared-log)) est le chemin plus facile. Les soigneux utilisent Phant0m, qui laisse le fichier complètement tranquille.

## Pour aller plus loin

- [Andreas Schuster : Introducing the Microsoft Vista Event Log File Format](https://digital-forensics.sans.org/blog/2008/05/01/the-windows-vista-event-log-file-format) (travail de reverse-engineering original)
- [Documentation libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc) (la spec de format la plus complète existante)
- [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (parser Rust, la build WASM alimente le parser navigateur sur ce site)
