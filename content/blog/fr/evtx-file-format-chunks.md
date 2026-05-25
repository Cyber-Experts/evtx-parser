---
title: "Format de fichier EVTX expliqué : chunks, templates et internals BinXML"
description: "Comment un fichier .evtx est agencé au niveau octet — en-tête de fichier, chunks de 64 Ko, table de templates et flux d'enregistrements BinXML qui la référence."
date: "2026-05-17"
---

Le [format Windows Event Log — `.evtx`](/fr/blog/what-is-an-evtx-file) — a été introduit avec Windows Vista pour remplacer le `.evt` orienté ligne. C'est un conteneur binaire, append-only, par chunks, conçu pour être écrit par un seul processus (le service EventLog) et tourné ou scellé une fois plein. Comprendre son agencement rend beaucoup plus simples les cas de récupération forensique — fichiers partiels, chunks sales, carving.

## En-tête de fichier

Tout `.evtx` commence par un en-tête de 4 Ko (magic `ElfFile\0\0`, version, nombre de chunks, indices du chunk le plus ancien/courant, et un CRC32). L'en-tête est réécrit en place chaque fois que le fichier est tourné ou qu'un chunk est scellé, ce qui rend ses flags `Dirty` et `Full` des indices utiles : un fichier avec `Dirty` posé était ouvert quand l'hôte a planté ou que l'image disque a été acquise à chaud.

Après l'en-tête vient une séquence de chunks de taille fixe.

## Chunks (64 Ko)

Chaque chunk fait exactement 64 Ko et possède son propre en-tête de 512 octets (magic `ElfChnk\0`, IDs d'enregistrements log du premier et dernier enregistrement du chunk, offsets de fichier, deux CRC32 — un pour l'en-tête, un pour les données d'enregistrement). Les chunks sont indépendants : vous pouvez carver un chunk hors de l'espace non alloué et le parser sans le reste du fichier. C'est ce qui rend EVTX récupérable depuis des fragments disque.

À l'intérieur d'un chunk :

- **Table de chaînes** — chaînes internées dans ce chunk, référencées par offset.
- **Table de templates** — templates XML utilisés par les enregistrements de ce chunk, également indexés par offset.
- **Enregistrements** — un flux d'enregistrements BinXML, chacun référençant un template plus des valeurs de substitution par enregistrement.

## BinXML et templates

Les enregistrements EVTX ne sont pas stockés en XML texte. Ils sont stockés en **BinXML**, une représentation binaire tokenisée d'un document XML. Pour économiser l'espace, le squelette structurel (noms d'éléments, noms d'attributs, forme de l'arbre) est factorisé dans un **template** stocké une seule fois dans la table de templates du chunk. Chaque enregistrement dit alors « utilise le template ID 5, avec les valeurs [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`] ».

Pour reconstruire le XML d'un enregistrement, un parseur :

1. Lit le flux de tokens de l'enregistrement.
2. Cherche le template par ID dans la table de templates du chunk.
3. Substitue les valeurs par-enregistrement dans les positions de placeholder du template.
4. Émet le XML résultant.

C'est pour cela que les [parseurs](/fr/blog/how-to-open-an-evtx-file) (y compris celui qui anime cette page, [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx)) doivent tracer le contexte chunk-local — les IDs de template ne sont pas globaux à travers le fichier.

## Chunks scellés vs sales

Quand le service EventLog finit d'écrire un chunk et passe au suivant, il calcule et écrit le CRC32 du chunk et marque l'en-tête du chunk `Full`. Un fichier propre a chaque chunk dans cet état sauf le dernier.

Un chunk `Dirty` — date de dernière modification postérieure à la dernière mise à jour de l'en-tête de fichier — est la queue active. Il est souvent parseable, mais les outils refusent parfois de le lire parce que le flux d'enregistrements peut se terminer en plein milieu d'un token. Pour la forensique, cela compte : un attaquant qui a acquis un hôte en pleine écriture verra un dernier chunk sale, et le comportement de votre parseur sur ce chunk doit être connu (saute-t-il, lève-t-il une erreur, récupère-t-il ce qu'il peut ?).

## Implications pratiques pour le parsing

- Un `.evtx` tronqué — fréquent quand vous [collectez depuis un hôte actif](/fr/blog/collecting-evtx-from-live-system) — reste souvent largement récupérable, parce que chaque chunk complet est indépendant.
- Les chunks carvés depuis l'espace non alloué peuvent être enveloppés d'un en-tête de fichier synthétique et parsés.
- Un échec de parsing d'un chunk ne signifie pas l'échec du fichier — les parseurs robustes passent au chunk suivant.
- Le CRC32 du chunk est ce qui flag le tampering : un enregistrement modifié qui ne recalcule pas le CRC est détectable.
