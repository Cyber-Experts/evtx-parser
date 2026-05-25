---
title: "Lire le format binaire du journal d'événements Windows"
description: "Un court rappel sur la structure des fichiers .evtx, ce que contient chaque événement, et pourquoi ce format binaire compte en forensique."
date: "2026-05-16"
---

Le journal d'événements Windows — `.evtx` — est le format binaire introduit par Microsoft avec Windows Vista pour remplacer l'ancien `.evt`. Il est l'épine dorsale de presque toutes les réponses à incidents Windows : connexions, démarrages de services, lignes de commande PowerShell, créations de processus Sysmon et une longue liste de canaux propres aux fournisseurs y sont sérialisés.

Vous débutez avec `.evtx` ? Commencez par [ce qu'est un fichier .evtx](/fr/blog/what-is-an-evtx-file) et [comment l'ouvrir](/fr/blog/how-to-open-an-evtx-file). La suite de ce post est l'orientation canaux et Event ID pour les analystes déjà à l'aise avec le format.

## Comment un fichier est structuré

Tout fichier `.evtx` commence par un en-tête de 4 Ko (signature `ElfFile\0`, somme de contrôle, nombre de blocs), suivi d'une suite de blocs de 64 Ko. Chaque bloc possède son propre en-tête (`ElfChnk`), une table de modèles XML utilisés dans le bloc, et un flux d'enregistrements binaires qui référencent ces modèles par ID. L'analyseur reconstruit chaque événement en liant les emplacements des modèles aux valeurs présentes dans chaque enregistrement.

## À quoi ressemble un enregistrement

Une fois décodé, chaque enregistrement est un document XML composé de deux blocs principaux :

- `<System>` — nom du fournisseur, canal, ID d'événement, niveau (1 Critique → 5 Détaillé), nom de l'ordinateur, contexte de sécurité et horodatage UTC de l'écriture.
- `<EventData>` — paramètres propres au fournisseur : compte cible d'une connexion, chemin d'image d'une création de processus, etc.

L'ID d'événement seul suffit rarement au triage ; c'est dans la charge utile `<EventData>` que se trouve le signal forensique.

## Comment cet outil le lit

L'analyseur est le crate Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx), compilé en WebAssembly et chargé dans un Web Worker. Quand vous déposez un fichier, le worker le charge en mémoire, parcourt chaque bloc et reconstitue le XML de chaque enregistrement. Rien ne transite par le réseau — coupez votre wifi pour le vérifier.
