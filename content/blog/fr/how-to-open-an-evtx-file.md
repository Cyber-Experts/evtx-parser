---
title: "Comment ouvrir un fichier .evtx (5 méthodes, sans installation requise)"
description: "Cinq façons d'ouvrir un fichier .evtx Windows : dans votre navigateur, dans Event Viewer, avec wevtutil, avec EvtxECmd ou avec python-evtx. Choisissez selon l'OS de l'hôte et la friction que vous tolérez."
date: "2026-05-24"
howto:
  name: "Comment ouvrir un fichier .evtx"
  steps:
    - name: "Ouvrez-le dans votre navigateur (sans installation)"
      text: "Allez sur la page d'accueil du parser EVTX, déposez votre fichier .evtx sur la zone d'upload. Le fichier est parsé localement dans un Web Worker utilisant un parser EVTX Rust compilé en WebAssembly. Rien n'est uploadé. Fonctionne sur Windows, macOS et Linux."
    - name: "Ouvrez-le dans Event Viewer (Windows uniquement)"
      text: "Lancez eventvwr.msc, choisissez Action puis Ouvrir le journal enregistré, parcourez jusqu'au fichier .evtx, nommez la vue et cliquez OK. Bon pour parcourir un canal ; faible pour filtrer à travers des milliers d'enregistrements."
    - name: "Faites-en le dump avec wevtutil ou Get-WinEvent (ligne de commande Windows)"
      text: "Exécutez wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt pour exporter chaque enregistrement comme texte. Depuis PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 retourne des objets parsés que vous pouvez piper plus loin."
    - name: "Parsez-le avec EvtxECmd (CLI multi-plateforme)"
      text: "Téléchargez EvtxECmd depuis les outils d'Eric Zimmerman, puis exécutez EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv pour aplatir chaque enregistrement (y compris tous les champs EventData) en une ligne CSV par événement."
    - name: "Scriptez-le avec python-evtx (Python multi-plateforme)"
      text: "pip install python-evtx, puis exécutez python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml pour obtenir chaque enregistrement comme XML sur stdout. Plus lent que le parser Rust mais facile à intégrer dans des pipelines et notebooks Jupyter."
---

Un fichier `.evtx` est le format binaire du journal d'événements Windows ([ce qu'il y a dedans](/en/blog/what-is-an-evtx-file)). Vous ne pouvez pas le lire avec un éditeur de texte. C'est du BinXML dans des conteneurs binaires en chunks. Il existe cinq méthodes qui couvrent tout cas réaliste, dans un ordre approximatif de "déposez le fichier et c'est fini" à "câblez-le dans un pipeline Python".

## Méthode 1 : ouvrez-le dans votre navigateur, sans installation

Le chemin le plus rapide sur n'importe quel système d'exploitation. Déposez le `.evtx` sur le parser de la [page d'accueil de ce site](/en). Le fichier est lu dans la mémoire de votre navigateur et parsé localement par un Web Worker exécutant le crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilé en WebAssembly. Rien ne quitte votre machine. Confirmez en vous déconnectant du réseau avant de déposer le fichier.

Vous obtenez la même vue au niveau de l'enregistrement qu'un outil de bureau produit : timeline filtrable, `<EventData>` complet aplati dans la table, XML complet à un clic, export CSV/JSON du set filtré. Bon pour le triage ad-hoc quand vous ne voulez rien installer, ne voulez rien uploader, ou êtes sur une machine qui n'est pas la vôtre.

Contrainte. Les plafonds de mémoire du navigateur signifient que les fichiers plus grands que ~500 Mo deviennent lents. Pour des logs archivés de plusieurs gigaoctets, descendez à un outil natif.

## Méthode 2 : Event Viewer, Windows uniquement, intégré

Chaque installation Windows livre Event Viewer. Lancez `eventvwr.msc`, puis **Action / Ouvrir le journal enregistré** et choisissez le `.evtx`. Event Viewer propose d'importer le fichier dans votre vue actuelle. Acceptez et vous pouvez le parcourir comme n'importe quel canal en direct.

```text
Action -> Ouvrir le journal enregistré -> Parcourir -> sélectionner .evtx -> OK
```

Bon pour parcourir un seul fichier, regarder le message formaté convivialement d'un enregistrement, copier-coller une vue XML. Faible pour filtrer des milliers d'enregistrements (l'UI ralentit), pour l'export en masse, ou pour lancer des requêtes que vous voulez scripter. Aussi le plus strict sur les trailing chunks dirty : il refusera des fichiers que d'autres outils acceptent.

## Méthode 3 : wevtutil et Get-WinEvent, ligne de commande Windows

`wevtutil` est l'intégré Windows pour la gestion de logs. `Get-WinEvent` est sa contrepartie PowerShell. Les deux fonctionnent sur des fichiers `.evtx` enregistrés, pas seulement sur des canaux en direct.

Dumper chaque enregistrement d'un `.evtx` enregistré en texte :

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filtrer avec XPath. Chaque 4624 dans les dernières 24 heures :

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell avec la même intention, mais retournant des objets typés :

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Bon pour l'extraction scriptée, les jobs planifiés, le filtrage chirurgical. Le compromis est la verbosité. XPath contre XML est précis mais pas convivial.

## Méthode 4 : EvtxECmd, le standard DFIR

L'[`EvtxECmd` d'Eric Zimmerman](https://ericzimmerman.github.io/) est le parser auquel la plupart des praticiens IR se réfèrent par défaut. Il tourne nativement sur Windows et sur macOS / Linux sous .NET. Il parse plus vite que `wevtutil` et aplatit chaque champ `<EventData>` en une colonne CSV. Une ligne par enregistrement.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Pour un dossier `winevt\Logs\` entier en une passe, avec des maps qui décodent les champs d'événements connus en colonnes conviviales :

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Adéquat pour le parse en masse de collections multi-fichiers, l'importation vers un SIEM ou notebook, le workflow d'analyste multi-plateforme. EvtxECmd est la bonne réponse pour presque chaque tâche de "parsez ceci hors ligne". Appariez-le avec la target `EventLogs` de KAPE et vous avez une engagement à une commande.

## Méthode 5 : python-evtx, scriptez-le dans un pipeline

Quand le fichier doit alimenter un pipeline Python, [`python-evtx`](https://github.com/williballenthin/python-evtx) est le parser Python pur.

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

Dans un notebook ou script :

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Plus lent que le crate Rust (Python interprété sur des chunks binaires) mais le bon appel quand vous êtes déjà dans une toolchain Python : notebooks forensiques Jupyter, jobs de threat-hunting, enrichissement personnalisé, joindre les données EVTX aux artefacts [registre](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN](https://www.usnparser.com), ou [prefetch](https://www.prefetchparser.com) du même cas.

## Quelle méthode utiliser quand

- Vous voulez juste regarder le fichier : déposez-le sur le [parser de la page d'accueil](/en). Le plus rapide, zéro installation.
- Endpoint Windows avec admin et le fichier est petit : Event Viewer.
- Extraction one-shot scriptée : `wevtutil` ou `Get-WinEvent`.
- Vraie DFIR sur des collections multi-canaux : EvtxECmd.
- Construire un pipeline en Python : `python-evtx`.

## Erreurs courantes et comment les lire

- "Le fichier ne semble pas valide" dans Event Viewer signifie presque toujours que le chunk de queue est dirty (le fichier a été copié pendant que le service EventLog écrivait encore). La plupart des parsers gèrent ça. Essayez [le parser navigateur](/en) ou `EvtxECmd`, qui signalent tous deux les chunks dirty comme avertissement et continuent.
- "Accès refusé" de `wevtutil` contre un fichier dans `winevt\Logs\` est le service EventLog qui tient un verrou exclusif. Voir [collecter .evtx d'un système vivant](/en/blog/collecting-evtx-from-live-system) pour les quatre façons standard de le contourner.
- Sortie vide de `Get-WinEvent` sur un log enregistré. Passez le fichier avec `-Path`, pas `-LogName`. `-LogName` ne lit que les canaux en direct.
- PowerShell `Get-WinEvent` dit "Aucun événement n'a été trouvé correspondant aux critères de sélection spécifiés". Vos clés `-FilterHashtable` sont sensibles à la casse sur certaines propriétés. Essayez sans le filtre d'abord pour confirmer que le fichier parse.

Pour du fond sur ce qu'il y a réellement dans un `.evtx` et pourquoi le format ressemble à ce qu'il est, voir [le deep dive au niveau du chunk](/en/blog/evtx-file-format-chunks).

## Pour aller plus loin

- [Les outils d'Eric Zimmerman](https://ericzimmerman.github.io/)
- [omerbenamram/evtx (Rust)](https://github.com/omerbenamram/evtx)
- [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx)
