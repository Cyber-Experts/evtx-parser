---
title: "Comment ouvrir un fichier .evtx (5 méthodes, sans installation requise)"
description: "Cinq façons d'ouvrir un fichier Windows .evtx — dans votre navigateur, dans l'Observateur d'événements, avec wevtutil, EvtxECmd ou python-evtx. Choisissez selon l'OS hôte et la friction acceptable."
date: "2026-05-24"
howto:
  name: "Comment ouvrir un fichier .evtx"
  steps:
    - name: "L'ouvrir dans votre navigateur (sans installation)"
      text: "Allez sur la page d'accueil de l'analyseur EVTX, déposez votre fichier .evtx sur la zone d'envoi. Le fichier est analysé localement dans un Web Worker à l'aide d'un analyseur EVTX en Rust compilé en WebAssembly. Rien n'est envoyé — déconnectez votre réseau si vous voulez le vérifier. Fonctionne sur Windows, macOS et Linux."
    - name: "L'ouvrir dans l'Observateur d'événements (Windows uniquement)"
      text: "Lancez eventvwr.msc, choisissez Action → Ouvrir un journal enregistré…, naviguez jusqu'au fichier .evtx, nommez la vue, et cliquez sur OK. Bon pour parcourir un canal ; faible pour filtrer parmi des milliers d'enregistrements."
    - name: "Le vider avec wevtutil ou Get-WinEvent (ligne de commande Windows)"
      text: "Exécutez wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt pour exporter chaque enregistrement en texte. Depuis PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 renvoie des objets analysés que vous pouvez piper plus loin."
    - name: "L'analyser avec EvtxECmd (CLI multiplateforme)"
      text: "Téléchargez EvtxECmd depuis les outils d'Eric Zimmerman, puis exécutez EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv pour aplatir chaque enregistrement (y compris tous les champs EventData) en une ligne CSV par événement. S'exécute directement sur Windows et sur macOS/Linux via .NET."
    - name: "Le scripter avec python-evtx (Python multiplateforme)"
      text: "pip install python-evtx, puis exécutez python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml pour obtenir chaque enregistrement en XML sur stdout. Plus lent que l'analyseur Rust mais facile à intégrer dans des pipelines et des notebooks Jupyter."
---

Un fichier `.evtx` est le format binaire des journaux d'événements Windows ([ce qu'il contient →](/fr/blog/what-is-an-evtx-file)). Vous ne pouvez pas le lire avec un éditeur de texte — c'est du BinXML à l'intérieur de conteneurs binaires découpés en chunks. Ci-dessous, les cinq méthodes qui couvrent tous les cas réalistes, classées du « déposez le fichier et c'est fait » au « branchez-le dans un pipeline Python ».

## Méthode 1 — ouvrir le fichier dans votre navigateur (sans installation)

La voie la plus rapide sur n'importe quel système d'exploitation : déposez le `.evtx` sur l'analyseur de la [page d'accueil de ce site](/fr). Le fichier est chargé dans la mémoire de votre navigateur et analysé localement par un Web Worker exécutant la crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilée en WebAssembly. Rien ne quitte votre machine — vous pouvez le confirmer en vous déconnectant du réseau avant de déposer le fichier.

Vous obtenez la même vue au niveau de l'enregistrement qu'un outil de bureau : une timeline filtrable, le `<EventData>` complet aplati dans le tableau, le XML complet à un clic, et un export CSV/JSON de l'ensemble filtré. Idéal pour un triage ad hoc lorsque vous ne voulez rien installer, rien envoyer, ou que vous êtes sur une machine qui n'est pas la vôtre.

**Limites.** Les plafonds de mémoire des navigateurs font que les fichiers de plus de ~500 Mo deviennent lents. Pour des journaux archivés de plusieurs gigaoctets, repassez à un outil natif.

## Méthode 2 — Observateur d'événements (Windows uniquement, intégré)

Chaque installation de Windows est livrée avec l'Observateur d'événements. Lancez-le avec `eventvwr.msc`, puis **Action → Ouvrir un journal enregistré…** et choisissez le `.evtx`. L'Observateur d'événements vous proposera d'importer le fichier dans votre vue actuelle ; acceptez et vous pourrez le parcourir comme n'importe quel canal en direct.

```text
Action → Ouvrir un journal enregistré… → Parcourir → sélectionner .evtx → OK
```

Adapté pour : parcourir un seul fichier, regarder le message formaté lisible d'un enregistrement, copier-coller une vue XML. Faible pour : filtrer des milliers d'enregistrements (l'interface devient lente), l'export en masse, ou exécuter des requêtes que vous voulez scripter.

## Méthode 3 — wevtutil / Get-WinEvent (ligne de commande Windows)

`wevtutil` est l'outil intégré à Windows pour la gestion des journaux ; `Get-WinEvent` est son équivalent PowerShell. Tous deux fonctionnent sur des fichiers `.evtx` enregistrés, pas seulement sur les canaux en direct.

Vider chaque enregistrement d'un `.evtx` enregistré en texte :

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filtrer avec XPath (ici, chaque 4624 des 24 dernières heures) :

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell avec la même intention, mais en renvoyant des objets typés :

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Adapté pour : l'extraction scriptée, les tâches planifiées, le filtrage chirurgical. Le compromis est la verbosité — du XPath contre du XML, c'est précis mais peu convivial.

## Méthode 4 — EvtxECmd (CLI multiplateforme, le standard DFIR)

L'analyseur [`EvtxECmd` d'Eric Zimmerman](https://ericzimmerman.github.io/) est celui vers lequel se tournent par défaut la plupart des praticiens IR. Il s'exécute nativement sous Windows et sous macOS / Linux via .NET, analyse plus vite que `wevtutil`, et aplatit chaque champ `<EventData>` en une colonne CSV. Une ligne par enregistrement.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Pour traiter tout un dossier `winevt\Logs\` en une passe, avec des maps qui décodent les champs d'événements bien connus en colonnes lisibles :

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Adapté pour : l'analyse en masse de collections multi-fichiers, l'import vers un SIEM ou un notebook, le workflow analyste multiplateforme. EvtxECmd est la bonne réponse pour presque toutes les tâches « analyse-moi ça hors ligne ».

## Méthode 5 — python-evtx (le scripter dans un pipeline)

Lorsque le fichier doit alimenter un pipeline Python, [`python-evtx`](https://github.com/williballenthin/python-evtx) est l'analyseur pur Python.

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

Dans un notebook ou un script :

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Plus lent que la crate Rust (Python interprété sur des chunks binaires) mais le bon choix quand vous êtes déjà à l'intérieur d'une chaîne d'outils Python — notebooks forensiques Jupyter, jobs de threat hunting, enrichissement personnalisé.

## Quelle méthode utiliser et quand

- **Vous voulez juste regarder le fichier** : déposez-le sur [l'analyseur de la page d'accueil](/fr). Voie la plus rapide, zéro installation.
- **Vous êtes sur un endpoint Windows avec les droits admin et le fichier est petit** : Observateur d'événements.
- **Vous devez scripter une extraction ponctuelle** : `wevtutil` ou `Get-WinEvent`.
- **Vous faites du vrai DFIR sur des collections multi-canaux** : EvtxECmd.
- **Vous construisez un pipeline en Python** : `python-evtx`.

## Erreurs courantes et comment les lire

- **« The file does not appear to be valid »** dans l'Observateur d'événements signifie généralement que le chunk final est dirty (le fichier a été copié pendant que le service EventLog écrivait encore). La plupart des analyseurs gèrent cela — essayez [l'analyseur en navigateur](/fr) ou `EvtxECmd`, qui signalent tous deux les dirty chunks en avertissement et continuent.
- **« Access is denied »** depuis `wevtutil` contre un fichier dans `winevt\Logs\` correspond au service EventLog qui détient un verrou exclusif. Voir [collecter des .evtx depuis un système actif](/fr/blog/collecting-evtx-from-live-system) pour les quatre façons standard de contourner cela.
- **Sortie vide depuis `Get-WinEvent`** sur un journal enregistré : passez le fichier avec `-Path`, pas `-LogName`. `-LogName` ne lit que les canaux en direct.
- **PowerShell `Get-WinEvent` indique « No events were found that match the specified selection criteria »** — les clés de votre `-FilterHashtable` sont sensibles à la casse sur certaines propriétés. Essayez sans filtre d'abord pour confirmer que le fichier s'analyse.

Pour le contexte sur ce que contient réellement un `.evtx` et pourquoi le format est tel qu'il est, voir [Qu'est-ce qu'un fichier .evtx ?](/fr/blog/what-is-an-evtx-file).
