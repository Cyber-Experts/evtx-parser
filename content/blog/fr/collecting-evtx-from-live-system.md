---
title: "Comment collecter les journaux .evtx d'un système Windows vivant (4 méthodes)"
description: "Quatre façons de récupérer du .evtx depuis un hôte Windows vivant : wevtutil, FTK Imager, KAPE, NTFS brut. Avec les compromis de chaîne de garde de chacune et les commandes que vous lancerez vraiment."
date: "2026-05-17"
howto:
  name: "Comment collecter les journaux .evtx d'un système Windows vivant"
  steps:
    - name: "Exporter avec wevtutil"
      text: "Lancez wevtutil epl Security C:\\triage\\Security.evtx en administrateur pour sceller une copie portable du canal Security actif sans prendre le fichier vivant."
    - name: "Acquérir avec FTK Imager"
      text: "Ouvrez FTK Imager, Add Evidence Item, naviguez jusqu'à \\Windows\\System32\\winevt\\Logs\\, sélectionnez les fichiers de canal (y compris les *.evtx archivés) et Export Files. FTK lit NTFS directement, contournant les verrous de fichier du service EventLog."
    - name: "Collecte en masse avec KAPE"
      text: "Lancez kape.exe --tsource C: --target EventLogs --tdest C:\\triage pour tirer tous les .evtx sous winevt\\Logs\\ en un passage, avec métadonnées de chaîne de garde. Associez avec le module EvtxECmd pour parser à la collecte."
    - name: "Lecture NTFS brute"
      text: "Quand une altération est suspectée, utilisez RawCopy ou tsk_recover pour ouvrir le volume sous la couche système de fichiers (\\\\.\\PhysicalDriveN ou \\\\.\\C:) et lire chaque .evtx octet par octet depuis la MFT. Le service EventLog ne peut pas bloquer ce chemin."
---

Le premier problème difficile sur une mission journaux d'événements n'est pas le parsing. C'est de récupérer les fichiers de l'hôte sans que le service EventLog ne vous tape sur les doigts. Sur une machine Windows en marche, le service tient des handles ouverts sur les [fichiers `.evtx`](/fr/blog/what-is-an-evtx-file) actifs dans `C:\Windows\System32\winevt\Logs\`, donc un `copy` naïf renvoie des erreurs de violation de partage. Quatre méthodes couvrent presque tous les cas que j'ai croisés.

## wevtutil et Get-WinEvent : intégrés, les plus rapides

Le chemin le moins coûteux utilise l'API documentée par Microsoft :

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Cela produit un `.evtx` scellé contenant chaque enregistrement actuellement dans le canal. Pas d'outillage tiers, shell administrateur requis. Le bémol qui mérite d'être dit à haute voix : `epl` ne capture que le journal actif. Les fichiers `Archive-Security-*.evtx` ayant subi rotation dans le même répertoire sont laissés derrière. Si la rotation est récente et que les enregistrements voulus sont dans une archive, cette méthode les manque.

PowerShell fait des enregistrements parsés à la place :

```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Security.evtx |
  Export-Csv triage.csv -NoTypeInformation
```

Cela vous donne un CSV, pas un `.evtx`. Pratique pour un triage ad hoc sur la machine. Inutile pour [la récupération niveau chunk, l'inspection de dirty chunks ou le carving depuis l'espace non alloué](/fr/blog/evtx-file-format-chunks), parce que vous avez jeté la fidélité binaire.

## FTK Imager : acquisition niveau NTFS

Quand vous voulez le fichier, pas les enregistrements, FTK Imager est le cheval de trait. Ajoutez le disque vivant comme preuve (Physical Drive ou Logical Drive), naviguez jusqu'à `\Windows\System32\winevt\Logs\`, clic droit sur les fichiers de canal et Export Files. FTK lit les structures NTFS sous-jacentes directement, ce qui esquive le verrou du système de fichiers que tient le service EventLog. Il capture aussi les fichiers `Archive-*.evtx` archivés que `wevtutil epl` saute.

Compromis : FTK lit des fichiers qui peuvent être en cours d'écriture. Le chunk de queue sur le canal actif peut être dirty. La plupart des parsers gèrent ça gracieusement (y compris le [parser navigateur de ce site](/fr/blog/how-to-open-an-evtx-file)) mais vérifiez sur l'établi avant de l'écrire dans un rapport. Les entrées correspondantes du [journal USN](https://www.usnparser.com) sont une corroboration utile quand vous soupçonnez le service EventLog d'avoir fait quelque chose de non standard durant l'acquisition.

## KAPE : collecte en masse à vitesse IR

Quand la mission a plus d'un hôte, le Kroll Artifact Parser and Extractor se rembourse en une heure.

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

Le target `EventLogs` balaie tous les `.evtx` sous `winevt\Logs\` (plus les anciens `.evt` et les copies sous `Windows.old`). Associez avec le module `!EZParser` ou `EvtxECmd` et KAPE lancera aussi EvtxECmd contre la collecte en sortant, vous donnant des CSV parsés à côté de la preuve brute. Tant que vous y êtes, les targets `RegistryHives`, `FileSystem` et `Prefetch` ramassent les données [registre](https://www.registryparser.com), [MFT](https://www.mftparser.com), [journal USN](https://www.usnparser.com) et [prefetch](https://www.prefetchparser.com) que vous voudrez de toute façon.

La sortie de KAPE arrive avec des métadonnées de copy log. Cela compte pour la chaîne de garde plus que les gens ne lui en accordent.

## Lecture NTFS brute : quand vous soupçonnez une altération

Pour une fidélité maximale, plongez sous la couche système de fichiers. Les `tsk_recover` et `icat` du Sleuth Kit, ou le `RawCopy.exe` de Joakim Schicht, ouvrent le volume via `\\.\PhysicalDriveN` ou `\\.\C:`, parcourent la MFT et émettent le contenu du fichier octet par octet. Le service EventLog ne peut pas bloquer ça parce que la lecture ne passe pas par l'API fichier Win32.

Utilisez ceci quand un rootkit est dans le périmètre, quand vous avez de bonnes raisons de penser qu'un pilote filtre noyau intercepte les lectures de `\winevt\Logs\`, ou quand simplement vous ne faites pas confiance à l'OS en marche. Associez le résultat à un [dump RAM](https://www.ramparser.com) pris au même moment. Le service event log cache les enregistrements récents en mémoire, et un snapshot pris quelques minutes avant l'altération contient parfois des enregistrements qui ne sont jamais arrivés sur le disque.

## Lequel quand

- Un hôte, vous avez admin, vous avez une heure : `wevtutil epl` pour chaque canal qui compte, zippez le répertoire, terminé.
- Image disque déjà en main : FTK Imager ou `tsk_recover` contre l'image. Plus rapide que l'hôte vivant, et vous n'avez pas à vous coordonner avec le SOC.
- Plusieurs hôtes, vraie mission IR : KAPE. Rien d'autre ne s'en rapproche en débit.
- Altération vivante ou rootkit soupçonnés : RawCopy ou TSK contre le volume, hôte isolé du réseau.

Quel que soit votre choix, documentez-le. Les CSV parsés ne disent rien sur la provenance. Une ligne dans les notes du dossier qui dit `KAPE 1.3.0.2 EventLogs target, hash file attached` fait la différence entre une pièce à conviction et une opinion.

## Pour aller plus loin

- [Documentation KAPE](https://ericzimmerman.github.io/KapeDocs/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)
