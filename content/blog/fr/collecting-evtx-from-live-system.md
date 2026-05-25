---
title: "Comment collecter les logs .evtx d'un système Windows actif (4 méthodes)"
description: "Quatre façons d'extraire des .evtx d'un hôte Windows actif — wevtutil, FTK Imager, KAPE, NTFS brut — avec les compromis de chaîne de possession et les commandes à utiliser."
date: "2026-05-17"
howto:
  name: "Comment collecter les logs .evtx d'un système Windows actif"
  steps:
    - name: "Exporter avec wevtutil"
      text: "Exécutez wevtutil epl Security C:\\triage\\Security.evtx en administrateur pour figer une copie portable du canal Security actif sans toucher au fichier en cours d'écriture."
    - name: "Acquérir avec FTK Imager"
      text: "Ouvrez FTK Imager, Add Evidence Item → Physical or Logical Drive, naviguez jusqu'à \\Windows\\System32\\winevt\\Logs\\, sélectionnez les fichiers de canal (y compris les *.evtx archivés) puis Export Files. FTK lit NTFS directement et contourne les verrous du service EventLog."
    - name: "Collecte en masse avec KAPE"
      text: "Exécutez kape.exe --tsource C: --target EventLogs --tdest C:\\triage pour récupérer en une passe tous les .evtx sous winevt\\Logs\\, avec les métadonnées de chaîne de possession. Combinez-le avec le module WindowsEventLogs pour parser à la collecte."
    - name: "Lecture NTFS brute"
      text: "En cas de soupçon d'altération, utilisez RawCopy ou tsk_recover pour ouvrir le volume sous la couche système de fichiers (\\\\.\\PhysicalDriveN ou \\\\.\\C:) et lire chaque .evtx octet par octet depuis la MFT. Le service EventLog ne peut pas bloquer cette voie."
---

Le premier vrai problème d'une enquête sur les journaux d'événements n'est pas le parsing, c'est *obtenir les fichiers*. Sur un hôte Windows actif, le service EventLog conserve des handles ouverts sur les [`.evtx` actifs](/fr/blog/what-is-an-evtx-file) situés dans `C:\Windows\System32\winevt\Logs\`, ce qui signifie qu'un `copy` naïf échoue. Quatre approches couvrent presque tous les cas.

## Intégré : wevtutil / Get-WinEvent

La méthode la plus simple exporte les enregistrements (pas le fichier) via l'API documentée :

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Cela produit un `.evtx` scellé contenant tous les enregistrements actuellement présents dans le journal. Rapide, sans outil tiers, à exécuter en administrateur. Inconvénient : il ne capture pas les `.evtx` archivés (faits l'objet d'une rotation), seulement l'actif.

Équivalent PowerShell :

```powershell
Get-WinEvent -LogName Security |
  Export-Csv triage.csv
```

`Get-WinEvent` renvoie des enregistrements parsés, pas le fichier. Utile pour un CSV de triage rapide, mais on perd la fidélité binaire nécessaire à une investigation plus profonde — [récupération au niveau chunk, inspection des chunks sales, carving](/fr/blog/evtx-file-format-chunks).

## FTK Imager

Pour une acquisition complète au niveau disque ou système de fichiers, FTK Imager est le standard. Ajoutez le disque actif comme preuve (Physical Drive ou Logical Drive), naviguez jusqu'à `\Windows\System32\winevt\Logs\`, clic droit sur les fichiers de canal, puis Export Files. FTK lit directement les structures NTFS sous-jacentes, en contournant le verrou que pose le service EventLog. Il exporte aussi les `*.evtx` archivés (ceux avec un horodatage dans le nom) que `wevtutil` ne touche pas.

Le compromis : FTK lit des fichiers qui peuvent être en cours d'écriture — le `.evtx` résultant peut avoir un dernier chunk sale. La plupart des parseurs ([y compris celui-ci](/fr/blog/how-to-open-an-evtx-file)) gèrent cela proprement, mais cela mérite vérification.

## KAPE

Pour la réponse à incident à grande échelle, le Kroll Artifact Parser and Extractor (KAPE) automatise la collecte de tous les fichiers pertinents en une seule passe :

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

Le target `EventLogs` extrait tous les `.evtx` sous `winevt\Logs\` ainsi que les fichiers de traçage d'événements liés. Couplez-le au module `WindowsEventLogs` pour exécuter un parsing immédiat et produire un CSV à côté des fichiers bruts. Recommandé pour toute mission IR touchant plus d'un hôte.

## Lecture NTFS brute

Pour une fidélité maximale — utile quand vous suspectez que les API du système de fichiers sont interceptées ou voulez une acquisition bit-à-bit — lisez le volume sous la couche système de fichiers. Des outils comme [The Sleuth Kit](https://www.sleuthkit.org/) (`tsk_recover`, `icat`) ou `RawCopy.exe` d'Eric Zimmerman ouvrent le volume via `\\.\PhysicalDriveN` ou `\\.\C:`, parcourent la MFT et émettent le contenu du fichier octet par octet. Le service EventLog ne peut pas bloquer ça parce que la lecture contourne entièrement la couche système de fichiers.

## Laquelle utiliser quand

- **Triage rapide sur un hôte, avec droits admin** : `wevtutil`.
- **Acquisition forensique complète, vous disposez déjà d'une image disque** : FTK Imager ou `tsk_recover` contre l'image.
- **Mission IR, plusieurs hôtes** : KAPE.
- **Suspicion de rootkit ou de tampering actif** : NTFS brut via RawCopy ou TSK sur le volume actif, avec l'hôte isolé du réseau.

Quel que soit votre choix, documentez-le. La chaîne de provenance compte dans les rapports d'incident — un CSV parsé ne dit rien sur le fait qu'il provient d'un hôte actif avec le service EventLog en marche ou d'une image scellée.
