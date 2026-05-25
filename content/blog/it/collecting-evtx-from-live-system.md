---
title: "Come raccogliere log .evtx da un sistema Windows attivo (4 metodi)"
description: "Quattro modi per estrarre file .evtx da un host Windows attivo — wevtutil, FTK Imager, KAPE, lettura NTFS raw — con i compromessi sulla chain-of-custody e i comandi che userai davvero."
date: "2026-05-17"
howto:
  name: "Come raccogliere log .evtx da un sistema Windows attivo"
  steps:
    - name: "Esportare con wevtutil"
      text: "Esegui wevtutil epl Security C:\\triage\\Security.evtx come amministratore per sigillare una copia portatile del canale Security attivo senza toccare il file in uso."
    - name: "Acquisire con FTK Imager"
      text: "Apri FTK Imager, Add Evidence Item → Physical or Logical Drive, vai a \\Windows\\System32\\winevt\\Logs\\, seleziona i file di canale (compresi gli *.evtx archiviati) e Export Files. FTK legge NTFS direttamente e bypassa i lock del servizio EventLog."
    - name: "Raccolta massiva con KAPE"
      text: "Esegui kape.exe --tsource C: --target EventLogs --tdest C:\\triage per estrarre in un'unica passata tutti i .evtx sotto winevt\\Logs\\ con i metadati di chain-of-custody. Abbinalo al modulo WindowsEventLogs per parsare durante la raccolta."
    - name: "Lettura NTFS raw"
      text: "Quando si sospetta manomissione, usa RawCopy o tsk_recover per aprire il volume sotto il livello del file system (\\\\.\\PhysicalDriveN o \\\\.\\C:) e leggere ogni .evtx byte per byte dalla MFT. Il servizio EventLog non può bloccare questa via."
---

Il primo problema serio in un'indagine sui log eventi non è il parsing, è *ottenere i file*. Su un host Windows attivo il servizio EventLog mantiene handle aperti sui [file `.evtx`](/it/blog/what-is-an-evtx-file) attivi in `C:\Windows\System32\winevt\Logs\`, il che significa che una `copy` ingenua fallisce. Quattro approcci coprono quasi tutti i casi.

## Built-in: wevtutil / Get-WinEvent

Il metodo più semplice esporta i record (non il file) tramite l'API documentata:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Produce un `.evtx` sigillato che contiene tutti i record attualmente nel log. Veloce, non richiede tool di terze parti e si esegue da amministratore. Il rovescio: non cattura i `.evtx` archiviati (ruotati), solo quello attivo.

Equivalente PowerShell:

```powershell
Get-WinEvent -LogName Security |
  Export-Csv triage.csv
```

`Get-WinEvent` restituisce record già parsati, non il file. Utile per un CSV di triage veloce ma perde la fedeltà binaria necessaria per analisi forensi più approfondite — [recupero a livello di chunk, ispezione dei chunk dirty, carving](/it/blog/evtx-file-format-chunks).

## FTK Imager

Per l'acquisizione a livello di disco o filesystem, FTK Imager è lo standard. Aggiungi il drive attivo come evidence (Physical Drive o Logical Drive), naviga fino a `\Windows\System32\winevt\Logs\`, fai clic destro sui file del canale e seleziona Export Files. FTK legge direttamente le strutture NTFS sottostanti, bypassando il lock a livello di filesystem che il servizio EventLog detiene. Esporta anche i file `*.evtx` archiviati (quelli con timestamp nel nome) che `wevtutil` non tocca.

Il compromesso è che FTK legge file che potrebbero essere in fase di scrittura — l'`.evtx` risultante può avere un chunk dirty in coda. La maggior parte dei parser ([incluso questo](/it/blog/how-to-open-an-evtx-file)) li gestisce con grazia, ma vale la pena verificarlo.

## KAPE

Per la risposta agli incidenti su larga scala, il Kroll Artifact Parser and Extractor (KAPE) automatizza la raccolta di ogni file forensicamente rilevante in un singolo passaggio:

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

Il target `EventLogs` estrae ogni `.evtx` sotto `winevt\Logs\` più i file di event tracing correlati. Abbinalo al modulo `WindowsEventLogs` per eseguire anche un parse immediato e produrre un CSV affiancato ai file grezzi. Raccomandato per qualsiasi engagement IR che tocchi più di un host.

## Lettura NTFS raw

Per la massima fedeltà — utile quando sospetti che le API del filesystem live siano intercettate o vuoi un'acquisizione bit-for-bit — leggi il volume al di sotto del filesystem. Tool come [The Sleuth Kit](https://www.sleuthkit.org/) (`tsk_recover`, `icat`) o `RawCopy.exe` di Eric Zimmerman aprono il volume tramite `\\.\PhysicalDriveN` o `\\.\C:`, percorrono la MFT ed emettono il contenuto dei file byte per byte. Il servizio EventLog non può bloccare questa via perché la lettura bypassa interamente il livello filesystem.

## Quale usare quando

- **Triage veloce su un host, hai admin**: `wevtutil`.
- **Acquisizione forense completa, hai già un'immagine disco**: FTK Imager o `tsk_recover` contro l'immagine.
- **Engagement IR, più host**: KAPE.
- **Sospetto rootkit o tampering live**: NTFS raw via RawCopy o TSK sul volume attivo, con l'host isolato dalla rete.

Qualunque tu scelga, documentalo. La catena di provenance conta nei report di incidente — un CSV parsato non dice nulla sul fatto che provenga da un host attivo con il servizio EventLog in esecuzione o da un'immagine sigillata.
