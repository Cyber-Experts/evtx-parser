---
title: "Come raccogliere i log .evtx da un sistema Windows vivo (4 metodi)"
description: "Quattro modi per prelevare .evtx da un host Windows vivo: wevtutil, FTK Imager, KAPE, NTFS grezzo. Con i compromessi sulla catena di custodia per ciascuno e i comandi che lancerai davvero."
date: "2026-05-17"
howto:
  name: "Come raccogliere i log .evtx da un sistema Windows vivo"
  steps:
    - name: "Esportare con wevtutil"
      text: "Esegui wevtutil epl Security C:\\triage\\Security.evtx come amministratore per sigillare una copia portatile del canale Security attivo senza prendere il file vivo."
    - name: "Acquisire con FTK Imager"
      text: "Apri FTK Imager, Add Evidence Item, naviga fino a \\Windows\\System32\\winevt\\Logs\\, seleziona i file di canale (inclusi i *.evtx archiviati) ed Export Files. FTK legge NTFS direttamente, aggirando i lock del file del servizio EventLog."
    - name: "Raccolta massiva con KAPE"
      text: "Esegui kape.exe --tsource C: --target EventLogs --tdest C:\\triage per tirare ogni .evtx sotto winevt\\Logs\\ in un solo passaggio, con metadati di catena di custodia. Abbina al modulo WindowsEventLogs per fare il parsing alla raccolta."
    - name: "Lettura NTFS grezza"
      text: "Quando si sospetta manomissione, usa RawCopy o tsk_recover per aprire il volume sotto il livello del filesystem (\\\\.\\PhysicalDriveN o \\\\.\\C:) e leggere ogni .evtx byte per byte dalla MFT. Il servizio EventLog non può bloccare questo percorso."
---

Il primo problema duro in un lavoro di event log non è il parsing. È portare via i file dall'host senza che il servizio EventLog ti dia un colpo sulla mano. Su una macchina Windows attiva il servizio tiene aperti handle ai [file `.evtx`](/it/blog/what-is-an-evtx-file) attivi in `C:\Windows\System32\winevt\Logs\`, quindi un `copy` ingenuo restituisce errori di violazione di condivisione. Quattro metodi coprono quasi ogni caso in cui mi sono imbattuto.

## wevtutil e Get-WinEvent: integrati, i più veloci

Il percorso più economico usa l'API documentata da Microsoft:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Produce un `.evtx` sigillato contenente ogni record attualmente nel canale. Nessun tooling di terze parti, shell admin richiesta. La nota da dire ad alta voce: `epl` cattura solo il log attivo. I file `Archive-Security-*.evtx` ruotati nella stessa directory restano indietro. Se la rotazione è avvenuta da poco e i record che vuoi sono in un archivio, questo metodo li perde.

PowerShell fa record parsati invece:

```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Security.evtx |
  Export-Csv triage.csv -NoTypeInformation
```

Ti dà un CSV, non un `.evtx`. Comodo per triage ad-hoc sulla macchina. Inutile per [recupero a livello di chunk, ispezione di dirty chunk o carving da spazio non allocato](/it/blog/evtx-file-format-chunks), perché hai gettato via la fedeltà binaria.

## FTK Imager: acquisizione a livello NTFS

Quando vuoi il file, non i record, FTK Imager è il cavallo da tiro. Aggiungi il disco vivo come evidenza (Physical Drive o Logical Drive), naviga fino a `\Windows\System32\winevt\Logs\`, tasto destro sui file di canale ed Export Files. FTK legge le strutture NTFS sottostanti direttamente, scavalcando il lock del filesystem che il servizio EventLog tiene. Cattura anche i file `Archive-*.evtx` archiviati che `wevtutil epl` salta.

Trade-off: FTK legge file che possono essere a metà scrittura. Il chunk di coda sul canale attivo può essere dirty. La maggior parte dei parser lo gestisce con eleganza (incluso il [parser browser di questo sito](/it/blog/how-to-open-an-evtx-file)) ma verifica sul banco prima di scriverlo in un report. Le voci corrispondenti del [journal USN](https://www.usnparser.com) sono una conferma utile quando sospetti che il servizio EventLog abbia fatto qualcosa di non standard durante l'acquisizione.

## KAPE: raccolta massiva a velocità IR

Quando l'ingaggio ha più di un host, il Kroll Artifact Parser and Extractor si ripaga in un'ora.

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

Il target `EventLogs` spazza ogni `.evtx` sotto `winevt\Logs\` più i file ETW correlati. Abbinalo al modulo `!EZParser` o `WindowsEventLogs` e KAPE eseguirà anche EvtxECmd sulla raccolta in uscita, dandoti CSV parsati accanto alla prova grezza. Già che ci sei, i target `RegistryHives` e `FileSystem` raccolgono i dati di [registro](https://www.registryparser.com), [MFT](https://www.mftparser.com), [journal USN](https://www.usnparser.com) e [prefetch](https://www.prefetchparser.com) che vorrai comunque.

L'output di KAPE arriva con metadati di copy log. Conta per la catena di custodia più di quanto la gente gli riconosca.

## Lettura NTFS grezza: quando sospetti manomissione

Per massima fedeltà, scendi sotto il livello del filesystem. I `tsk_recover` e `icat` del Sleuth Kit, o `RawCopy.exe` di Eric Zimmerman, aprono il volume tramite `\\.\PhysicalDriveN` o `\\.\C:`, percorrono la MFT ed emettono il contenuto del file byte per byte. Il servizio EventLog non può bloccarlo perché la lettura non passa per l'API file Win32.

Usa questo quando un rootkit è nel perimetro, quando hai motivo di pensare che un kernel filter driver stia intercettando letture di `\winevt\Logs\`, o quando semplicemente non ti fidi dell'OS in esecuzione. Abbina il risultato a un [dump RAM](https://www.ramparser.com) preso nello stesso momento. Il servizio event log mette in cache record recenti in memoria, e uno snapshot preso minuti prima della manomissione contiene a volte record che non sono mai arrivati sul disco.

## Quale quando

- Un host, hai admin, hai un'ora: `wevtutil epl` per ogni canale che conta, zip della directory, fatto.
- Immagine di disco già in mano: FTK Imager o `tsk_recover` contro l'immagine. Più veloce dell'host vivo, e non devi coordinarti con il SOC.
- Più host, vero ingaggio IR: KAPE. Niente altro si avvicina in throughput.
- Manomissione live o rootkit sospettato: RawCopy o TSK contro il volume, con la rete dell'host isolata.

Qualunque tu scelga, documentalo. I CSV parsati non dicono niente sulla provenienza. Una riga nelle note di caso che recita `KAPE 1.3.0.2 EventLogs target, hash file attached` è la differenza tra una prova e un'opinione.

## Per approfondire

- [Documentazione KAPE](https://ericzimmerman.github.io/KapeDocs/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)
