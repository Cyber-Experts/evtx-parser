---
title: "Cos'è un file .evtx? Il formato del Windows Event Log spiegato"
description: "Un file .evtx è un Windows Event Log binario. Dove si trovano, cosa contengono, in cosa differiscono dai .evt e come aprirli senza installare nulla."
date: "2026-05-24"
faq:
  - question: "Cos'è un file .evtx?"
    answer: "Un file .evtx è il formato binario del Windows Event Log introdotto con Windows Vista. Contiene gli eventi di sistema, sicurezza e applicazione scritti dal servizio EventLog. Ogni macchina Windows ha decine di file .evtx in C:\\Windows\\System32\\winevt\\Logs\\, uno per canale."
  - question: "Dove vengono salvati i file .evtx su Windows?"
    answer: "La posizione predefinita è C:\\Windows\\System32\\winevt\\Logs\\. I tre file ad alto traffico sono Security.evtx, System.evtx e Application.evtx. I canali per singola applicazione risiedono nella stessa cartella con nomi del tipo Microsoft-Windows-Sysmon%4Operational.evtx."
  - question: "Qual è la differenza tra .evtx e .evt?"
    answer: ".evt è il formato binario legacy usato da Windows fino a XP e Server 2003. .evtx l'ha sostituito in Windows Vista (2007) con una struttura a chunk basata su BinXML che supporta metadati di evento più ricchi, log più grandi e query strutturate via wevtutil e Get-WinEvent. I due formati non sono interscambiabili."
  - question: "Come si apre un file .evtx?"
    answer: "Strumenti integrati di Windows: Visualizzatore eventi (eventvwr.msc), wevtutil da riga di comando o Get-WinEvent da PowerShell. Multipiattaforma: aprilo nel parser browser di questo sito (nessuna installazione, nessun upload) o usa evtxecmd da riga di comando. Vedi il post how-to-open-an-evtx-file per tutte le opzioni."
  - question: "Posso aprire un file .evtx su macOS o Linux?"
    answer: "Sì. Gli strumenti nativi di Windows non funzionano, ma diversi parser multipiattaforma sì: il parser browser di questo sito (qualsiasi OS con un browser moderno), python-evtx, la crate Rust evtx ed evtxecmd via mono. Nessuno di questi richiede un host Windows."
---

Un file `.evtx` è il formato binario del Windows Event Log che Microsoft ha introdotto con Windows Vista nel 2007 per sostituire il vecchio formato `.evt`. Ogni evento scritto sul Windows Event Log dal sistema operativo, da un driver, da un servizio o da un'applicazione finisce in un file `.evtx` su disco. Sono la spina dorsale di qualsiasi indagine su Windows.

## Risposta rapida

I file `.evtx` vengono scritti dal servizio EventLog di Windows in `C:\Windows\System32\winevt\Logs\`. C'è un file per **canale** (`Security.evtx`, `System.evtx`, `Application.evtx`, più i canali per singola applicazione). Internamente ogni file è un contenitore binario a chunk con record codificati in `BinXML` — non testo semplice. Si leggono con il Visualizzatore eventi, `wevtutil`, `Get-WinEvent` o un parser di terze parti.

## Dove vivono i file .evtx

La posizione standard su tutte le versioni Windows supportate (da Vista a Windows 11 / Server 2025):

```text
C:\Windows\System32\winevt\Logs\
```

Ogni file `.evtx` mappa un canale di eventi. I default che troverai sempre:

- `Security.evtx` — accessi, uso dei privilegi, modifiche alla audit policy. Il valore forense più alto nella maggior parte dei casi.
- `System.evtx` — driver, servizi, errori a livello kernel.
- `Application.evtx` — errori applicativi ed eventi informativi.
- `Setup.evtx` — record di installazione.
- `ForwardedEvents.evtx` — eventi raccolti da altri host via Windows Event Forwarding (WEF).

I canali per singola applicazione sono salvati nella stessa cartella con `%4` al posto del separatore di percorso:

- `Microsoft-Windows-Sysmon%4Operational.evtx` — eventi Sysmon di processi, rete e file (quando installato).
- `Microsoft-Windows-PowerShell%4Operational.evtx` — scriptblock e module logging di PowerShell.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` — creazione ed esecuzione di attività pianificate.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` — ciclo di vita delle sessioni RDP.

I canali ruotati producono file di archivio con timestamp nella stessa cartella (`Security.evtx`, `Archive-Security-2026-05-23-…evtx`). Il file attivo resta tenuto aperto dal servizio EventLog finché Windows è in esecuzione.

## Cosa c'è dentro un file .evtx

Il file è un contenitore binario, non testo semplice. Un header di 4 KB (magic `ElfFile\0`) è seguito da una sequenza di **chunk** da 64 KB. Ogni chunk ha il suo header (`ElfChnk`), una tabella dei **template** XML che compaiono al suo interno e un flusso di record che fanno riferimento a quei template tramite ID. Un parser ricostruisce ogni evento sostituendo i valori a livello di record nei placeholder del template — è ciò che rende `.evtx` più compatto di XML letterale su disco.

Una volta decodificato, ogni record è un documento XML diviso in due metà:

- `<System>` — nome del provider, canale, Event ID, livello (1 Critico → 5 Verbose), nome del computer, contesto di sicurezza e timestamp UTC di scrittura.
- `<EventData>` — parametri specifici del provider: l'account target su un logon, il path dell'immagine su un process create, la chiave di registro su una scrittura sottoposta ad audit, e così via.

Il solo Event ID raramente basta per il triage. Il segnale forense vive in `<EventData>`. Per la meccanica del formato in profondità — chunk, BinXML, template, recupero dei dirty chunk — vedi [Dentro il formato di file EVTX](/it/blog/evtx-file-format-chunks).

## .evtx vs .evt: perché il formato è cambiato

Il vecchio formato `.evt` usato da Windows fino a XP e Server 2003 aveva tre limiti rigidi che il nuovo formato è stato progettato per risolvere:

- **Stringhe a dimensione fissa.** I record `.evt` portavano riferimenti a message-table invece del messaggio completo; le join al render-time si rompevano quando le DLL sorgenti erano mancanti o aggiornate.
- **Nessuna query strutturata.** Filtrare richiedeva di leggere e analizzare ogni record linearmente.
- **Un solo canale per file.** I log applicativi custom dovevano usare formati non standard propri.

`.evtx` (Vista, 2007) ha introdotto record BinXML, file per canale con annidamento arbitrario, filtri in stile XPath via `wevtutil qe` e `Get-WinEvent -FilterHashtable`, e una struttura a chunk che sopravvive a scritture parziali. Il trade-off è stata una rottura completa di compatibilità — `.evt` ed `.evtx` non sono interscambiabili, e l'unico strumento integrato che legge `.evt` su un Windows moderno è `wevtutil` con il flag legacy (e solo per l'export verso `.evtx`).

## Come aprire un file .evtx

Cinque percorsi comuni, in ordine approssimativo di attrito:

1. **Nel browser, senza installazione** — trascina il file nel parser sulla home page di questo sito. Esegue la crate Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilata in WebAssembly dentro un Web Worker. Niente lascia la tua macchina. Adatto per il triage ad-hoc quando non vuoi accendere una VM forense.
2. **Visualizzatore eventi (`eventvwr.msc`)** — la GUI integrata di Windows. Apri il Visualizzatore eventi → Azione → Apri registro salvato… → seleziona il file `.evtx`. Buono per la navigazione, debole per filtrare su scala.
3. **`wevtutil` / `Get-WinEvent`** — riga di comando e PowerShell, entrambi inclusi in Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` esporta ogni record; `Get-WinEvent -Path` restituisce oggetti pipeable verso `Where-Object`.
4. **EvtxECmd** — il parser di Eric Zimmerman. Multipiattaforma via .NET, veloce, produce CSV con una riga per record e l'intero `<EventData>` appiattito.
5. **`python-evtx`** — pure-Python, facile da scriptare. Più lento della crate Rust ma utile quando hai già una toolchain Python.

Per una guida completa di ciascun metodo con i comandi che useresti davvero, vedi [Come aprire un file .evtx](/it/blog/how-to-open-an-evtx-file).

## Quando incontri .evtx sul campo

- **Incident response.** Estratto da un host compromesso come parte del triage. I canali di interesse dipendono dal lead — `Security` per accessi e abuso di privilegi, `Sysmon` per gli alberi di processo, `PowerShell` per il contenuto degli scriptblock.
- **Audit di compliance.** Gli auditor richiedono `Security.evtx` su una finestra definita per verificare la storia di logon e modifiche di policy.
- **Debug applicativo.** `Application.evtx` insieme ai canali per vendor spesso contengono contesto di crash ed errori che i log propri dell'applicazione non hanno.
- **Threat hunting.** Regole long-tail su `.evtx` archiviati (o un SIEM che inoltra il canale live) catturano pattern lenti come RDP fuori orario o drift del `LogonType` su un service account.

Il pivot singolo più utile è l'Event ID. Per la shortlist che vale la pena conoscere in un SOC reale — [4624 logon riuscito](/it/blog/understanding-event-id-4624), [4625 logon fallito](/it/blog/detecting-4625-brute-force), [1102 log cancellato](/it/blog/event-id-1102-cleared-log), [4104 scriptblock PowerShell](/it/blog/powershell-4104-scriptblock), [7045 servizio installato](/it/blog/service-creation-event-id-7045), [Sysmon 1 process create](/it/blog/sysmon-event-id-1-process-create) — vedi [l'orientamento di partenza](/it/blog/welcome).
