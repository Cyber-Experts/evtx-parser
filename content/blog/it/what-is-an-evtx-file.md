---
title: "Cos'è un file .evtx? Il formato del log eventi di Windows spiegato"
description: "Un file .evtx è un log eventi di Windows binario. Dove si trovano, cosa contengono, in cosa differiscono dai .evt e come aprirli. Nessuna installazione richiesta."
date: "2026-05-24"
faq:
  - question: "Cos'è un file .evtx?"
    answer: "Un file .evtx è il formato binario del log eventi di Windows introdotto con Windows Vista. Contiene gli eventi di sistema, sicurezza e applicazione scritti dal servizio EventLog. Ogni macchina Windows ha decine di file .evtx in C:\\Windows\\System32\\winevt\\Logs\\, uno per canale."
  - question: "Dove vengono salvati i file .evtx su Windows?"
    answer: "La posizione predefinita è C:\\Windows\\System32\\winevt\\Logs\\. I tre file ad alto traffico sono Security.evtx, System.evtx e Application.evtx. I canali per singola applicazione risiedono nella stessa cartella con nomi del tipo Microsoft-Windows-Sysmon%4Operational.evtx."
  - question: "Qual è la differenza tra .evtx e .evt?"
    answer: ".evt è il formato binario legacy usato da Windows fino a XP e Server 2003. .evtx l'ha sostituito in Windows Vista (2007) con una struttura a chunk basata su BinXML che supporta metadati di evento più ricchi, log più grandi e query strutturate via wevtutil e Get-WinEvent. I due formati non sono interscambiabili."
  - question: "Come si apre un file .evtx?"
    answer: "Strumenti integrati di Windows: Visualizzatore eventi (eventvwr.msc), wevtutil da riga di comando o Get-WinEvent da PowerShell. Multipiattaforma: aprilo nel parser browser di questo sito (nessuna installazione, nessun upload) o usa evtxecmd da riga di comando. Vedi il post how-to-open-an-evtx-file per tutte le opzioni."
  - question: "Posso aprire un file .evtx su macOS o Linux?"
    answer: "Sì. Gli strumenti nativi di Windows non funzionano, ma diversi parser multipiattaforma sì: il parser browser di questo sito (qualsiasi OS con un browser moderno), python-evtx, la crate Rust evtx ed evtxecmd via .NET. Nessuno di questi richiede un host Windows."
---

Un file `.evtx` è il formato binario del log eventi di Windows che Microsoft ha consegnato con Vista nel 2007 per sostituire il vecchio `.evt`. Ogni evento scritto sul log eventi di Windows dal sistema operativo, da un driver, da un servizio o da un'applicazione finisce in un file `.evtx` su disco. Sono la spina dorsale di qualsiasi indagine su Windows. Se fai DFIR su Windows, passerai più tempo dentro questi file che con qualsiasi altra classe di artefatti.

## Risposta rapida

I file `.evtx` vengono scritti dal servizio EventLog di Windows in `C:\Windows\System32\winevt\Logs\`. Un file per **canale** (`Security.evtx`, `System.evtx`, `Application.evtx`, più i canali per singola applicazione). Internamente ogni file è un contenitore binario a chunk con record codificati in `BinXML`. Non testo semplice. Si leggono con il Visualizzatore eventi, `wevtutil`, `Get-WinEvent` o un parser di terze parti.

## Dove vivono i file .evtx

Posizione standard su tutte le versioni Windows supportate (da Vista a Windows 11 e Server 2025):

```text
C:\Windows\System32\winevt\Logs\
```

Ogni file `.evtx` mappa un canale di eventi. I predefiniti:

- `Security.evtx`. Accessi, uso dei privilegi, modifiche alla audit policy. Il valore forense più alto nella maggior parte dei casi.
- `System.evtx`. Driver, servizi, errori a livello kernel.
- `Application.evtx`. Errori applicativi ed eventi informativi.
- `Setup.evtx`. Record di installazione.
- `ForwardedEvents.evtx`. Eventi raccolti da altri host via Windows Event Forwarding (WEF).

I canali per singola applicazione sono salvati nella stessa cartella con `%4` al posto del separatore di percorso:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Eventi Sysmon di processi, rete e file (quando installato).
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Scriptblock e module logging di PowerShell.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Creazione ed esecuzione di attività pianificate.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Ciclo di vita delle sessioni RDP.

I canali ruotati producono file di archivio con timestamp nella stessa cartella (`Security.evtx`, `Archive-Security-2026-05-23-...evtx`). Il file attivo resta tenuto aperto dal servizio EventLog finché Windows è in esecuzione, che è l'intero motivo per cui esiste [un post sulla raccolta che spiega come ottenere questi file da un host vivo](/it/blog/collecting-evtx-from-live-system).

## Cosa c'è dentro un file .evtx

Il file è un contenitore binario, non testo semplice. Un header di 4 KB (magic `ElfFile\0`) è seguito da una sequenza di **chunk** da 64 KB. Ogni chunk ha il suo header (`ElfChnk`), una tabella dei **template** XML che compaiono al suo interno e un flusso di record che fanno riferimento a quei template tramite ID. Un parser ricostruisce ogni evento sostituendo i valori a livello di record nei placeholder del template. È ciò che rende `.evtx` più compatto di XML letterale su disco.

Una volta decodificato, ogni record è un documento XML diviso in due metà:

- `<System>`. Nome del provider, canale, Event ID, livello (1 Critical fino a 5 Verbose), nome del computer, contesto di sicurezza e timestamp UTC di scrittura.
- `<EventData>`. Parametri specifici del provider: l'account target su un logon, il path dell'immagine su un process create, la chiave di registro su una scrittura sottoposta ad audit, e così via.

Il solo Event ID raramente basta per il triage. Il segnale forense vive in `<EventData>`. Per la meccanica del formato in profondità (chunk, BinXML, template, recupero dei dirty chunk), vedi [l'approfondimento a livello di chunk](/it/blog/evtx-file-format-chunks).

## .evtx vs .evt: perché il formato è cambiato

Il vecchio formato `.evt` usato da Windows fino a XP e Server 2003 aveva tre limiti rigidi che il nuovo formato è stato progettato per risolvere:

- **Stringhe a dimensione fissa.** I record `.evt` portavano riferimenti a message-table invece del messaggio completo. Le join al render-time si rompevano quando le DLL sorgenti erano mancanti o aggiornate.
- **Nessuna query strutturata.** Filtrare richiedeva di leggere e analizzare ogni record linearmente.
- **Un solo canale per file.** I log applicativi custom dovevano usare formati non standard propri.

`.evtx` (Vista, 2007) ha introdotto record BinXML, file per canale con annidamento arbitrario, filtri in stile XPath via `wevtutil qe` e `Get-WinEvent -FilterHashtable`, e una struttura a chunk che sopravvive a scritture parziali. Il trade-off è stata una rottura completa di compatibilità. `.evt` ed `.evtx` non sono interscambiabili, e l'unico strumento integrato che legge `.evt` su un Windows moderno è `wevtutil` con il flag legacy (e solo per l'export verso `.evtx`).

## Come aprire un file .evtx

Cinque percorsi comuni, in ordine approssimativo di attrito:

1. **Nel browser, senza installazione.** Trascina il file nel parser sulla home page di questo sito. Esegue la crate Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilata in WebAssembly dentro un Web Worker. Niente lascia la tua macchina. Adatto per il triage ad-hoc quando non vuoi accendere una VM forense.
2. **Visualizzatore eventi (`eventvwr.msc`).** La GUI integrata di Windows. Azione / Apri registro salvato / seleziona il file `.evtx`. Buono per la navigazione, debole per filtrare su scala.
3. **`wevtutil` / `Get-WinEvent`.** Riga di comando e PowerShell, entrambi inclusi in Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` esporta ogni record. `Get-WinEvent -Path` restituisce oggetti pipeable verso `Where-Object`.
4. **EvtxECmd.** Il parser di Eric Zimmerman. Multipiattaforma via .NET, veloce, produce CSV con una riga per record e l'intero `<EventData>` appiattito.
5. **`python-evtx`.** Pure-Python, facile da scriptare. Più lento della crate Rust ma utile quando hai già una toolchain Python.

Per una guida completa di ciascun metodo con i comandi che useresti davvero, vedi [Come aprire un file .evtx](/it/blog/how-to-open-an-evtx-file).

## Quando incontri .evtx sul campo

- **Incident response.** Estratto da un host compromesso come parte del triage. I canali di interesse dipendono dal lead: `Security` per accessi e abuso di privilegi, `Sysmon` per gli alberi di processo, `PowerShell` per il contenuto degli scriptblock. Abbina con i parser per [registro](https://www.registryparser.com), [MFT](https://www.mftparser.com), [journal USN](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com) e [prefetch](https://www.prefetchparser.com) per la conferma di esecuzione.
- **Audit di compliance.** Gli auditor richiedono `Security.evtx` su una finestra definita per verificare la storia di logon e modifiche di policy.
- **Debug applicativo.** `Application.evtx` insieme ai canali per vendor spesso contengono contesto di crash ed errori che i log propri dell'applicazione non hanno.
- **Threat hunting.** Regole long-tail su `.evtx` archiviati (o un SIEM che inoltra il canale live) catturano pattern lenti come RDP fuori orario o drift del `LogonType` su un service account.

Il pivot singolo più utile è l'Event ID. Per la shortlist che vale la pena conoscere in un SOC reale ([4624](/it/blog/understanding-event-id-4624), [4625](/it/blog/detecting-4625-brute-force), [1102](/it/blog/event-id-1102-cleared-log), [4104](/it/blog/powershell-4104-scriptblock), [7045](/it/blog/service-creation-event-id-7045), [Sysmon 1](/it/blog/sysmon-event-id-1-process-create)), vedi [l'orientamento di partenza](/it/blog/welcome).

## Per approfondire

- [Documentazione Microsoft: Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Specifica del formato EVTX di libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)
- [omerbenamram/evtx (parser Rust)](https://github.com/omerbenamram/evtx)
