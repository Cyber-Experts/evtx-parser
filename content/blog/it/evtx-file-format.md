---
title: "Il formato di file EVTX, decodificato"
description: "Un tour pratico del formato binario EVTX: header del file, chunk ELFCHNK, template BinXML, array di sostituzione, e perché fare il parsing di questa cosa è più difficile di quanto sembri."
date: "2026-05-27"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

Il vecchio formato EVT era quasi leggibile con un editor esadecimale e un po' di pazienza. EVTX no. Microsoft l'ha sostituito in Vista con qualcosa progettato per throughput di scrittura e consumo macchina, e l'effetto collaterale è che chiunque voglia leggere un file EVTX finisce a reimplementare le stesse poche centinaia di pagine di note di reverse-engineering di Andreas Schuster. Il formato è documentato in `[MS-EVEN6]` solo a livello di protocollo. La struttura on-disk te la devi capire da solo o prenderla in prestito da `libevtx`.

Questo post è la versione di tutto ciò che avrei voluto avere quando ho iniziato.

## L'header del file, brevemente

Ogni file EVTX si apre con un header da 4096 byte. Il magic è `ElfFile\0` a offset 0. Dopo di che i campi che ti interessano davvero durante il triage:

- `FirstChunkNumber` e `LastChunkNumber` indici di chunk, non offset di byte.
- `NextRecordIdentifier` il prossimo RecordID che verrebbe scritto. Utile per individuare il troncamento.
- `HeaderSize` quasi sempre 128, con il resto dei 4096 byte riempito di zeri.
- `MinorVersion` / `MajorVersion` `3.1` è la versione che ogni Windows moderno scrive.
- `FileFlags` bit 0 impostato significa che il file è dirty (non chiuso pulitamente), bit 1 significa che è stato "pieno" ed è in rotazione. Entrambi importano per l'interpretazione forense.
- Un CRC32 sui primi 120 byte dell'header. Gli strumenti che ignorano il CRC fanno parsing tranquillamente di header corrotti; gli strumenti che lo impongono rifiutano file da cui puoi ancora recuperare record. Sappi cosa fa il tuo.

Dopo l'header, ottieni una sequenza di chunk da 65.536 byte. Sempre 64 KB, sempre allineati. Questa è l'unità che Windows scrive atomicamente, ed è l'unità che fai carving.

## ELFCHNK: l'header del chunk

Ogni chunk inizia con `ElfChnk\0` al confine del chunk. L'header è di 512 byte e porta i campi che rendono possibile il parsing:

- `FirstEventRecordNumber` e `LastEventRecordNumber` il range di RecordID coperto da questo chunk.
- `FirstEventRecordIdentifier` e `LastEventRecordIdentifier` la stessa cosa, conservata per legacy.
- `FirstEventRecordOffset` dove iniziano i byte del primo record dentro questo chunk.
- `LastEventRecordOffset` dove inizia l'ultimo record. Se è oltre la fine del chunk popolato, il chunk è stato scritto parzialmente; il writer ha crashato.
- Una `StringTable` e una `TemplateTable`, entrambe tabelle hash indicizzate da hash in stile FNV, che puntano dentro al payload BinXML del chunk.
- Due CRC: uno sull'header, uno sull'area dei record.

Le tabelle string e template sono la parte che frega le persone. Template e string sono memorizzati *una volta per chunk* e referenziati per offset all'interno del chunk. Questo significa che non puoi fare parsing in modo significativo di un record in isolamento. Hai bisogno del suo chunk contenitore, con le sue tabelle risolte, per renderizzare l'XML del record. Fai carving di un record senza il suo chunk e otterrai un array di sostituzione senza template in cui sostituire.

`NumLogRecords` vive implicitamente come `LastEventRecordNumber - FirstEventRecordNumber + 1`. Della documentazione vecchia chiamava questo campo per nome; i parser moderni lo calcolano.

## Codifica EventRecord

Oltre l'header del chunk ottieni record, uno dietro l'altro, finché il chunk non è pieno o il resto è azzerato. Ogni record inizia col magic `2a 2a 00 00` (cosa che rende fattibile il signature carving da disco grezzo, ne parliamo in un post separato) seguito da:

- `Size` lunghezza totale del record inclusa la ripetizione di size in coda.
- `EventRecordIdentifier` il RecordID monotonicamente crescente.
- `WriteTime` un Windows FILETIME, tick da 100 ns dal 1601-01-01 UTC.
- Il payload BinXML.
- `Size` di nuovo, ripetuto in coda così che un lettore possa camminare i record all'indietro.

Il payload BinXML è dove inizia il vero lavoro.

## BinXML e il modello template/sostituzione

BinXML è uno stream di token che codifica XML come opcode binari. Gli opcode che contano:

- `0x00` end-of-stream.
- `0x01` open start tag (con attributi).
- `0x02` close start tag.
- `0x03` close empty tag.
- `0x04` end element.
- `0x05` value, seguito da un `ValueType` e dai byte del valore.
- `0x06` attribute.
- `0x0c` template instance.
- `0x0d` normal substitution.
- `0x0e` conditional substitution.
- `0x0f` start of stream (con un preambolo di 3 byte).

Il writer del Windows event log non emette quasi mai XML grezzo per un evento. Emette una *template instance* (`0x0c`), che referenzia una definizione di template (memorizzata una volta per chunk per ID) e fornisce un *array di sostituzione* contenente i valori delle variabili per quel template. Per renderizzare un singolo record XML leggibile da umani devi:

1. Localizzare il template nella tabella template del chunk per ID e offset.
2. Camminare il BinXML del template, trattandolo come uno scheletro con placeholder di sostituzione numerati.
3. Per ogni placeholder, cercare l'entry corrispondente nell'array di sostituzione, type-checkarla contro il tipo dichiarato del placeholder, e inlinearla.

L'array di sostituzione ha entry tipate: UInt32, UInt64, Boolean, GUID, FILETIME, SID, HexInt32, HexInt64, BinXML, EvtHandle, EvtXml, più stringhe sia in UTF-16LE inline che per riferimento di offset, più array di qualsiasi di queste. Il tipo 0x21 è "BinXML" che significa che la sostituzione è essa stessa uno stream BinXML annidato, che significa che i parser devono ricorsare. È qui che le implementazioni ingenue crollano.

Due trappole che vale la pena segnalare:

- I template possono essere referenziati da *altri* record nello stesso chunk per offset. Se costruisci un parser che risolve i template solo quando ne vede la dichiarazione inline, ti perdi record che referenziano un template precedente solo per ID.
- Il tipo "conditional substitution" (`0x0e`) significa: sostituisci se il valore non è null, altrimenti ometti l'elemento padre. Saltare questa distinzione produce XML che sembra ok ma ha elementi vuoti dove il log reale non avrebbe nulla.

## Perché questo è più difficile del parsing di EVT

EVT era un file flat di record a forma fissa. Le stringhe erano memorizzate inline. Potevi scrivere un parser in un pomeriggio.

EVTX è un formato paginato, ottimizzato in scrittura, auto-deduplicante. La stessa stringa ("Microsoft-Windows-Security-Auditing") è memorizzata una volta per chunk e referenziata da ogni record che la usa. Lo stesso scheletro XML ("un evento 4624") è memorizzato una volta per chunk come template, e ogni record 4624 in quel chunk è un array di sostituzione contro di esso. Lo stato cross-record conta. Lo stato cross-chunk no, che è la grazia salvatrice: perdi un chunk e perdi i suoi record, ma il resto del file è recuperabile.

Questa deduplicazione è ciò che rende EVTX abbastanza piccolo da tenere su host occupati e ciò che rende i parser ingenui sbagliati. Se hai mai visto un EVTX "parsato" dove il campo `Provider` di ogni record dice "Unknown", hai visto un parser che non ha risolto la string table.

## Gli strumenti che funzionano davvero

- `python-evtx` (Willi Ballenthin) lento, Python puro, ma l'implementazione di riferimento più pulita. Leggi il sorgente prima di scrivere il tuo.
- `evtx_dump` dal crate Rust `evtx` di Omer Ben-Amram veloce, robusto, il default per il dump da linea di comando. Output JSONL che si pipe ovunque.
- `libevtx` e `evtxtools` (Joachim Metz) libreria C, il riferimento canonico per il formato. I binding Python (`pyevtx`) sono più lenti di `python-evtx` su certi carichi ma gestiscono meglio i casi limite.
- `EvtxECmd` di Eric Zimmerman .NET, di gran lunga il migliore per il lavoro di campo IR per via del suo sistema di map. Le map sono file YAML che appiattiscono le sostituzioni di EventData in colonne nominate, che è quello che vuoi per il grep e il lavoro di timeline. Abbinalo a `Timeline Explorer`.
- Il parser su questo sito browser-based, utile quando non vuoi caricare dati regolamentati a un vendor e non hai il tuo kit sulla macchina da cui stai lavorando.

Se stai scrivendo un parser da zero (non farlo, ma se devi), il test corpus contro cui validare sono i sample EVTX pubblici dal repo del [poster SANS DFIR](https://github.com/forensicmatt/EVTX-ETW-Resources) e i sample log `hayabusa` di Yamato Security. Coprono i casi di chunk malformato e record parziale su cui il tuo codice sbaglierà alla prima passata.

L'altra cosa che vale la pena dire: il formato è condiviso con altri artefatti Windows. La stessa codifica FILETIME compare nel [registry](https://www.registryparser.com), nei timestamp `$STANDARD_INFORMATION` di [MFT](https://www.mftparser.com), negli header [Prefetch](https://www.prefetchparser.com). Diventa bravo a leggere FILETIME a mente e tanta forensics Windows diventa più silenziosa.

## Per approfondire

- L'originale di Andreas Schuster ["Introducing the Microsoft Vista Event Log File Format"](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf) (DFRWS 2007). Il paper di reverse-engineering che tutto cita da allora.
- La [specifica del formato libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc) di Joachim Metz. La cosa più vicina a un riferimento completo.
- Il [sorgente python-evtx](https://github.com/williballenthin/python-evtx) di Willi Ballenthin. Leggi `Evtx/Nodes.py` per la gerarchia di nodi BinXML.
- Il [crate Rust evtx di Omer Ben-Amram](https://github.com/omerbenamram/evtx). Il path veloce su cui poggia la maggior parte del tooling moderno.
