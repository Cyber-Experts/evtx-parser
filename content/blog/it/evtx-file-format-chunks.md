---
title: "Formato di file EVTX spiegato: chunk, template e interni BinXML"
description: "Come un file .evtx è disposto a livello di byte: header del file, chunk da 64 KB, la tabella template, e lo stream di record BinXML che la referenzia."
date: "2026-05-17"
---

Il [formato Windows Event Log `.evtx`](/en/blog/what-is-an-evtx-file) è arrivato con Vista per sostituire `.evt` orientato a riga. È un container binario, append-only, a chunk scritto da un singolo processo (il servizio EventLog) e ruotato quando pieno. La maggior parte degli analisti non ha mai bisogno di sapere come è disposto a livello byte. Quelli che carvano record da spazio non allocato, parsano a mano chunk danneggiati, o discutono con un parser che rifiuta di leggere un file troncato eccome.

Questo post è la versione pratica. Abbastanza interni per debuggare un parse rotto, non così tanti che finiate a scrivere il vostro parser da zero.

## Header del file

Ogni `.evtx` inizia con un header da 4 KB. Il magic è `ElfFile\0\0`. I campi che contano per un investigatore sono versione, conteggio chunk, indici del chunk più vecchio e corrente, e un CRC32 sull'header stesso. L'header viene riscritto in place ogni volta che il file ruota o un chunk viene sigillato, quindi i suoi flag `Dirty` e `Full` sono indicatori utili. Un file con `Dirty` impostato era aperto quando l'host è crashato o quando l'immagine del disco è stata acquisita live.

Dopo l'header viene una sequenza di chunk a dimensione fissa.

## Chunk: 64 KB ciascuno

Ogni chunk è esattamente 65.536 byte e ha il proprio header da 512 byte. Il magic del chunk è `ElfChnk\0`. L'header porta gli ID record di log del primo e ultimo record nel chunk, gli offset di file, e due CRC32: uno sull'header, uno sui dati record.

I chunk sono indipendenti. Potete carvare un chunk da spazio non allocato e parsarlo senza il resto del file. È questo che rende EVTX [recuperabile da frammenti di disco](/en/blog/carve-deleted-evtx-records), ed è anche ciò che rende il formato più amichevole al tooling forensics rispetto a qualcosa che comprimeva attraverso l'intero file.

Dentro un chunk:

- **String table.** Stringhe internate dentro questo chunk, referenziate per offset.
- **Template table.** Template XML usati dai record in questo chunk, anche indicizzati per offset.
- **Record.** Uno stream di record BinXML, ciascuno che referenzia un template più valori di sostituzione per-record.

## BinXML e template

I record EVTX non sono memorizzati come testo XML. Sono memorizzati come **BinXML**, una rappresentazione binaria tokenizzata di un documento XML. Per risparmiare spazio, lo scheletro strutturale (nomi di elementi, nomi di attributi, forma dell'albero) è fattorizzato in un **template** memorizzato una volta nella tabella template del chunk. Ogni record poi dice "usa template ID 5, con valori [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

Per ricostruire l'XML per un record, un parser:

1. Legge lo stream di token del record.
2. Cerca il template per ID nella tabella template del chunk.
3. Sostituisce i valori per-record nelle posizioni placeholder del template.
4. Emette l'XML risultante.

Per questo i parser (il [parser browser su questo sito](/en/blog/how-to-open-an-evtx-file), il crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) che avvolge, e python-evtx condividono tutti questo requisito) devono tracciare il contesto chunk-local. Gli ID template non sono globali attraverso il file. Due chunk possono avere tabelle template interamente diverse; lo stesso numero di ID template significa cose diverse in ciascuno.

Questo è anche la ragione singola più comune per cui gli analisti vedono "XML spazzatura" quando provano a decodare a mano un record che hanno tirato fuori con `xxd`. Senza la tabella template, i valori di sostituzione sono solo un sacco di valori tipati senza schema.

## Chunk sealed versus dirty

Quando il servizio EventLog finisce di scrivere un chunk e si sposta al successivo, calcola e scrive il CRC32 del chunk e marca l'header del chunk come `Full`. Un file pulito ha ogni chunk in questo stato tranne l'ultimo.

Un chunk `Dirty` (ultima modifica dopo l'ultimo aggiornamento dell'header file) è la coda viva. Spesso è parsabile, ma a volte i tool rifiutano di leggerlo perché lo stream di record può terminare a metà token. Per la forensics conta: un bundle [raccolto da un host vivo](/en/blog/collecting-evtx-from-live-system) avrà un trailing chunk dirty sul canale attivo, e il comportamento del vostro parser su quel chunk deve essere conosciuto. Salta il chunk, errore sul file, o recupera quello che può?

EvtxECmd, hayabusa e python-evtx recuperano tutti chunk dirty con tolleranza variabile. Native Event Viewer è il più severo e rifiuterà il file completamente più spesso degli altri.

## Implicazioni pratiche

- Un `.evtx` troncato, comune quando [raccogliete da un host vivo](/en/blog/collecting-evtx-from-live-system), è spesso in larga parte recuperabile. Ogni chunk completo è indipendente.
- Chunk carvati da non allocato possono essere avvolti con un header di file sintetico e parsati. È così che libevtx e python-evtx recuperano da `pagefile.sys` (vedi [parser pagefile](https://www.pagefilesysparser.com)) e sweep di carving su [dump RAM](https://www.ramparser.com).
- Un parse fallito di un chunk non significa fallimento del file. Parser robusti si spostano al chunk successivo e segnalano quello cattivo separatamente.
- Il CRC32 del chunk è ciò che flagga la manomissione. Un record modificato che non ricalcola il CRC è rilevabile. La maggior parte degli attaccanti non si disturba perché cancellare il log (scattando [1102](/en/blog/event-id-1102-cleared-log)) è il percorso più facile. Quelli attenti usano Phant0m, che lascia il file totalmente in pace.

## Per approfondire

- [Andreas Schuster: Introducing the Microsoft Vista Event Log File Format](https://digital-forensics.sans.org/blog/2008/05/01/the-windows-vista-event-log-file-format) (lavoro di reverse-engineering originale)
- [Documentazione libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc) (la spec di formato più completa in circolazione)
- [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (parser Rust, la build WASM alimenta il parser browser su questo sito)
