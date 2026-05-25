---
title: "Formato file EVTX spiegato: chunk, template e interni BinXML"
description: "Come è strutturato un file .evtx a livello di byte — header del file, chunk da 64 KB, tabella dei template e lo stream di record BinXML che la referenzia."
date: "2026-05-17"
---

Il [formato Windows Event Log — `.evtx`](/it/blog/what-is-an-evtx-file) — è stato introdotto con Windows Vista per sostituire il `.evt` line-oriented. È un container binario, append-only, chunked, progettato per essere scritto da un singolo processo (il servizio EventLog) e ruotato o sigillato quando pieno. Capire come è strutturato rende molto più semplici i casi di recovery forense — file parziali, chunk dirty, carving.

## Header del file

Ogni `.evtx` inizia con un header da 4 KB (magic `ElfFile\0\0`, versione, conteggio dei chunk, indici del chunk oldest/current e un CRC32). L'header viene riscritto in posto ogni volta che il file viene ruotato o un chunk viene sigillato, il che rende i suoi flag `Dirty` e `Full` utili tells: un file con `Dirty` impostato era aperto quando l'host è crashato o l'immagine disco è stata acquisita live.

Dopo l'header viene una sequenza di chunk a dimensione fissa.

## Chunk (64 KB)

Ogni chunk è esattamente 64 KB e ha il proprio header da 512 byte (magic `ElfChnk\0`, ID dei record log del primo e dell'ultimo record nel chunk, offset di file, due CRC32 — uno per l'header, uno per i dati dei record). I chunk sono indipendenti: puoi carved un chunk dallo spazio non allocato e parsearlo senza il resto del file. È questo che rende l'EVTX recuperabile da frammenti di disco.

Dentro un chunk:

- **String table** — stringhe internate dentro questo chunk, referenziate per offset.
- **Template table** — template XML usati dai record in questo chunk, anch'essi indicizzati per offset.
- **Records** — uno stream di record BinXML, ciascuno che referenzia un template più i valori di sostituzione per-record.

## BinXML e template

I record EVTX non sono memorizzati come testo XML. Sono memorizzati come **BinXML**, una rappresentazione binaria tokenizzata di un documento XML. Per risparmiare spazio, lo scheletro strutturale (nomi degli elementi, nomi degli attributi, la forma dell'albero) viene fattorizzato in un **template** memorizzato una sola volta nella template table del chunk. Ogni record dice poi «usa il template ID 5, con valori [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]».

Per ricostruire l'XML di un record, un parser:

1. Legge lo stream di token del record.
2. Cerca il template per ID nella template table del chunk.
3. Sostituisce i valori per-record nelle posizioni placeholder del template.
4. Emette l'XML risultante.

È per questo che i [parser](/it/blog/how-to-open-an-evtx-file) (incluso quello che alimenta questa pagina, [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx)) devono tracciare il contesto chunk-local — i template ID non sono globali nel file.

## Chunk sigillati vs dirty

Quando il servizio EventLog finisce di scrivere un chunk e passa al successivo, calcola e scrive il CRC32 del chunk e marca l'header del chunk come `Full`. Un file pulito ha ogni chunk in questo stato eccetto l'ultimo.

Un chunk `Dirty` — last-modified time dopo l'ultimo aggiornamento dell'header del file — è la coda live. È spesso parseable, ma i tool a volte rifiutano di leggerlo perché lo stream di record può terminare a metà token. Per la forensica questo conta: un attaccante che ha acquisito un host a metà scrittura vedrà un chunk dirty in coda, e il comportamento del tuo parser su quel chunk va conosciuto (salta, dà errore, o recupera ciò che può?).

## Implicazioni pratiche per il parsing

- Un `.evtx` troncato — comune quando lo [raccogli da un host attivo](/it/blog/collecting-evtx-from-live-system) — è spesso ancora largamente recuperabile, perché ogni chunk completo è indipendente.
- Chunk carved da non allocato possono essere wrappati con un header di file sintetico e parseati.
- Un parse fallito di un chunk non significa fallimento del file — i parser robusti passano al chunk successivo.
- Il CRC32 del chunk è ciò che segnala il tampering: un record modificato che non ricalcola il CRC è rilevabile.
