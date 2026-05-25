---
title: "Leggere il formato binario del log eventi di Windows"
description: "Una breve introduzione su come sono strutturati i file .evtx, cosa contiene ogni evento e perché il formato binario è importante in ambito forense."
date: "2026-05-16"
---

Il log eventi di Windows — `.evtx` — è il formato binario che Microsoft ha introdotto con Windows Vista per sostituire il vecchio `.evt`. È la spina dorsale di quasi ogni incident response su Windows: accessi, avvii di servizi, righe di comando PowerShell, creazioni di processi Sysmon e una lunga lista di canali specifici dei provider vi vengono serializzati.

Nuovo a `.evtx`? Parti da [cos'è un file .evtx](/it/blog/what-is-an-evtx-file) e [come aprirne uno](/it/blog/how-to-open-an-evtx-file). Il resto di questo post è l'orientamento per canali ed Event ID, pensato per gli analisti già a loro agio col formato.

## Com'è strutturato un file

Ogni `.evtx` inizia con un'intestazione da 4 KB (magic `ElfFile\0`, checksum, numero di chunk), seguita da una sequenza di blocchi da 64 KB. Ogni blocco ha la propria intestazione (`ElfChnk`), una tabella dei template XML usati nel blocco e un flusso di record binari che li referenziano per ID. Il parser ricostruisce ogni evento legando i segnaposto del template ai valori contenuti nel record.

## Com'è fatto un record

Una volta decodificato, ogni record è un documento XML con due parti principali:

- `<System>` — nome del provider, canale, Event ID, livello (1 Critico → 5 Dettagliato), nome del computer, contesto di sicurezza e timestamp UTC di scrittura.
- `<EventData>` — parametri specifici del provider: account target in un evento di accesso, percorso dell'immagine in una creazione di processo, ecc.

L'Event ID da solo raramente basta per il triage; il segnale forense vive nel payload `<EventData>`.

## Come questo strumento lo legge

Il parser è il crate Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx), compilato in WebAssembly e caricato in un Web Worker. Quando trascini un file, il worker lo carica in memoria, percorre ogni blocco e ricostruisce l'XML di ogni record. Nulla viaggia in rete — stacca il wifi per verificarlo.
