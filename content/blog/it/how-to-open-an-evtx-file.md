---
title: "Come aprire un file .evtx (5 metodi, nessuna installazione richiesta)"
description: "Cinque modi per aprire un file .evtx di Windows — nel browser, con il Visualizzatore eventi, wevtutil, EvtxECmd o python-evtx. Scegli in base al tuo OS e all'attrito che puoi tollerare."
date: "2026-05-24"
howto:
  name: "Come aprire un file .evtx"
  steps:
    - name: "Aprirlo nel browser (nessuna installazione)"
      text: "Vai alla home page del parser EVTX, trascina il tuo file .evtx sulla zona di upload. Il file viene analizzato localmente in un Web Worker usando un parser EVTX Rust compilato in WebAssembly. Niente viene caricato — disconnetti la rete se vuoi verificarlo. Funziona su Windows, macOS e Linux."
    - name: "Aprirlo nel Visualizzatore eventi (solo Windows)"
      text: "Avvia eventvwr.msc, scegli Azione → Apri registro salvato…, sfoglia fino al file .evtx, dai un nome alla vista e clicca OK. Buono per sfogliare un canale; debole per filtrare migliaia di record."
    - name: "Esportarlo con wevtutil o Get-WinEvent (riga di comando Windows)"
      text: "Esegui wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt per esportare ogni record come testo. Da PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 restituisce oggetti parsati che puoi inoltrare nella pipeline."
    - name: "Analizzarlo con EvtxECmd (CLI multipiattaforma)"
      text: "Scarica EvtxECmd dai tool di Eric Zimmerman, poi esegui EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv per appiattire ogni record (inclusi tutti i campi EventData) in una riga CSV per evento. Gira nativamente su Windows e su macOS/Linux via .NET."
    - name: "Scriptarlo con python-evtx (Python multipiattaforma)"
      text: "pip install python-evtx, poi esegui python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml per ottenere ogni record come XML su stdout. Più lento del parser Rust ma facile da integrare in pipeline e notebook Jupyter."
---

Un file `.evtx` è il formato binario del Windows Event Log ([cosa contiene →](/it/blog/what-is-an-evtx-file)). Non puoi leggerlo con un editor di testo — è BinXML dentro contenitori binari a chunk. Qui sotto ci sono i cinque metodi che coprono ogni caso realistico, in ordine da «trascina il file e hai finito» fino a «collegalo a una pipeline Python».

## Metodo 1 — aprirlo nel browser (nessuna installazione)

Il percorso più rapido su qualsiasi sistema operativo: trascina il file `.evtx` sul parser nella [home page di questo sito](/it). Il file viene letto nella memoria del tuo browser e analizzato localmente da un Web Worker che esegue la crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilata in WebAssembly. Niente lascia la tua macchina — puoi confermarlo disconnettendoti dalla rete prima di rilasciare il file.

Ottieni la stessa vista a livello di record che produce un tool desktop: una timeline filtrabile, l'intero `<EventData>` appiattito in tabella, l'XML completo a un clic e l'export CSV/JSON del set filtrato. Ideale per il triage ad-hoc quando non vuoi installare nulla, non vuoi caricare nulla o sei su una macchina che non è la tua.

**Vincoli.** I limiti di memoria del browser fanno sì che file più grandi di ~500 MB diventino lenti. Per log archiviati di più gigabyte, scendi a uno strumento nativo.

## Metodo 2 — Visualizzatore eventi (solo Windows, integrato)

Ogni installazione Windows include il Visualizzatore eventi. Avvialo con `eventvwr.msc`, poi **Azione → Apri registro salvato…** e seleziona il file `.evtx`. Il Visualizzatore eventi proporrà di importare il file nella vista corrente; accetta e potrai sfogliarlo come qualsiasi canale live.

```text
Azione → Apri registro salvato… → Sfoglia → seleziona .evtx → OK
```

Buono per: sfogliare un singolo file, vedere il messaggio formattato in modo amichevole di un record, copiare-incollare una vista XML. Debole per: filtrare migliaia di record (la UI diventa lenta), export massivo o eseguire query da scriptare.

## Metodo 3 — wevtutil / Get-WinEvent (riga di comando Windows)

`wevtutil` è lo strumento integrato di Windows per la gestione dei log; `Get-WinEvent` è la sua controparte PowerShell. Entrambi funzionano su file `.evtx` salvati, non solo sui canali live.

Esporta ogni record da un `.evtx` salvato in testo:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filtra con XPath (qui, ogni 4624 nelle ultime 24 ore):

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell con la stessa intenzione, ma restituendo oggetti tipizzati:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Buono per: estrazioni scriptate, job pianificati, filtraggio chirurgico. Il trade-off è la verbosità — XPath contro XML è preciso ma non amichevole.

## Metodo 4 — EvtxECmd (CLI multipiattaforma, lo standard DFIR)

[`EvtxECmd` di Eric Zimmerman](https://ericzimmerman.github.io/) è il parser su cui ripiega la maggior parte dei praticanti IR. Gira nativamente su Windows e su macOS / Linux sotto .NET, analizza più velocemente di `wevtutil` e appiattisce ogni campo di `<EventData>` in una colonna CSV. Una riga per record.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Per un'intera cartella `winevt\Logs\` in una sola passata, con map che decodificano i campi degli eventi noti in colonne amichevoli:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Buono per: parsing massivo di collezioni multi-file, import verso un SIEM o un notebook, workflow analista cross-platform. EvtxECmd è la risposta giusta per quasi ogni compito di tipo «analizza questo offline».

## Metodo 5 — python-evtx (scriptarlo in una pipeline)

Quando il file deve alimentare una pipeline Python, [`python-evtx`](https://github.com/williballenthin/python-evtx) è il parser pure-Python.

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

In un notebook o script:

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Più lento della crate Rust (Python interpretato su chunk binari) ma la scelta giusta quando sei già dentro una toolchain Python — notebook forensi Jupyter, job di threat hunting, arricchimenti custom.

## Quale metodo usare e quando

- **Vuoi solo dare un'occhiata al file**: trascinalo sul [parser della home page](/it). Percorso più veloce, zero installazione.
- **Sei su un endpoint Windows con admin e il file è piccolo**: Visualizzatore eventi.
- **Devi scriptare un'estrazione una tantum**: `wevtutil` o `Get-WinEvent`.
- **Stai facendo vero DFIR su collezioni multi-canale**: EvtxECmd.
- **Stai costruendo una pipeline in Python**: `python-evtx`.

## Errori comuni e come leggerli

- **«Il file non sembra essere valido»** nel Visualizzatore eventi di solito significa che il chunk finale è sporco (il file è stato copiato mentre il servizio EventLog ci stava ancora scrivendo). La maggior parte dei parser lo gestisce — prova [il parser nel browser](/it) o `EvtxECmd`, che entrambi segnalano i dirty chunk come avviso e continuano.
- **«Accesso negato»** da `wevtutil` su un file in `winevt\Logs\` è il servizio EventLog che mantiene un lock esclusivo. Vedi [raccogliere .evtx da un sistema live](/it/blog/collecting-evtx-from-live-system) per i quattro modi standard per aggirarlo.
- **Output vuoto da `Get-WinEvent`** su un log salvato: passa il file con `-Path`, non con `-LogName`. `-LogName` legge solo i canali live.
- **`Get-WinEvent` di PowerShell dice «No events were found that match the specified selection criteria»** — le chiavi del tuo `-FilterHashtable` sono case-sensitive su alcune proprietà. Prova prima senza filtro per confermare che il file viene analizzato.

Per il background su cosa c'è davvero dentro un `.evtx` e perché il formato è fatto così, vedi [Cos'è un file .evtx?](/it/blog/what-is-an-evtx-file).
