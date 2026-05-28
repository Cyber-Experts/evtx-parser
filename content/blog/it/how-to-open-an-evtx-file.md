---
title: "Come aprire un file .evtx (5 metodi, nessuna installazione richiesta)"
description: "Cinque modi per aprire un file .evtx di Windows: nel browser, in Event Viewer, con wevtutil, con EvtxECmd o con python-evtx. Scegliete in base all'OS dell'host e a quanta frizione tollerate."
date: "2026-05-24"
howto:
  name: "Come aprire un file .evtx"
  steps:
    - name: "Apritelo nel browser (nessuna installazione)"
      text: "Andate alla home page del parser EVTX, droppate il vostro file .evtx nella zona di upload. Il file viene parsato localmente in un Web Worker usando un parser EVTX Rust compilato in WebAssembly. Niente viene caricato. Funziona su Windows, macOS e Linux."
    - name: "Apritelo in Event Viewer (solo Windows)"
      text: "Lanciate eventvwr.msc, scegliete Azione poi Apri registro salvato, navigate al file .evtx, nominate la vista e cliccate OK. Buono per sfogliare un canale; debole per filtrare migliaia di record."
    - name: "Fatene il dump con wevtutil o Get-WinEvent (riga di comando Windows)"
      text: "Eseguite wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt per esportare ogni record come testo. Da PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 ritorna oggetti parsati che potete pipare oltre."
    - name: "Parsatelo con EvtxECmd (CLI cross-platform)"
      text: "Scaricate EvtxECmd dagli strumenti di Eric Zimmerman, poi eseguite EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv per appiattire ogni record (inclusi tutti i campi EventData) in una riga CSV per evento."
    - name: "Scriptatelo con python-evtx (Python cross-platform)"
      text: "pip install python-evtx, poi eseguite python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml per ottenere ogni record come XML su stdout. Più lento del parser Rust ma facile da embeddare in pipeline e notebook Jupyter."
---

Un file `.evtx` è il formato binario di Windows Event Log ([cosa c'è dentro uno](/en/blog/what-is-an-evtx-file)). Non potete leggerlo con un editor di testo. È BinXML dentro container binari a chunk. Ci sono cinque metodi che coprono ogni caso realistico, in ordine approssimativo da "droppa il file e hai finito" a "cablalo in una pipeline Python".

## Metodo 1: apritelo nel browser, nessuna installazione

Il percorso più veloce su qualsiasi sistema operativo. Droppate il `.evtx` sul parser nella [home page di questo sito](/en). Il file viene letto nella memoria del browser e parsato localmente da un Web Worker che esegue il crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilato in WebAssembly. Niente lascia la vostra macchina. Confermate disconnettendovi dalla rete prima di droppare il file.

Ottenete la stessa vista a livello record che produce un tool desktop: timeline filtrabile, `<EventData>` completo appiattito nella tabella, XML completo a un click di distanza, export CSV/JSON del set filtrato. Adatto per triage ad-hoc quando non volete installare nulla, non volete caricare nulla, o siete su una macchina che non è vostra.

Vincolo. I cap di memoria del browser significano che file più grandi di circa 500 MB diventano lenti. Per log archiviati di più gigabyte, scendete a un tool nativo.

## Metodo 2: Event Viewer, solo Windows, integrato

Ogni installazione Windows ha Event Viewer. Lanciate `eventvwr.msc`, poi **Azione / Apri registro salvato** e scegliete il `.evtx`. Event Viewer si offre di importare il file nella vostra vista corrente. Accettate e potete sfogliarlo come qualsiasi canale live.

```text
Azione -> Apri registro salvato -> Sfoglia -> seleziona .evtx -> OK
```

Buono per sfogliare un singolo file, guardare il messaggio formattato in modo amichevole di un record, copia-incolla una vista XML. Debole per filtrare migliaia di record (la UI rallenta), export di massa, o eseguire query che volete scriptare. Anche il più severo sui trailing chunk dirty: rifiuterà file che altri tool accettano.

## Metodo 3: wevtutil e Get-WinEvent, riga di comando Windows

`wevtutil` è l'integrato Windows per la gestione log. `Get-WinEvent` è la sua controparte PowerShell. Entrambi funzionano su file `.evtx` salvati, non solo su canali live.

Dumpare ogni record da un `.evtx` salvato in testo:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filtrare con XPath. Ogni 4624 nelle ultime 24 ore:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell con stessa intenzione, ma ritornando oggetti tipati:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Buono per estrazione scriptata, job pianificati, filtro chirurgico. Il trade-off è la verbosità. XPath contro XML è preciso ma non amichevole.

## Metodo 4: EvtxECmd, lo standard DFIR

L'[`EvtxECmd` di Eric Zimmerman](https://ericzimmerman.github.io/) è il parser a cui la maggior parte dei praticanti IR si rivolge di default. Gira nativamente su Windows e su macOS / Linux sotto .NET. Parsa più veloce di `wevtutil` e appiattisce ogni campo `<EventData>` in una colonna CSV. Una riga per record.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Per un'intera cartella `winevt\Logs\` in una passata, con map che decodificano campi di eventi noti in colonne amichevoli:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Giusto per parse di massa di collezioni multi-file, importazione in un SIEM o notebook, workflow analista cross-platform. EvtxECmd è la risposta giusta per quasi ogni task di "parsa questo offline". Abbinatelo al target `EventLogs` di KAPE e avete una engagement a un comando.

## Metodo 5: python-evtx, scriptatelo in una pipeline

Quando il file deve alimentare una pipeline Python, [`python-evtx`](https://github.com/williballenthin/python-evtx) è il parser Python puro.

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

Più lento del crate Rust (Python interpretato su chunk binari) ma la chiamata giusta quando siete già dentro una toolchain Python: notebook forensi Jupyter, job di threat-hunting, arricchimento custom, joinare dati EVTX agli artefatti [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN](https://www.usnparser.com), o [prefetch](https://www.prefetchparser.com) dallo stesso caso.

## Quale metodo usare quando

- Volete solo guardare il file: droppatelo sul [parser della home page](/en). Il più veloce, zero installazione.
- Endpoint Windows con admin e il file è piccolo: Event Viewer.
- Estrazione one-shot scriptata: `wevtutil` o `Get-WinEvent`.
- DFIR vero su collezioni multi-canale: EvtxECmd.
- Costruire una pipeline in Python: `python-evtx`.

## Errori comuni e come leggerli

- "Il file non sembra essere valido" in Event Viewer significa quasi sempre che il trailing chunk è dirty (il file è stato copiato mentre il servizio EventLog stava ancora scrivendo). La maggior parte dei parser gestisce questo. Provate [il parser browser](/en) o `EvtxECmd`, che entrambi riportano chunk dirty come warning e continuano.
- "Accesso negato" da `wevtutil` contro un file in `winevt\Logs\` è il servizio EventLog che tiene un lock esclusivo. Vedete [raccogliere .evtx da un sistema live](/en/blog/collecting-evtx-from-live-system) per i quattro modi standard di aggirarlo.
- Output vuoto da `Get-WinEvent` su un log salvato. Passate il file con `-Path`, non `-LogName`. `-LogName` legge solo canali live.
- PowerShell `Get-WinEvent` dice "Nessun evento corrispondente ai criteri di selezione specificati". Le vostre chiavi `-FilterHashtable` sono case-sensitive su alcune proprietà. Provate prima senza il filtro per confermare che il file parsa.

Per background su cosa c'è realmente dentro un `.evtx` e perché il formato sembra come sembra, vedete [il deep dive a livello chunk](/en/blog/evtx-file-format-chunks).

## Per approfondire

- [Strumenti di Eric Zimmerman](https://ericzimmerman.github.io/)
- [omerbenamram/evtx (Rust)](https://github.com/omerbenamram/evtx)
- [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx)
