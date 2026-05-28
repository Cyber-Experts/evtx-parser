---
title: "Carving di record EVTX cancellati e recupero di log sovrascritti"
description: "Carving per firma di record EVTX da spazio non allocato, pagefile e memoria, e gli strumenti che gestiscono con grazia i chunk malformati quando al log vivo manca ciò che serve."
date: "2026-05-27"
tags:
  - evtx
  - carving
  - dfir
  - data-recovery
  - anti-forensics
author: "Florian Amette"
---

Il log Security su un domain controller carico si avvolge in ore, non in giorni. La dimensione di canale predefinita è 20 MB, che su un host rumoroso fanno qualche migliaio di record. Quando immagini il disco in risposta a un incidente iniziato tre settimane fa, gli eventi che volevi davvero sono già usciti dal file vivo e si trovano nello spazio non allocato, nel pagefile e possibilmente nell'hibernation. Recuperarli con carving fa parte della routine di ogni indagine guidata da EVTX, e la maggior parte dei difensori salta questo passaggio perché tratta il file vivo come fonte di verità.

Non lo è. Il file vivo sono gli ultimi 20 MB. Il disco ha il resto.

## La firma: `2a 2a 00 00`

Ogni record EVTX inizia con il magic da 4 byte `2a 2a 00 00`. Cioè `**` seguito da due null byte. Questa firma è abbastanza distintiva che scansionare un'immagine di disco grezza con `bulk_extractor`, `scalpel` o anche un grep da 4 byte fatto in casa restituisce un insieme utile di candidati. La densità di firma su un volume Windows è bassa; la maggior parte degli hit sono record reali.

La struttura che segue il magic è definita abbastanza bene da poter validare gli hit a basso costo:

- Byte 4-7: `Size` (uint32). Deve essere plausibile (minimo 32 byte, tipicamente sotto i 4 KB).
- Byte 8-15: `EventRecordIdentifier` (uint64). Deve essere un RecordID ragionevole per la finestra temporale.
- Byte 16-23: `WriteTime` come FILETIME. Deve cadere tra Vista (la prima versione con EVTX) e ora.
- Byte da `Size-4` a `Size`: lo stesso valore `Size`, ripetuto come marker di coda.

Un candidato dove il `Size` di testa corrisponde al `Size` di coda, il FILETIME si decodifica in una data plausibile e il RecordID è nel range, è con probabilità schiacciante un record reale. I falsi positivi crollano quasi a zero con questi quattro controlli.

La sfida è cosa fare con i byte tra testa e coda.

## Il problema del chunk

I record EVTX referenziano template e stringhe memorizzati una volta per chunk. Un record carvato in isolamento ha array di sostituzione senza un template a cui applicarli. Puoi leggere i valori tipizzati direttamente dall'array di sostituzione, il che basta per recuperare dati a livello di campo ("l'utente X ha effettuato il logon al tempo T dall'IP Y"), ma l'XML renderizzato che otterresti da un parser vivo non è ricostruibile senza il chunk.

Questa è la differenza tra due esiti di carving:

- **Carving solo del record**: recuperi RecordID, timestamp, EventID e i valori di sostituzione. Puoi costruire una vista campo per campo dell'evento, ma non l'XML renderizzato leggibile.
- **Carving di chunk**: trovi un chunk (magic `ElfChnk\0`, allineato a 64 KB) e recuperi la sua tabella dei template insieme ai record. Adesso hai tutto.

Anche `ElfChnk\0` è carvabile per firma. L'allineamento a 64 KB aiuta perché i chunk cadono sui confini di settore su disco; uno scan di firma allineato per offset è veloce. La maggior parte degli strumenti di carving supporta entrambe le modalità, e dovresti eseguirle entrambe. I chunk ti danno eventi leggibili; i record orfani ti danno il resto quando nessun chunk avvolgente è sopravvissuto.

## Dove vivono i byte

I posti che vale la pena scansionare, per resa:

- **Cluster non allocati sul volume che ospita `%SystemRoot%\System32\winevt\Logs\`**. Quando un file EVTX si avvolge o viene svuotato, i contenuti vecchi diventano non allocati. NTFS non azzera i cluster non allocati, quindi i byte sono recuperabili finché non vengono riutilizzati. Su un server con poco churn in scrittura, possono essere settimane.
- **Slack space nel file EVTX vivo**. I file EVTX sono scritti in chunk da 64 KB. L'ultimo chunk del file è spesso parzialmente riempito, con lo slack che contiene la generazione precedente di dati scritti in quei byte prima che il chunk corrente venisse ridimensionato. Vale la pena scansionarlo.
- **[pagefile.sys](https://www.pagefilesysparser.com)**. Il servizio event log mette in cache record e template recenti in memoria. Le pagine che supportano quelle strutture vengono swappate sotto pressione di memoria. Il pagefile è una miniera d'oro per record mai scritti su disco perché l'host è crashato o è stato ucciso prima che ci arrivassero.
- **`hiberfil.sys`**. Snapshot compresso della memoria fisica al momento dell'hibernation. Decomprimi con `Volatility 3` o Hibr2Bin e cerca le firme dei record nella memoria grezza risultante.
- **[Dump RAM](https://www.ramparser.com)** catturato durante la risposta dal vivo. Il working set del servizio event log conterrà record recenti e i template necessari a renderizzarli.
- **Shadow copy (VSS)**. Vecchi snapshot del volume contengono vecchie versioni dei file EVTX vivi. `vshadow` o `vssadmin list shadows` seguito da `mklink /d` per montare lo shadow ti dà una copia di generazione precedente del file con i record che erano vivi al momento dello shadow.

VSS è la fonte a maggior leva sugli host che lo hanno abilitato e che non sono stati manipolati a livello VSS. Un server Windows moderno ha tipicamente 7-30 giorni di shadow copy. Se l'incidente è successo tre settimane fa, lo shadow del momento dell'incidente potrebbe avere il log vivo così come esisteva allora, non manomesso.

## Strumenti che gestiscono input malformato

Un file EVTX pulito è raro negli scenari di carving. Avrai chunk parziali, record senza coda, template che referenziano offset fuori dal chunk, e fallimenti di CRC ovunque. I parser che gestiscono questo non sono gli stessi che gestiscono file puliti.

- **`EvtxECmd`** (Eric Zimmerman). Il migliore della categoria per il lavoro IR sul campo. Passa `--inc` per includere record che hanno fallito il parsing normale ed emetterà quello che è riuscito a leggere dei record parziali. L'output CSV è quello che vuoi per il lavoro di timeline.
- **`hayabusa`** (Yamato Security). Costruito per l'hunting su grandi corpora EVTX, con regole in stile sigma. Gestisce ragionevolmente i chunk parziali ed è veloce. Il filtro `--exclude-status` ti permette di ridurre il rumore dai record corrotti.
- **`evtx_dump`** (la crate Rust di Omer Ben-Amram). Robusto contro strutture malformate, output JSONL. Buono per il pipelining in `jq` o in un SIEM.
- **`evtxtools`** (Joachim Metz, parte di libevtx). L'implementazione di riferimento canonica del formato. Più lento degli altri ma ti dice esattamente quale campo ha fallito quale validazione quando un record è parzialmente recuperato, che è ciò che vuoi quando debugghi output di carving.
- **`bulk_extractor`** con lo scanner EVTX. Il passo di carving in sé. Restituisce i record candidati con i loro offset nell'immagine sorgente per validazione successiva.

Una pipeline pratica:

1. `bulk_extractor -E evtx -o out/ image.dd` per carvare record e chunk candidati dall'immagine di disco.
2. Riassembla i chunk in file EVTX sintetici concatenando i chunk carvati con un header di file forgiato. Gli esempi di `libevtx` includono un riassemblatore di chunk compatibile con `evtxexport`.
3. Esegui `EvtxECmd` sul file riassemblato con `--inc` per scaricare tutto ciò che è leggibile in CSV.
4. Diffa i RecordID carvati contro i RecordID del file vivo per trovare i record che non c'erano nel log vivo.

L'output del passo 4 è ciò che il carving ti dà: gli eventi che l'attaccante o il tempo hanno rimosso dal file vivo.

## Quando il log vivo non mostra niente perché si è avvolto

Il caso comune per il carving non è la cancellazione anti-forense; è il rollover. Un incidente di 30 giorni fa su un host con log Security da 20 MB e 50 eventi al secondo ha avvolto l'intero file dozzine di volte. Il log vivo mostra le ultime ore. Tutto il resto in mezzo è nel non allocato.

Il carving qui è semplice perché non c'è stata manipolazione. Scansioni il non allocato, trovi chunk, riassembli. La resa dipende da quanto churn in scrittura ha avuto il volume dal rollover. Un volume server con file di sistema per lo più statici e con la directory EVTX come fonte di scrittura dominante terrà a lungo i vecchi chunk intatti. Un volume con scritture applicative pesanti sovrascriverà più velocemente le regioni non allocate.

Un trucco che aiuta: la directory EVTX è a `%SystemRoot%\System32\winevt\Logs\`, che è uno dei punti più freddi del volume in termini di scritture concorrenti. I run di cluster che si sono liberati al rollover del file EVTX restano spesso non allocati per settimane. Lo stesso non vale per i volumi che ospitano dati applicativi.

## Cosa fare con ciò che recuperi

I record carvati vanno nella stessa timeline dei record vivi. Il RecordID e il WriteTime sopravvivono al carving e sono le chiavi di join. Un `4624 Type 3` carvato al momento dell'accesso iniziale sospettato è utile quanto uno vivo, con la precisazione che potresti non essere in grado di renderizzarne l'XML completo.

Incrocia con:

- Le voci della [Master File Table](https://www.mftparser.com) per `Security.evtx` per vedere quando il file è stato riscritto per cancellazione o rollover.
- Il [journal USN](https://www.usnparser.com) per eventi `DATA_OVERWRITE` sul file EVTX, che dà timestamp ad alta risoluzione per ogni rollover.
- Il [Prefetch](https://www.prefetchparser.com) per i binari che sono girati durante il buco, dato che `Prefetch` è indipendente da `Security.evtx` e sopravvive alla cancellazione del log.
- [AmCache](https://www.amcacheparser.com) e [Shimcache](https://www.shimcacheparser.com) per le prove di prima esecuzione.
- Gli hive del [registro](https://www.registryparser.com) negli shadow per lo stato al momento dell'incidente.

Un record carvato che si allinea con una voce di Prefetch e un timestamp MFT su un binario sospetto è una scoperta. Un record carvato da solo è un indizio che vale la pena inseguire.

## Per approfondire

- Il lavoro originale di carving di Andreas Schuster nel [paper DFRWS 2007](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf). Le euristiche di carving in ogni strumento moderno tornano qui.
- La documentazione di [EvtxECmd](https://github.com/EricZimmerman/evtx) di Eric Zimmerman e il flag `--inc` per la gestione dei record parziali.
- [hayabusa](https://github.com/Yamato-Security/hayabusa) di Yamato Security e il suo corpus di esempio fornito, utile per testare le pipeline di carving.
- [bulk_extractor](https://github.com/simsong/bulk_extractor) di Simson Garfinkel e il suo modulo scanner EVTX.
