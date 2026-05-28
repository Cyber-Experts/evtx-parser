---
title: "Cancellazione del log eventi e i buchi che sopravvivono"
description: "Come gli attaccanti svuotano i log eventi di Windows, quali prove restano su disco e nei canali inoltrati, e la differenza tra wevtutil cl e strumenti di sospensione thread come Invoke-Phant0m."
date: "2026-05-27"
tags:
  - evtx
  - anti-forensics
  - dfir
  - incident-response
  - log-tampering
author: "Florian Amette"
---

La cancellazione dei log eventi è la tecnica anti-forense che ogni operatore impara per prima e quella che lascia la scia più utilizzabile. Quella seconda parte è controintuitiva. Tutto il senso di cancellare i log è rimuovere le prove, e un attaccante che riesce a cancellare `Security.evtx` ha rimosso migliaia di eventi che volevi leggere. Ma l'atto di cancellare è di per sé rumoroso, le tecniche che provano a essere più silenziose lasciano una firma diversa e ugualmente diagnostica, e i canali che la maggior parte degli operatori dimenticano preservano abbastanza da ricostruire ciò che è stato cancellato.

Sapere cosa sopravvive conta perché cambia la domanda che fai all'host. „Cosa c'è nel log Security" diventa „cosa manca nel log Security, e dove sono andati altrove quegli eventi".

## 1102, 104, 1100: il modo rumoroso

Il riflesso di default di un operatore che vuole il log Security sparito è `wevtutil cl Security`. Questo produce:

- Un singolo `EventID=1102` in `Security.evtx`, generato subito dopo la cancellazione, che registra l'account che l'ha fatta e l'orario. Questo evento sopravvive nel log svuotato perché è il primo evento scritto nel file appena svuotato. Trattalo come la pistola fumante. Il nome account, la workstation sorgente e l'ora della cancellazione sono tutti nei dati dell'evento.
- Un `EventID=104` corrispondente in `System.evtx` dal provider `Microsoft-Windows-Eventlog`, con il nome del canale svuotato. È lo specchio del log System di `1102`. A volte solo uno dei due sopravvive perché l'operatore ha svuotato più canali e l'ordine conta.
- Un `1100` dal servizio Event Log che indica lo shutdown del servizio, se l'operatore ha fermato il servizio prima di svuotare. La combinazione di `1100` seguito da un buco inspiegato seguito da `1102` è il pattern classico di „shutdown, manomissione, restart".

Questi tre eventi sono la firma rumorosa. Un attaccante che sa quel che fa non li genererà, o li genererà e poi cancellerà *di nuovo* per rimuoverli, il che produce un secondo `1102` e un log superstite ancora più piccolo. Ogni passata di cancellazione lascia un `1102`. Il fatto che un host abbia più `1102` nella sua storia è di per sé anomalo.

Gli eventi che vengono cancellati non sono le uniche vittime. Svuotare un canale resetta il file EVTX sottostante, il che significa che il file su disco viene riscritto. I chunk del vecchio file sono non allocati. Sono recuperabili da disco se imagini l'host in una finestra ragionevole, che è l'altra branca di questa storia (trattata nel post sul carving).

## `wevtutil cl` contro la sospensione thread

Un operatore più sofisticato non svuota i log affatto. Sospende i thread del servizio Windows Event Log (`eventlog`), fa la cosa rumorosa che vuole fare e riprende i thread. Mentre i thread sono sospesi, gli eventi generati dall'OS e dalle applicazioni vengono accodati nell'infrastruttura ETW ma non scritti nel file EVTX. Alla ripresa dei thread, la coda viene per lo più svuotata, ma gli eventi che hanno traboccato il buffer durante la finestra di sospensione sono persi per sempre.

Questo è ciò che fa `Invoke-Phant0m` (PowerShell, di Halil Dalabasmaz). Il modulo Mimikatz `event::drop` fa qualcosa di simile ma opera agganciando il callback ETW all'interno del processo del servizio. Entrambi lasciano:

- Nessun `1102`. Non è stato cancellato nulla.
- Nessun `104`. Stesso motivo.
- Un buco. Gli eventi di prima e dopo la finestra di sospensione sono presenti; quelli interni mancano. Questa è la detection.

Il buco è rilevabile in due modi. Il primo è un controllo di sanità dei RecordID contigui: l'header del chunk EVTX registra `FirstEventRecordIdentifier` e `LastEventRecordIdentifier`, e puoi verificare che i record ID siano monotoni tra chunk. La sospensione non rompe il contatore RecordID (il servizio è sospeso, non il provider ETW kernel), ma i timestamp all'interno del chunk mostreranno una finestra senza eventi da provider attivi, il che su un domain controller è clamorosamente ovvio.

Il secondo è la correlazione contro canali che non puoi sospendere senza elevare di nuovo. Il canale `Microsoft-Windows-EventLog%4Operational.evtx` logga il ciclo di vita del servizio event log stesso. La sospensione thread non genera qui eventi espliciti di „thread sospeso", ma l'heartbeat interno del servizio (eventi `105`, `106` e eventi di debug specifici del provider quando il canale Operational è a verbosità più alta) registra a volte l'incoerenza.

Il terzo, più difficile, è la traccia [Sysmon](https://github.com/SwiftOnSecurity/sysmon-config). Sysmon scrive sul proprio canale tramite il proprio driver e non è influenzato dalla sospensione del servizio event log. Un host con Sysmon avrà un record continuo di creazioni di processo e image load attraverso la finestra di sospensione. Incrocia il tempo del buco sospettato in `Security.evtx` contro il canale `Operational` di Sysmon; se Sysmon mostra un processo `powershell.exe` con contenuto di command-line che combaci col sorgente di Phant0m (o una qualsiasi delle dozzine di varianti pubbliche) in esecuzione all'inizio del buco, hai la tua risposta.

## Il canale forwarded events

Windows Event Collector (WEC) è il meccanismo standard per inoltrare eventi a un collector centrale. Gli eventi inoltrati arrivano al collector in `Microsoft-Windows-EventLog%4ForwardedEvents` (sui subscriber Windows Event Collector) e mantengono il campo `Computer` dell'host originante, il `RecordID` originale e i timestamp originali.

Se il tuo ambiente ha WEC e il collector stesso non è stato compromesso, il canale forwarded events è a volte l'unico record intatto di ciò che è successo su un host il cui log locale è stato svuotato. Gli eventi sono byte-identici a quelli generati sull'host originante (modulo metadati aggiunti dal collector), e il `RecordID` dell'host originante ti permette di ricucire la copia inoltrata nella timeline RecordID del log locale.

L'inghippo: le subscription WEC sono in pull per default, con heartbeat di 15 minuti. Un attaccante veloce può svuotare il log locale tra gli heartbeat di forwarding e il collector avrà solo gli eventi precedenti all'ultimo pull riuscito. Configura le subscription in modalità `MinLatency` (push, con latenza di batch di 30 secondi) sui canali che ti interessano. Costa throughput di rete e collector; si ripaga la prima volta che ne hai bisogno.

L'altro inghippo: WEC non inoltra per default. Se nessuno ha configurato la subscription, il canale collector è vuoto. Controlla lo stato della subscription sui collector candidati prima di scommettere un'indagine su questa via probatoria.

## Cancellazione selettiva e la questione a livello EVTX

La cancellazione selettiva di record (rimuovere eventi specifici da un EVTX vivo lasciando il resto) è teoricamente possibile editando il file con la conoscenza del formato e ricalcolando i CRC del chunk. In pratica nessuno lo fa in operazioni vive perché il servizio event log ha il file aperto e bloccato; non puoi editarlo da user-land senza tirare giù il servizio, e tirare giù il servizio genera eventi `1100`/`105`.

Quello che succede in libertà è la manomissione offline a posteriori. Un operatore che esfiltra il file EVTX, lo edita sulla propria macchina e lo ri-carica per sostituire il file vivo (dopo aver fermato il servizio) lascerà:

- CRC incoerenti sui chunk editati, a meno che non abbia ricalcolato correttamente sia il CRC dell'header del chunk sia il CRC della regione record.
- `LastEventRecordNumber` incoerenti negli header dei chunk se non li ha aggiornati anche.
- Discontinuità nei RecordID attraverso i confini dei chunk.

Qualsiasi parser decente segnala questi. `evtx_dump` avvisa su mismatch CRC per default. `EvtxECmd` logga la discrepanza nel suo output. Tratta qualsiasi warning di CRC durante il parsing di un EVTX da un host sospetto come potenziale indicatore di manomissione e imagina il disco sottostante prima di fare altro.

## Cosa emerge solo in `Microsoft-Windows-EventLog%4Operational.evtx`

Questo canale è separato da `Security.evtx` e la maggior parte degli attaccanti lo ignora. Registra:

- Avvio e arresto del servizio event log (`105`, `106`).
- Cambi di stato del canale (subscription avviata, canale abilitato/disabilitato).
- Eventi di registrazione manifest.

Quando il servizio Event Log viene riavviato (perché l'operatore ha usato `Stop-Service eventlog`, o perché hanno patchato qualcosa e riavviato), qui ottieni eventi che si abbinano alla famiglia `1100`/`105`/`106`. Se `Security.evtx` mostra `1100` al tempo T e `EventLog%4Operational.evtx` mostra un corrispondente cambio di stato del servizio alla stessa T, lo shutdown è stato ordinato. Se `Security.evtx` mostra un buco senza `1100` ma `EventLog%4Operational.evtx` mostra che il servizio è stato riavviato, il servizio è crashato o è stato ucciso senza shutdown ordinato, il che è sospetto di per sé.

Questo canale è piccolo e si legge in fretta. Aggiungilo alla tua checklist di triage di default.

## Convalida incrociata contro artefatti host

Quando il log Security è sparito o doctored, gli artefatti che sopravvivono sono i soliti sospetti:

- La [Master File Table](https://www.mftparser.com) per il file EVTX stesso. I timestamp `$STANDARD_INFORMATION` e `$FILE_NAME` mostreranno quando il file è stato riscritto per cancellazione.
- Il [journal USN](https://www.usnparser.com) per eventi `DATA_OVERWRITE` e `DATA_TRUNCATION` su `Security.evtx`. Questi mostrano la cancellazione in termini journal con timestamp ad alta risoluzione.
- Il [Prefetch](https://www.prefetchparser.com) per l'esecuzione di `wevtutil.exe`, o per esecuzioni di `powershell.exe` che combaciano con la cancellazione sospettata.
- [Shimcache](https://www.shimcacheparser.com) e [AmCache](https://www.amcacheparser.com) per il tooling che l'operatore ha portato per eseguire la cancellazione, in particolare se ha usato un binario non standard.
- Artefatti di [dump RAM](https://www.ramparser.com) se ne hai catturato uno. La cache in memoria del servizio event log avrà record che non sono mai stati flushati sul disco.

Il log Security è una fonte. Trattalo come una fonte. L'indagine che dipende solo da esso è a un file manomesso dall'essere inutile. Il [parser di questo sito](https://www.evtxparser.com) segnala mismatch di CRC dei chunk e buchi di RecordID nel suo output, che è il controllo di prima passata più economico per sapere se stai guardando un log manomesso prima di averci investito un'ora di lettura.

## Per approfondire

- Il [sorgente di Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m) di Halil Dalabasmaz. Leggi cosa fa. La detection ne segue direttamente.
- La [voce del ThreatHunter-Playbook su 1102](https://threathunterplaybook.com/hunts/windows/180815-WindowsLogCleared.html) di Roberto Rodriguez e il materiale di clearing-detection circostante.
- La documentazione Microsoft sulle [subscription Windows Event Collector](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription) per la configurazione WEC che ti dà la rete di sicurezza dei forwarded events.
