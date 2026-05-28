---
title: "Triage EVTX: cosa leggere per primo quando hai un'ora e un host"
description: "L'ordine delle operazioni di un praticante per fare triage di Windows Event Logs durante incident response: quali canali contano, quali event ID vi mentono, e dove Sysmon fa il lavoro pesante."
date: "2026-05-27"
tags:
  - evtx
  - incident-response
  - windows-event-logs
  - sysmon
  - dfir
author: "Florian Amette"
---

Se qualcuno vi consegna un bundle EVTX da un host che pensa sia compromesso e vi dà un'ora, non avete tempo per l'eleganza. Avete tempo per un ordine di operazioni che ha funzionato abbastanza volte da fidarvene prima di aver letto un singolo record.

Questo è il mio. Non è il riferimento completo e non è la cosa giusta per ogni caso, le indagini insider a fuoco lento richiedono una postura completamente diversa, ma per la domanda standard "questa cosa è bucata, e come", questo è quello che faccio girare.

## Quali canali ripagano davvero il tempo

Un'installazione Windows di default porta da qualche parte oltre i trecento canali EVTX. Ne guarderete forse sette. Quelli che contano costantemente:

- `Security.evtx` logon, uso di privilegi, modifiche di account. Prima fermata per ogni incidente interattivo.
- `Microsoft-Windows-Sysmon%4Operational.evtx` se Sysmon è deployato (e dovreste implorare, supplicare, minacciare finché non lo è), qui vive il segnale vero. Process create con command line, file create, connessioni di rete, DNS, image load. Tutto ciò a cui `Security.evtx` allude senza dirlo.
- `System.evtx` installazioni di servizio, driver caricati, eventi di boot, cambi di ora. Spesso l'unico posto dove il lateral movement lascia un'installazione di servizio.
- `Application.evtx` di solito rumore, ma errori di macro di Office, eccezioni .NET e alcuni side-channel di EDR emergono qui.
- `Microsoft-Windows-PowerShell%4Operational.evtx` module logging ed eventi di pipeline, se abilitati. Il log script block `4104` è dove trovate ogni riga di PowerShell malevolo, supposto che il logging fosse acceso. È il secondo canale più importante dopo Sysmon quando entrambi sono attivi.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` creazione, eliminazione ed esecuzione di task pianificati. Si legge corto, ripaga veloce.
- `Microsoft-Windows-WMI-Activity%4Operational.evtx` sottoscrizioni WMI e registrazioni di consumer. Economico da leggere; cattura uno schema di persistenza specifico.

Se l'host ha Defender, prendetevi anche `Microsoft-Windows-Windows Defender%4Operational.evtx`. La famiglia `1116` / `1117` è a volte l'unica menzione contemporanea del file che contava.

Tutto il resto potete lasciarlo per la seconda passata.

## La prima cosa che apro non è il Security log

Il riflesso di default è grepare `Security.evtx` per `4624`. Ho smesso di farlo alla prima passata e probabilmente dovreste anche voi. Il Security log su un server occupato logga migliaia di logon legittimi all'ora. Annegherete nel rumore prima di aver inquadrato la domanda.

Quello che apro per primo, quando esiste, è `Sysmon%4Operational.evtx` filtrato a `EventID=1` (process create) dentro la finestra sospetta. Sysmon vi dà il processo padre, la command line come invocata effettivamente, l'utente, l'integrity level, e gli hash sia del padre che del figlio. È abbastanza per leggere una storia dallo schermo.

Se Sysmon non c'è (e su un numero deprimente di parchi Windows aziendali ancora non c'è), la mia mossa successiva è `Security.evtx` filtrato a `4688` *con auditing di command line abilitato*. Se le command line non sono auditate ottenete solo il nome del programma, che è appena utile, a quel punto salto ad AmCache, Prefetch e l'[USN journal](https://www.usnparser.com) per ricostruire cosa è girato.

Il corollario che vale la pena dire ad alta voce: un'indagine EVTX senza Sysmon e senza command line `4688` è in gran parte un gioco di indovinello. Se state leggendo questo prima di un incidente, sistemate quello prima.

## Gli event ID che smettete di dover cercare

Li imparate a memoria col tempo. La versione corta, con il modo in cui penso a ciascuno in IR:

- `4624` logon riuscito. Leggete `LogonType` per primo: `3` è rete (file share, strumento remoto), `10` è RDP / Terminal Services, `2` è interattivo, `9` è `runas` con credenziali esplicite. `5` è servizio. Il `LogonType` porta più significato dell'evento stesso.
- `4625` logon fallito. Raffiche sono attacchi spray; isolati su molti account sono credential stuffing.
- `4634` / `4647` logoff e logoff iniziato dall'utente. Utile per chiudere la parentesi su una sessione.
- `4648` logon con credenziali esplicite. Quello che volete davvero per attribuzione lateral movement: quando l'account A usa le credenziali dell'account B per avviare un processo o connettersi da qualche parte, è quel record. La maggior parte dei difensori lo sottoutilizza.
- `4672` privilegi speciali assegnati al logon. La riga "questo account è appena diventato admin". Abbinare al `4624` che segue.
- `4688` process create. Utile solo quando l'auditing di command line è abilitato (Group Policy: *Audit Process Creation* e *Include command line in process creation events*). Senza, ottenete nomi di programma.
- `4697` servizio installato. Lateral movement via PsExec, Impacket-`smbexec`, e tooling simile vive qui.
- `4720` / `4732` / `4738` account creato, cambio di appartenenza a gruppo, account modificato. La persistenza ama questi.
- `1102` il Security log è stato cancellato. Se vedete questo, il resto del security log fino a quel punto è sospetto o assente. Il fatto che l'evento esista è la pistola fumante.
- `5140` / `5145` accesso a share di rete. Il secondo logga il nome del file; se è attivo, lateral movement via SMB è auditabile in dettaglio.
- `7045` servizio installato (System log). Riflette `4697` ma dal canale System.
- `Sysmon 1` process create con contesto completo. L'event ID più utile in DFIR se Sysmon è attivo.
- `Sysmon 3` connessione di rete. Cattura C2 in uscita anche quando Defender non l'ha fatto.
- `Sysmon 10` process access. Quello che cattura credential dumping da `lsass.exe`.
- `Sysmon 11` file create. Cattura attività di dropper che non ha avuto la possibilità di eseguire.
- `PowerShell 4104` script block logging. Registra il testo completo di ogni comando PowerShell, inclusi quelli offuscati (deoffuscati post-decode in molti casi).

Tengo un cheat sheet stampato accanto alla scrivania e dovreste anche voi. Non è glamour e fa risparmiare minuti veri.

## Gli eventi che vi mentono o sono facili da fraintendere

`4624 Type 3` da `\\NT AUTHORITY\ANONYMOUS LOGON` non è "l'attaccante è dentro". Di solito è un'enumerazione di share mal configurata, uno scanner di vulnerabilità, o uno tra mezza dozzina di meccanismi interni Windows. Validate prima di escalare.

`4625` contro un singolo service account al ritmo di uno al minuto è quasi sempre una credenziale stale cachata da qualche parte. Guardate il campo source workstation prima di chiamarlo brute force.

I timestamp in Security.evtx sono ora locale sull'host che li ha generati di default in alcuni tool, UTC in altri. Quando caricate un bundle in un nuovo tool, fate una sanity check trovando un logon che potete correlare con un evento esterno conosciuto (un aggiornamento di ticket, una sessione VPN) e confermate gli offset. Ho visto interi report sfasati di 4 ore perché qualcuno si è dimenticato di controllare.

Il clearing dell'event log (`1102`) è di solito rumoroso, ma la cancellazione selettiva di record è un'altra bestia. `wevtutil cl` cancella l'intero canale, che è rilevabile. Tool come `phant0m` e `Invoke-Phant0m` invece sospendono i thread del servizio eventi, che non lascia evento di clearing ma crea un gap visibile. Cercate il gap, non solo il `1102`.

I forwarded events (`Microsoft-Windows-EventLog%4ForwardedEvents`) preservano il RecordID originale dell'host di origine e i timestamp originali. Se avete un subscriber WEC che è sopravvissuto all'incidente, quelle copie sono a volte l'unico record intatto rimasto.

Se il Security log mostra `1100` (shutdown del servizio eventi) seguito da un gap inspiegato, state guardando uno dei tentativi più puliti di cancellare evidenze. Cross-validate contro [hive del registro](https://www.registryparser.com), la [Master File Table](https://www.mftparser.com), e Prefetch.

## Carving e recupero, quando mancano record

I record EVTX possono essere carvati da disco non allocato e da [pagefile.sys](https://www.pagefilesysparser.com) quando il file vivo è stato cancellato o ruotato. L'header del record (magic `2a 2a 00 00`) è abbastanza distintivo da rendere il signature carving ragionevolmente funzionante. `hayabusa` di Yamato Security ed `evtx_dump` gestiscono entrambi file malformati con stream di record rappezzati.

Se avete a che fare con un host dove sospettate che il log sia stato manomesso, provate anche a recuperare record EVTX da un [dump RAM](https://www.ramparser.com). Il servizio event log cacha record recenti in memoria; uno snapshot preso vicino all'incidente a volte contiene record che non sono mai arrivati sul disco.

## Dove andare da un hit

Un singolo evento raramente chiude un caso. I pivot a cui mi rivolgo, in ordine:

- Un `4624` sospetto cercate il `4672` corrispondente, i fallimenti `4625` precedenti, e quale processo è stato creato con quel token successivamente (Sysmon 1 con `LogonId` corrispondente).
- Un'installazione di servizio `7045` o `4697` controllate `Microsoft-Windows-TaskScheduler%4Operational.evtx` per task successivi, e il [registry](https://www.registryparser.com) `HKLM\SYSTEM\CurrentControlSet\Services\` per il path del binario.
- Un Sysmon 10 contro `lsass.exe` albero dei processi del processo richiedente, drop di file nella working directory, connessioni di rete a destinazioni non-aziendali.
- Un PowerShell 4104 con contenuto offuscato decodate in una sandbox, poi cercate lo stesso payload che atterra su altri host (la maggior parte degli attori enterprise riutilizza).

## Leggere EVTX nel browser

Il parser su questo sito legge EVTX interamente client-side: droppate un file e ottenete una tabella ordinabile e filtrabile con canale, RecordID, EventID, ora, computer e l'XML renderizzato. Nessun upload, che conta perché EVTX da ambienti regolamentati contiene quasi sempre PII che non volete attraversi un confine di vendor.

## Per approfondire

- [JPCERT/CC "Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) il singolo documento più utile sulla correlazione di eventi di lateral movement. Vale una lettura lenta.
- [EvtxECmd](https://github.com/EricZimmerman/evtx) di Eric Zimmerman parser offline con gli output canonici di field-mapping.
- La configurazione Sysmon che Microsoft Threat Intelligence (precedentemente SwiftOnSecurity) mantiene come baseline: [sysmon-modular](https://github.com/olafhartong/sysmon-modular). Partite da qui, non scrivete la vostra da zero.

La versione cinica di tutto sopra: con Sysmon e auditing di command line, EVTX vi dà l'80% di quello che vi serve per ricostruire un'intrusione. Senza, state facendo forensics sulla sagoma dell'evento piuttosto che sull'evento stesso.
