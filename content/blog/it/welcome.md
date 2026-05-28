---
title: "Inizia qui: guida a .evtx per l'analista DFIR"
description: "Cos'è .evtx, quali canali contano, gli Event ID da conoscere e dove trovare ciascuno su disco. Un punto di partenza per tutto il resto del blog."
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` è il formato binario del log eventi di Windows che Microsoft ha introdotto con Vista per sostituire il vecchio `.evt`. È la spina dorsale di ogni incident response su Windows: accessi, installazioni di servizi, attività pianificate, righe di comando PowerShell, alberi di processo Sysmon. Tutto viene serializzato in questo formato. Questo post è l'indice. Un orientamento su una schermata, poi i link ai post più approfonditi sui canali e sugli Event ID che davvero contano in un caso.

Nuovo a `.evtx`? Parti da [cos'è un file .evtx](/it/blog/what-is-an-evtx-file) e [come aprirne uno](/it/blog/how-to-open-an-evtx-file). Il resto di questo post presume che tu sia già a tuo agio con il formato e voglia sapere cosa leggere per primo quando un host sta bruciando.

## Dove stanno i file

I log attivi risiedono sotto `C:\Windows\System32\winevt\Logs\`. Un canale, un file `.evtx`. I predefiniti che avrai sempre:

- `Security.evtx`. Accessi, uso di privilegi, modifiche alla policy di audit. Il valore forense più alto nella maggior parte dei casi.
- `System.evtx`. Driver, servizi, errori a livello OS.
- `Application.evtx`. Errori a livello applicativo.
- `Setup.evtx` e `ForwardedEvents.evtx`. Record di installazione e traffico WEF inoltrato.

Più i canali per applicazione sotto `Microsoft-Windows-*`. Quelli che si guadagnano il pane in un caso:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Presente solo se Sysmon è installato. Vale oro quando c'è.
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Logging di scriptblock e moduli.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Creazione ed esecuzione di attività pianificate.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Ciclo di vita delle sessioni RDP.

Per i dettagli profondi su come un file è strutturato (i chunk da 64 KB, le tabelle di template XML, BinXML), vedi [l'approfondimento a livello di chunk](/it/blog/evtx-file-format-chunks).

## Gli Event ID da conoscere

La lista breve che copre la maggior parte di ciò su cui pivota un analista:

- [**4624** accesso riuscito](/it/blog/understanding-event-id-4624). Leggilo tramite `LogonType`. Il campo decide se stai guardando console (2), rete (3), RDP (10) o `runas /netonly` (9).
- [**4625** accesso fallito](/it/blog/detecting-4625-brute-force). Le raffiche sono ricognizione, brute force o password spray a seconda di quali campi si raggruppano.
- [**1102** log di sicurezza svuotato](/it/blog/event-id-1102-cleared-log). Se lo vedi, il log che hai in mano ha un buco noto. Annotalo a chiare lettere.
- [**4104** scriptblock PowerShell](/it/blog/powershell-4104-scriptblock). Il corpo dello script *dopo* decodifica e riflessione. Il controllo difensivo gratuito più utile della piattaforma.
- [**7045** servizio installato](/it/blog/service-creation-event-id-7045). Una delle tecniche di persistenza più citate di MITRE ATT&CK (T1543.003). Anche la firma di PsExec.
- [**Sysmon 1** creazione di processo](/it/blog/sysmon-event-id-1-process-create). Il record di creazione di processo più ricco che Windows possa produrre quando Sysmon è presente.

Per il workflow che li lega, leggi [triage EVTX quando hai un'ora e un host](/it/blog/evtx-triage-incident-response).

## Come si inserisce questo sito

Il parser nella home page è il crate Rust [omerbenamram/evtx](https://github.com/omerbenamram/evtx) compilato in WebAssembly ed eseguito dentro un Web Worker. Trascini un `.evtx`, il worker percorre i chunk e ottieni una timeline di eventi filtrabile più l'XML per record. Tutto nel browser, niente viene caricato. Usalo per triage ad hoc quando non vuoi tirare su un EDR o spostare un file da un sistema che non ti appartiene.

Se stai [raccogliendo `.evtx` da un host vivo](/it/blog/collecting-evtx-from-live-system) (KAPE, FTK Imager, `wevtutil`), quel post copre i quattro metodi standard con i compromessi sulla catena di custodia di ciascuno.

EVTX raramente è l'unico artefatto di cui hai bisogno. Abbinalo ai parser per [registro](https://www.registryparser.com), [MFT](https://www.mftparser.com), [journal USN](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com), [Shimcache](https://www.shimcacheparser.com), [prefetch](https://www.prefetchparser.com) e [LNK](https://www.lnkparser.com). Quando serve scavare più a fondo, il parsing del [pagefile](https://www.pagefilesysparser.com) e del [dump RAM](https://www.ramparser.com) recupera ciò che i log su disco hanno perso. Per le timeline di attività utente, [SRUM](https://www.srumparser.com), [jump list](https://www.jumplistparser.com), [cestino](https://www.recyclebinparser.com), [recent file cache](https://www.recentfilecacheparser.com) e [cronologia browser](https://www.browserforensics.app) coprono le lacune che EVTX non può colmare.
