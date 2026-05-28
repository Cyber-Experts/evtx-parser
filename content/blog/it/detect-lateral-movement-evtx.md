---
title: "Rilevare il movimento laterale in Security.evtx"
description: "Come gli strumenti reali degli avversari si spostano da host a host nei parchi Windows, e le combinazioni precise di Event ID in Security.evtx che catturano PsExec, Impacket e WMIExec."
date: "2026-05-27"
tags:
  - evtx
  - lateral-movement
  - dfir
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

Il movimento laterale è dove la maggior parte delle intrusioni passa da „hanno un punto d'appoggio" a „possiedono il dominio". È anche dove il logging di Windows è al massimo della sua utilità e della sua ambiguità. Gli eventi che ti servono sono tutti in `Security.evtx` e `System.evtx`. Leggerli isolatamente non ti porta da nessuna parte. Leggerli nelle coppie giuste, con la corretta correlazione cross-host, è ciò che separa una timeline utile da un muro di `4624`.

Questa è la parte di un'indagine in cui smetto di scorrere e inizio a greppare per `LogonId`.

## Lo scheletro: cosa succede quando un attaccante si muove

Non esiste un pattern universale di movimento laterale, ma esiste una *forma* universale:

1. L'attaccante si autentica dall'host A all'host B, o col token dell'utente corrente (pass-the-hash, pass-the-ticket o un TGT/TGS Kerberos rubato) o con credenziali esplicite per un altro account.
2. Qualcosa sull'host B esegue il loro payload: un servizio, un'attività pianificata, un WMI process create, una sessione PowerShell remota o un'invocazione DCOM.
3. Tornano fuori per tooling, segreti o il prossimo hop.

Ogni passo lascia eventi. La domanda è se stai guardando quelli giusti, e se il tooling è stato strumentato del tutto.

## 4624 LogonType 3 è la porta d'ingresso

Un logon di rete riuscito, `EventID=4624` con `LogonType=3`, è la primitiva di movimento laterale più comune nel log. È anche l'evento più rumoroso che Windows genera. Un file server in un ufficio da 500 postazioni ne produce decine di migliaia al giorno, tutti legittimi. Filtrare solo per `LogonType=3` non ti porterà da nessuna parte.

Cosa ti porta da qualche parte:

- `IpAddress` e `WorkstationName` nei dati dell'evento. Le anomalie si raggruppano qui. Una workstation che fa logon su un server da una subnet diversa alle 02:14 UTC non è una bazzecola.
- `AuthenticationPackageName` e `LogonProcessName`. I logon NTLM (`NTLM` / `NtLmSsp`) tra host in dominio in un ambiente Kerberos sono sospetti per default. Un ambiente Kerberos pulito dovrebbe essere solo Kerberos per l'auth intra-dominio, con NTLM in fallback solo per accessi a nomi non-DNS e legacy.
- Pattern di `TargetUserName`. Account di servizio che si loggano interattivamente sono bandiere rosse. Account di domain admin che si loggano su workstation sono bandiere rosse.

Il pivot che vuoi: abbina ogni `4624 Type 3` interessante con il corrispondente `4672` (privilegi speciali) sullo stesso `TargetLogonId`. Se il logon ha ottenuto privilegi admin, hai un candidato per abuso di credenziali. Se no, l'attaccante opera con un token a privilegio inferiore e hai tempo.

## 4648 è l'evento che la maggior parte dei difensori sottoutilizza

`4648`, „è stato tentato un logon usando credenziali esplicite", viene generato quando un processo eseguito come account A invoca credenziali per l'account B per fare qualcosa. Questo è l'evento che vuoi per l'attribuzione. Quando `mimikatz` o `Rubeus` inietta un ticket e l'operatore esegue `net use \\TARGET /user:CORP\admin <pass>`, ottieni un `4648` sull'host originante che mostra entrambi gli account e il target.

I campi che contano:

- `SubjectUserName` / `SubjectLogonId`: chi ha iniziato.
- `TargetUserName` / `TargetServerName`: credenziali di chi, contro cosa.
- `ProcessName`: quale binario ha fatto l'invocazione. `cmd.exe`, `powershell.exe`, `wmic.exe`, `psexec.exe`, `wmiprvse.exe` (per esecuzione basata su WMI) e sempre più `pwsh.exe` sono i soliti sospetti.

`4648` è il legame tra un host compromesso e il prossimo hop. Se hai un host sospetto, scarica prima `4648` dal suo log Security. Ti dirà quali credenziali ha l'attaccante e dove ha tentato di usarle, in ordine temporale, in un unico posto.

## 4672 e la storia dei privilegi

`4672` viene lasciato immediatamente dopo `4624` per qualsiasi logon che finisca con almeno un privilegio sensibile (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, ecc.). Viene generato per ogni logon di un membro di `Administrators`, `Domain Admins` o di qualunque account con privilegi che elevano il token.

Trattalo come un tag, non come un finding. La query utile è „mostrami ogni `4672` seguito entro 60 secondi da un `4624 Type 3` da un IP sorgente non-DC", che fa emergere l'uso di token admin da workstation che non dovrebbero emetterli. La query non utile è „mostrami ogni `4672`", che restituirà ogni avvio di servizio su ogni server.

## 4697 e 7045: i servizi come esecuzione remota

PsExec, `psexec.py` di Impacket e `smbexec.py` funzionano scrivendo un binario di servizio sullo share `ADMIN$` del target, registrandolo tramite il Service Control Manager, avviandolo e smontandolo. Questo lascia:

- `5145` sul target che mostra l'accesso a `\\target\ADMIN$` col nome del file scritto (se l'auditing di accesso agli oggetti è attivo).
- `7045` in `System.evtx` che mostra l'installazione del servizio. Il path del binario del servizio e il nome del servizio sono nei dati dell'evento. PsExec usa per default `PSEXESVC` in `%SystemRoot%`; Impacket randomizza entrambi, con pattern che variano per versione e sono ben documentati.
- `4697` in `Security.evtx` per la stessa installazione di servizio se hai la policy di audit di sistema impostata.
- `4624 Type 3` dalla workstation sorgente dell'operatore.

La firma è la *combinazione*: `4624 Type 3` da una sorgente inusuale, immediatamente seguito da `5145` verso `ADMIN$`, immediatamente seguito da `7045` per un servizio il cui binario vive da qualche parte dove non dovrebbe. Ogni evento da solo è plausibile. La combinazione, in pochi secondi, con lo stesso `LogonId` a legarli, no.

Nomi di servizio da tenere d'occhio in `7045`: stringhe casuali di 8 caratteri minuscoli (default Impacket), `PSEXESVC` (default PsExec), `WinExec` o le sue varianti, qualunque cosa con un path di binario sotto `C:\Windows\` che non sia firmato e non sia nell'insieme normale dei servizi del sistema.

## 5140 e 5145: accesso a share SMB nel dettaglio

`5140` registra che è stato acceduto uno share; `5145` registra il nome del file acceduto all'interno dello share, *se* l'auditing di accesso agli oggetti per lo share è abilitato. La maggior parte degli ambienti non abilita `5145` per il rumore. La maggior parte degli ambienti vorrebbe anche averlo durante un incidente.

Per il movimento laterale, gli eventi `5145` che contano sono accessi ad `ADMIN$`, `C$`, `IPC$` e qualunque path `SYSVOL`/`NETLOGON` da sorgenti inusuali. `psexec.py` scrive il suo binario di servizio scrivendo in `\\target\ADMIN$\<random>.exe`. `secretsdump.py` legge `\\target\C$\Windows\System32\config\SAM` (e SYSTEM e SECURITY). Ciascuno di questi è un `5145` con un `RelativeTargetName` che dovrebbe spiccare.

Abbina `5145` al [journal USN](https://www.usnparser.com) sul target. Il journal avrà un `FILE_CREATE` per lo stesso file con lo stesso timestamp, il che ti dà una conferma da seconda fonte che il file è effettivamente arrivato, e un riferimento di record [MFT](https://www.mftparser.com) da inseguire.

## WMI come vettore di movimento laterale

L'esecuzione remota basata su WMI (`wmic /node:... process call create`, `wmiexec.py` di Impacket, `Invoke-WmiMethod` di PowerShell) è più difficile da individuare in Security.evtx da solo perché non installa un servizio. Ottieni:

- `4624 Type 3` sul target.
- Una creazione di processo sul target con `WmiPrvSE.exe` come parent. Questo è in Sysmon `EventID=1` se Sysmon è attivo. In `4688` è la stessa immagine se l'auditing della command-line è attivo.
- Eventi WMI in `Microsoft-Windows-WMI-Activity%4Operational.evtx` che mostrano il consumer.

Se Sysmon non è attivo, il movimento laterale basato su WMI è per lo più invisibile nei log eventi con config di default. Questo è uno dei motivi per cui ogni baseline di config spinge Sysmon con forza.

## Correlare tra host

Il movimento laterale è un problema di grafi. Un `4648` sull'host A che nomina l'host B e l'account `corp\admin` è un arco. Il `4624 Type 3` corrispondente sull'host B dall'IP dell'host A, con `TargetUserName=admin`, è l'altra estremità dello stesso arco. Il `4769` (ticket di servizio Kerberos) sul DC che mostra la richiesta di ticket per `cifs/hostB` da `admin@CORP` è il terzo testimone.

In pratica vuoi tutto di:

- Eventi di logon dal `Security.evtx` dell'host sorgente.
- Eventi di logon dal `Security.evtx` dell'host target.
- Eventi TGT (`4768`) e TGS (`4769`) dal `Security.evtx` del domain controller.
- Eventi inoltrati da qualunque collector WEC, che a volte hanno l'unica copia intatta se il log locale di un host è stato cancellato.

Legali tramite `LogonId` all'interno di un host e tramite timestamp + account + IP tra host. Il classico paper di JPCERT/CC lo espone nel dettaglio ed è il singolo migliore documento gratuito sul tema.

Per gli artefatti host-side che sopravvivono alla cancellazione del log, appoggiati a [Prefetch](https://www.prefetchparser.com) come prova di esecuzione del tooling dell'attaccante, alla chiave `Services` del [registro](https://www.registryparser.com) per la traccia di un binario di servizio installato e rimosso, e ai [file LNK](https://www.lnkparser.com) e alle [jump list](https://www.jumplistparser.com) come prova di file che un operatore ha aperto in una sessione hands-on.

## Per approfondire

- ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) di JPCERT/CC. Il riferimento. Leggilo due volte.
- La [matrice Lateral Movement](https://attack.mitre.org/tactics/TA0008/) di MITRE ATT&CK e i mapping di data source per tecnica.
- La [directory examples](https://github.com/fortra/impacket/tree/master/examples) di Impacket. Se non hai letto cosa fanno davvero `psexec.py`, `wmiexec.py` e `smbexec.py` sul cavo, le tue detection sono congetture.
