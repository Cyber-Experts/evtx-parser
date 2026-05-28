---
title: "Event ID 1102 spiegato: log di audit Security cancellato (e cosa sopravvive)"
description: "1102 è l'unico evento che non puoi sopprimere senza lasciare più prove. Ecco cosa ti dice, cosa sopravvive alla cancellazione e dove guardare quando lo vedi."
date: "2026-05-17"
---

L'Event ID **1102** è ciò che Windows scrive sul [canale `Security`](/it/blog/what-is-an-evtx-file) quando qualcuno svuota il log di audit. Per design, è uno dei record più difficili da sopprimere per un attaccante. Sopprimerlo in modo pulito richiede o di sostituire il binario del servizio EventLog prima che si avvii, o di accettare che l'atto stesso di svuotare lasci un proprio 1102. La maggior parte degli operatori sceglie la seconda opzione, sperando che nessuno stia prestando attenzione.

Se vedi un 1102, qualcuno con privilegi sufficienti ha cancellato deliberatamente la traccia di audit. Non è praticamente mai un'azione admin di routine, e quando lo è, dovrebbe esserci un ticket. Tratta ogni 1102 fuori da una finestra di manutenzione approvata come un incidente fino a prova contraria.

## Cosa c'è nel record

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-1234-...-500</SubjectUserSid>
    <SubjectUserName>Administrator</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
    <SubjectLogonId>0x3e7</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

Nota il blocco `UserData` invece del solito `EventData`. 1102 usa uno schema strutturato user-data, che fa inciampare alcuni parser ingenui che guardano solo `EventData`. I campi ti dicono chi ha svuotato il log sotto quale sessione di logon. Pivota su `SubjectLogonId` verso il [4624](/it/blog/understanding-event-id-4624) corrispondente e hai l'IP sorgente, il tipo di logon e la credenziale che ha prodotto la sessione privilegiata.

## Cosa cavalca accanto

Una cancellazione di log raramente è l'unica azione anti-forense nella catena. I record che tendono a scattare nei pressi, in ordine cronologico approssimativo:

- **104** sul canale `System`. Stesso atto del 1102 ma registrato dall'SCM per canali non-Security. Se 104 è presente e 1102 manca, l'attaccante ha cancellato solo Security e si è dimenticato System.
- **4719**, „la policy di audit di sistema è stata modificata". A volte l'attaccante riduce la copertura di audit *prima* di cancellare, per lasciare meno record la prossima volta.
- **4616**, „l'orario di sistema è stato modificato". Il timestomping pre-cancellazione rende la ricostruzione della timeline più difficile.
- Una lacuna nei 4624 nell'ora o due precedenti il 1102. L'attaccante potrebbe aver usato un canale laterale non loggato per entrare.

## Cosa sopravvive a una cancellazione

Svuotare il log eventi in memoria non tocca:

- Altri canali. `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, canali di eventi inoltrati. Nessuno di questi viene svuotato da un wipe di Security.
- Eventi inoltrati. Se Windows Event Forwarding sta inviando Security a un collector, i record svuotati sono già su un altro host. I RecordID e i timestamp originanti sono preservati.
- Il file su disco stesso. Una `Security.evtx` svuotata viene sostituita da un file fresco. I cluster del file precedente persistono spesso nello spazio non allocato. I record EVTX [si carvano puliti](/it/blog/carve-deleted-evtx-records) da quei cluster.
- Le voci del [journal USN](https://www.usnparser.com) per la sostituzione del file. Anche l'atto di svuotare lascia artefatti a livello di filesystem.
- La voce [MFT](https://www.mftparser.com) per il nuovo file, che porta un timestamp di creazione che dovrebbe coincidere con il 1102 al secondo.

Una cancellazione di log „riuscita" è raramente così pulita come l'attaccante spera.

## Sigma: log svuotato

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared). Anti-forensic actions.
references:
  - https://attack.mitre.org/techniques/T1070/001/
logsource:
  product: windows
  service: security
detection:
  selection_security:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  selection_system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection_security or selection_system
falsepositives:
  - Legitimate administrative log clearing during maintenance (rare, should be ticketed)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

## KQL: cancellazione correlata a sessione privilegiata

```kusto
let clears =
    SecurityEvent
    | where EventID == 1102
    | project ClearTime=TimeGenerated, Host=Computer, ClearLogonId=SubjectLogonId,
              ClearUser=SubjectUserName;
let privileged =
    SecurityEvent
    | where EventID == 4672
    | project PrivTime=TimeGenerated, PrivLogonId=SubjectLogonId,
              PrivilegeList;
clears
| join kind=inner privileged on $left.ClearLogonId == $right.PrivLogonId
| project ClearTime, Host, ClearUser, PrivTime, PrivilegeList
| order by ClearTime desc
```

Ogni 1102 si traccia indietro a un [4672](/it/blog/event-id-4672-special-privileges) che concede `SeSecurityPrivilege`, che si traccia indietro a un [4624](/it/blog/understanding-event-id-4624). Il join completa il quadro.

## Splunk: la catena di manomissione

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Un LogonId che ha toccato la policy di audit (4719) o l'orario di sistema (4616) e poi ha svuotato un log (1102/104) è la catena di manomissione.

## Mapping ATT&CK

- T1070.001 Indicator Removal: Clear Windows Event Logs. Il titolo. 1102 *è* l'indicatore primario.
- T1562.002 Impair Defenses: Disable Windows Event Logging. 4719 prima di 1102 mappa qui.
- T1070.006 Indicator Removal: Timestomp. Abbinato a 4616 nella stessa catena.
- T1078.003 Valid Accounts: Local Accounts. 1102 da un Administrator locale che non avrebbe dovuto essere loggato in quel momento.

## Falsi positivi, rari ma reali

- Workflow di migrazione o decom. Tecnici che svuotano log su un host in dismissione. Dovrebbe sempre esserci un ticket.
- Laboratori forensi che eseguono loop di svuota-e-riproduci durante lo sviluppo di detection.
- Alcuni strumenti legacy svuotano il log per „resettare le baseline". Quasi sempre un errore procedurale, ma reale.

Non c'è una ragione sicura per un 1102 in operazioni normali. Anche quelli legittimi dovrebbero essere indagati e documentati a posteriori.

## Quando ne trovi uno nel bundle

Quando carichi un [file .evtx in uno strumento forense](/it/blog/how-to-open-an-evtx-file), le prime due ricerche che vale la pena eseguire sono `EventID:1102` e `EventID:104`. Se uno dei due è presente, il log che hai in mano ha lacune note. Qualsiasi timeline costruita su di esso è incompleta. Annotalo a chiare lettere nel report. Poi vai a vedere cosa è sopravvissuto: il [registro](https://www.registryparser.com), il [journal USN](https://www.usnparser.com), la [MFT](https://www.mftparser.com), il [prefetch](https://www.prefetchparser.com) e l'[AmCache](https://www.amcacheparser.com). Insieme ricostruiscono la maggior parte di ciò che 1102 ha tentato di cancellare.

Strumenti come `Invoke-Phant0m` saltano il 1102 del tutto sospendendo i thread del servizio eventi invece di svuotare. Se vedi un silenzio di più ore in Security senza 1102 e senza shutdown di sistema, questa è l'altra forma dello stesso problema.

## Per approfondire

- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [Documentazione Microsoft per 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)
