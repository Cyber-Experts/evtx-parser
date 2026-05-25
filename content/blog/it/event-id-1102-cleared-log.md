---
title: "Event ID 1102 spiegato: log di audit Security cancellato (e cosa sopravvive)"
description: "Il 1102 è l'unico evento che non puoi sopprimere senza lasciare ulteriori tracce. Ecco cosa ti dice e cosa sopravvive alla cancellazione."
date: "2026-05-17"
---

L'Event ID **1102** è il record che Windows scrive sul [canale `Security`](/it/blog/what-is-an-evtx-file) quando il log di audit viene cancellato. È — per progettazione — uno dei record più difficili da sopprimere per un attaccante, perché sopprimerlo richiede o di sostituire con successo il servizio EventLog prima del boot, o di accettare che l'atto di cancellare lasci a sua volta un 1102.

Per i difensori questo significa: se vedi un 1102, qualcuno con privilegi sufficienti ha deliberatamente cancellato la traccia di audit. Quasi mai è un'azione normale di un admin.

## Cosa contiene il record

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

Nota il blocco `UserData` al posto del solito `EventData` — 1102 è uno dei record che usa uno schema user-data strutturato. I campi ti dicono *chi* ha cancellato il log e sotto quale sessione di logon. Pivota su `SubjectLogonId` per trovare il [4624](/it/blog/understanding-event-id-4624) corrispondente e otterrai l'IP sorgente e il logon type che hanno prodotto la sessione privilegiata.

## Cosa scatta insieme al 1102

Una log clear è raramente l'*unica* azione anti-forense. Compagne comuni, in ordine cronologico approssimativo:

- **104** sul canale `System` — stesso atto, registrato dall'SCM. Se il 104 è presente ma manca il 1102, l'attaccante ha cancellato solo il Security log e si è dimenticato del System.
- **4719** — «System audit policy was changed». A volte un attaccante riduce la copertura di audit *prima* di cancellare, per lasciare meno record al giro successivo.
- **4616** — «The system time was changed». Uno skew temporale pre-cancellazione rende più difficile ricostruire la timeline.
- **Un gap nei 4624** per un'ora o due prima del 1102 — l'attaccante può aver usato un canale laterale non loggato.

## Cosa sopravvive a una cancellazione

Cancellare il log eventi in memoria non tocca:

- **Altri canali**: `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, canali forwarded — nessuno di questi viene cancellato dal wipe di Security.
- **Eventi forwarded**: se Windows Event Forwarding (WEF) è configurato verso un collector centrale, i record cancellati sono già su un altro host.
- **Il file su disco stesso**: un `Security.evtx` cancellato viene sostituito da un nuovo file; i cluster del file *eliminato* precedente spesso persistono nello spazio non allocato e possono essere carved con tool NTFS.
- **Voci nel journal USN** per la sostituzione del file: anche l'operazione di cancellazione lascia artefatti a livello di filesystem.

Una log clear «riuscita» è raramente così pulita come l'attaccante spera.

## Esempio di regola Sigma — log cancellato

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared) — anti-forensic actions.
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

Se vedi un 1102 al di fuori di una finestra di manutenzione approvata, trattalo come incidente — senza eccezioni.

## Esempio KQL — log clear + correlazione sessione privilegiata

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

Ogni 1102 riconduce a un [4672](/it/blog/event-id-4672-special-privileges) che concede `SeSecurityPrivilege` — che riconduce a un [4624](/it/blog/understanding-event-id-4624). La join completa il quadro.

## Esempio Splunk — catena anti-forense compagna

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Un `LogonId` che ha toccato l'audit policy (4719) o l'orario di sistema (4616) e poi ha cancellato un log (1102/104) è la catena di tampering.

## Mappatura ATT&CK

- **T1070.001 — Indicator Removal: Clear Windows Event Logs**: la tecnica di punta. Il 1102 *è* l'indicatore primario di questa tecnica.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: 4719 (cambio audit policy) che precede il 1102 mappa qui.
- **T1070.006 — Indicator Removal: Timestomp**: abbinato a 4616 (orario di sistema cambiato) nella stessa catena.
- **T1078.003 — Valid Accounts: Local Accounts**: 1102 da un Administrator locale che non avrebbe dovuto loggarsi in quell'orario.

## Falsi positivi — rari ma reali

- **Workflow di migrazione / dismissione**: tecnici che cancellano il log su un host che viene dismesso. Dovrebbe essere sempre tracciato con un ticket.
- **Lab forensi / di test**: workflow di clear-e-riproduzione durante lo sviluppo di detection.
- **Alcuni tool legacy** cancellano il log per resettare le baseline — quasi sempre un errore procedurale, ma reale.

Il segnale è così direttamente anti-forense che anche i 1102 legittimi andrebbero investigati e documentati a posteriori. Non esiste un motivo «sicuro» per un 1102 nelle operazioni normali.

## Perché conta per il parsing

Quando [carichi un file .evtx in un tool forense](/it/blog/how-to-open-an-evtx-file), la *prima* ricerca che vale la pena fare è `EventID:1102` e `EventID:104`. Se uno dei due è presente, il log che hai in mano ha gap noti e qualsiasi timeline costruita su di esso è incompleta. Annotalo chiaramente nel report.
