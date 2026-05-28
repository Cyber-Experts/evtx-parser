---
title: "Event ID 1102 erklärt: Security-Audit-Log geleert (und was überlebt)"
description: "1102 ist das eine Ereignis, das du nicht unterdrücken kannst, ohne mehr Beweise zu hinterlassen. Hier ist, was es dir sagt, was das Löschen überlebt und wo du suchst, wenn du es siehst."
date: "2026-05-17"
---

Event ID **1102** ist das, was Windows in den [`Security`-Kanal](/de/blog/what-is-an-evtx-file) schreibt, wenn jemand das Audit-Log leert. Es ist per Design einer der für einen Angreifer schwerer zu unterdrückenden Datensätze. Sauber zu unterdrücken erfordert entweder, die EventLog-Dienst-Binary zu ersetzen, bevor sie startet, oder zu akzeptieren, dass der Akt des Löschens ein eigenes 1102 hinterlässt. Die meisten Operatoren wählen die zweite Option und hoffen, dass niemand aufpasst.

Wenn du 1102 siehst, hat jemand mit ausreichendem Privileg den Audit-Trail absichtlich gewischt. Das ist praktisch nie eine routinemäßige Admin-Aktion, und wenn doch, sollte es ein Ticket geben. Behandle jedes 1102 außerhalb eines genehmigten Wartungsfensters als Vorfall, bis das Gegenteil bewiesen ist.

## Was im Datensatz steht

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

Beachte den `UserData`-Block statt des üblichen `EventData`. 1102 verwendet ein strukturiertes User-Data-Schema, was einige naive Parser stolpern lässt, die nur auf `EventData` schauen. Die Felder sagen dir, wer das Log unter welcher Anmeldesitzung geleert hat. Pivotiere auf `SubjectLogonId` zum passenden [4624](/de/blog/understanding-event-id-4624) und du hast die Quell-IP, den Logon-Typ und die Credential, die die privilegierte Sitzung erzeugt haben.

## Was nebenan reitet

Ein Log-Clear ist selten die einzige anti-forensische Aktion in der Kette. Die Datensätze, die in seiner Nähe feuern, grob chronologisch:

- **104** auf dem `System`-Kanal. Dieselbe Tat wie 1102, aber vom SCM für Nicht-Security-Kanäle aufgezeichnet. Wenn 104 vorhanden und 1102 fehlt, hat der Angreifer nur Security geleert und System vergessen.
- **4719**, „System-Audit-Richtlinie wurde geändert". Manchmal reduziert der Angreifer die Audit-Abdeckung *vor* dem Löschen, um beim nächsten Mal weniger Datensätze zu hinterlassen.
- **4616**, „die Systemzeit wurde geändert". Vor-Lösch-Timestomping macht die Timeline-Rekonstruktion schwieriger.
- Eine Lücke in 4624s in der Stunde oder zwei vor 1102. Der Angreifer hat möglicherweise einen nicht-geloggten Seitenkanal genutzt, um reinzukommen.

## Was ein Clear überlebt

Das Leeren des In-Memory-Event-Logs berührt nicht:

- Andere Kanäle. `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, Forwarded-Event-Kanäle. Keiner davon wird durch ein Security-Wipe geleert.
- Weitergeleitete Ereignisse. Wenn Windows Event Forwarding Security an einen Collector schickt, sind die geleerten Datensätze schon auf einem anderen Host. Die ursprünglichen RecordIDs und Zeitstempel sind erhalten.
- Die Datei auf der Festplatte selbst. Eine geleerte `Security.evtx` wird durch eine frische Datei ersetzt. Die Cluster der vorherigen Datei bleiben oft im nicht zugewiesenen Speicher bestehen. EVTX-Datensätze [carven sauber](/de/blog/carve-deleted-evtx-records) aus diesen Clustern.
- [USN-Journal](https://www.usnparser.com)-Einträge für die Dateiersetzung. Sogar der Akt des Löschens hinterlässt Artefakte auf Dateisystem-Ebene.
- Der [MFT](https://www.mftparser.com)-Eintrag für die neue Datei, der einen Erstellungszeitstempel trägt, der dem 1102 sekundengenau entsprechen sollte.

Ein „erfolgreicher" Log-Clear ist selten so sauber, wie der Angreifer hofft.

## Sigma: Log geleert

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

## KQL: Clear korreliert mit privilegierter Sitzung

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

Jedes 1102 verfolgt zurück zu einem [4672](/de/blog/event-id-4672-special-privileges), das `SeSecurityPrivilege` gewährt, das zurück zu einem [4624](/de/blog/understanding-event-id-4624) verfolgt. Der Join vervollständigt das Bild.

## Splunk: die Manipulationskette

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Eine LogonId, die die Audit-Richtlinie (4719) oder die Systemzeit (4616) berührt und dann ein Log geleert hat (1102/104), ist die Manipulationskette.

## ATT&CK-Mapping

- T1070.001 Indicator Removal: Clear Windows Event Logs. Die Schlagzeile. 1102 *ist* der primäre Indikator.
- T1562.002 Impair Defenses: Disable Windows Event Logging. 4719 vor 1102 mappt hier.
- T1070.006 Indicator Removal: Timestomp. Gepaart mit 4616 in derselben Kette.
- T1078.003 Valid Accounts: Local Accounts. 1102 durch einen lokalen Administrator, der zu dieser Zeit nicht angemeldet sein sollte.

## False Positives, selten aber real

- Migrations- oder Decom-Workflows. Techniker, die Logs auf einem außer Dienst gestellten Host leeren. Sollte immer ein Ticket haben.
- Forensische Labore, die während der Detection-Entwicklung Clear-and-Reproduce-Schleifen fahren.
- Einige Legacy-Tools leeren das Log, um „Baselines zurückzusetzen". Fast immer ein Verfahrensfehler, aber ein realer.

Es gibt keinen sicheren Grund für ein 1102 im normalen Betrieb. Sogar die legitimen sollten nachträglich untersucht und dokumentiert werden.

## Wenn du eines im Bundle findest

Wenn du eine [.evtx-Datei in ein forensisches Tool lädst](/de/blog/how-to-open-an-evtx-file), sind die ersten zwei Suchen, die sich lohnen, `EventID:1102` und `EventID:104`. Wenn eines davon vorhanden ist, hat das Log, das du in der Hand hältst, bekannte Lücken. Jede Timeline, die daraus gebaut ist, ist unvollständig. Notiere es deutlich im Report. Dann schau, was überlebt hat: die [Registry](https://www.registryparser.com), das [USN-Journal](https://www.usnparser.com), die [MFT](https://www.mftparser.com), [Prefetch](https://www.prefetchparser.com) und [AmCache](https://www.amcacheparser.com). Zusammen rekonstruieren sie das meiste, was 1102 zu löschen versuchte.

Tools wie `Invoke-Phant0m` überspringen 1102 komplett, indem sie die Event-Service-Threads suspendieren statt zu löschen. Wenn du ein mehrstündiges Schweigen in Security ohne 1102 und ohne System-Shutdown siehst, ist das die andere Form desselben Problems.

## Weiterführende Lektüre

- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [Microsoft-Dokumentation zu 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)
